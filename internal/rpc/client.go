package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// clientEventBuffer is the demuxed event channel size. Sized for a
// discovery burst (a /24 scan can push ~250 device.discovered events
// back-to-back). Slow consumers still drop events past this point, but
// Dropped() makes the loss visible.
const clientEventBuffer = 512

// Client is a JSON-RPC 2.0 client that demuxes responses from server-pushed events.
type Client struct {
	conn    net.Conn
	br      *bufio.Reader
	writeMu sync.Mutex // serialises writes across concurrent Calls

	mu      sync.Mutex
	nextID  int
	pending map[int]chan *Response
	events  chan Event
	closed  bool

	// dropped counts events the readLoop discarded because events was
	// full (consumer too slow). Exposed via Dropped() so the TUI/CLI
	// can surface the loss instead of silently missing updates.
	dropped atomic.Uint64
}

// Dial connects to a daemon at sockPath.
func Dial(sockPath string) (*Client, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:    conn,
		br:      bufio.NewReader(conn),
		pending: map[int]chan *Response{},
		events:  make(chan Event, clientEventBuffer),
	}
	go c.readLoop()
	return c, nil
}

// Events returns a channel of server-pushed events. The channel is closed
// when the underlying connection is lost (including when Close is called).
func (c *Client) Events() <-chan Event { return c.events }

// Dropped returns the cumulative count of events the client had to discard
// because the consumer wasn't draining Events() fast enough. Monotonically
// increasing; non-zero values indicate the UI is missing state updates.
func (c *Client) Dropped() uint64 { return c.dropped.Load() }

// Close terminates the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.conn.Close()
}

// Call invokes method with params (any JSON-encodable value or nil) and
// decodes the response into out (pointer or nil).
func (c *Client) Call(ctx context.Context, method string, params any, out any) error {
	c.mu.Lock()
	if c.pending == nil {
		c.mu.Unlock()
		return errors.New("rpc: connection closed")
	}
	c.nextID++
	id := c.nextID
	ch := make(chan *Response, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	cleanup := func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}

	idBytes, _ := json.Marshal(id)
	var pb json.RawMessage
	if params != nil {
		pj, err := json.Marshal(params)
		if err != nil {
			cleanup()
			return err
		}
		pb = pj
	}
	req := Request{JSONRPC: "2.0", ID: idBytes, Method: method, Params: pb}
	line, _ := json.Marshal(req)
	c.writeMu.Lock()
	_, werr := c.conn.Write(append(line, '\n'))
	c.writeMu.Unlock()
	if werr != nil {
		cleanup()
		return werr
	}

	select {
	case resp, ok := <-ch:
		if !ok || resp == nil {
			return errors.New("rpc: connection closed before response")
		}
		if resp.Error != nil {
			return resp.Error
		}
		if out != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, out)
		}
		return nil
	case <-ctx.Done():
		cleanup()
		return ctx.Err()
	}
}

func (c *Client) readLoop() {
	defer close(c.events)
	for {
		line, err := c.br.ReadBytes('\n')
		if err != nil {
			c.mu.Lock()
			for _, ch := range c.pending {
				close(ch)
			}
			c.pending = nil
			c.mu.Unlock()
			return
		}
		// Frame is either Response (has "id") or Event (no "id" field, has "method").
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			continue
		}
		if len(probe.ID) > 0 && probe.Method == "" {
			var resp Response
			if err := json.Unmarshal(line, &resp); err != nil {
				continue
			}
			var idNum int
			_ = json.Unmarshal(resp.ID, &idNum)
			c.mu.Lock()
			ch, ok := c.pending[idNum]
			delete(c.pending, idNum)
			c.mu.Unlock()
			if ok {
				ch <- &resp
			}
			continue
		}
		if probe.Method != "" {
			var ev Event
			if err := json.Unmarshal(line, &ev); err == nil {
				select {
				case c.events <- ev:
				default:
					c.dropped.Add(1)
				}
			}
		}
	}
}

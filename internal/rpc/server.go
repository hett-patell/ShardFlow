package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Handler is a method handler.
type Handler func(ctx context.Context, params json.RawMessage) (result any, err *Error)

// clientSendQueue is the per-client outbound buffer. Size 256 is large
// enough to absorb a discovery burst (one Scan can produce ~hundreds of
// device events back-to-back) without blocking the broadcast goroutine.
const clientSendQueue = 256

// idleReadTimeout caps how long a client connection can sit silent before
// the server reaps it. The TUI re-issues DevicesList every 3s and the
// CLI Dial-then-die path closes immediately, so 10 minutes is generous
// for any real consumer. A wedged peer (half-open socket after laptop
// sleep, KILL'd shell, etc.) used to pin a serve goroutine forever;
// now it gets booted after this window.
const idleReadTimeout = 10 * time.Minute

// Server is a JSON-RPC 2.0 server with broadcast-event support.
//
// Broadcast model: each connected client gets a writer goroutine that
// drains its own bounded send queue. Broadcast appends to the queue and
// never blocks on slow/dead peers — a hung Unix socket on client A cannot
// stall events to client B. On Write error the client is pruned. On
// queue overflow event broadcasts are dropped (counted), while RPC
// responses force-disconnect the client (response loss desyncs the
// request stream).
type Server struct {
	handlers map[string]Handler

	mu       sync.Mutex
	clients  map[*client]struct{}
	listener net.Listener
}

type client struct {
	conn net.Conn
	send chan []byte   // pre-marshalled lines, \n-terminated
	done chan struct{} // closed exactly once when the client is gone

	dropped atomic.Uint64

	closeOnce sync.Once
}

// close marks the client as gone: closes done (signalling broadcasters and
// the writer to stop), then closes the underlying conn so an in-flight
// reader unblocks. Idempotent. Never closes c.send — closing the send
// channel would panic any concurrent broadcaster mid-send.
func (c *client) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

// NewServer constructs a Server with the given method table.
func NewServer(h map[string]Handler) *Server {
	return &Server{handlers: h, clients: map[*client]struct{}{}}
}

// Listen binds the Unix socket at path and serves until ctx is cancelled
// or Stop is called. The socket is created with mode 0600 (owner-only).
func (s *Server) Listen(ctx context.Context, path string) error {
	_ = os.Remove(path)
	// Set restrictive umask before creating the socket so it's never
	// exposed with permissive mode even briefly (avoids TOCTOU race
	// between net.Listen and os.Chmod).
	oldUmask := syscall.Umask(0o077)
	l, err := net.Listen("unix", path)
	syscall.Umask(oldUmask) // restore immediately
	if err != nil {
		return err
	}
	// Explicitly chmod to 0600 as a defense-in-depth measure — the umask
	// should have done it, but some systems have quirks.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return err
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = l.Close()
		_ = os.Remove(path)
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		c := &client{
			conn: conn,
			send: make(chan []byte, clientSendQueue),
			done: make(chan struct{}),
		}
		s.mu.Lock()
		s.clients[c] = struct{}{}
		s.mu.Unlock()
		go s.writer(c)
		go s.serve(ctx, c)
	}
}

// Stop closes the listener; in-flight connections drain naturally.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Broadcast sends a notification to every connected client. Non-blocking:
// queues onto each client's send channel, drops on overflow rather than
// stalling the caller. Dropped events are counted per client.
func (s *Server) Broadcast(method string, params any) {
	pb, _ := json.Marshal(params)
	ev := Event{JSONRPC: "2.0", Method: method, Params: pb}
	line, _ := json.Marshal(ev)
	line = append(line, '\n')

	s.mu.Lock()
	clients := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()

	for _, c := range clients {
		// Skip clients already torn down. The select below would also
		// notice via <-c.done, but checking up-front avoids racing
		// the send case against done when both are ready (Go select
		// picks randomly between ready cases).
		select {
		case <-c.done:
			continue
		default:
		}
		select {
		case c.send <- line:
		case <-c.done:
		default:
			c.dropped.Add(1)
		}
	}
}

// remove deletes the client from the active set and signals it closed.
// Idempotent.
func (s *Server) remove(c *client) {
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()
	c.close()
}

// writer drains the client's send queue to the wire. Exits when c.done
// fires or when Write fails (peer dead).
func (s *Server) writer(c *client) {
	defer s.remove(c)
	for {
		select {
		case <-c.done:
			return
		case line := <-c.send:
			if _, err := c.conn.Write(line); err != nil {
				return
			}
		}
	}
}

// serve reads requests from c.conn and dispatches each to its handler in
// its own goroutine. JSON-RPC 2.0 responses are id-keyed so out-of-order
// responses on the wire are demuxed correctly by the client; running the
// handlers concurrently keeps a slow Scan from blocking unrelated
// DevicesList / SessionGet / Stats calls on the same connection.
//
// Earlier versions called handlers synchronously here, which meant a
// 5-second active sweep also stalled every other request the TUI made
// during that window — the dashboard would freeze, show stale device
// counts, and on slow Wi-Fi (where Sweep blocks for many seconds on
// kernel TX backpressure) the whole UI could appear hung.
func (s *Server) serve(ctx context.Context, c *client) {
	defer s.remove(c)
	br := bufio.NewReader(c.conn)
	for {
		// Refresh the deadline before every read so an active client
		// (sending requests faster than idleReadTimeout) never trips it.
		// On error (EOF or timeout) we exit and remove the client; the
		// caller can Dial again if they meant to stay connected.
		_ = c.conn.SetReadDeadline(time.Now().Add(idleReadTimeout))
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.send(c, Response{JSONRPC: "2.0", Error: &Error{Code: CodeParseError, Message: err.Error()}})
			continue
		}
		h, ok := s.handlers[req.Method]
		if !ok {
			s.send(c, Response{JSONRPC: "2.0", ID: req.ID, Error: &Error{Code: CodeMethodNotFound, Message: "unknown method " + req.Method}})
			continue
		}
		go s.dispatch(ctx, c, h, req)
	}
}

// dispatch invokes a single handler and writes its response. Run in its
// own goroutine off the read loop so handlers don't serialise.
func (s *Server) dispatch(ctx context.Context, c *client, h Handler, req Request) {
	result, herr := h(ctx, req.Params)
	resp := Response{JSONRPC: "2.0", ID: req.ID}
	if herr != nil {
		resp.Error = herr
	} else {
		b, mErr := json.Marshal(result)
		if mErr != nil {
			resp.Error = &Error{Code: CodeInternalError, Message: mErr.Error()}
		} else {
			resp.Result = b
		}
	}
	s.send(c, resp)
}

// send queues a response line onto the client's send channel. Unlike
// events, dropping a response is fatal to the caller's RPC (Call() would
// hang on ctx.Done). On full queue we close the connection rather than
// silently desync the request/response stream — the client can Dial again.
func (s *Server) send(c *client, r Response) {
	b, _ := json.Marshal(r)
	b = append(b, '\n')
	select {
	case c.send <- b:
	case <-c.done:
	default:
		s.remove(c)
	}
}

// DroppedEvents returns the total events dropped across all live clients
// since their connections opened. Used by the daemon to emit a periodic
// warning when consumers can't keep up.
func (s *Server) DroppedEvents() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total uint64
	for c := range s.clients {
		total += c.dropped.Load()
	}
	return total
}

// HasClients reports whether any clients are currently connected. The
// daemon uses this to skip purely informational broadcasts (the 1 Hz
// counters tick) when nobody is listening — saves ~3500 idle Marshal+
// queue ops per hour with zero observable behaviour change.
func (s *Server) HasClients() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients) > 0
}

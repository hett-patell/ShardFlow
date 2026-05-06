package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
)

// Handler is a method handler.
type Handler func(ctx context.Context, params json.RawMessage) (result any, err *Error)

// Server is a JSON-RPC 2.0 server with broadcast-event support.
type Server struct {
	handlers map[string]Handler

	mu       sync.Mutex
	clients  map[*client]struct{}
	listener net.Listener
}

type client struct {
	conn net.Conn
	mu   sync.Mutex // serialises writes (response + events)
}

// NewServer constructs a Server with the given method table.
func NewServer(h map[string]Handler) *Server {
	return &Server{handlers: h, clients: map[*client]struct{}{}}
}

// Listen binds the Unix socket at path and serves until ctx is cancelled
// or Stop is called. The socket is removed at startup if stale, and at
// shutdown.
func (s *Server) Listen(ctx context.Context, path string) error {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		c := &client{conn: conn}
		s.mu.Lock()
		s.clients[c] = struct{}{}
		s.mu.Unlock()
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

// Broadcast sends a notification to every connected client.
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
		c.mu.Lock()
		_, _ = c.conn.Write(line)
		c.mu.Unlock()
	}
}

func (s *Server) serve(ctx context.Context, c *client) {
	defer func() {
		_ = c.conn.Close()
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
	}()
	br := bufio.NewReader(c.conn)
	for {
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
}

func (s *Server) send(c *client, r Response) {
	b, _ := json.Marshal(r)
	b = append(b, '\n')
	c.mu.Lock()
	_, _ = c.conn.Write(b)
	c.mu.Unlock()
}

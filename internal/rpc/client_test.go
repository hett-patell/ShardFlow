package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientCallReceivesResult(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		line, _ := br.ReadBytes('\n')
		var req Request
		_ = json.Unmarshal(line, &req)
		resp := Response{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`"pong"`)}
		b, _ := json.Marshal(resp)
		_, _ = conn.Write(append(b, '\n'))
	}()

	c, err := Dial(sock)
	require.NoError(t, err)
	defer c.Close()
	var res string
	require.NoError(t, c.Call(context.Background(), "ping", nil, &res))
	assert.Equal(t, "pong", res)
}

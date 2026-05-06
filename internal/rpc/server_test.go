package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerEchoesPing(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	srv := NewServer(map[string]Handler{
		"ping": func(_ context.Context, _ json.RawMessage) (any, *Error) {
			return "pong", nil
		},
	})
	go func() { _ = srv.Listen(context.Background(), sock) }()
	t.Cleanup(func() { _ = srv.Stop(); _ = os.Remove(sock) })

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sock)
	require.NoError(t, err)
	defer conn.Close()

	req := Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "ping"}
	b, _ := json.Marshal(req)
	_, _ = conn.Write(append(b, '\n'))

	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	require.NoError(t, err)
	var resp Response
	require.NoError(t, json.Unmarshal(line, &resp))
	require.Nil(t, resp.Error)
	var result string
	require.NoError(t, json.Unmarshal(resp.Result, &result))
	assert.Equal(t, "pong", result)
}

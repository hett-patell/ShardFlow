package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/policycompiler"
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

func TestSetPolicyConcurrentRMWDoesNotClobber(t *testing.T) {
	// Two concurrent setPolicy calls for different targets; both must
	// land in the compiler's current state. Without the applyMu serialise,
	// one would clobber the other via stale Snapshot.
	store := devicestore.New()
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	store.Upsert(devicestore.Observation{MAC: mac1, IP: net.ParseIP("10.0.0.1").To4()})
	store.Upsert(devicestore.Observation{MAC: mac2, IP: net.ParseIP("10.0.0.2").To4()})

	// Use the real Compiler with no-op fakes for effectors.
	nft := noopNFT{}
	tc := noopTC{}
	pc := noopPcap{}
	arp := noopARP{}
	comp := policycompiler.New(nft, tc, pc, arp, "lo")

	deps := &HandlerDeps{
		Store:    store,
		Compiler: comp,
		Scanner:  func(context.Context) error { return nil },
		GwMAC:    net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		GwIP:     net.ParseIP("10.0.0.254").To4(),
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, e := setPolicy(context.Background(), deps, PolicySpec{
			Target: mac1.String(), Kind: PolicyDrop,
		})
		if e != nil {
			t.Errorf("setPolicy(mac1): %v", e)
		}
	}()
	go func() {
		defer wg.Done()
		_, e := setPolicy(context.Background(), deps, PolicySpec{
			Target: mac2.String(), Kind: PolicyDrop,
		})
		if e != nil {
			t.Errorf("setPolicy(mac2): %v", e)
		}
	}()
	wg.Wait()

	snap := comp.Snapshot()
	require.Len(t, snap, 2, "both policies must survive the RMW serialisation")
}

// no-op effectors for testing.
type noopNFT struct{}

func (noopNFT) EnsureTables(context.Context, string) error                              { return nil }
func (noopNFT) AddTargetDrop(context.Context, net.HardwareAddr) error                   { return nil }
func (noopNFT) AddTargetMark(context.Context, net.HardwareAddr, uint32) error           { return nil }
func (noopNFT) AddReturnMark(context.Context, net.HardwareAddr, net.HardwareAddr, net.IP, uint32) error {
	return nil
}
func (noopNFT) RemoveTarget(context.Context, net.HardwareAddr) error { return nil }
func (noopNFT) Teardown(context.Context) error                       { return nil }

type noopTC struct{}

func (noopTC) EnsureIFB(context.Context) error                              { return nil }
func (noopTC) EnsureCaptureIface(context.Context) error                     { return nil }
func (noopTC) EnsureRedirect(context.Context, string) error                 { return nil }
func (noopTC) SetThrottle(context.Context, string, string, string, uint32) error { return nil }
func (noopTC) ClearThrottle(context.Context, string, string, uint32) error  { return nil }
func (noopTC) SetCapture(context.Context, string, uint32) error             { return nil }
func (noopTC) ClearCapture(context.Context, string, uint32) error           { return nil }
func (noopTC) Teardown(context.Context) error                               { return nil }

type noopPcap struct{}

func (noopPcap) Open(string, string, string, string, int64, time.Duration) error { return nil }
func (noopPcap) Close(string) error                                              { return nil }

type noopARP struct{}

func (noopARP) Start(arpengine.Target) error { return nil }
func (noopARP) Stop(arpengine.Target) error  { return nil }
func (noopARP) StopAll() error               { return nil }

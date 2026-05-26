package policycompiler

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
)

type fakeNFT struct{ calls []string }

func (f *fakeNFT) EnsureTables(_ context.Context, _ string) error {
	f.calls = append(f.calls, "EnsureTables")
	return nil
}
func (f *fakeNFT) AddTargetDrop(_ context.Context, mac net.HardwareAddr) error {
	f.calls = append(f.calls, "AddDrop:"+mac.String())
	return nil
}
func (f *fakeNFT) AddTargetMark(_ context.Context, mac net.HardwareAddr, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("AddMark:%s:%d", mac.String(), mark))
	return nil
}
func (f *fakeNFT) AddReturnMark(_ context.Context, mac, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("AddReturnMark:%s:%d", mac.String(), mark))
	return nil
}
func (f *fakeNFT) RemoveTarget(_ context.Context, mac net.HardwareAddr) error {
	f.calls = append(f.calls, "Remove:"+mac.String())
	return nil
}
func (f *fakeNFT) Teardown(_ context.Context) error { f.calls = append(f.calls, "Teardown"); return nil }

type fakeTC struct{ calls []string }

func (f *fakeTC) EnsureIFB(_ context.Context) error          { f.calls = append(f.calls, "EnsureIFB"); return nil }
func (f *fakeTC) EnsureCaptureIface(_ context.Context) error { f.calls = append(f.calls, "EnsureCap"); return nil }
func (f *fakeTC) EnsureRedirect(_ context.Context, _ string) error {
	f.calls = append(f.calls, "EnsureRedirect")
	return nil
}
func (f *fakeTC) SetThrottle(_ context.Context, _, mac, rate string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("SetThrottle:%s:%s:%d", mac, rate, mark))
	return nil
}
func (f *fakeTC) ClearThrottle(_ context.Context, _, mac string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("ClearThrottle:%s:%d", mac, mark))
	return nil
}
func (f *fakeTC) SetCapture(_ context.Context, _, _ string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("SetCapture:%d", mark))
	return nil
}
func (f *fakeTC) ClearCapture(_ context.Context, _ string, mark uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("ClearCapture:%d", mark))
	return nil
}
func (f *fakeTC) Teardown(_ context.Context) error { f.calls = append(f.calls, "TC.Teardown"); return nil }

type fakePcap struct{ calls []string }

func (f *fakePcap) Open(mac, _, _, _ string, _ int64, _ time.Duration) error {
	f.calls = append(f.calls, "Open:"+mac)
	return nil
}
func (f *fakePcap) Close(mac string) error {
	f.calls = append(f.calls, "Close:"+mac)
	return nil
}

type fakeARP struct{ calls []string }

func (f *fakeARP) Start(t arpengine.Target) error {
	f.calls = append(f.calls, "Start:"+t.MAC.String())
	return nil
}
func (f *fakeARP) Stop(t arpengine.Target) error {
	f.calls = append(f.calls, "Stop:"+t.MAC.String())
	return nil
}
func (f *fakeARP) StopAll() error { f.calls = append(f.calls, "StopAll"); return nil }

func TestApplyDropFromEmpty(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	nft, tc, pc, arp := &fakeNFT{}, &fakeTC{}, &fakePcap{}, &fakeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	desired := map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac, IP: net.ParseIP("10.0.0.42"), GwMAC: nil, GwIP: net.ParseIP("10.0.0.1")}, Kind: KindDrop},
	}
	err := c.Apply(context.Background(), desired)
	require.NoError(t, err)

	// Order: nft drop rule, then arp start.
	assert.Equal(t, []string{"AddDrop:aa:bb:cc:dd:ee:01"}, nft.calls)
	assert.Equal(t, []string{"Start:aa:bb:cc:dd:ee:01"}, arp.calls)
}

func TestApplyThrottleSequence(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	nft, tc, pc, arp := &fakeNFT{}, &fakeTC{}, &fakePcap{}, &fakeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	desired := map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac}, Kind: KindThrottle, RateKbit: 200},
	}
	require.NoError(t, c.Apply(context.Background(), desired))

	// nft is no longer in the throttle path (tc-flower matches src_mac
	// directly without an nft-mark intermediary; see compiler comment).
	assert.Empty(t, nft.calls)
	assert.Equal(t, fmt.Sprintf("SetThrottle:%s:200kbit:11", mac.String()), tc.calls[0])
	assert.Equal(t, "Start:"+mac.String(), arp.calls[0])
}

func TestApplyTransitionDropToThrottleTearsDownThenBringsUp(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")
	nft, tc, pc, arp := &fakeNFT{}, &fakeTC{}, &fakePcap{}, &fakeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	require.NoError(t, c.Apply(context.Background(), map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac}, Kind: KindDrop},
	}))
	require.NoError(t, c.Apply(context.Background(), map[string]Spec{
		mac.String(): {Target: arpengine.Target{MAC: mac}, Kind: KindThrottle, RateKbit: 50},
	}))

	assert.Contains(t, arp.calls, "Stop:"+mac.String())
	assert.True(t, containsPrefix(tc.calls, "SetThrottle:"+mac.String()+":50kbit:"))
}

func containsPrefix(haystack []string, prefix string) bool {
	for _, s := range haystack {
		if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// slowSafeNFT is a goroutine-safe NFT fake whose RemoveTarget blocks
// for a configurable delay, used to assert that Phase 1 teardown runs
// in parallel across targets.
type slowSafeNFT struct {
	mu        sync.Mutex
	calls     []string
	removeDel time.Duration
}

func (f *slowSafeNFT) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}
func (f *slowSafeNFT) EnsureTables(_ context.Context, _ string) error { return nil }
func (f *slowSafeNFT) AddTargetDrop(_ context.Context, mac net.HardwareAddr) error {
	f.record("AddDrop:" + mac.String())
	return nil
}
func (f *slowSafeNFT) AddTargetMark(_ context.Context, mac net.HardwareAddr, mark uint32) error {
	return nil
}
func (f *slowSafeNFT) AddReturnMark(_ context.Context, _, _ net.HardwareAddr, _ net.IP, _ uint32) error {
	return nil
}
func (f *slowSafeNFT) RemoveTarget(_ context.Context, mac net.HardwareAddr) error {
	time.Sleep(f.removeDel)
	f.record("Remove:" + mac.String())
	return nil
}
func (f *slowSafeNFT) Teardown(_ context.Context) error { return nil }

type safeARP struct {
	mu    sync.Mutex
	calls []string
}

func (f *safeARP) Start(t arpengine.Target) error {
	f.mu.Lock()
	f.calls = append(f.calls, "Start:"+t.MAC.String())
	f.mu.Unlock()
	return nil
}
func (f *safeARP) Stop(t arpengine.Target) error {
	f.mu.Lock()
	f.calls = append(f.calls, "Stop:"+t.MAC.String())
	f.mu.Unlock()
	return nil
}
func (f *safeARP) StopAll() error { return nil }

// TestApplyTearsDownInParallel: with 4 drop policies each whose
// RemoveTarget takes 200ms, sequential teardown would take >=800ms.
// Parallel teardown should complete in ~200ms (one delay's worth).
// We tolerate >=2x speedup as the assertion (so a 1-CPU CI runner with
// scheduling overhead still passes).
func TestApplyTearsDownInParallel(t *testing.T) {
	nft := &slowSafeNFT{removeDel: 200 * time.Millisecond}
	tc, pc, arp := &fakeTC{}, &fakePcap{}, &safeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	// Bring up 4 drop policies.
	desired := map[string]Spec{}
	const n = 4
	for i := 0; i < n; i++ {
		m, _ := net.ParseMAC(fmt.Sprintf("aa:bb:cc:dd:ee:%02x", 0xa0+i))
		desired[m.String()] = Spec{Target: arpengine.Target{MAC: m}, Kind: KindDrop}
	}
	require.NoError(t, c.Apply(context.Background(), desired))

	// Now tear them all down — pass empty desired so Phase 1 evicts all
	// 4. Measure wallclock.
	start := time.Now()
	require.NoError(t, c.Apply(context.Background(), map[string]Spec{}))
	elapsed := time.Since(start)

	// Sequential would be n * 200ms = 800ms. Parallel should be ~200ms.
	// Assert <500ms (>= 1.6x speedup) — generous to absorb scheduler
	// jitter on shared CI hardware.
	assert.Less(t, elapsed, 500*time.Millisecond,
		"4 teardowns × 200ms each must run in parallel (got %v, want <500ms)", elapsed)

	// All 4 Remove calls should have landed (order is non-deterministic).
	nft.mu.Lock()
	var removes []string
	for _, s := range nft.calls {
		if len(s) > 7 && s[:7] == "Remove:" {
			removes = append(removes, s)
		}
	}
	nft.mu.Unlock()
	assert.Len(t, removes, n, "every target must have its Remove called")
}

func TestSnapshotDeepCopiesTargetSlices(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:04")
	nft, tc, pc, arp := &fakeNFT{}, &fakeTC{}, &fakePcap{}, &fakeARP{}
	c := New(nft, tc, pc, arp, "eth0")

	require.NoError(t, c.Apply(context.Background(), map[string]Spec{
		mac.String(): {Target: arpengine.Target{
			MAC:   mac,
			IP:    net.ParseIP("10.0.0.42").To4(),
			GwMAC: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			GwIP:  net.ParseIP("10.0.0.1").To4(),
		}, Kind: KindDrop},
	}))

	snap := c.Snapshot()
	got := snap[mac.String()]
	// Mutate the returned slice fields and verify the compiler's internal
	// state is unaffected.
	got.Target.IP[0] = 0xff
	got.Target.GwMAC[0] = 0xff

	again := c.Snapshot()[mac.String()]
	assert.Equal(t, "10.0.0.42", again.Target.IP.String(), "Snapshot must deep-copy Target.IP")
	assert.Equal(t, "11:22:33:44:55:66", again.Target.GwMAC.String(), "Snapshot must deep-copy Target.GwMAC")
}

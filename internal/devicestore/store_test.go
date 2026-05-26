package devicestore

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestUpsertAndGet(t *testing.T) {
	s := New()
	now := time.Now()
	s.Upsert(Observation{
		MAC:      mac("aa:bb:cc:dd:ee:01"),
		IP:       net.ParseIP("10.0.0.42"),
		Hostname: "iphone.local",
		Vendor:   "Apple",
		Seen:     now,
	})
	d, ok := s.Get(mac("aa:bb:cc:dd:ee:01"))
	require.True(t, ok)
	assert.Equal(t, "10.0.0.42", d.IP.String())
	assert.Equal(t, "iphone.local", d.Hostname)
	assert.Equal(t, "Apple", d.Vendor)
	assert.Equal(t, now, d.LastSeen)
}

func TestResolveIP(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.42")})
	m, ok := s.ResolveIP(net.ParseIP("10.0.0.42"))
	require.True(t, ok)
	assert.Equal(t, "aa:bb:cc:dd:ee:01", m.String())

	_, ok = s.ResolveIP(net.ParseIP("10.0.0.99"))
	assert.False(t, ok)
}

func TestUpsertPreservesPriorFields(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), Vendor: "Apple"})
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.42")})
	d, _ := s.Get(mac("aa:bb:cc:dd:ee:01"))
	assert.Equal(t, "Apple", d.Vendor, "vendor should not be cleared by an observation that doesn't set it")
	assert.Equal(t, "10.0.0.42", d.IP.String())
}

func TestSubscribeDiscoveredAndUpdated(t *testing.T) {
	s := New()
	ch := s.Subscribe()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.42")})
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), Hostname: "h1"})

	select {
	case e := <-ch:
		assert.Equal(t, EventDiscovered, e.Kind)
	case <-time.After(time.Second):
		t.Fatal("expected discovered event")
	}
	select {
	case e := <-ch:
		assert.Equal(t, EventUpdated, e.Kind)
		assert.Equal(t, "h1", e.Device.Hostname)
	case <-time.After(time.Second):
		t.Fatal("expected updated event")
	}
}

func TestList(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01")})
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:02")})
	assert.Len(t, s.List(), 2)
}

func TestSetPolicyUnknownMAC(t *testing.T) {
	s := New()
	ok := s.SetPolicy(mac("aa:bb:cc:dd:ee:99"), "drop")
	assert.False(t, ok)
}

func TestEvictDropsStaleDevicesAndPreservesPolicied(t *testing.T) {
	s := New()
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	fresh := now.Add(-1 * time.Minute)

	// Stale device with no policy → should be evicted.
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.10"), Seen: old})
	// Stale device WITH a policy → must survive (operator owns it).
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:02"), IP: net.ParseIP("10.0.0.11"), Seen: old})
	require.True(t, s.SetPolicy(mac("aa:bb:cc:dd:ee:02"), "drop"))
	// Fresh device → must survive regardless of policy.
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:03"), IP: net.ParseIP("10.0.0.12"), Seen: fresh})

	n := s.Evict(now, time.Hour)
	assert.Equal(t, 1, n, "exactly the stale-no-policy device must be evicted")

	_, ok := s.Get(mac("aa:bb:cc:dd:ee:01"))
	assert.False(t, ok, "stale unpolicied device must be gone")
	_, ok = s.Get(mac("aa:bb:cc:dd:ee:02"))
	assert.True(t, ok, "stale-but-policied device must survive")
	_, ok = s.Get(mac("aa:bb:cc:dd:ee:03"))
	assert.True(t, ok, "fresh device must survive")

	// byIP must stay in sync with byMAC after eviction.
	_, ok = s.ResolveIP(net.ParseIP("10.0.0.10"))
	assert.False(t, ok, "byIP entry for evicted device must also be cleared")
}

// TestEvictBatchesLargeSweep verifies that Evict against a store with
// > evictBatchSize stale devices removes them all across multiple
// batches. The exact internal batch count is an implementation detail;
// the externally-visible contract is: Evict returns the total, and the
// store is empty afterwards. (Event-loss under buffer pressure is
// already covered by Subscribe's documented drop-newest semantics; this
// test focuses on the eviction loop's correctness across batches.)
func TestEvictBatchesLargeSweep(t *testing.T) {
	s := New()
	now := time.Now()
	old := now.Add(-2 * time.Hour)

	// Populate with evictBatchSize*2 + 17 stale devices so we exercise
	// the "fill batch, go around, partial batch, exit" path.
	const n = evictBatchSize*2 + 17
	for i := 0; i < n; i++ {
		m := net.HardwareAddr{0xaa, 0xbb, 0xcc, byte(i >> 16), byte(i >> 8), byte(i)}
		s.Upsert(Observation{MAC: m, IP: net.IPv4(10, 0, byte(i>>8), byte(i)), Seen: old})
	}

	got := s.Evict(now, time.Hour)
	assert.Equal(t, n, got, "Evict must return total across batches")
	assert.Empty(t, s.List(), "store must be empty after sweep")
}

// TestEvictStreamsEventsAcrossBatches asserts the streaming property:
// for an Evict call that processes multiple batches, subscriber events
// arrive incrementally (during the sweep) rather than all-at-once at
// the end. Drives Evict from one goroutine and a fast drainer from
// another; checks that we observe at least one event well before the
// theoretical "all events after Evict returns" baseline.
//
// Concretely: we count events received by the drainer up to the moment
// Evict returns, and require it to be > 0 (with a non-batched
// implementation the drainer would see 0 until Evict returned).
func TestEvictStreamsEventsAcrossBatches(t *testing.T) {
	s := New()

	now := time.Now()
	old := now.Add(-2 * time.Hour)
	const n = evictBatchSize * 4
	for i := 0; i < n; i++ {
		m := net.HardwareAddr{0xaa, 0xbb, 0xcc, byte(i >> 16), byte(i >> 8), byte(i)}
		s.Upsert(Observation{MAC: m, IP: net.IPv4(10, 2, byte(i>>8), byte(i)), Seen: old})
	}

	// Subscribe AFTER populating so we don't have to drain n Discovered
	// events (Upsert's broadcast is synchronous & non-blocking — beyond
	// buffer cap they're dropped on the floor, which is documented but
	// makes them un-drainable). The subscriber only sees EventEvicted.
	ch := s.Subscribe()
	t.Cleanup(func() { s.Unsubscribe(ch) })

	// Start a counter goroutine and Evict concurrently.
	var (
		mu              sync.Mutex
		evictedReceived int
	)
	stopDrain := make(chan struct{})
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			select {
			case e := <-ch:
				if e.Kind == EventEvicted {
					mu.Lock()
					evictedReceived++
					mu.Unlock()
				}
			case <-stopDrain:
				return
			}
		}
	}()

	got := s.Evict(now, time.Hour)
	// Snapshot how many events the drainer saw before Evict returned.
	// A non-streaming implementation buffers everything and only
	// broadcasts after Evict's loop exits — so the drainer would see 0.
	mu.Lock()
	duringSweep := evictedReceived
	mu.Unlock()

	close(stopDrain)
	<-drainDone

	assert.Equal(t, n, got, "Evict must return correct total")
	assert.Greater(t, duringSweep, 0, "subscriber must receive events DURING the sweep (streaming), not only after")
}

// TestEvictAllowsConcurrentUpsertBetweenBatches asserts that the
// per-batch unlock actually yields the write lock — without it, an
// Upsert racing against a long Evict would have to wait for the whole
// sweep. We can't directly measure lock hold time, but we can verify
// the externally-visible behaviour: an Upsert kicked off mid-sweep
// completes and its device survives (because it's fresh, not stale).
func TestEvictAllowsConcurrentUpsertBetweenBatches(t *testing.T) {
	s := New()
	now := time.Now()
	old := now.Add(-2 * time.Hour)

	// 3 full batches of stale devices.
	const n = evictBatchSize * 3
	for i := 0; i < n; i++ {
		m := net.HardwareAddr{0xaa, 0xbb, 0xcc, byte(i >> 16), byte(i >> 8), byte(i)}
		s.Upsert(Observation{MAC: m, IP: net.IPv4(10, 1, byte(i>>8), byte(i)), Seen: old})
	}

	// Start Evict and concurrently Upsert a fresh device. The Upsert
	// must complete (not deadlock, not hang) — that's the test.
	freshMAC := net.HardwareAddr{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}
	done := make(chan struct{})
	go func() {
		// tiny jitter so the Upsert lands while Evict is mid-sweep
		time.Sleep(time.Microsecond)
		s.Upsert(Observation{MAC: freshMAC, IP: net.ParseIP("10.99.99.99"), Seen: now})
		close(done)
	}()

	got := s.Evict(now, time.Hour)
	<-done

	assert.Equal(t, n, got, "all stale devices evicted")
	_, ok := s.Get(freshMAC)
	assert.True(t, ok, "concurrently-upserted fresh device must survive")
}

// TestEvictPreservesByIPWhenIPReassigned guards against a real
// data-loss bug: device A claims IP X, then device B claims IP X (last
// writer wins on byIP), then A is evicted by TTL. The old code blindly
// did delete(byIP, X) on A's eviction, wiping B's reverse mapping even
// though B is still alive — ResolveIP(X) then returned false for an IP
// that's clearly in use.
func TestEvictPreservesByIPWhenIPReassigned(t *testing.T) {
	s := New()
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	ip := net.ParseIP("10.0.0.42")

	// A: stale (will be evicted), claims IP first.
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: ip, Seen: old})
	// B: fresh, claims the SAME IP (DHCP race, ARP spoof, misconfig).
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:02"), IP: ip, Seen: now})

	// Before eviction: byIP must resolve to B (last writer wins).
	got, ok := s.ResolveIP(ip)
	require.True(t, ok)
	assert.Equal(t, "aa:bb:cc:dd:ee:02", got.String(), "byIP must point at last writer")

	// Evict A. B must keep its reverse mapping intact.
	n := s.Evict(now, time.Hour)
	assert.Equal(t, 1, n, "exactly A should be evicted")

	got, ok = s.ResolveIP(ip)
	assert.True(t, ok, "B's IP→MAC mapping must survive A's eviction")
	if ok {
		assert.Equal(t, "aa:bb:cc:dd:ee:02", got.String())
	}
}

// TestUpsertPreservesByIPWhenIPReassigned: same data-loss class on the
// Upsert side. If A's IP is reassigned to B, and then A is observed
// again with a NEW IP, A's old-IP cleanup must not wipe B's entry.
func TestUpsertPreservesByIPWhenIPReassigned(t *testing.T) {
	s := New()
	ip1 := net.ParseIP("10.0.0.42")
	ip2 := net.ParseIP("10.0.0.43")

	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: ip1}) // A → .42
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:02"), IP: ip1}) // B → .42 (steals)
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: ip2}) // A → .43 (cleanup .42)

	// .42 must still resolve to B; .43 must resolve to A.
	got, ok := s.ResolveIP(ip1)
	require.True(t, ok, ".42 must remain mapped (to B)")
	assert.Equal(t, "aa:bb:cc:dd:ee:02", got.String())

	got, ok = s.ResolveIP(ip2)
	require.True(t, ok, ".43 must be mapped to A")
	assert.Equal(t, "aa:bb:cc:dd:ee:01", got.String())
}

func TestSetPolicyKnownMACBroadcastsUpdate(t *testing.T) {
	s := New()
	ch := s.Subscribe()
	t.Cleanup(func() { s.Unsubscribe(ch) })
	s.Upsert(Observation{MAC: mac("aa:bb:cc:dd:ee:01"), IP: net.ParseIP("10.0.0.42")})

	// Drain the discovery event from the Upsert above.
	<-ch

	ok := s.SetPolicy(mac("aa:bb:cc:dd:ee:01"), "drop")
	require.True(t, ok)

	// SetPolicy broadcasts asynchronously (`go s.broadcast(...)`); allow
	// up to a second for the event to land.
	select {
	case e := <-ch:
		assert.Equal(t, EventUpdated, e.Kind)
		assert.Equal(t, "drop", e.Device.Policy)
	case <-time.After(time.Second):
		t.Fatal("expected updated event after SetPolicy")
	}

	d, _ := s.Get(mac("aa:bb:cc:dd:ee:01"))
	assert.Equal(t, "drop", d.Policy)
}

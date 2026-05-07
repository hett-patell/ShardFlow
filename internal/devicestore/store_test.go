package devicestore

import (
	"net"
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

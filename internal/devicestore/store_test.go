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

package oui

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupKnownVendor(t *testing.T) {
	mac, _ := net.ParseMAC("3C:22:FB:AA:BB:CC") // Apple
	v := Lookup(mac)
	assert.Contains(t, v, "Apple")
}

func TestLookupUnknownVendor(t *testing.T) {
	// Locally-administered MACs have no IEEE OUI assignment, so Lookup
	// must return "". 02:* is the canonical "locally administered" prefix.
	mac, _ := net.ParseMAC("02:00:00:AA:BB:CC")
	v := Lookup(mac)
	assert.Equal(t, "", v)
}

func TestLookupShortMAC(t *testing.T) {
	assert.Equal(t, "", Lookup(net.HardwareAddr{0x01, 0x02}))
}

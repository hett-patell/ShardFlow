package iface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupLoopback(t *testing.T) {
	info, err := Lookup("lo")
	require.NoError(t, err)
	assert.Equal(t, "lo", info.Name)
	assert.Greater(t, info.Index, 0)
}

func TestLookupMissing(t *testing.T) {
	_, err := Lookup("definitely-not-a-real-iface-xyz")
	assert.Error(t, err)
}

func TestLookupGuaranteesNonNilIPv4(t *testing.T) {
	// `lo` on Linux always has 127.0.0.1; the contract is that on success
	// IP and IPNet are non-nil. This test guards against future refactors
	// that would let nil-IP through.
	info, err := Lookup("lo")
	require.NoError(t, err)
	require.NotNil(t, info.IP, "IP must be non-nil on success")
	require.NotNil(t, info.IPNet, "IPNet must be non-nil on success")
	assert.Equal(t, "127.0.0.1", info.IP.String())
}

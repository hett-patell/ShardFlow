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

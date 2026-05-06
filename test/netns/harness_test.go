//go:build integration
// +build integration

package netns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupAndPing(t *testing.T) {
	require.NoError(t, Setup())
	t.Cleanup(func() { _ = Teardown() })

	out, err := InNS("lab-vic", "ping", "-c", "1", "-W", "1", "10.0.99.1")
	require.NoError(t, err, string(out))
	require.True(t, strings.Contains(string(out), "1 received"))
}

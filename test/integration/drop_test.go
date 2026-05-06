//go:build integration
// +build integration

package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestDropPolicyBlocksPing(t *testing.T) {
	startDaemon(t)
	scanAndAwaitVictim(t)

	out, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
		"policy", "set", "10.0.99.42", "drop")
	require.NoError(t, err, string(out))

	time.Sleep(2 * time.Second)

	pingOut, _ := netns.InNS("lab-vic", "ping", "-c", "1", "-W", "2", "10.0.99.1")
	require.False(t, strings.Contains(string(pingOut), "1 received"),
		"expected ping to fail under drop policy, got: %s", string(pingOut))

	out, err = netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
		"policy", "clear", "10.0.99.42")
	require.NoError(t, err, string(out))
	time.Sleep(2 * time.Second)
	pingOut, err = netns.InNS("lab-vic", "ping", "-c", "1", "-W", "2", "10.0.99.1")
	require.NoError(t, err, string(pingOut))
	require.True(t, strings.Contains(string(pingOut), "1 received"))
}

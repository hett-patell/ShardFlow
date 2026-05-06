//go:build integration
// +build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestPcapPolicyWritesFile(t *testing.T) {
	startDaemon(t)
	scanAndAwaitVictim(t)

	pcapDir := t.TempDir()
	out, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
		"policy", "set", "10.0.99.42", "pcap", pcapDir)
	require.NoError(t, err, string(out))

	for i := 0; i < 5; i++ {
		_, _ = netns.InNS("lab-vic", "ping", "-c", "1", "10.0.99.1")
		time.Sleep(200 * time.Millisecond)
	}

	entries, err := os.ReadDir(pcapDir)
	require.NoError(t, err)
	var found bool
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pcapng") {
			continue
		}
		fi, err := os.Stat(filepath.Join(pcapDir, e.Name()))
		require.NoError(t, err)
		if fi.Size() > 28 {
			found = true
			break
		}
	}
	require.True(t, found, "expected at least one non-empty .pcapng in %s", pcapDir)
}

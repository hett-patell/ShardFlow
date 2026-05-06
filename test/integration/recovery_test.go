//go:build integration
// +build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestRecoveryRefusesOrphanedNFTTable(t *testing.T) {
	require.NoError(t, netns.Setup())
	t.Cleanup(func() { _ = netns.Teardown() })

	_, err := netns.InNS("lab-op", "nft", "add", "table", "inet", "shardflow")
	require.NoError(t, err)

	build := exec.Command("go", "build", "-o", "/tmp/shardflowd", "./cmd/shardflowd")
	build.Dir = repoRoot()
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "build shardflowd: %s", buildOut)

	cmd := exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force")
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	require.True(t, strings.Contains(string(out), "orphaned"), "expected refusal message, got: %s", out)

	// With --clean-on-start: should start successfully. We assert the daemon
	// reaches "ready" by polling for its Unix socket — a simple Sleep +
	// ProcessState check would falsely pass even if the daemon exited
	// immediately, since ProcessState is nil until Wait() is called.
	cmd = exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force", "--clean-on-start")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	ready := false
	for i := 0; i < 50; i++ {
		if _, err := os.Stat("/tmp/sf.sock"); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, ready, "expected daemon to create /tmp/sf.sock under --clean-on-start within timeout")
}

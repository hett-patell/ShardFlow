//go:build integration
// +build integration

package integration

import (
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

	cmd = exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force", "--clean-on-start")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	time.Sleep(1 * time.Second)
	require.True(t, cmd.ProcessState == nil || !cmd.ProcessState.Exited(),
		"expected daemon to be running with --clean-on-start")
}

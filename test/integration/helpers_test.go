//go:build integration
// +build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

// repoRoot returns the absolute path to the repository root. Needed because
// `go test` sets cwd to the test package directory, so `go build ./cmd/...`
// would not resolve module paths without an explicit cmd.Dir.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// file: <repo>/test/integration/helpers_test.go
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func startDaemon(t *testing.T) {
	t.Helper()
	require.NoError(t, netns.Setup())
	t.Cleanup(func() { _ = netns.Teardown() })

	// Strip any stale socket from a prior test before launching, so the
	// post-Start polling can't see a leftover and report ready prematurely.
	_ = os.Remove("/tmp/sf.sock")

	build := exec.Command("go", "build", "-o", "/tmp/shardflowd", "./cmd/shardflowd")
	build.Dir = repoRoot()
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build shardflowd: %s", out)

	build = exec.Command("go", "build", "-o", "/tmp/shardflow", "./cmd/shardflow")
	build.Dir = repoRoot()
	out, err = build.CombinedOutput()
	require.NoError(t, err, "build shardflow: %s", out)

	daemon := exec.Command("ip", "netns", "exec", "lab-op",
		"/tmp/shardflowd", "-i", "eth0", "-sock", "/tmp/sf.sock", "--force", "--clean-on-start")
	daemon.Stdout = os.Stderr
	daemon.Stderr = os.Stderr
	require.NoError(t, daemon.Start())
	t.Cleanup(func() { _ = daemon.Process.Kill() })

	// Poll for the socket plus a real connectivity check — `test -S` only
	// proves the inode exists; an actual dial proves the daemon is past
	// srv.Listen and accepting connections.
	for i := 0; i < 100; i++ {
		if _, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock", "devices", "list", "--json"); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("daemon socket /tmp/sf.sock did not become reachable")
}

func scanAndAwaitVictim(t *testing.T) {
	t.Helper()
	scan, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock", "scan")
	require.NoError(t, err, string(scan))
	for i := 0; i < 50; i++ {
		out, _ := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
			"devices", "list", "--json")
		if strings.Contains(string(out), "10.0.99.42") {
			// Warm lab-vic's ARP cache for the gateway. Real-world targets
			// have chatty caches; arpengine relies on its gratuitous replies
			// updating an *existing* entry (Linux's default arp_accept=0
			// ignores unsolicited gratuitous replies that would create new
			// entries). Without this, the poison silently no-ops.
			_, _ = netns.InNS("lab-vic", "ping", "-c", "1", "-W", "1", "10.0.99.1")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("victim 10.0.99.42 not observed within timeout")
}

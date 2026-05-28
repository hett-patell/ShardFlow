// Package nftmgr is the typed wrapper around nft(8). Owns two tables:
//   - inet shardflow / forward_chain     — drop rules for the drop policy
//   - netdev shardflow_ingress / ingress — mark rules for throttle and pcap
package nftmgr

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// cmdTimeout caps every nft invocation so a wedged kernel transaction
// (rare but possible under heavy contention) cannot hang the policy
// compiler — which would block every Policy.Set/Clear handler waiting
// on the same mutex. 10s is generous for real nft transactions while
// short enough that an operator notices the failure and can react.
const cmdTimeout = 10 * time.Second

// withTimeout returns a derived context bounded by cmdTimeout, plus its
// cancel func. If parent already has a tighter deadline we leave it.
func withTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	if dl, ok := parent.Deadline(); ok && time.Until(dl) < cmdTimeout {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, cmdTimeout)
}

// Runner runs a nft(8) command. Tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, args []string) ([]byte, error)
	// RunScript pipes a multi-line nft script to `nft -f -`. Used for
	// initialisation where we want one atomic transaction containing
	// chain definitions whose curly-brace bodies are awkward to express
	// as a single argv element.
	RunScript(ctx context.Context, script string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, args []string) ([]byte, error) {
	tCtx, cancel := withTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(tCtx, "nft", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("nft %v: %w: %s", args, err, out.String())
	}
	return out.Bytes(), nil
}

func (execRunner) RunScript(ctx context.Context, script string) ([]byte, error) {
	tCtx, cancel := withTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(tCtx, "nft", "-f", "-")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Stdin = bytes.NewBufferString(script)
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("nft -f - (script): %w: %s", err, out.String())
	}
	return out.Bytes(), nil
}

// Manager owns the two ShardFlow nft tables. Not safe for concurrent use;
// callers (policycompiler) serialise.
type Manager struct {
	r Runner
}

func New() *Manager                   { return &Manager{r: execRunner{}} }
func NewWithRunner(r Runner) *Manager { return &Manager{r: r} }

// EnsureTables creates both tables and chains in one atomic nft transaction
// piped via `nft -f -`. Using stdin sidesteps any argv-quoting concerns
// around the curly-brace chain definition bodies.
func (m *Manager) EnsureTables(ctx context.Context, realIface string) error {
	// realIface comes from iface.Lookup which calls net.InterfaceByName;
	// IFNAMSIZ caps it at 15 bytes with no spaces or shell metacharacters,
	// so direct interpolation is safe.
	script := fmt.Sprintf(`
add table inet %s
add chain inet %s %s { type filter hook forward priority 0; policy accept; }
add table netdev %s
add chain netdev %s %s { type filter hook ingress device %s priority 0; policy accept; }
`, dropTableName,
		dropTableName, dropChainName,
		markTableName,
		markTableName, markChainName, realIface)
	_, err := m.r.RunScript(ctx, script)
	return err
}

func (m *Manager) AddTargetDrop(ctx context.Context, mac net.HardwareAddr) error {
	// Add egress rule: blocks traffic FROM victim (victim → gateway)
	if _, err := m.r.Run(ctx, argvAddDropRuleEgress(mac)); err != nil {
		return fmt.Errorf("add egress drop rule: %w", err)
	}
	// Add ingress rule: blocks traffic TO victim (gateway → victim)
	if _, err := m.r.Run(ctx, argvAddDropRuleIngress(mac)); err != nil {
		// Rollback the egress rule we just added. RemoveTarget finds all
		// rules tagged with this MAC's comment and deletes them.
		_ = m.RemoveTarget(ctx, mac)
		return fmt.Errorf("add ingress drop rule: %w", err)
	}
	return nil
}

// AddTargetMark inserts the netdev-ingress rule that sets fwmark on frames
// from mac. The same mark is then matched by tc redirect / mirror filters.
func (m *Manager) AddTargetMark(ctx context.Context, mac net.HardwareAddr, mark uint32) error {
	_, err := m.r.Run(ctx, argvAddMarkRule(mac, mark))
	return err
}

// AddReturnMark adds the second rule for bidirectional policies (pcap):
// matches gateway-sourced frames bound for the target and applies the same
// mark. Both rules share a comment tag for cleanup by RemoveTarget.
func (m *Manager) AddReturnMark(ctx context.Context, mac, gwMAC net.HardwareAddr, targetIP net.IP, mark uint32) error {
	_, err := m.r.Run(ctx, argvAddReturnMarkRule(mac, gwMAC, targetIP, mark))
	return err
}

// RemoveTarget deletes every rule that mentions the given MAC across both
// tables, by parsing handle ids from `nft -a list`. Returns the first
// non-table-missing error so the compiler can keep in-memory state in sync
// with kernel state. List failures with output containing "No such file"
// are tolerated; other list errors and any delete error surface.
func (m *Manager) RemoveTarget(ctx context.Context, mac net.HardwareAddr) error {
	tables := []struct {
		listArgs             []string
		family, table, chain string
	}{
		{argvListDropTable(), dropTableFamily, dropTableName, dropChainName},
		{argvListMarkTable(), markTableFamily, markTableName, markChainName},
	}
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, t := range tables {
		out, err := m.r.Run(ctx, t.listArgs)
		if err != nil {
			if nftMissing(out) {
				continue
			}
			record(fmt.Errorf("list %s/%s: %w", t.family, t.table, err))
			continue
		}
		handles := parseRuleHandlesForMAC(out, mac)
		for _, h := range handles {
			_, derr := m.r.Run(ctx, []string{"delete", "rule", t.family, t.table, t.chain, "handle", h})
			record(derr)
		}
	}
	return firstErr
}

func (m *Manager) Teardown(ctx context.Context) error {
	var firstErr error
	for _, args := range [][]string{argvFlushDropTable(), argvDeleteDropTable(), argvFlushMarkTable(), argvDeleteMarkTable()} {
		out, err := m.r.Run(ctx, args)
		if err != nil && firstErr == nil && !nftMissing(out) {
			firstErr = err
		}
	}
	return firstErr
}

// nftMissing returns true when nft output indicates the table being
// flushed/deleted didn't exist — treated as idempotent success.
func nftMissing(out []byte) bool {
	for _, marker := range []string{"No such file or directory", "could not process rule"} {
		if bytes.Contains(out, []byte(marker)) {
			return true
		}
	}
	return false
}

// parseRuleHandlesForMAC scans `nft -a list` output for `comment "shardflow:<mac>"`
// tags and returns the handle ids of every matching rule. Both egress and
// return-direction rules carry the same tag so a single MAC keys them all.
func parseRuleHandlesForMAC(out []byte, mac net.HardwareAddr) []string {
	// Match the exact nft-printed comment form, including double-quotes,
	// so user comments containing the substring don't false-match.
	tag := `"shardflow:` + mac.String() + `"`
	var handles []string
	for _, line := range bytes.Split(out, []byte("\n")) {
		s := string(line)
		if !strings.Contains(s, tag) || !strings.Contains(s, "# handle ") {
			continue
		}
		idx := strings.Index(s, "# handle ")
		fs := strings.Fields(s[idx+len("# handle "):])
		if len(fs) == 0 {
			continue
		}
		handles = append(handles, fs[0])
	}
	return handles
}

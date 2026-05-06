// Package tcmgr wraps tc(8) and ip(8) for ShardFlow's data-plane: the
// shardflow0 IFB iface (throttle), the shardflow-cap dummy iface
// (capture), and the per-real-iface ingress qdisc plus the fw-match
// filters that redirect or mirror marked frames.
package tcmgr

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

const (
	IFBName     = "shardflow0"
	CaptureName = "shardflow-cap"
)

// Runner abstracts tc/ip invocation for testability.
type Runner interface {
	Run(ctx context.Context, bin string, args []string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, bin string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %v: %w: %s", bin, args, err, out.String())
	}
	return out.Bytes(), nil
}

// Manager owns the IFB + capture-dummy ifaces and per-target HTB classes.
// Class IDs and fwmarks are not allocated here — policycompiler passes them
// in. The HTB class id is deterministic (`1:<mark>`), so SetThrottle and
// ClearThrottle both derive it from the mark; no per-mac state is kept,
// which means a failed cleanup is fully retryable.
type Manager struct {
	r Runner
}

func New() *Manager {
	return &Manager{r: execRunner{}}
}

func NewWithRunner(r Runner) *Manager {
	return &Manager{r: r}
}

// classIDFor returns the deterministic HTB class id for a given fwmark.
func classIDFor(mark uint32) string {
	return "1:" + strconv.FormatUint(uint64(mark), 10)
}

// EnsureIFB creates shardflow0 (idempotent), sets it up, attaches root HTB.
func (m *Manager) EnsureIFB(ctx context.Context) error {
	if out, err := m.r.Run(ctx, "ip", argvAddIFB(IFBName)); err != nil && !isExisting(out) {
		return fmt.Errorf("add ifb: %w", err)
	}
	if _, err := m.r.Run(ctx, "ip", argvSetUp(IFBName)); err != nil {
		return fmt.Errorf("set up ifb: %w", err)
	}
	if out, err := m.r.Run(ctx, "tc", argvAddRootHTB(IFBName)); err != nil && !isExisting(out) {
		return fmt.Errorf("add root htb: %w", err)
	}
	return nil
}

// EnsureCaptureIface creates shardflow-cap (dummy) and brings it up. The
// pcapwriter reads frames mirrored here.
func (m *Manager) EnsureCaptureIface(ctx context.Context) error {
	if out, err := m.r.Run(ctx, "ip", argvAddDummy(CaptureName)); err != nil && !isExisting(out) {
		return fmt.Errorf("add dummy: %w", err)
	}
	if _, err := m.r.Run(ctx, "ip", argvSetUp(CaptureName)); err != nil {
		return fmt.Errorf("set up dummy: %w", err)
	}
	return nil
}

// EnsureRedirect installs an ingress qdisc on the operator's real iface so
// later filters have somewhere to attach. Idempotent.
func (m *Manager) EnsureRedirect(ctx context.Context, realIface string) error {
	if out, err := m.r.Run(ctx, "tc", argvAddIngressQdisc(realIface)); err != nil && !isExisting(out) {
		return fmt.Errorf("add ingress qdisc on %s: %w", realIface, err)
	}
	return nil
}

// SetThrottle adds an HTB class for a target at the given rate, plus a flow
// filter on the IFB iface that maps the fwmark to that class, plus a
// redirect filter on the real iface ingress. Caller (the compiler) supplies
// the mark; mark must already be set on the frame by nftmgr's netdev-ingress
// chain.
//
// Atomicity: self-rollbacking. On failure of any step the already-completed
// steps are reversed before returning. No per-mac bookkeeping — class id is
// derived from the mark, so a failed cleanup is fully retryable.
func (m *Manager) SetThrottle(ctx context.Context, realIface, mac, rate string, mark uint32) error {
	classID := classIDFor(mark)
	if _, err := m.r.Run(ctx, "tc", argvAddHTBClass(IFBName, classID, rate)); err != nil {
		return err
	}
	if _, err := m.r.Run(ctx, "tc", argvAddFlowFilterByMark(IFBName, mark, classID)); err != nil {
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return err
	}
	if _, err := m.r.Run(ctx, "tc", argvAddRedirectFilter(realIface, mark, IFBName)); err != nil {
		_, _ = m.r.Run(ctx, "tc", argvDelFlowFilterByMark(IFBName, mark))
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return err
	}
	_ = mac // kept for symmetry / future diagnostics
	return nil
}

// ClearThrottle removes every tc object SetThrottle added for the target.
// Always runs every step (no in-memory short-circuit) so a failed previous
// cleanup is fully retryable. "Object missing" outputs are tolerated as
// idempotent success.
func (m *Manager) ClearThrottle(ctx context.Context, realIface, mac string, mark uint32) error {
	classID := classIDFor(mark)

	var firstErr error
	record := func(out []byte, err error) {
		if err == nil || isMissing(out) || firstErr != nil {
			return
		}
		firstErr = err
	}
	out, err := m.r.Run(ctx, "tc", argvDelFilterByMark(realIface, mark, "1"))
	record(out, err)
	out, err = m.r.Run(ctx, "tc", argvDelFlowFilterByMark(IFBName, mark))
	record(out, err)
	out, err = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
	record(out, err)
	_ = mac
	return firstErr
}

// SetCapture installs a mirror filter on real iface ingress that copies
// marked frames to the shardflow-cap dummy iface.
func (m *Manager) SetCapture(ctx context.Context, realIface string, mark uint32) error {
	_, err := m.r.Run(ctx, "tc", argvAddMirrorFilter(realIface, mark, CaptureName))
	return err
}

func (m *Manager) ClearCapture(ctx context.Context, realIface string, mark uint32) error {
	out, err := m.r.Run(ctx, "tc", argvDelFilterByMark(realIface, mark, "2"))
	if err != nil && !isMissing(out) {
		return err
	}
	return nil
}

// Teardown removes both ShardFlow ifaces. The real iface's ingress qdisc is
// left in place because removing it would also destroy any unrelated tc
// state; per-mark filters were already cleared by ClearThrottle /
// ClearCapture (the daemon's shutdown calls comp.Apply with empty desired
// before this). Returns the first non-missing error encountered.
func (m *Manager) Teardown(ctx context.Context) error {
	var firstErr error
	for _, name := range []string{IFBName, CaptureName} {
		out, err := m.r.Run(ctx, "ip", argvDelLink(name))
		if err != nil && !isMissing(out) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// isMissing returns true when iproute2/tc/ip output indicates the object
// being deleted didn't exist — treated as success (idempotent cleanup).
func isMissing(out []byte) bool {
	for _, marker := range []string{"Cannot find", "does not exist", "No such file", "RTNETLINK answers: No such"} {
		if bytes.Contains(out, []byte(marker)) {
			return true
		}
	}
	return false
}

// isExisting returns true when iproute2/tc/ip output indicates the object
// being added already exists — treated as success (idempotent setup).
func isExisting(out []byte) bool {
	for _, marker := range []string{"File exists", "already exists", "Exclusivity flag"} {
		if bytes.Contains(out, []byte(marker)) {
			return true
		}
	}
	return false
}

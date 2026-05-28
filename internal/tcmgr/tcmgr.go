// Package tcmgr wraps tc(8) and ip(8) for ShardFlow's data-plane: the
// shardflow0 IFB iface (upload throttle), an egress HTB on the real iface
// (download throttle), the shardflow-cap dummy iface (capture), and the
// per-real-iface ingress qdisc plus the fw-match filters that redirect or
// mirror marked frames.
//
// Throttle is BIDIRECTIONAL:
//   - UPLOAD (victim → internet): ingress filter on real iface redirects
//     src_mac=victim frames to shardflow0 IFB, where an HTB class shapes them
//   - DOWNLOAD (internet → victim): egress filter on real iface matches
//     dst_mac=victim and directs to an HTB class on the real iface's root qdisc
package tcmgr

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// cmdTimeout caps every ip/tc invocation. Same rationale as nftmgr's:
// a wedged netlink call must not hang the policy compiler.
const cmdTimeout = 10 * time.Second

func withTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	if dl, ok := parent.Deadline(); ok && time.Until(dl) < cmdTimeout {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, cmdTimeout)
}

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
	tCtx, cancel := withTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(tCtx, bin, args...)
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
// in. The HTB class id is deterministic (`1:<hex mark>`), so SetThrottle and
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

// classIDFor returns the deterministic HTB class id for a given mark.
// Uses hex format to match iproute2's parsing convention, avoiding the
// ambiguity where "1:10" could be parsed as decimal 10 or hex 0x10.
// Format: "1:<hex>" e.g. mark=11 → "1:b", mark=255 → "1:ff".
//
// Mark 0xffff is reserved for the default HTB class (catch-all for
// unclassified traffic). The policy compiler allocates marks starting
// at 10 and increments, so it would take 65k+ allocations to hit this
// boundary — but defensive: classIDFor returns "1:fffe" for mark=0xffff
// to never produce the default class id.
func classIDFor(mark uint32) string {
	if mark == 0xffff {
		mark = 0xfffe
	}
	return fmt.Sprintf("1:%x", mark)
}

// EnsureIFB creates shardflow0 (idempotent), sets it up, attaches root HTB,
// and creates the default HTB class for unclassified traffic.
func (m *Manager) EnsureIFB(ctx context.Context) error {
	if out, err := m.r.Run(ctx, "ip", argvAddIFB(IFBName)); err != nil && !isExisting(out) {
		return fmt.Errorf("add ifb: %w", err)
	}
	if _, err := m.r.Run(ctx, "ip", argvSetUp(IFBName)); err != nil {
		return fmt.Errorf("set up ifb: %w", err)
	}
	// Root HTB qdisc (replace is idempotent).
	if _, err := m.r.Run(ctx, "tc", argvAddRootHTB(IFBName)); err != nil {
		return fmt.Errorf("add root htb: %w", err)
	}
	// Default class for unclassified traffic (idempotent: class add fails
	// harmlessly if class already exists).
	if out, err := m.r.Run(ctx, "tc", argvAddDefaultHTBClass(IFBName)); err != nil && !isExisting(out) {
		return fmt.Errorf("add default htb class: %w", err)
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

// EnsureRedirect installs an ingress qdisc AND an egress HTB qdisc on the
// operator's real iface. The ingress qdisc is for redirect/mirror filters;
// the egress HTB is for download throttling (dst_mac matching).
//
// CRITICAL: The egress HTB includes a default class (1:ffff) so unclassified
// traffic (the host's own traffic!) isn't dropped. Without this, replacing
// the iface's native root qdisc (noqueue on wireless, fq_codel on wired)
// would break host networking.
func (m *Manager) EnsureRedirect(ctx context.Context, realIface string) error {
	// Ingress qdisc for upload-direction filters (redirect to IFB).
	if out, err := m.r.Run(ctx, "tc", argvAddIngressQdisc(realIface)); err != nil && !isExisting(out) {
		return fmt.Errorf("add ingress qdisc on %s: %w", realIface, err)
	}
	// Egress HTB qdisc for download-direction shaping (dst_mac filter).
	// Using replace makes this idempotent and handles pre-existing qdiscs.
	if _, err := m.r.Run(ctx, "tc", argvAddEgressHTB(realIface)); err != nil {
		return fmt.Errorf("add egress htb on %s: %w", realIface, err)
	}
	// Default class for unclassified traffic — MUST exist or host breaks.
	if out, err := m.r.Run(ctx, "tc", argvAddDefaultHTBClass(realIface)); err != nil && !isExisting(out) {
		return fmt.Errorf("add default htb class on %s: %w", realIface, err)
	}
	return nil
}

// SetThrottle enforces bandwidth limiting on a target bidirectionally:
//
//   - UPLOAD (victim → internet): flower filter on real iface ingress matches
//     src_mac=victim, redirects to shardflow0 IFB; an HTB class on the IFB
//     shapes at `rate`.
//
//   - DOWNLOAD (internet → victim): flower filter on real iface egress matches
//     dst_mac=victim, directs to an HTB class on the real iface's root qdisc
//     which shapes at `rate`.
//
// The mark argument is used as a stable, target-unique tc filter priority and
// HTB class id (in hex). On failure, partial state is rolled back.
func (m *Manager) SetThrottle(ctx context.Context, realIface, mac, rate string, mark uint32) error {
	classID := classIDFor(mark)
	prio := mark & 0x7FFF // pack into uint16 (0..32767), pcap uses 0x8000+

	// --- UPLOAD PATH (victim → internet via IFB) ---

	// 1. HTB class on IFB for upload shaping.
	if _, err := m.r.Run(ctx, "tc", argvAddHTBClass(IFBName, classID, rate)); err != nil {
		return fmt.Errorf("add ifb htb class: %w", err)
	}

	// 2. Flower filter on IFB that directs src_mac=victim to that class.
	if _, err := m.r.Run(ctx, "tc", argvAddFlowFilterByMAC(IFBName, mac, classID, prio)); err != nil {
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return fmt.Errorf("add ifb flow filter: %w", err)
	}

	// 3. Redirect filter on real iface ingress: src_mac=victim → IFB.
	if _, err := m.r.Run(ctx, "tc", argvAddRedirectFilterByMAC(realIface, mac, IFBName, prio)); err != nil {
		_, _ = m.r.Run(ctx, "tc", argvDelFlowFilterByPrio(IFBName, prio))
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return fmt.Errorf("add ingress redirect filter: %w", err)
	}

	// --- DOWNLOAD PATH (internet → victim via real iface egress) ---

	// 4. HTB class on real iface egress for download shaping.
	if _, err := m.r.Run(ctx, "tc", argvAddHTBClass(realIface, classID, rate)); err != nil {
		// Rollback upload path.
		_, _ = m.r.Run(ctx, "tc", argvDelFilterByPrio(realIface, prio))
		_, _ = m.r.Run(ctx, "tc", argvDelFlowFilterByPrio(IFBName, prio))
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return fmt.Errorf("add egress htb class: %w", err)
	}

	// 5. Flower filter on real iface egress: dst_mac=victim → egress HTB class.
	if _, err := m.r.Run(ctx, "tc", argvAddEgressShapeFilterByMAC(realIface, mac, classID, prio)); err != nil {
		// Rollback everything.
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(realIface, classID))
		_, _ = m.r.Run(ctx, "tc", argvDelFilterByPrio(realIface, prio))
		_, _ = m.r.Run(ctx, "tc", argvDelFlowFilterByPrio(IFBName, prio))
		_, _ = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
		return fmt.Errorf("add egress shape filter: %w", err)
	}

	return nil
}

// ClearThrottle removes every tc object SetThrottle added for the target.
// Always runs every step (no in-memory short-circuit) so a failed previous
// cleanup is fully retryable. "Object missing" outputs are tolerated as
// idempotent success.
func (m *Manager) ClearThrottle(ctx context.Context, realIface, mac string, mark uint32) error {
	classID := classIDFor(mark)
	prio := mark & 0x7FFF

	var firstErr error
	record := func(out []byte, err error) {
		if err == nil || isMissing(out) || firstErr != nil {
			return
		}
		firstErr = err
	}

	// Download path cleanup (egress).
	out, err := m.r.Run(ctx, "tc", argvDelEgressFilterByPrio(realIface, prio))
	record(out, err)
	out, err = m.r.Run(ctx, "tc", argvDelHTBClass(realIface, classID))
	record(out, err)

	// Upload path cleanup (ingress + IFB).
	out, err = m.r.Run(ctx, "tc", argvDelFilterByPrio(realIface, prio))
	record(out, err)
	out, err = m.r.Run(ctx, "tc", argvDelFlowFilterByPrio(IFBName, prio))
	record(out, err)
	out, err = m.r.Run(ctx, "tc", argvDelHTBClass(IFBName, classID))
	record(out, err)

	_ = mac
	return firstErr
}

// SetCapture installs flower mirror filters on real iface that copy frames
// FROM the victim (ingress: src_mac=victim) AND TO the victim (egress:
// dst_mac=victim) to the shardflow-cap dummy iface (where pcapwriter reads
// them). prio is the mark — stable per-target.
func (m *Manager) SetCapture(ctx context.Context, realIface, mac string, mark uint32) error {
	// pcap uses prio=mark|0x8000 to keep it disjoint from throttle's prio
	// (so a single MAC can have both policies without filter collision in
	// theory — though in practice policies are mutually exclusive).
	prio := (mark & 0x7FFF) | 0x8000

	// Ingress mirror: src_mac=victim (upload direction).
	if _, err := m.r.Run(ctx, "tc", argvAddMirrorFilterByMAC(realIface, mac, CaptureName, prio)); err != nil {
		return fmt.Errorf("add ingress mirror filter: %w", err)
	}

	// Egress mirror: dst_mac=victim (download direction).
	if _, err := m.r.Run(ctx, "tc", argvAddReturnMirrorFilterByMAC(realIface, mac, CaptureName, prio)); err != nil {
		// Rollback ingress mirror.
		_, _ = m.r.Run(ctx, "tc", argvDelFilterByPrio(realIface, prio))
		return fmt.Errorf("add egress mirror filter: %w", err)
	}

	return nil
}

func (m *Manager) ClearCapture(ctx context.Context, realIface string, mark uint32) error {
	prio := (mark & 0x7FFF) | 0x8000

	var firstErr error
	record := func(out []byte, err error) {
		if err == nil || isMissing(out) || firstErr != nil {
			return
		}
		firstErr = err
	}

	// Egress mirror cleanup.
	out, err := m.r.Run(ctx, "tc", argvDelEgressFilterByPrio(realIface, prio))
	record(out, err)

	// Ingress mirror cleanup.
	out, err = m.r.Run(ctx, "tc", argvDelFilterByPrio(realIface, prio))
	record(out, err)

	return firstErr
}

// Teardown removes both ShardFlow ifaces and the ingress+egress qdiscs on
// the real iface. Returns the first non-missing error encountered.
//
// Order: delete filters' backing qdiscs first (ingress, egress), then the
// ifaces. This avoids "device busy" errors from lingering mirred targets.
func (m *Manager) Teardown(ctx context.Context, realIface string) error {
	var firstErr error
	record := func(out []byte, err error) {
		if err != nil && !isMissing(out) && firstErr == nil {
			firstErr = err
		}
	}

	// Delete qdiscs on real iface first (removes all attached filters).
	if realIface != "" {
		out, err := m.r.Run(ctx, "tc", argvDelIngressQdisc(realIface))
		record(out, err)
		out, err = m.r.Run(ctx, "tc", argvDelEgressHTB(realIface))
		record(out, err)
	}

	// Then delete the IFB and capture ifaces.
	for _, name := range []string{IFBName, CaptureName} {
		out, err := m.r.Run(ctx, "ip", argvDelLink(name))
		record(out, err)
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

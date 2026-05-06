package policycompiler

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
)

// Compiler orchestrates the four effectors.
type Compiler struct {
	nft       NFT
	tc        TC
	pcap      Pcap
	arp       ARP
	realIface string

	mu       sync.RWMutex
	current  map[string]Spec   // key: MAC.String()
	markOf   map[string]uint32 // key: MAC.String() — deterministic per-target fwmark
	nextMark uint32
}

// New constructs a compiler bound to the operator's real iface (used by
// nft and tc when installing per-target rules and filters).
func New(nft NFT, tc TC, pcap Pcap, arp ARP, realIface string) *Compiler {
	return &Compiler{
		nft: nft, tc: tc, pcap: pcap, arp: arp,
		realIface: realIface,
		current:   map[string]Spec{},
		markOf:    map[string]uint32{},
		nextMark:  10, // start at 10 so 1..9 are reserved for future use
	}
}

// markFor returns the stable fwmark for mac, allocating one on first use.
func (c *Compiler) markFor(mac string) uint32 {
	if m, ok := c.markOf[mac]; ok {
		return m
	}
	c.nextMark++
	c.markOf[mac] = c.nextMark
	return c.nextMark
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

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Phase 1: tear down (best-effort across all targets).
	for mac, cur := range c.current {
		want, ok := desired[mac]
		if !ok || want.Kind != cur.Kind {
			if err := c.tearDownOne(ctx, cur); err != nil {
				record(err)
				continue
			}
			delete(c.current, mac)
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

	for i, st := range steps {
		if err := st.do(); err != nil {
			// Run the failing step's own undo first — its do() may have
			// partially applied state. Then unwind earlier successful steps.
			_ = st.undo()
			for j := i - 1; j >= 0; j-- {
				_ = steps[j].undo()
			}
			return fmt.Errorf("step %d: %w", i, err)
		}
	}
	return nil
}

func (c *Compiler) tearDownOne(ctx context.Context, s Spec) error {
	macStr := s.Target.MAC.String()
	mark := c.markFor(macStr)

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

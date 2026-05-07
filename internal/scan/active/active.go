// Package active sends ARP requests to every IP in a CIDR and feeds
// observed replies into a callback.
package active

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/oui"
)

// sendBudget is the wall-clock cap on the ARP send phase. Independent of
// how many hosts the CIDR contains: on a fast LAN /16 finishes the send
// phase in ~6.5s with our 100µs pacing, on a contended Wi-Fi link each
// WritePacketData can block on kernel TX backpressure for tens of
// milliseconds and a full /16 then takes minutes. We'd rather cover the
// first ~hundreds of IPs (which are typically the operator's own /24,
// since the kernel iterates the CIDR in order) and let passive sniffing
// fill in the rest than have the dashboard hang.
const sendBudget = 3 * time.Second

// Sweep sends ARP requests for every host in cidr from the operator's
// (srcMAC, srcIP) on the given iface, listens for replies for window, and
// invokes onObs for each reply.
//
// onObs is invoked from a dedicated listener goroutine; it must be safe
// for concurrent use. Sweep returns only after the listener goroutine has
// exited, so onObs is never called after Sweep returns.
func Sweep(ctx context.Context, ifaceName string, srcMAC net.HardwareAddr, srcIP net.IP, cidr *net.IPNet, window time.Duration, onObs func(devicestore.Observation)) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w", ifaceName, err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("bpf: %w", err)
	}

	listenCtx, cancelListen := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// Order matters: defers fire LIFO, so on return we execute
	// cancelListen → wg.Wait → handle.Close. The listener goroutine
	// exits when listenCtx is cancelled; wg.Wait then blocks until that
	// exit completes, and only then is the pcap handle closed. This
	// covers every early-return path (BPF setup, send errors) as well
	// as the normal window-expiry path.
	defer wg.Wait()
	defer cancelListen()

	wg.Add(1)
	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
		for {
			select {
			case <-listenCtx.Done():
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				arpL := pkt.Layer(layers.LayerTypeARP)
				if arpL == nil {
					continue
				}
				arp := arpL.(*layers.ARP)
				if arp.Operation != layers.ARPReply {
					continue
				}
				mac := net.HardwareAddr(append([]byte{}, arp.SourceHwAddress...))
				obs := devicestore.Observation{
					MAC:    mac,
					IP:     net.IP(append([]byte{}, arp.SourceProtAddress...)),
					Vendor: oui.Lookup(mac),
					Seen:   time.Now(),
				}
				onObs(obs)
			}
		}
	}()

	// Sender loop — also respects ctx so a cancelled sweep doesn't block
	// flushing the entire CIDR through the kernel.
	//
	// Pacing: on Wi-Fi a /24 (256 frames) takes <50ms unpaced and is fine,
	// but a /16 (65k frames) saturates the AP for ~1s and we lose replies
	// to our own back-pressure. We rate-cap at ~10k frames/sec by sleeping
	// 100µs between sends — total time for a /24 is ~25ms (negligible),
	// for a /16 is ~6.5s (vs the listener window, which the caller sets
	// at 2s; tune up at your CIDR's discretion).
	hostBits, _ := cidr.Mask.Size()
	totalHosts := 1 << uint(32-hostBits)
	const pacingThreshold = 256
	pacingDelay := time.Duration(0)
	if totalHosts > pacingThreshold {
		pacingDelay = 100 * time.Microsecond
	}
	// Pre-build the Eth+ARP frame once. Only DstProtAddress (offset
	// 0x26..0x29) changes per iteration; everything else — DstMAC,
	// SrcMAC, EtherType, ARP operation, source addresses — is constant.
	// On a /16 sweep this avoids ~65k allocations and ~65k gopacket
	// serialise passes. The shape is verified once via gopacket so we
	// don't hand-spell a wire format that drifts from the layers
	// definition.
	tmpl, err := buildARPRequest(srcMAC, srcIP, net.IPv4(0, 0, 0, 0).To4())
	if err != nil {
		return err
	}
	if len(tmpl) < 42 {
		return fmt.Errorf("internal: ARP template too short (%d bytes)", len(tmpl))
	}
	frame := append([]byte(nil), tmpl...)
	const dstIPOffset = 0x26 // 14 (eth) + 24 (ARP up to TPA) = 38 = 0x26
	srcIP4 := srcIP.To4()
	sendStart := time.Now()
	sent := 0
	for ip := nextIP(cidr.IP.Mask(cidr.Mask)); cidr.Contains(ip); ip = nextIP(ip) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// Wall-clock send budget: WritePacketData can block on the
		// kernel TX queue when Wi-Fi contention is high, so the ctx
		// deadline alone isn't enough — we'd be stuck inside the call
		// when the deadline fires. Stop early instead and let the
		// listener window run; whatever replies we got plus passive
		// sniffing will populate the device store.
		if time.Since(sendStart) >= sendBudget {
			log.Printf("active sweep: send budget reached after %d frames in %s; %d hosts unscanned (passive sniffing will pick them up)",
				sent, sendBudget, totalHosts-sent)
			break
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		// Don't send an ARP request to ourselves — we already know our
		// own MAC, and it just generates a self-reply that the listener
		// has to filter.
		if srcIP4 != nil && bytes.Equal(ip4, srcIP4) {
			continue
		}
		copy(frame[dstIPOffset:dstIPOffset+4], ip4)
		if err := handle.WritePacketData(frame); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		sent++
		if pacingDelay > 0 {
			time.Sleep(pacingDelay)
		}
	}

	// Wait for either window expiry or context cancellation.
	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	return nil
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func nextIP(ip net.IP) net.IP {
	out := append(net.IP{}, ip...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

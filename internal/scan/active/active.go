// Package active sends ARP requests to every IP in a CIDR and feeds
// observed replies into a callback.
package active

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

// Sweep sends ARP requests for every host in cidr from the operator's
// (srcMAC, srcIP) on the given iface, listens for replies for window, and
// invokes onObs for each reply.
func Sweep(ctx context.Context, ifaceName string, srcMAC net.HardwareAddr, srcIP net.IP, cidr *net.IPNet, window time.Duration, onObs func(devicestore.Observation)) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w", ifaceName, err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("bpf: %w", err)
	}

	// Listener goroutine.
	listenCtx, cancelListen := context.WithCancel(ctx)
	defer cancelListen()
	var wg sync.WaitGroup
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
				obs := devicestore.Observation{
					MAC:  net.HardwareAddr(append([]byte{}, arp.SourceHwAddress...)),
					IP:   net.IP(append([]byte{}, arp.SourceProtAddress...)),
					Seen: time.Now(),
				}
				onObs(obs)
			}
		}
	}()

	// Sender: blast one request per host in the CIDR.
	for ip := nextIP(cidr.IP.Mask(cidr.Mask)); cidr.Contains(ip); ip = nextIP(ip) {
		frame, err := buildARPRequest(srcMAC, srcIP, ip)
		if err != nil {
			return err
		}
		if err := handle.WritePacketData(frame); err != nil {
			return fmt.Errorf("send: %w", err)
		}
	}

	// Wait for either window expiry or context cancellation.
	select {
	case <-time.After(window):
	case <-ctx.Done():
	}
	cancelListen()
	wg.Wait()
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

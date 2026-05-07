// Package passive runs an always-on broadcast sniffer on the iface and
// feeds learned MAC/IP/hostname facts into a callback. onObs is invoked
// from this function's goroutine; it must be safe for concurrent use if
// called from multiple Run invocations.
package passive

import (
	"context"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

// Run blocks until ctx is done. Every observation extracted from a
// supported broadcast frame is passed to onObs. The order of parsers
// matters: ARP/DHCP yield strictly more identity info than the generic
// UDP-broadcast parser, so try them first; the UDP-broadcast fallback
// is what extracts (MAC, IP) from mDNS/SSDP/NetBIOS frames whose upper
// protocol we don't parse, plus mDNS hostname enrichment when present.
func Run(ctx context.Context, ifaceName string, onObs func(devicestore.Observation)) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w", ifaceName, err)
	}
	defer handle.Close()
	// arp || (udp && (port 67 or 68 or 5353 or 137 or 1900))
	if err := handle.SetBPFFilter("arp or (udp and (port 67 or port 68 or port 5353 or port 137 or port 1900))"); err != nil {
		return fmt.Errorf("bpf: %w", err)
	}
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil
			}
			if obs, ok := parseARP(pkt); ok {
				onObs(obs)
				continue
			}
			if obs, ok := parseDHCP(pkt); ok {
				onObs(obs)
				continue
			}
			if obs, ok := parseMDNSAnswer(pkt); ok {
				onObs(obs)
				continue
			}
			if obs, ok := parseNetBIOS(pkt); ok {
				onObs(obs)
				continue
			}
			if obs, ok := parseUDPBroadcast(pkt); ok {
				onObs(obs)
			}
		}
	}
}

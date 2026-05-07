package passive

import (
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/oui"
)

// parseARP extracts a (MAC, IP, vendor) observation from an ARP reply or a
// gratuitous ARP request. Returns ok=false if the packet isn't ARP.
func parseARP(pkt gopacket.Packet) (devicestore.Observation, bool) {
	l := pkt.Layer(layers.LayerTypeARP)
	if l == nil {
		return devicestore.Observation{}, false
	}
	a := l.(*layers.ARP)
	if len(a.SourceHwAddress) != 6 || len(a.SourceProtAddress) != 4 {
		return devicestore.Observation{}, false
	}
	// RFC 5227 ARP probes carry SPA=0.0.0.0 — the sender does not yet own
	// the IP. Recording such observations would clobber the device's
	// previously known address until the next legitimate ARP arrives.
	if a.SourceProtAddress[0] == 0 && a.SourceProtAddress[1] == 0 &&
		a.SourceProtAddress[2] == 0 && a.SourceProtAddress[3] == 0 {
		return devicestore.Observation{}, false
	}
	mac := net.HardwareAddr(append([]byte{}, a.SourceHwAddress...))
	return devicestore.Observation{
		MAC:    mac,
		IP:     net.IP(append([]byte{}, a.SourceProtAddress...)),
		Vendor: oui.Lookup(mac),
		Seen:   time.Now(),
	}, true
}

// parseDHCP extracts (MAC, optional hostname) from a DHCP frame using the
// client hardware address and option 12 (host name).
func parseDHCP(pkt gopacket.Packet) (devicestore.Observation, bool) {
	l := pkt.Layer(layers.LayerTypeDHCPv4)
	if l == nil {
		return devicestore.Observation{}, false
	}
	d := l.(*layers.DHCPv4)
	if len(d.ClientHWAddr) != 6 {
		return devicestore.Observation{}, false
	}
	mac := net.HardwareAddr(append([]byte{}, d.ClientHWAddr...))
	obs := devicestore.Observation{
		MAC:    mac,
		Vendor: oui.Lookup(mac),
		Seen:   time.Now(),
	}
	for _, opt := range d.Options {
		if opt.Type == layers.DHCPOptHostname {
			obs.Hostname = string(opt.Data)
		}
	}
	return obs, true
}

// parseUDPBroadcast extracts (MAC, IP, vendor) from any UDP frame on the
// always-on capture (mDNS/SSDP/NetBIOS broadcasts). Even without parsing
// the upper protocol, this learns "MAC X currently has IP Y" — which is
// the single most useful fact for the device list. Hostname enrichment
// rides on top via parseMDNSAnswer.
//
// Returns ok=false unless the frame has an Ethernet, IPv4, AND UDP layer
// — guarding against the parseDNS case where someone reads decapsulated
// data without an outer Eth/IP.
func parseUDPBroadcast(pkt gopacket.Packet) (devicestore.Observation, bool) {
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ipL := pkt.Layer(layers.LayerTypeIPv4)
	if ethL == nil || ipL == nil {
		return devicestore.Observation{}, false
	}
	if pkt.Layer(layers.LayerTypeUDP) == nil {
		return devicestore.Observation{}, false
	}
	eth := ethL.(*layers.Ethernet)
	ip := ipL.(*layers.IPv4)
	if len(eth.SrcMAC) != 6 || len(ip.SrcIP) == 0 {
		return devicestore.Observation{}, false
	}
	// Skip 0.0.0.0 source IPs (DHCP DISCOVER/REQUEST before lease).
	src := ip.SrcIP.To4()
	if src == nil || (src[0] == 0 && src[1] == 0 && src[2] == 0 && src[3] == 0) {
		return devicestore.Observation{}, false
	}
	// Skip frames where SrcMAC is all-zero or broadcast (defensive — shouldn't
	// happen on live wire but happens in malformed test pcaps).
	zero := true
	bcast := true
	for _, b := range eth.SrcMAC {
		if b != 0 {
			zero = false
		}
		if b != 0xff {
			bcast = false
		}
	}
	if zero || bcast {
		return devicestore.Observation{}, false
	}
	mac := net.HardwareAddr(append([]byte{}, eth.SrcMAC...))
	return devicestore.Observation{
		MAC:    mac,
		IP:     net.IP(append([]byte{}, src...)),
		Vendor: oui.Lookup(mac),
		Seen:   time.Now(),
	}, true
}

// parseMDNSAnswer extracts hostnames from mDNS responses on UDP/5353.
// Looks at the DNS payload and pulls A-record names — ".local" suffix
// is trimmed for display. Returns ok=false unless we can pair a name
// with the L2 source MAC.
func parseMDNSAnswer(pkt gopacket.Packet) (devicestore.Observation, bool) {
	udpL := pkt.Layer(layers.LayerTypeUDP)
	if udpL == nil {
		return devicestore.Observation{}, false
	}
	udp := udpL.(*layers.UDP)
	if udp.SrcPort != 5353 && udp.DstPort != 5353 {
		return devicestore.Observation{}, false
	}
	dnsL := pkt.Layer(layers.LayerTypeDNS)
	if dnsL == nil {
		return devicestore.Observation{}, false
	}
	dns := dnsL.(*layers.DNS)
	if !dns.QR {
		return devicestore.Observation{}, false // queries don't carry answers
	}
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	if ethL == nil {
		return devicestore.Observation{}, false
	}
	eth := ethL.(*layers.Ethernet)
	if len(eth.SrcMAC) != 6 {
		return devicestore.Observation{}, false
	}
	// Prefer A-record hostnames; fall back to PTR/SRV target names.
	var hostname string
	for _, ans := range dns.Answers {
		switch ans.Type {
		case layers.DNSTypeA:
			if name := string(ans.Name); name != "" {
				hostname = trimLocal(name)
			}
		case layers.DNSTypeSRV:
			if hostname == "" {
				hostname = trimLocal(string(ans.SRV.Name))
			}
		}
		if hostname != "" {
			break
		}
	}
	if hostname == "" {
		return devicestore.Observation{}, false
	}
	mac := net.HardwareAddr(append([]byte{}, eth.SrcMAC...))
	obs := devicestore.Observation{
		MAC:      mac,
		Hostname: hostname,
		Vendor:   oui.Lookup(mac),
		Seen:     time.Now(),
	}
	if ipL := pkt.Layer(layers.LayerTypeIPv4); ipL != nil {
		if ip4 := ipL.(*layers.IPv4).SrcIP.To4(); ip4 != nil {
			obs.IP = net.IP(append([]byte{}, ip4...))
		}
	}
	return obs, true
}

// trimLocal strips the trailing dot the DNS layer always emits. The
// ".local" suffix is intentionally preserved so consumers can distinguish
// mDNS-derived names from DHCP-option-12 names if they ever need to —
// the existing mdns package preserves it as well.
func trimLocal(s string) string {
	return strings.TrimSuffix(s, ".")
}

// parseNetBIOS extracts the NetBIOS source name from a NetBIOS Name
// Service frame on UDP/137 (RFC 1002). NBNS shares the DNS header
// format so we reuse gopacket's DNS parser to grab the QUESTION_NAME,
// then NetBIOS first-level decode it (each name byte split into two
// nibbles, each nibble OR'd with 0x41 to make ASCII 'A'..'P'). The
// 16-byte decoded form is `<15-char name><1-byte suffix>` — typical
// suffixes: 0x00 workstation, 0x20 file-server, 0x1B domain-master.
//
// The most useful frames are Name-Registration broadcasts (Windows
// hosts emit these at boot and on share access): the QUESTION_NAME
// is the host's own claim, ideal for hostname enrichment.
func parseNetBIOS(pkt gopacket.Packet) (devicestore.Observation, bool) {
	udpL := pkt.Layer(layers.LayerTypeUDP)
	if udpL == nil {
		return devicestore.Observation{}, false
	}
	udp := udpL.(*layers.UDP)
	if udp.SrcPort != 137 && udp.DstPort != 137 {
		return devicestore.Observation{}, false
	}
	// gopacket usually decodes UDP/137 as DNS (NBNS shares the format).
	// On versions where it doesn't, fall back to the raw payload.
	payload := udp.Payload
	if dnsL := pkt.Layer(layers.LayerTypeDNS); dnsL != nil {
		dns := dnsL.(*layers.DNS)
		if len(dns.Questions) > 0 {
			if name, ok := decodeNetBIOSName(dns.Questions[0].Name); ok {
				return netBIOSObs(pkt, name)
			}
		}
		return devicestore.Observation{}, false
	}
	// Manual decode: skip the 12-byte NBNS header, read the encoded
	// name's length-prefix (always 0x20 = 32 bytes for first-level NBNS
	// names), then 32 bytes of encoded name.
	if len(payload) < 12+1+32 {
		return devicestore.Observation{}, false
	}
	if payload[12] != 0x20 {
		return devicestore.Observation{}, false
	}
	if name, ok := decodeNetBIOSName(payload[13 : 13+32]); ok {
		return netBIOSObs(pkt, name)
	}
	return devicestore.Observation{}, false
}

// netBIOSObs extracts the (MAC, IP, vendor) carrier facts from the
// frame's L2/L3 layers and pairs them with the decoded hostname.
// Mirrors parseUDPBroadcast's eth/ip extraction; kept private so the
// generic UDP-broadcast code path is unaffected.
func netBIOSObs(pkt gopacket.Packet, hostname string) (devicestore.Observation, bool) {
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ipL := pkt.Layer(layers.LayerTypeIPv4)
	if ethL == nil || ipL == nil {
		return devicestore.Observation{}, false
	}
	eth := ethL.(*layers.Ethernet)
	ip := ipL.(*layers.IPv4)
	if len(eth.SrcMAC) != 6 || ip.SrcIP.To4() == nil {
		return devicestore.Observation{}, false
	}
	mac := net.HardwareAddr(append([]byte{}, eth.SrcMAC...))
	src4 := ip.SrcIP.To4()
	return devicestore.Observation{
		MAC:      mac,
		IP:       net.IP(append([]byte{}, src4...)),
		Hostname: hostname,
		Vendor:   oui.Lookup(mac),
		Seen:     time.Now(),
	}, true
}

// decodeNetBIOSName reverses NetBIOS first-level encoding (RFC 1001
// §4.2.1.2) and returns the trimmed 15-char name. Each pair of input
// bytes encodes one output byte: hi-nibble = (b1 - 'A'), lo-nibble =
// (b2 - 'A'). The 16th decoded byte is the resource-type suffix —
// dropped from the returned name. Names are space-padded, so trailing
// spaces are trimmed.
//
// Accepts the input as either a string (gopacket DNS Question.Name) or
// a byte slice (raw payload). Returns ("", false) if the input is not
// 32 chars, contains non-A..P bytes, or decodes to an empty name.
func decodeNetBIOSName(in any) (string, bool) {
	var src []byte
	switch v := in.(type) {
	case string:
		src = []byte(v)
	case []byte:
		src = v
	default:
		return "", false
	}
	if len(src) != 32 {
		return "", false
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi, lo := src[i*2], src[i*2+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return "", false
		}
		out[i] = ((hi - 'A') << 4) | (lo - 'A')
	}
	// Drop the suffix byte and trim trailing spaces.
	name := strings.TrimRight(string(out[:15]), " \x00")
	if name == "" {
		return "", false
	}
	return name, true
}

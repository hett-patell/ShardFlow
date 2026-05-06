package passive

import (
	"net"
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

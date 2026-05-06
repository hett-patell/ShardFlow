package passive

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureDHCPDiscoverWithHostname builds a synthetic DHCP DISCOVER frame
// with option 12 (host name) set, for parser testing.
func captureDHCPDiscoverWithHostname(t *testing.T, hostname string) gopacket.Packet {
	t.Helper()
	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		ClientHWAddr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		Options: []layers.DHCPOption{
			{Type: layers.DHCPOptHostname, Data: []byte(hostname), Length: uint8(len(hostname))},
			{Type: layers.DHCPOptEnd},
		},
	}
	udp := layers.UDP{SrcPort: 68, DstPort: 67}
	ip := layers.IPv4{Version: 4, IHL: 5, Protocol: layers.IPProtocolUDP, SrcIP: []byte{0, 0, 0, 0}, DstIP: []byte{255, 255, 255, 255}}
	eth := layers.Ethernet{SrcMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, DstMAC: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeIPv4}
	require.NoError(t, udp.SetNetworkLayerForChecksum(&ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &ip, &udp, &dhcp))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestParseDHCPHostname(t *testing.T) {
	pkt := captureDHCPDiscoverWithHostname(t, "iphone-of-alice")
	obs, ok := parseDHCP(pkt)
	require.True(t, ok)
	assert.Equal(t, "iphone-of-alice", obs.Hostname)
	assert.Equal(t, "aa:bb:cc:dd:ee:01", obs.MAC.String())
}

func TestParseARPReply(t *testing.T) {
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply,
		SourceHwAddress: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}, SourceProtAddress: []byte{10, 0, 0, 55},
		DstHwAddress: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, DstProtAddress: []byte{10, 0, 0, 1},
	}
	eth := layers.Ethernet{SrcMAC: arp.SourceHwAddress, DstMAC: arp.DstHwAddress, EthernetType: layers.EthernetTypeARP}
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	obs, ok := parseARP(pkt)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.55", obs.IP.String())
	assert.Equal(t, "aa:bb:cc:dd:ee:02", obs.MAC.String())
}

package active

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildARPRequestFrame(t *testing.T) {
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	srcIP := net.ParseIP("10.0.0.5").To4()
	dstIP := net.ParseIP("10.0.0.42").To4()

	frame, err := buildARPRequest(srcMAC, srcIP, dstIP)
	require.NoError(t, err)

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	arp := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)

	assert.Equal(t, layers.EthernetTypeARP, eth.EthernetType)
	assert.Equal(t, "ff:ff:ff:ff:ff:ff", net.HardwareAddr(eth.DstMAC).String())
	assert.Equal(t, uint16(layers.ARPRequest), arp.Operation)
	assert.Equal(t, "10.0.0.42", net.IP(arp.DstProtAddress).String())
}

// TestARPRequestDstIPOffset pins the byte offset of DstProtAddress in
// the serialised Eth+ARP request frame. Sweep relies on this offset to
// patch each iteration's destination IP into a pre-built template; if
// gopacket ever changes the wire layout (or someone "improves"
// buildARPRequest with options), this test catches it before the live
// sweep silently broadcasts zero-IP requests.
func TestARPRequestDstIPOffset(t *testing.T) {
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	frame, err := buildARPRequest(srcMAC, net.ParseIP("10.0.0.5").To4(), net.ParseIP("1.2.3.4").To4())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(frame), 42, "minimum Eth+ARP request size")
	const dstIPOffset = 0x26
	assert.Equal(t, []byte{1, 2, 3, 4}, frame[dstIPOffset:dstIPOffset+4],
		"buildARPRequest must place DstProtAddress at offset 0x26 — Sweep's pre-built template patches there")
}

func TestNextIPCarry(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"10.0.0.0", "10.0.0.1"},
		{"10.0.0.254", "10.0.0.255"},
		{"10.0.0.255", "10.0.1.0"},
		{"10.0.255.255", "10.1.0.0"},
	}
	for _, tc := range cases {
		got := nextIP(net.ParseIP(tc.in).To4())
		assert.Equal(t, tc.want, got.String(), "nextIP(%s)", tc.in)
	}
}

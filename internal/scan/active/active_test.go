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

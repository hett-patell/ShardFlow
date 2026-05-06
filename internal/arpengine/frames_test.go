package arpengine

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPoisonReply(t *testing.T) {
	opMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	gwMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	gwIP := net.ParseIP("10.0.0.1").To4()
	tgtMAC, _ := net.ParseMAC("77:88:99:aa:bb:cc")
	tgtIP := net.ParseIP("10.0.0.42").To4()

	// Poison reply telling target: "the gateway's MAC is opMAC".
	frame, err := buildARPReply(opMAC, gwIP, tgtMAC, tgtIP)
	require.NoError(t, err)

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arp := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	assert.Equal(t, uint16(layers.ARPReply), arp.Operation)
	assert.Equal(t, opMAC.String(), net.HardwareAddr(arp.SourceHwAddress).String())
	assert.Equal(t, gwIP.String(), net.IP(arp.SourceProtAddress).String())
	assert.Equal(t, tgtMAC.String(), net.HardwareAddr(arp.DstHwAddress).String())
	assert.Equal(t, tgtIP.String(), net.IP(arp.DstProtAddress).String())
	_ = gwMAC // gwMAC is for the symmetric "tell the gateway" frame; tested separately
}

func TestStopAllUnknownTargetsIsNil(t *testing.T) {
	// StopAll on an empty engine returns nil (no errors to aggregate).
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	e := New("lo", mac, time.Millisecond)
	require.NoError(t, e.StopAll())
}

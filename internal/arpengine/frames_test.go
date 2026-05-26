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
	frame, err := buildARPReply(opMAC, opMAC, gwIP, tgtMAC, tgtIP)
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
	// New requires a working pcap iface; lo is always present and works
	// for OpenLive even though we never actually transmit anything here.
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	e, err := New("lo", mac, time.Millisecond)
	if err != nil {
		t.Skipf("pcap.OpenLive(lo) failed (likely missing CAP_NET_RAW in test env): %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	require.NoError(t, e.StopAll())
}

// TestStartPrebuildsCadenceFrames asserts that Start populates the four
// cadence frames on the runner. The frames are static for the lifetime
// of the poison; if they ever start coming back nil/empty the loop will
// silently send zero-length packets.
func TestStartPrebuildsCadenceFrames(t *testing.T) {
	opMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	e, err := New("lo", opMAC, time.Hour) // long cadence so the loop barely fires
	if err != nil {
		t.Skipf("pcap.OpenLive(lo) failed (likely missing CAP_NET_RAW in test env): %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	tgt := Target{
		MAC:   mustMAC(t, "77:88:99:aa:bb:cc"),
		IP:    net.ParseIP("10.0.0.42").To4(),
		GwMAC: mustMAC(t, "11:22:33:44:55:66"),
		GwIP:  net.ParseIP("10.0.0.1").To4(),
	}
	require.NoError(t, e.Start(tgt))
	t.Cleanup(func() { _ = e.StopAll() })

	e.mu.Lock()
	r, ok := e.active[tgt.MAC.String()]
	e.mu.Unlock()
	require.True(t, ok)
	// Every frame is Eth(14) + ARP body — minimum useful size is 42 bytes.
	assert.GreaterOrEqual(t, len(r.poisonTargetReq), 42)
	assert.GreaterOrEqual(t, len(r.poisonTargetRep), 42)
	assert.GreaterOrEqual(t, len(r.poisonGwReq), 42)
	assert.GreaterOrEqual(t, len(r.poisonGwRep), 42)

	// Spot-check operation codes: the parsed ARP layer must distinguish
	// request from reply, otherwise the receiver kernel will treat them
	// uniformly and the dual-frame approach loses its point.
	parseOp := func(b []byte) uint16 {
		pkt := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
		return pkt.Layer(layers.LayerTypeARP).(*layers.ARP).Operation
	}
	assert.Equal(t, uint16(layers.ARPRequest), parseOp(r.poisonTargetReq))
	assert.Equal(t, uint16(layers.ARPReply), parseOp(r.poisonTargetRep))
	assert.Equal(t, uint16(layers.ARPRequest), parseOp(r.poisonGwReq))
	assert.Equal(t, uint16(layers.ARPReply), parseOp(r.poisonGwRep))
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	require.NoError(t, err)
	return m
}

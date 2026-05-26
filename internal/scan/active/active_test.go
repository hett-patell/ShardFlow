package active

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

// fakeWriter records every frame it's asked to send, plus its
// invocation count. Used by TestSweepWithWriterUsesInjectedWriter to
// assert that SweepWithWriter routes its send path through the
// injected writer (not through its own pcap handle).
type fakeWriter struct {
	mu     sync.Mutex
	frames [][]byte
}

func (f *fakeWriter) WriteFrame(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Copy because Sweep reuses its frame buffer across iterations
	// (patching only the dst IP). Without copying, every recorded
	// entry would alias the last iteration's bytes.
	cp := append([]byte(nil), b...)
	f.frames = append(f.frames, cp)
	return nil
}

func (f *fakeWriter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames)
}

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

// TestSweepWithWriterUsesInjectedWriter asserts that when a FrameWriter
// is provided, Sweep routes every send through it. The test runs against
// 'lo', uses a tiny CIDR, and a short window — the listener may catch
// nothing on lo, but the send path runs regardless.
func TestSweepWithWriterUsesInjectedWriter(t *testing.T) {
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	_, cidr, err := net.ParseCIDR("127.0.0.0/30") // 4 addresses
	require.NoError(t, err)

	fw := &fakeWriter{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Sweep skips its own source IP and the network/broadcast addresses
	// aren't pre-skipped — every address in the /30 should produce a
	// send except 127.0.0.5 (our srcIP). srcIP isn't in the CIDR so all
	// 4 hosts in 127.0.0.0/30 get a send attempt.
	err = SweepWithWriter(ctx, "lo", srcMAC, net.ParseIP("127.0.0.5").To4(),
		cidr, 100*time.Millisecond, fw, func(devicestore.Observation) {})
	if err != nil {
		// On systems without CAP_NET_RAW the read handle won't open;
		// the write injection still works. Skip rather than fail.
		t.Skipf("Sweep failed (likely missing CAP_NET_RAW): %v", err)
	}

	// 127.0.0.0/30 has 4 IPs (.0 .1 .2 .3); all 4 should have been sent.
	assert.GreaterOrEqual(t, fw.count(), 4, "writer must receive one frame per host in CIDR")
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

package mdns

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/internal/devicestore"
)

// buildMinimalMDNSAResponse constructs a synthetic mDNS response containing a
// single A record (hostname → ip), packed via dnsmessage.Builder.
func buildMinimalMDNSAResponse(t *testing.T, hostname string, ip net.IP) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.EnableCompression()
	require.NoError(t, b.StartAnswers())
	require.NoError(t, b.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(hostname + "."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   120,
		},
		dnsmessage.AResource{A: [4]byte{ip.To4()[0], ip.To4()[1], ip.To4()[2], ip.To4()[3]}},
	))
	out, err := b.Finish()
	require.NoError(t, err)
	return out
}

func TestParseAResponse(t *testing.T) {
	pkt := buildMinimalMDNSAResponse(t, "iphone.local", net.ParseIP("10.0.0.42"))
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.42"), Port: 5353}

	var got []devicestore.Observation
	parseMDNS(pkt, src, func(obs devicestore.Observation) { got = append(got, obs) })

	require.Len(t, got, 1)
	assert.Equal(t, "iphone.local", got[0].Hostname)
	assert.Equal(t, "10.0.0.42", got[0].IP.String())
}

func TestParseAResponseMultipleA(t *testing.T) {
	// Response with two A records: hostA → 10.0.0.10, hostB → 10.0.0.11.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.EnableCompression()
	require.NoError(t, b.StartAnswers())
	for _, e := range []struct {
		name string
		ip   [4]byte
	}{
		{"hostA.local", [4]byte{10, 0, 0, 10}},
		{"hostB.local", [4]byte{10, 0, 0, 11}},
	} {
		require.NoError(t, b.AResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(e.name + "."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   120,
			},
			dnsmessage.AResource{A: e.ip},
		))
	}
	pkt, err := b.Finish()
	require.NoError(t, err)

	var got []devicestore.Observation
	parseMDNS(pkt, &net.UDPAddr{}, func(obs devicestore.Observation) { got = append(got, obs) })

	require.Len(t, got, 2)
	assert.Equal(t, "hostA.local", got[0].Hostname)
	assert.Equal(t, "hostB.local", got[1].Hostname)
}

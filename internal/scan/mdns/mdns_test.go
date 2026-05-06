package mdns

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	obs, ok := parseMDNS(pkt, src)
	require.True(t, ok)
	assert.Equal(t, "iphone.local", obs.Hostname)
	assert.Equal(t, "10.0.0.42", obs.IP.String())
}

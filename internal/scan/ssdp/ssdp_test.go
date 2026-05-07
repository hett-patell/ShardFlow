package ssdp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSSDPResponseExtractsServer(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"USN: uuid:abc::upnp:rootdevice\r\n" +
		"SERVER: Linux/3.14 UPnP/1.1 RouterOS/6.45\r\n" +
		"\r\n"
	obs, ok := parseSSDPResponse([]byte(resp), net.ParseIP("10.0.0.1"))
	require.True(t, ok)
	// SERVER lands in Model so it doesn't clobber the OUI-derived Vendor.
	assert.Contains(t, obs.Model, "RouterOS")
	assert.Empty(t, obs.Vendor, "SSDP must not populate Vendor (would clobber OUI)")
	assert.Equal(t, "10.0.0.1", obs.IP.String())
}

package wifi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIwLinkAssociated(t *testing.T) {
	out := `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
	SSID: HomeWiFi-5G
	freq: 5180
	RX: 1234 bytes (123 packets)
	TX: 5678 bytes (45 packets)
	signal: -52 dBm
	rx bitrate: 234.0 MBit/s
	tx bitrate: 130.0 MBit/s MCS 7 short GI`
	var info Info
	parseIwLink(out, &info)
	assert.Equal(t, "HomeWiFi-5G", info.SSID)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", info.BSSID)
	assert.Equal(t, -52, info.SignalDBm)
	assert.InDelta(t, 130.0, info.TxRateMbit, 0.01)
	assert.Equal(t, 5180, info.FreqMHz)
}

func TestParseIwLinkNotAssociated(t *testing.T) {
	out := `Not connected.`
	var info Info
	parseIwLink(out, &info)
	assert.Empty(t, info.SSID)
	assert.Empty(t, info.BSSID)
	assert.Zero(t, info.SignalDBm)
}

func TestParseIwLinkSpacesInSSID(t *testing.T) {
	// Real-world SSIDs frequently contain spaces — guest networks like
	// "Free WiFi" must parse cleanly.
	out := `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
	SSID: Free Coffee Shop WiFi
	freq: 2412
	signal: -70 dBm`
	var info Info
	parseIwLink(out, &info)
	assert.Equal(t, "Free Coffee Shop WiFi", info.SSID)
}

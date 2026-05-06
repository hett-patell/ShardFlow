//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hett-patell/ShardFlow/test/netns"
)

func TestThrottlePolicyLimitsBandwidth(t *testing.T) {
	startDaemon(t)
	scanAndAwaitVictim(t)

	out, err := netns.InNS("lab-op", "/tmp/shardflow", "--sock", "/tmp/sf.sock",
		"policy", "set", "10.0.99.42", "throttle", "200kbit")
	require.NoError(t, err, string(out))

	time.Sleep(2 * time.Second)

	go func() { _, _ = netns.InNS("lab-gw", "iperf3", "-s", "-1") }()
	time.Sleep(500 * time.Millisecond)
	out, err = netns.InNS("lab-vic", "iperf3", "-c", "10.0.99.1", "-t", "3", "-J")
	require.NoError(t, err, string(out))

	// Read sum_received, not sum_sent: under throttle the kernel drops
	// excess packets and TCP retransmits inflate sum_sent above the wire
	// rate. sum_received is what actually arrived at the receiver, which
	// is what HTB caps.
	var report struct {
		End struct {
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	require.NoError(t, json.Unmarshal(out, &report), "iperf3 json parse: %s", out)
	require.Less(t, report.End.SumReceived.BitsPerSecond, float64(300_000),
		"throttle did not limit bandwidth: %v bps", report.End.SumReceived.BitsPerSecond)
}

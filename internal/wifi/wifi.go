// Package wifi exposes a best-effort probe for the operator's wireless
// connection details (SSID, BSSID, signal, frequency, tx rate). It
// shells out to `iw dev <iface> link` because (a) `iw` is part of the
// standard iproute2 toolchain on every modern Linux WiFi system,
// (b) parsing nl80211 directly via netlink is overkill for read-only
// status, and (c) the data is only ever displayed to a human in the
// TUI's SESSION panel — accuracy is more important than microseconds.
package wifi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Info is the snapshot returned by Probe. All fields are zero/empty
// when the iface isn't wireless OR `iw` is unavailable OR the iface is
// associated to no AP. Wireless==true means "this iface is a wireless
// device" (regardless of association); SSID!="" means "currently
// associated to that network".
type Info struct {
	Wireless   bool
	SSID       string
	BSSID      string
	SignalDBm  int
	TxRateMbit float64
	FreqMHz    int
}

// IsWireless reports whether the named iface is a wireless device
// without invoking `iw`. Cheap enough to always run; the kernel
// exposes a `wireless` directory under /sys/class/net only for
// nl80211-managed interfaces.
func IsWireless(iface string) bool {
	_, err := os.Stat("/sys/class/net/" + iface + "/wireless")
	return err == nil
}

// Probe returns the current wireless association state of iface. The
// 1-second timeout caps the absolute time `iw` may run — it normally
// finishes in single-digit milliseconds, but the daemon's startup
// path can't afford to hang here if `iw` is wedged.
//
// Returns an Info with Wireless=false when:
//   - the iface isn't a WiFi device (no /sys/class/net/X/wireless)
//   - the `iw` binary isn't in PATH
//   - `iw dev <iface> link` fails (wedged kernel module, permissions, etc.)
func Probe(iface string) Info {
	info := Info{Wireless: IsWireless(iface)}
	if !info.Wireless {
		return info
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iw", "dev", iface, "link").Output()
	if err != nil {
		return info
	}
	parseIwLink(string(out), &info)
	return info
}

// parseIwLink fills info from the textual output of `iw dev X link`.
// Tolerates extra leading/trailing whitespace on each line and
// trailing-unit suffixes (e.g. `tx bitrate: 130.0 MBit/s ...`). Lines
// it doesn't recognise are skipped silently — the goal is best-effort
// status, not exhaustive validation.
func parseIwLink(out string, info *Info) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Connected to "):
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				info.BSSID = fields[2]
			}
		case strings.HasPrefix(line, "SSID: "):
			info.SSID = strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
		case strings.HasPrefix(line, "freq: "):
			_, _ = fmt.Sscanf(line, "freq: %d", &info.FreqMHz)
		case strings.HasPrefix(line, "signal: "):
			// "signal: -52 dBm" — Sscanf stops at whitespace.
			_, _ = fmt.Sscanf(line, "signal: %d", &info.SignalDBm)
		case strings.HasPrefix(line, "tx bitrate: "):
			// "tx bitrate: 130.0 MBit/s MCS 7"
			_, _ = fmt.Sscanf(line, "tx bitrate: %f", &info.TxRateMbit)
		}
	}
}

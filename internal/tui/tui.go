// Package tui implements the bubbletea dashboard for the shardflow client.
package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

// Run blocks running the TUI connected to the daemon at sockPath. If the
// daemon dies mid-session the TUI does NOT exit — it shows a reconnecting
// indicator and retries Dial in the background until either the daemon
// comes back or the user quits.
//
// Lifecycle: on reconnect the old client is closed inside the message
// handler before the model swaps in the new one, so we never leak FDs.
// At program exit, p.Run returns the final model — we close whatever
// client it holds (which is the most recent reconnect, if any happened).
func Run(sockPath string, defaultRateKbit int, defaultPcapDir string) error {
	c, err := rpc.Dial(sockPath)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	m := newModel(c, defaultRateKbit, defaultPcapDir)
	m.sockPath = sockPath
	p := tea.NewProgram(m, tea.WithAltScreen())
	final, err := p.Run()
	if fm, ok := final.(model); ok && fm.client != nil {
		_ = fm.client.Close()
	} else {
		_ = c.Close()
	}
	return err
}

// loadSessionNow issues a Session.Get and returns sessionLoadedMsg. If
// the daemon doesn't support the method (older build) the message
// carries a zero-value DTO; the SESSION panel renders a "—" line then.
func loadSessionNow(c *rpc.Client) tea.Msg {
	var s rpc.SessionDTO
	_ = c.Call(context.Background(), rpc.MethodSessionGet, nil, &s)
	return sessionLoadedMsg{session: s}
}

func refreshSessionCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg { return loadSessionNow(c) }
}

func loadDevicesNow(c *rpc.Client) tea.Msg {
	var devs []rpc.DeviceDTO
	if err := c.Call(context.Background(), rpc.MethodDevicesList, nil, &devs); err != nil {
		return eventMsg{text: "load devices: " + err.Error()}
	}
	rows := make([]deviceRow, 0, len(devs))
	for _, d := range devs {
		// Prefer Model (UPnP firmware string) over Vendor (OUI) for the
		// vendor column when both are present — Model says "PhilipsHue"
		// while Vendor just says "Signify". The OUI is still kept on
		// the DTO for the target panel.
		venText := d.Vendor
		if d.Model != "" {
			venText = d.Model
		}
		rows = append(rows, deviceRow{
			ip:       d.IP,
			mac:      d.MAC,
			hostname: d.Hostname,
			vendor:   venText,
			policy:   d.Policy, // populated server-side now
		})
	}
	return devicesLoadedMsg{rows: rows}
}

func refreshDevicesCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg { return loadDevicesNow(c) }
}

func waitForEventCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-c.Events()
		if !ok {
			return disconnectedMsg{}
		}
		refresh := ev.Method == rpc.EventDeviceDiscovered || ev.Method == rpc.EventDeviceUpdated
		return eventMsg{text: ev.Method + " " + string(ev.Params), refreshDevices: refresh}
	}
}

func applyPolicyCmd(c *rpc.Client, target string, key rune, defaultRateKbit int, defaultPcapDir string) tea.Cmd {
	return func() tea.Msg {
		spec := rpc.PolicySpec{Target: target}
		switch key {
		case 'd':
			spec.Kind = rpc.PolicyDrop
		case 't':
			spec.Kind = rpc.PolicyThrottle
			spec.RateKbit = defaultRateKbit
		case 'p':
			spec.Kind = rpc.PolicyPcap
			spec.PcapDir = defaultPcapDir
		case 'x':
			var r map[string]string
			if err := c.Call(context.Background(), rpc.MethodPolicyClear, map[string]string{"target": target}, &r); err != nil {
				return eventMsg{text: fmt.Sprintf("clear %s: %s", target, err)}
			}
			return eventMsg{text: "cleared " + target, refreshDevices: true}
		}
		var r map[string]string
		if err := c.Call(context.Background(), rpc.MethodPolicySet, spec, &r); err != nil {
			return eventMsg{text: fmt.Sprintf("policy %s %s: %s", target, spec.Kind, err)}
		}
		return eventMsg{text: fmt.Sprintf("policy %s → %s", target, spec.Kind), refreshDevices: true}
	}
}

// scanRPCTimeout is the client's hard ceiling on a single scan call. The
// daemon already enforces its own 15s scanHardTimeout, so we only need
// enough margin above that to absorb network jitter on the Unix socket.
const scanRPCTimeout = 30 * time.Second

// scanCmd issues a Scan RPC and returns scanCompleteMsg with the elapsed
// time and current device count. The RPC blocks for the full scan window
// (typically ~8s, capped at scanRPCTimeout) — the model uses the
// .scanning flag to show a spinner during that time so the dashboard
// isn't visibly frozen.
//
// Earlier versions used context.Background() with no deadline, which
// meant a daemon-side hang (e.g. WritePacketData stalling on Wi-Fi TX
// backpressure) left m.scanning stuck on true forever and the user saw
// the spinner running for many minutes with no progress.
func scanCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), scanRPCTimeout)
		defer cancel()
		var r map[string]string
		err := c.Call(ctx, rpc.MethodScan, nil, &r)
		elapsed := time.Since(start)
		listCtx, listCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer listCancel()
		var devs []rpc.DeviceDTO
		_ = c.Call(listCtx, rpc.MethodDevicesList, nil, &devs)
		return scanCompleteMsg{err: err, elapsed: elapsed, deviceCount: len(devs)}
	}
}

// reconnectCmd attempts to reach the daemon at sockPath. Returns a
// reconnectedMsg on success and a reconnectFailedMsg (with a backoff
// delay) on failure. The model arms another retry on failure.
func reconnectCmd(sockPath string) tea.Cmd {
	return func() tea.Msg {
		c, err := rpc.Dial(sockPath)
		if err != nil {
			return reconnectFailedMsg{err: err}
		}
		return reconnectedMsg{client: c}
	}
}

// reconnectAfter schedules a reconnect attempt after delay. Used for
// backoff between failures so we don't busy-spin on Dial.
func reconnectAfter(sockPath string, delay time.Duration) tea.Cmd {
	return tea.Tick(delay, func(time.Time) tea.Msg {
		c, err := rpc.Dial(sockPath)
		if err != nil {
			return reconnectFailedMsg{err: err}
		}
		return reconnectedMsg{client: c}
	})
}

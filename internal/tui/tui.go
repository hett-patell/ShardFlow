// Package tui implements the bubbletea dashboard for the shardflow client.
package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

// Run blocks running the TUI connected to the daemon at sockPath.
func Run(sockPath string, defaultRateKbit int, defaultPcapDir string) error {
	c, err := rpc.Dial(sockPath)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer c.Close()

	p := tea.NewProgram(newModel(c, defaultRateKbit, defaultPcapDir), tea.WithAltScreen())

	_, err = p.Run()
	return err
}

func loadDevicesNow(c *rpc.Client) tea.Msg {
	var devs []rpc.DeviceDTO
	if err := c.Call(context.Background(), rpc.MethodDevicesList, nil, &devs); err != nil {
		return eventMsg{text: "load devices: " + err.Error()}
	}
	var policies []rpc.PolicyEntryDTO
	if err := c.Call(context.Background(), rpc.MethodPolicyList, nil, &policies); err != nil {
		policies = nil
	}
	policyByMAC := make(map[string]rpc.PolicyEntryDTO, len(policies))
	for _, p := range policies {
		policyByMAC[p.MAC] = p
	}
	rows := make([]deviceRow, 0, len(devs))
	for _, d := range devs {
		row := deviceRow{ip: d.IP, mac: d.MAC, hostname: d.Hostname, vendor: d.Vendor}
		if p, ok := policyByMAC[d.MAC]; ok {
			row.policy = summarisePolicy(p)
		}
		rows = append(rows, row)
	}
	return devicesLoadedMsg{rows: rows}
}

func summarisePolicy(p rpc.PolicyEntryDTO) string {
	switch p.Kind {
	case "drop":
		return "drop"
	case "throttle":
		return fmt.Sprintf("throttle %dkbit", p.RateKbit)
	case "pcap":
		return "pcap"
	}
	return "?"
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

// scanCmd issues a Scan RPC and returns scanCompleteMsg with the elapsed
// time and current device count. The RPC blocks for the full scan window
// (~8s) — the model uses the .scanning flag to show a spinner during that
// time so the dashboard isn't visibly frozen.
func scanCmd(c *rpc.Client) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		var r map[string]string
		err := c.Call(context.Background(), rpc.MethodScan, nil, &r)
		elapsed := time.Since(start)
		// Best-effort device count.
		var devs []rpc.DeviceDTO
		_ = c.Call(context.Background(), rpc.MethodDevicesList, nil, &devs)
		return scanCompleteMsg{err: err, elapsed: elapsed, deviceCount: len(devs)}
	}
}

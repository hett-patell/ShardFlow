package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

type deviceRow struct {
	ip       string
	mac      string
	hostname string
	vendor   string
	policy   string
}

type model struct {
	client          *rpc.Client
	devices         []deviceRow
	cursor          int
	logLines        []string
	lastTick        time.Time
	width           int
	height          int
	defaultRateKbit int
	defaultPcapDir  string
}

func newModel(c *rpc.Client, defaultRateKbit int, defaultPcapDir string) model {
	return model{
		client: c, lastTick: time.Now(),
		defaultRateKbit: defaultRateKbit,
		defaultPcapDir:  defaultPcapDir,
	}
}

// update is a test adapter that returns model rather than tea.Model.
func (m model) update(msg tea.Msg) (model, tea.Cmd) {
	nm, cmd := m.Update(msg)
	return nm.(model), cmd
}

func (m model) Init() tea.Cmd {
	return tea.Batch(refreshDevicesCmd(m.client), waitForEventCmd(m.client))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		if r, ok := keyMatch(msg, "qQ"); ok && (r == 'q' || r == 'Q') {
			return m, tea.Quit
		}
		if _, ok := keyMatch(msg, "j"); ok {
			if m.cursor < len(m.devices)-1 {
				m.cursor++
			}
			return m, nil
		}
		if _, ok := keyMatch(msg, "k"); ok {
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		}
		if r, ok := keyMatch(msg, "dtpx"); ok && len(m.devices) > 0 {
			return m, applyPolicyCmd(m.client, m.devices[m.cursor].ip, r, m.defaultRateKbit, m.defaultPcapDir)
		}
		if _, ok := keyMatch(msg, "s"); ok {
			return m, tea.Batch(scanCmd(m.client), refreshDevicesCmd(m.client))
		}
	case devicesLoadedMsg:
		m.devices = msg.rows
		if m.cursor >= len(m.devices) {
			m.cursor = 0
		}
	case eventMsg:
		stamped := time.Now().Format("15:04:05") + " " + msg.text
		m.logLines = append(m.logLines, stamped)
		if len(m.logLines) > 200 {
			m.logLines = m.logLines[len(m.logLines)-200:]
		}
		next := waitForEventCmd(m.client)
		if msg.refreshDevices {
			return m, tea.Batch(next, refreshDevicesCmd(m.client))
		}
		return m, next
	case disconnectedMsg:
		m.logLines = append(m.logLines, time.Now().Format("15:04:05")+" ✗ daemon disconnected")
		return m, nil
	}
	return m, nil
}

// hacker palette: matrix-green, hot-pink alerts, cyan info, dim gray scaffolding
var (
	neonGreen   = lipgloss.Color("#00ff66")
	hotPink     = lipgloss.Color("#ff3a8c")
	cyan        = lipgloss.Color("#00e5ff")
	amber       = lipgloss.Color("#ffaa00")
	dim         = lipgloss.Color("#6a6a6a")
	deeperDim   = lipgloss.Color("#3a3a3a")
	whiteBright = lipgloss.Color("#ffffff")

	bannerStyle = lipgloss.NewStyle().Foreground(neonGreen).Bold(true)
	subBanner   = lipgloss.NewStyle().Foreground(cyan).Italic(true)
	headerCol   = lipgloss.NewStyle().Foreground(dim).Bold(true).Underline(true)
	rowDim      = lipgloss.NewStyle().Foreground(dim)
	rowSelected = lipgloss.NewStyle().Foreground(whiteBright).Background(lipgloss.Color("#003322")).Bold(true)
	macStyle    = lipgloss.NewStyle().Foreground(amber)
	ipStyle     = lipgloss.NewStyle().Foreground(cyan)
	vendorStyle = lipgloss.NewStyle().Foreground(neonGreen)
	hostStyle   = lipgloss.NewStyle().Foreground(whiteBright)
	dropTag     = lipgloss.NewStyle().Foreground(hotPink).Bold(true)
	throttleTag = lipgloss.NewStyle().Foreground(amber).Bold(true)
	pcapTag     = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	noPolicy    = lipgloss.NewStyle().Foreground(deeperDim)
	keyHint     = lipgloss.NewStyle().Foreground(neonGreen).Bold(true)
	keyLabel    = lipgloss.NewStyle().Foreground(dim)
	panelBorder = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(neonGreen).
			Padding(0, 1)
	panelTitle = lipgloss.NewStyle().Foreground(neonGreen).Bold(true)
	statusBar  = lipgloss.NewStyle().Foreground(dim).Background(lipgloss.Color("#0a0a0a"))
)

const banner = `   _____ __                   ____  _____
  / ___// /_  ____ __________/ / / / __  )___ _      __
  \__ \/ __ \/ __  / ___/ __  / /_/ / __  / __ \ | /| / /
 ___/ / / / / /_/ / /  / /_/ / __  / /_/ / /_/ / |/ |/ /
/____/_/ /_/\__,_/_/   \__,_/_/ /_/_/ /_/\____/|__/|__/  `

func renderBanner() string {
	return bannerStyle.Render(banner) + "\n" +
		subBanner.Render("    L A N   w o r k b e n c h  /  authorized pentest only") + "\n"
}

func policyTag(policy string) string {
	switch {
	case policy == "" || policy == "—":
		return noPolicy.Render("·")
	case policy == "drop":
		return dropTag.Render("⊘ DROP")
	case strings.HasPrefix(policy, "throttle"):
		return throttleTag.Render("◐ " + strings.ToUpper(policy))
	case policy == "pcap":
		return pcapTag.Render("◉ PCAP")
	}
	return policy
}

func (m model) View() string {
	// === Banner ===
	out := strings.Builder{}
	out.WriteString(renderBanner())

	// === Status line ===
	policies := 0
	for _, d := range m.devices {
		if d.policy != "" {
			policies++
		}
	}
	statusLine := fmt.Sprintf(" devices: %d  active-policies: %d  uplink: ◉ %s ",
		len(m.devices), policies, time.Now().Format("15:04:05"))
	out.WriteString(statusBar.Width(maxWidth(m.width, 80)).Render(statusLine))
	out.WriteString("\n\n")

	// === Devices panel (left) ===
	left := strings.Builder{}
	left.WriteString(panelTitle.Render(fmt.Sprintf("┳ DEVICES [%d]", len(m.devices))))
	left.WriteString("\n")
	left.WriteString(headerCol.Render(fmt.Sprintf(" %-15s  %-17s  %-22s  %-20s  %s",
		"IP", "MAC", "VENDOR", "HOSTNAME", "POLICY")))
	left.WriteString("\n")
	if len(m.devices) == 0 {
		left.WriteString(rowDim.Render(" (no devices yet — press [s] to scan)"))
		left.WriteString("\n")
	}
	for i, d := range m.devices {
		ip := ipStyle.Render(fmt.Sprintf("%-15s", d.ip))
		mac := macStyle.Render(fmt.Sprintf("%-17s", d.mac))
		vendor := truncate(d.vendor, 22)
		if vendor == "" {
			vendor = "—"
		}
		hostname := truncate(d.hostname, 20)
		if hostname == "" {
			hostname = "—"
		}
		ven := vendorStyle.Render(fmt.Sprintf("%-22s", vendor))
		host := hostStyle.Render(fmt.Sprintf("%-20s", hostname))
		tag := policyTag(d.policy)

		row := fmt.Sprintf(" %s  %s  %s  %s  %s", ip, mac, ven, host, tag)
		if i == m.cursor {
			left.WriteString(rowSelected.Render("▶" + row))
		} else {
			left.WriteString(" " + row)
		}
		left.WriteString("\n")
	}

	// === Detail / actions panel (right) ===
	right := strings.Builder{}
	right.WriteString(panelTitle.Render("┳ TARGET"))
	right.WriteString("\n")
	if len(m.devices) > 0 {
		d := m.devices[m.cursor]
		right.WriteString(rowDim.Render("ip      ") + ipStyle.Render(d.ip) + "\n")
		right.WriteString(rowDim.Render("mac     ") + macStyle.Render(d.mac) + "\n")
		if d.vendor != "" {
			right.WriteString(rowDim.Render("vendor  ") + vendorStyle.Render(d.vendor) + "\n")
		}
		if d.hostname != "" {
			right.WriteString(rowDim.Render("host    ") + hostStyle.Render(d.hostname) + "\n")
		}
		right.WriteString(rowDim.Render("policy  ") + policyTag(d.policy) + "\n")
	} else {
		right.WriteString(rowDim.Render("(no target)\n"))
	}
	right.WriteString("\n")
	right.WriteString(panelTitle.Render("┳ ACTIONS"))
	right.WriteString("\n")
	right.WriteString(keyHint.Render("[d]") + " " + keyLabel.Render("drop") + "      " +
		dropTag.Render("⊘") + " cut traffic\n")
	right.WriteString(keyHint.Render("[t]") + " " + keyLabel.Render("throttle") + "  " +
		throttleTag.Render("◐") + " rate-limit\n")
	right.WriteString(keyHint.Render("[p]") + " " + keyLabel.Render("pcap") + "      " +
		pcapTag.Render("◉") + " capture\n")
	right.WriteString(keyHint.Render("[x]") + " " + keyLabel.Render("clear") + "     restore\n")

	leftPanel := panelBorder.Copy().BorderForeground(neonGreen).Render(left.String())
	rightPanel := panelBorder.Copy().BorderForeground(cyan).Render(right.String())
	panels := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, "  ", rightPanel)
	out.WriteString(panels)
	out.WriteString("\n\n")

	// === Log panel ===
	logBox := strings.Builder{}
	logBox.WriteString(panelTitle.Render("┳ EVENT LOG"))
	logBox.WriteString("\n")
	logs := tail(m.logLines, 8)
	if len(logs) == 0 {
		logBox.WriteString(rowDim.Render("(quiet)"))
	} else {
		for _, line := range logs {
			logBox.WriteString(rowDim.Render(line))
			logBox.WriteString("\n")
		}
	}
	out.WriteString(panelBorder.Copy().BorderForeground(dim).Render(logBox.String()))
	out.WriteString("\n")

	// === Bottom keys ===
	out.WriteString(rowDim.Render(" "+
		keyHint.Render("[j/k]")+" "+keyLabel.Render("move")+"   "+
		keyHint.Render("[s]")+" "+keyLabel.Render("scan")+"   "+
		keyHint.Render("[d/t/p/x]")+" "+keyLabel.Render("policy")+"   "+
		keyHint.Render("[q]")+" "+keyLabel.Render("quit")) + "\n")

	return out.String()
}

func maxWidth(have, fallback int) int {
	if have <= 0 {
		return fallback
	}
	return have
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return s[:n-1] + "…"
}

func tail(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

type eventMsg struct {
	text           string
	refreshDevices bool
}

type devicesLoadedMsg struct{ rows []deviceRow }

type disconnectedMsg struct{}

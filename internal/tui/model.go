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
		client:          c,
		lastTick:        time.Now(),
		width:           120, // sane default until WindowSizeMsg arrives
		height:          40,
		defaultRateKbit: defaultRateKbit,
		defaultPcapDir:  defaultPcapDir,
	}
}

// update is a test adapter that returns model rather than tea.Model.
func (m model) update(msg tea.Msg) (model, tea.Cmd) {
	nm, cmd := m.Update(msg)
	return nm.(model), cmd
}

// tickMsg fires once a second for live clock + auto-refresh of devices.
type tickMsg time.Time

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		refreshDevicesCmd(m.client),
		waitForEventCmd(m.client),
		tickEverySecond(),
	)
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
		if _, ok := keyMatch(msg, "jJ"); ok {
			if m.cursor < len(m.devices)-1 {
				m.cursor++
			}
			return m, nil
		}
		if _, ok := keyMatch(msg, "kK"); ok {
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		}
		// Policy keys: D drop, T throttle, P pcap; C or X to clear/restore.
		// Lowercase and uppercase both work — a panicking operator should
		// not have to remember which case fires the kill switch.
		if r, ok := keyMatch(msg, "dDtTpPxXcCrR"); ok && len(m.devices) > 0 {
			actionKey := normalizePolicyKey(r)
			return m, applyPolicyCmd(m.client, m.devices[m.cursor].ip, actionKey,
				m.defaultRateKbit, m.defaultPcapDir)
		}
		if _, ok := keyMatch(msg, "sS"); ok {
			return m, tea.Batch(scanCmd(m.client), refreshDevicesCmd(m.client))
		}

	case devicesLoadedMsg:
		m.devices = msg.rows
		if m.cursor >= len(m.devices) {
			m.cursor = max0(len(m.devices) - 1)
		}

	case eventMsg:
		// Filter out the noisy 1Hz counter heartbeat — it's just a clock
		// from the daemon, not something an operator wants in their log.
		if !strings.HasPrefix(msg.text, "counters.tick") {
			stamped := time.Now().Format("15:04:05") + "  " + msg.text
			m.logLines = append(m.logLines, stamped)
			if len(m.logLines) > 200 {
				m.logLines = m.logLines[len(m.logLines)-200:]
			}
		}
		next := waitForEventCmd(m.client)
		if msg.refreshDevices {
			return m, tea.Batch(next, refreshDevicesCmd(m.client))
		}
		return m, next

	case tickMsg:
		m.lastTick = time.Time(msg)
		// Auto-refresh device list every 3 ticks (3s) so the dashboard
		// stays fresh even if no events fired (e.g., poison kept devices
		// quiet on the wire).
		if int(m.lastTick.Unix())%3 == 0 {
			return m, tea.Batch(tickEverySecond(), refreshDevicesCmd(m.client))
		}
		return m, tickEverySecond()

	case disconnectedMsg:
		m.logLines = append(m.logLines, time.Now().Format("15:04:05")+"  ✗ daemon disconnected")
		return m, nil
	}
	return m, nil
}

// normalizePolicyKey maps both cases and the alt clear-keys onto the four
// canonical actions ('d' drop, 't' throttle, 'p' pcap, 'x' clear) that the
// underlying applyPolicyCmd already understands.
func normalizePolicyKey(r rune) rune {
	switch r {
	case 'd', 'D':
		return 'd'
	case 't', 'T':
		return 't'
	case 'p', 'P':
		return 'p'
	case 'x', 'X', 'c', 'C', 'r', 'R':
		return 'x'
	}
	return r
}

// === styling ===

var (
	neonGreen   = lipgloss.Color("#00ff88")
	hotPink     = lipgloss.Color("#ff3a8c")
	cyan        = lipgloss.Color("#00e5ff")
	amber       = lipgloss.Color("#ffaa00")
	dim         = lipgloss.Color("#7a7a7a")
	deeperDim   = lipgloss.Color("#3a3a3a")
	whiteBright = lipgloss.Color("#ffffff")

	bannerStyle = lipgloss.NewStyle().Foreground(neonGreen).Bold(true)
	subBanner   = lipgloss.NewStyle().Foreground(cyan).Italic(true)

	headerCol   = lipgloss.NewStyle().Foreground(dim).Bold(true)
	rowDim      = lipgloss.NewStyle().Foreground(dim)
	rowSelected = lipgloss.NewStyle().Foreground(whiteBright).Background(lipgloss.Color("#003a22")).Bold(true)
	macStyle    = lipgloss.NewStyle().Foreground(amber)
	ipStyle     = lipgloss.NewStyle().Foreground(cyan)
	vendorStyle = lipgloss.NewStyle().Foreground(neonGreen)
	hostStyle   = lipgloss.NewStyle().Foreground(whiteBright)
	dropTag     = lipgloss.NewStyle().Foreground(hotPink).Bold(true)
	throttleTag = lipgloss.NewStyle().Foreground(amber).Bold(true)
	pcapTag     = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	noPolicy    = lipgloss.NewStyle().Foreground(deeperDim)

	keyChip = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#000000")).
		Background(neonGreen).
		Bold(true).
		Padding(0, 1)
	keyChipDanger = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(hotPink).
			Bold(true).
			Padding(0, 1)
	keyChipWarn = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(amber).
			Bold(true).
			Padding(0, 1)
	keyChipInfo = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(cyan).
			Bold(true).
			Padding(0, 1)
	keyDesc = lipgloss.NewStyle().Foreground(whiteBright)

	panelTitle = lipgloss.NewStyle().Foreground(neonGreen).Bold(true).Padding(0, 1)
	panelBox   = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(deeperDim).
			Padding(0, 1)
	statusBar = lipgloss.NewStyle().
			Foreground(neonGreen).
			Background(lipgloss.Color("#0a0a0a")).
			Padding(0, 1)
)

const banner = `
███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗██╗      ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔═══██╗██║    ██║
███████╗███████║███████║██████╔╝██║  ██║█████╗  ██║     ██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║     ██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██║  ██║██████╔╝██║     ███████╗╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ `

func renderBanner() string {
	return bannerStyle.Render(banner) + "\n" +
		subBanner.Render("                       L A N   w o r k b e n c h  ::  authorized pentest only")
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
	if m.width < 80 {
		// Tiny terminal — keep something usable rather than mis-aligned.
		return "shardflow tui needs ≥ 80 cols (you have " + fmt.Sprint(m.width) + ")"
	}

	totalW := m.width

	out := strings.Builder{}
	out.WriteString(renderBanner())
	out.WriteString("\n\n")

	// === STATUS BAR ===
	policies := 0
	for _, d := range m.devices {
		if d.policy != "" {
			policies++
		}
	}
	statusText := fmt.Sprintf(" ◉ devices: %d    ⊘ active-policies: %d    ⏱ %s ",
		len(m.devices), policies, m.lastTick.Format("15:04:05"))
	out.WriteString(statusBar.Width(totalW).Render(statusText))
	out.WriteString("\n\n")

	// === DEVICES + TARGET PANELS ===
	rightW := 30
	leftW := totalW - rightW - 4 // 4 = padding/borders allowance
	if leftW < 60 {
		leftW = 60
	}

	left := renderDevicesPanel(m, leftW)
	right := renderTargetPanel(m, rightW)
	panels := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
	out.WriteString(panels)
	out.WriteString("\n\n")

	// === ATTACK PANEL (big keys) ===
	out.WriteString(renderAttackPanel(totalW))
	out.WriteString("\n\n")

	// === EVENT LOG ===
	out.WriteString(renderLogPanel(m, totalW))
	out.WriteString("\n")

	// === BOTTOM HELP ===
	out.WriteString(rowDim.Render(" ") +
		keyChip.Render("J/K") + " " + keyDesc.Render("move") + "    " +
		keyChip.Render("S") + " " + keyDesc.Render("scan") + "    " +
		keyChip.Render("Q") + " " + keyDesc.Render("quit"))
	out.WriteString("\n")

	return out.String()
}

func renderDevicesPanel(m model, width int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render(fmt.Sprintf("┳ DEVICES [%d]", len(m.devices))))
	body.WriteString("\n")
	body.WriteString(headerCol.Render(fmt.Sprintf(" %-15s  %-17s  %-22s  %-25s  %s",
		"IP", "MAC", "VENDOR", "HOSTNAME", "POLICY")))
	body.WriteString("\n")
	if len(m.devices) == 0 {
		body.WriteString(rowDim.Render(" (no devices yet — press [s] to scan)"))
		body.WriteString("\n")
	}
	for i, d := range m.devices {
		ip := ipStyle.Render(fmt.Sprintf("%-15s", d.ip))
		mac := macStyle.Render(fmt.Sprintf("%-17s", d.mac))
		vendor := truncate(d.vendor, 22)
		if vendor == "" {
			vendor = "—"
		}
		hostname := truncate(d.hostname, 25)
		if hostname == "" {
			hostname = "—"
		}
		ven := vendorStyle.Render(fmt.Sprintf("%-22s", vendor))
		host := hostStyle.Render(fmt.Sprintf("%-25s", hostname))
		tag := policyTag(d.policy)

		row := fmt.Sprintf(" %s  %s  %s  %s  %s", ip, mac, ven, host, tag)
		if i == m.cursor {
			body.WriteString(rowSelected.Render("▶" + row))
		} else {
			body.WriteString(" " + row)
		}
		body.WriteString("\n")
	}
	return panelBox.Width(width).Render(body.String())
}

func renderTargetPanel(m model, width int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ TARGET"))
	body.WriteString("\n")
	if len(m.devices) > 0 {
		d := m.devices[m.cursor]
		body.WriteString(rowDim.Render("ip      ") + ipStyle.Render(d.ip) + "\n")
		body.WriteString(rowDim.Render("mac     ") + macStyle.Render(d.mac) + "\n")
		if d.vendor != "" {
			body.WriteString(rowDim.Render("vendor  ") + vendorStyle.Render(truncate(d.vendor, width-10)) + "\n")
		} else {
			body.WriteString(rowDim.Render("vendor  ") + noPolicy.Render("—") + "\n")
		}
		if d.hostname != "" {
			body.WriteString(rowDim.Render("host    ") + hostStyle.Render(truncate(d.hostname, width-10)) + "\n")
		} else {
			body.WriteString(rowDim.Render("host    ") + noPolicy.Render("—") + "\n")
		}
		body.WriteString(rowDim.Render("policy  ") + policyTag(d.policy) + "\n")
	} else {
		body.WriteString(rowDim.Render("(no target selected)\n"))
	}
	return panelBox.Width(width).Render(body.String())
}

func renderAttackPanel(width int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ ATTACK") + "\n")

	row1 := keyChipDanger.Render(" D ") + " " + keyDesc.Render("DROP — cut traffic to/from device") + "      " +
		keyChipWarn.Render(" T ") + " " + keyDesc.Render("THROTTLE — rate-limit (default 200kbit)")
	row2 := keyChipInfo.Render(" P ") + " " + keyDesc.Render("PCAP — passive capture to .pcapng") + "    " +
		keyChip.Render(" C ") + " " + keyDesc.Render("CLEAR — restore device, send corrective ARP")

	body.WriteString(" " + row1 + "\n")
	body.WriteString(" " + row2 + "\n")
	return panelBox.Width(width).Render(body.String())
}

func renderLogPanel(m model, width int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ EVENT LOG") + "\n")
	logs := tail(m.logLines, 8)
	if len(logs) == 0 {
		body.WriteString(rowDim.Render(" (quiet — daemon events will appear here)"))
		body.WriteString("\n")
	} else {
		for _, line := range logs {
			body.WriteString(" " + rowDim.Render(line))
			body.WriteString("\n")
		}
	}
	return panelBox.Width(width).Render(body.String())
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
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

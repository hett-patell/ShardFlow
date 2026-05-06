package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

// frameSize is the extra width that panelBox occupies beyond what its
// `Width()` call sets — for our `RoundedBorder() + Padding(0,1)` style,
// lipgloss puts the padding INSIDE the Width() and the border OUTSIDE,
// so external = Width() + 2 (one border char on each side).
const frameSize = 2

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
	tickCount       int
	width           int
	height          int
	defaultRateKbit int
	defaultPcapDir  string

	// Scan progress state. When the operator presses [S] we kick off a
	// scan RPC which can take up to ~8s (2s active sweep + 3s mDNS +
	// 3s SSDP, sequentially). Without explicit feedback the dashboard
	// looks frozen for that whole window.
	scanning    bool
	scanStarted time.Time
}

func newModel(c *rpc.Client, defaultRateKbit int, defaultPcapDir string) model {
	return model{
		client:          c,
		lastTick:        time.Now(),
		width:           120,
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

// spinnerTickMsg fires every 250ms but only while a scan is in progress
// (Update arms the next one only if m.scanning). Drives the animated
// spinner so it feels live without the regular 1Hz tick burning CPU.
type spinnerTickMsg time.Time

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func spinnerTick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return spinnerTickMsg(t) })
}

// scanSpinnerFrame returns one frame of a braille spinner animation.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func scanSpinnerFrame(tick int) string {
	return spinnerFrames[tick%len(spinnerFrames)]
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
		// D/T/P drop/throttle/pcap; C/X/R clear/restore. Both cases.
		if r, ok := keyMatch(msg, "dDtTpPxXcCrR"); ok && len(m.devices) > 0 {
			actionKey := normalizePolicyKey(r)
			return m, applyPolicyCmd(m.client, m.devices[m.cursor].ip, actionKey,
				m.defaultRateKbit, m.defaultPcapDir)
		}
		if _, ok := keyMatch(msg, "sS"); ok {
			if m.scanning {
				return m, nil // already scanning, ignore re-presses
			}
			m.scanning = true
			m.scanStarted = time.Now()
			return m, tea.Batch(scanCmd(m.client), spinnerTick())
		}

	case devicesLoadedMsg:
		m.devices = msg.rows
		if m.cursor >= len(m.devices) {
			m.cursor = max0(len(m.devices) - 1)
		}

	case eventMsg:
		// Skip the noisy 1Hz counter heartbeat.
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
		m.tickCount++
		// Every 3 seconds, force a device-list refresh so the screen
		// stays current even if no daemon events fire.
		if m.tickCount%3 == 0 {
			return m, tea.Batch(tickEverySecond(), refreshDevicesCmd(m.client))
		}
		return m, tickEverySecond()

	case spinnerTickMsg:
		// Only re-arm while scanning is still in flight. The View() will
		// re-render with the next spinner frame.
		m.tickCount++
		if m.scanning {
			return m, spinnerTick()
		}
		return m, nil

	case scanCompleteMsg:
		m.scanning = false
		elapsed := msg.elapsed.Truncate(time.Millisecond)
		var line string
		if msg.err != nil {
			line = fmt.Sprintf("%s  ✗ scan failed (%s): %s",
				time.Now().Format("15:04:05"), elapsed, msg.err)
		} else {
			line = fmt.Sprintf("%s  ✓ scan complete (%s, %d devices)",
				time.Now().Format("15:04:05"), elapsed, msg.deviceCount)
		}
		m.logLines = append(m.logLines, line)
		return m, refreshDevicesCmd(m.client)

	case disconnectedMsg:
		m.logLines = append(m.logLines, time.Now().Format("15:04:05")+"  ✗ daemon disconnected")
		return m, nil
	}
	return m, nil
}

// normalizePolicyKey maps both cases and the alt clear-keys onto the four
// canonical actions ('d' drop, 't' throttle, 'p' pcap, 'x' clear).
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
	selectBG    = lipgloss.Color("#1a3d2e") // muted forest-green for selection bg

	bannerStyle = lipgloss.NewStyle().Foreground(neonGreen).Bold(true)
	subBanner   = lipgloss.NewStyle().Foreground(cyan).Italic(true)

	headerCol = lipgloss.NewStyle().Foreground(dim).Bold(true)
	rowDim    = lipgloss.NewStyle().Foreground(dim)
	macStyle  = lipgloss.NewStyle().Foreground(amber)
	ipStyle   = lipgloss.NewStyle().Foreground(cyan)
	venStyle  = lipgloss.NewStyle().Foreground(neonGreen)
	hostStyle = lipgloss.NewStyle().Foreground(whiteBright)
	dropTag   = lipgloss.NewStyle().Foreground(hotPink).Bold(true)
	throttleTag = lipgloss.NewStyle().Foreground(amber).Bold(true)
	pcapTag     = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	noPolicy    = lipgloss.NewStyle().Foreground(deeperDim)

	// The selected row uses a single all-row style with background + bold.
	// Inner per-cell colors are intentionally NOT applied to the selected
	// row — otherwise the cell-foreground colors override the highlight
	// foreground and the user can't tell what's selected.
	selRowStyle = lipgloss.NewStyle().
			Foreground(whiteBright).
			Background(selectBG).
			Bold(true)

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

	panelTitle = lipgloss.NewStyle().Foreground(neonGreen).Bold(true)
	panelBox   = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(deeperDim).
			Padding(0, 1)
	statusBar = lipgloss.NewStyle().
			Foreground(neonGreen).
			Background(lipgloss.Color("#0a0a0a")).
			Padding(0, 1).
			Bold(true)
	scanSpinningStyle = lipgloss.NewStyle().Foreground(amber).Bold(true)
)

const banner = `███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗██╗      ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔═══██╗██║    ██║
███████╗███████║███████║██████╔╝██║  ██║█████╗  ██║     ██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║     ██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██║  ██║██████╔╝██║     ███████╗╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ `

const bannerSmall = `╔═══════════════╗
║   SHARDFLOW   ║
╚═══════════════╝`

func renderBanner(width int) string {
	if width < 80 {
		return bannerStyle.Render(bannerSmall)
	}
	return bannerStyle.Render(banner) + "\n" +
		subBanner.Render("           L A N   w o r k b e n c h  ::  authorized pentest only")
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

// maxRenderWidth caps how wide the dashboard renders. On ultrawide terminals
// (200+ cols) panels would otherwise stretch to ridiculous widths with most
// of the area being blank, which looks empty and is hard to read across.
// We render at ≤ maxRenderWidth and leave any remaining columns blank on
// the right.
const maxRenderWidth = 140

func (m model) View() string {
	totalW := m.width
	if totalW < 70 {
		return "shardflow tui needs ≥ 70 cols (you have " + fmt.Sprint(totalW) + ")\n" +
			"resize your terminal and re-launch."
	}
	if totalW > maxRenderWidth {
		totalW = maxRenderWidth
	}

	out := strings.Builder{}
	out.WriteString(renderBanner(totalW))
	out.WriteString("\n\n")

	// === STATUS BAR ===
	policies := 0
	for _, d := range m.devices {
		if d.policy != "" {
			policies++
		}
	}
	scanFragment := ""
	if m.scanning {
		elapsed := time.Since(m.scanStarted).Truncate(time.Second)
		scanFragment = "    " + scanSpinningStyle.Render(
			scanSpinnerFrame(m.tickCount)+fmt.Sprintf(" SCANNING… (%s)", elapsed))
	}
	statusText := fmt.Sprintf(" ◉ devices: %d    ⊘ active-policies: %d    ⏱ %s%s ",
		len(m.devices), policies, m.lastTick.Format("15:04:05"), scanFragment)
	out.WriteString(statusBar.Width(totalW).Render(statusText))
	out.WriteString("\n\n")

	// === DEVICES + TARGET (horizontal pair) ===
	// outer-width math: leftOuter + 2 (separator) + rightOuter == totalW
	// where outer = inner + frameSize (the border).
	rightInner := 32
	if totalW < 110 {
		rightInner = 28
	}
	rightOuter := rightInner + frameSize
	leftOuter := totalW - rightOuter - 2 // 2 = "  " separator
	leftInner := leftOuter - frameSize

	left := renderDevicesPanel(m, leftInner)
	right := renderTargetPanel(m, rightInner)
	panels := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
	out.WriteString(panels)
	out.WriteString("\n\n")

	// === ATTACK PANEL (full width) ===
	out.WriteString(renderAttackPanel(totalW - frameSize))
	out.WriteString("\n\n")

	// === EVENT LOG (full width) ===
	out.WriteString(renderLogPanel(m, totalW-frameSize))
	out.WriteString("\n")

	// === BOTTOM HELP ===
	out.WriteString(" " +
		keyChip.Render("J/K") + " " + keyDesc.Render("move") + "    " +
		keyChip.Render("S") + " " + keyDesc.Render("scan") + "    " +
		keyChip.Render("Q") + " " + keyDesc.Render("quit"))
	out.WriteString("\n")

	return out.String()
}

// Column widths for the devices list. Tuned so a row fits comfortably in
// inner widths ≥ ~88 chars (covered by terminals ≥ 100 cols). Total row
// content = 1 (lead) + 15 + 2 + 17 + 2 + 18 + 2 + 22 + 2 + 8 = 89 chars.
const (
	colIP     = 15
	colMAC    = 17
	colVendor = 18
	colHost   = 22
	colPolicy = 8
)

func renderDevicesPanel(m model, innerWidth int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render(fmt.Sprintf("┳ DEVICES [%d]", len(m.devices))))
	body.WriteString("\n")
	body.WriteString(headerCol.Render(fmt.Sprintf(" %-*s  %-*s  %-*s  %-*s  %-*s",
		colIP, "IP", colMAC, "MAC", colVendor, "VENDOR",
		colHost, "HOSTNAME", colPolicy, "POLICY")))
	body.WriteString("\n")
	if len(m.devices) == 0 {
		body.WriteString(rowDim.Render(" (no devices yet — press [s] to scan)"))
		body.WriteString("\n")
		return panelBox.Width(innerWidth).Render(body.String())
	}
	for i, d := range m.devices {
		vendor := truncate(d.vendor, colVendor)
		if vendor == "" {
			vendor = "—"
		}
		hostname := truncate(d.hostname, colHost)
		if hostname == "" {
			hostname = "—"
		}
		policy := compactPolicyText(d.policy)

		// Plain padded row — used for selected variant where outer style
		// must own the whole line.
		plain := fmt.Sprintf(" %-*s  %-*s  %-*s  %-*s  %-*s",
			colIP, d.ip, colMAC, d.mac,
			colVendor, vendor, colHost, hostname,
			colPolicy, policy)

		if i == m.cursor {
			body.WriteString(selRowStyle.Render("▶" + plain[1:]))
		} else {
			// Non-selected: per-cell color, identical layout.
			ip := ipStyle.Render(fmt.Sprintf("%-*s", colIP, d.ip))
			mac := macStyle.Render(fmt.Sprintf("%-*s", colMAC, d.mac))
			ven := venStyle.Render(fmt.Sprintf("%-*s", colVendor, vendor))
			host := hostStyle.Render(fmt.Sprintf("%-*s", colHost, hostname))
			tag := compactPolicyTag(d.policy, colPolicy)
			body.WriteString(fmt.Sprintf(" %s  %s  %s  %s  %s", ip, mac, ven, host, tag))
		}
		body.WriteString("\n")
	}
	return panelBox.Width(innerWidth).Render(body.String())
}

// compactPolicyText is the un-styled, fixed-width text form for the
// devices-list policy column. ≤ colPolicy (8) visible chars so the row
// budget never overflows.
func compactPolicyText(p string) string {
	switch {
	case p == "" || p == "—":
		return "·"
	case p == "drop":
		return "⊘ DROP"
	case strings.HasPrefix(p, "throttle"):
		// "throttle 200kbit" → "◐ 200K" (6 visual cells, well under 8)
		rest := strings.TrimSpace(strings.TrimPrefix(p, "throttle"))
		rest = strings.TrimSuffix(rest, "bit")
		rest = strings.ToUpper(rest)
		if rest == "" {
			return "◐ THR"
		}
		return "◐ " + rest
	case p == "pcap":
		return "◉ PCAP"
	}
	return p
}

func compactPolicyTag(p string, width int) string {
	text := compactPolicyText(p)
	// pad-or-truncate to `width` visible columns
	if lipglossWidth(text) < width {
		text = text + strings.Repeat(" ", width-lipglossWidth(text))
	}
	switch {
	case p == "drop":
		return dropTag.Render(text)
	case strings.HasPrefix(p, "throttle"):
		return throttleTag.Render(text)
	case p == "pcap":
		return pcapTag.Render(text)
	}
	return noPolicy.Render(text)
}

// lipglossWidth returns the visible width of s. Wraps lipgloss.Width so we
// don't have to import lipgloss in every spot.
func lipglossWidth(s string) int {
	return lipgloss.Width(s)
}

func renderTargetPanel(m model, innerWidth int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ TARGET"))
	body.WriteString("\n")
	if len(m.devices) > 0 {
		d := m.devices[m.cursor]
		// "label  " is 8 chars; add the panel's own (0,1) padding ⇒ 10 chars
		// of overhead inside Width(innerWidth). Truncate values to whatever
		// remains so they don't wrap.
		fieldW := innerWidth - 10
		if fieldW < 8 {
			fieldW = 8
		}
		body.WriteString(rowDim.Render("ip      ") + ipStyle.Render(truncate(d.ip, fieldW)) + "\n")
		body.WriteString(rowDim.Render("mac     ") + macStyle.Render(truncate(d.mac, fieldW)) + "\n")
		if d.vendor != "" {
			body.WriteString(rowDim.Render("vendor  ") + venStyle.Render(truncate(d.vendor, fieldW)) + "\n")
		} else {
			body.WriteString(rowDim.Render("vendor  ") + noPolicy.Render("—") + "\n")
		}
		if d.hostname != "" {
			body.WriteString(rowDim.Render("host    ") + hostStyle.Render(truncate(d.hostname, fieldW)) + "\n")
		} else {
			body.WriteString(rowDim.Render("host    ") + noPolicy.Render("—") + "\n")
		}
		body.WriteString(rowDim.Render("policy  ") + policyTag(d.policy) + "\n")
	} else {
		body.WriteString(rowDim.Render("(no target selected)\n"))
	}
	return panelBox.Width(innerWidth).Render(body.String())
}

func renderAttackPanel(innerWidth int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ ATTACK") + "\n")

	// Pad each left-cell to a fixed visible width so the right-cell's chip
	// starts at the same column on both rows. Without this the right
	// chips (T, C) drift because their left-cell descriptions differ in
	// length.
	const cellW = 48

	leftD := padCell(keyChipDanger.Render(" D ")+" "+keyDesc.Render("DROP — cut traffic to/from device"), cellW)
	leftP := padCell(keyChipInfo.Render(" P ")+" "+keyDesc.Render("PCAP — passive capture to .pcapng"), cellW)

	rightT := keyChipWarn.Render(" T ") + " " + keyDesc.Render("THROTTLE — rate-limit (default 200kbit)")
	rightC := keyChip.Render(" C ") + " " + keyDesc.Render("CLEAR — restore device, send corrective ARP")

	body.WriteString(" " + leftD + rightT + "\n")
	body.WriteString(" " + leftP + rightC)
	return panelBox.Width(innerWidth).Render(body.String())
}

// padCell pads s with trailing spaces until its visible width (ignoring
// ANSI escapes) is at least w. Used to align columns in mixed-style rows.
func padCell(s string, w int) string {
	have := lipgloss.Width(s)
	if have >= w {
		return s
	}
	return s + strings.Repeat(" ", w-have)
}

func renderLogPanel(m model, innerWidth int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ EVENT LOG") + "\n")
	logs := tail(m.logLines, 8)
	if len(logs) == 0 {
		body.WriteString(rowDim.Render(" (quiet — daemon events will appear here)"))
	} else {
		for i, line := range logs {
			body.WriteString(" " + rowDim.Render(line))
			if i < len(logs)-1 {
				body.WriteString("\n")
			}
		}
	}
	return panelBox.Width(innerWidth).Render(body.String())
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

// scanCompleteMsg is delivered when an [S]-triggered scan returns. The
// model uses it to clear the scanning flag and log a result line.
type scanCompleteMsg struct {
	err         error
	elapsed     time.Duration
	deviceCount int
}

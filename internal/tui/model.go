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
	sockPath        string
	devices         []deviceRow
	cursor          int
	logLines        []string
	lastTick        time.Time
	tickCount       int
	width           int
	height          int
	defaultRateKbit int
	defaultPcapDir  string

	// session caches the last Session.Get response so the SESSION
	// panel renders without a per-frame RPC round-trip. Refreshed
	// periodically by the regular tick loop and on every scan
	// completion (that's when LastScanReplies / PoisonsActive shift).
	session rpc.SessionDTO

	// Scan progress state. When the operator presses [S] we kick off a
	// scan RPC which can take up to ~8s (2s active sweep + 3s mDNS +
	// 3s SSDP, sequentially). Without explicit feedback the dashboard
	// looks frozen for that whole window.
	scanning    bool
	scanStarted time.Time

	// Reconnect state. When the daemon disconnects we flip
	// reconnecting=true, schedule a Dial retry with backoff, and keep
	// the dashboard interactive (showing stale data) instead of dying.
	reconnecting bool
	reconnectTry int

	// Filter state. filterMode=true when the user is actively typing a
	// filter expression (after pressing /); filter holds the current
	// query whether we're typing or already committed. cursor refers
	// into the FILTERED list, not m.devices, so all index work goes
	// through visibleDevices().
	filterMode bool
	filter     string

	// Viewport offset into the filtered device list — index of the
	// first row visible in the devices panel. Updated by ensureCursorVisible
	// after every cursor move so a long list scrolls naturally.
	viewportOffset int

	// showHelp expands the bottom keybind row into a multi-line help
	// panel listing every shortcut. Toggled with [?].
	showHelp bool
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

type tickMsg time.Time
type spinnerTickMsg time.Time

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func spinnerTick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return spinnerTickMsg(t) })
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func scanSpinnerFrame(tick int) string {
	return spinnerFrames[tick%len(spinnerFrames)]
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		refreshDevicesCmd(m.client),
		refreshSessionCmd(m.client),
		waitForEventCmd(m.client),
		tickEverySecond(),
	)
}

// visibleDevices returns m.devices filtered by m.filter (substring,
// case-insensitive match against ip/mac/hostname/vendor). When the
// filter is empty the original slice is returned without copying.
func (m model) visibleDevices() []deviceRow {
	if m.filter == "" {
		return m.devices
	}
	q := strings.ToLower(m.filter)
	out := make([]deviceRow, 0, len(m.devices))
	for _, d := range m.devices {
		if strings.Contains(strings.ToLower(d.ip), q) ||
			strings.Contains(strings.ToLower(d.mac), q) ||
			strings.Contains(strings.ToLower(d.hostname), q) ||
			strings.Contains(strings.ToLower(d.vendor), q) {
			out = append(out, d)
		}
	}
	return out
}

// devicesViewportHeight estimates how many device rows can fit in the
// devices panel given the current terminal height. The rest of the
// dashboard (banner, status bar, target panel cap, attack panel, log,
// help row, separators) eats roughly 24 lines of fixed chrome on a
// large banner, slightly less on the small one. We leave a safety
// margin of 5 minimum rows so a tiny terminal still shows something.
func (m model) devicesViewportHeight() int {
	const fixedChrome = 24
	h := m.height - fixedChrome
	if m.showHelp {
		h -= 6 // help panel adds ~6 lines
	}
	if h < 5 {
		return 5
	}
	return h
}

func (m *model) ensureCursorVisible() {
	vis := len(m.visibleDevices())
	if vis == 0 {
		m.cursor = 0
		m.viewportOffset = 0
		return
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= vis {
		m.cursor = vis - 1
	}
	height := m.devicesViewportHeight()
	if m.cursor < m.viewportOffset {
		m.viewportOffset = m.cursor
	}
	if m.cursor >= m.viewportOffset+height {
		m.viewportOffset = m.cursor - height + 1
	}
	if m.viewportOffset < 0 {
		m.viewportOffset = 0
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ensureCursorVisible()
		return m, nil

	case tea.KeyMsg:
		// Filter-mode input intercepts most keys: characters extend
		// the filter, backspace shortens, Enter/Esc commit/clear.
		// Action keys (D/T/P/S/Q etc.) are intentionally NOT consumed
		// here so the operator can still escape with Esc and then act.
		if m.filterMode {
			switch msg.Type {
			case tea.KeyEsc:
				// Esc while typing: drop the filter entirely and
				// return to nav mode so the operator gets back the
				// full list with one keystroke.
				m.filterMode = false
				m.filter = ""
				m.cursor = 0
				m.viewportOffset = 0
				return m, nil
			case tea.KeyEnter:
				// Commit: leave nav mode but keep the filter live.
				m.filterMode = false
				m.ensureCursorVisible()
				return m, nil
			case tea.KeyBackspace:
				if len(m.filter) > 0 {
					m.filter = m.filter[:len(m.filter)-1]
					m.cursor = 0
					m.viewportOffset = 0
				}
				return m, nil
			case tea.KeyRunes:
				// Append printable runes to the filter string.
				m.filter += string(msg.Runes)
				m.cursor = 0
				m.viewportOffset = 0
				return m, nil
			}
			// Other special keys ignored while typing a filter.
			return m, nil
		}

		// Esc clears, in priority order: an active filter, the help
		// overlay, or a stuck scanning indicator. The third case is a
		// rescue path: if c.Call(MethodScan) is somehow wedged (e.g. a
		// daemon-side bug past its 15s scanHardTimeout) we let the
		// operator dismiss the spinner so the dashboard isn't visually
		// frozen. The in-flight RPC still resolves on its own; its
		// late scanCompleteMsg just toggles m.scanning back to false
		// (already false), which is harmless.
		if msg.Type == tea.KeyEsc {
			switch {
			case m.filter != "":
				m.filter = ""
				m.cursor = 0
				m.viewportOffset = 0
			case m.showHelp:
				m.showHelp = false
				m.ensureCursorVisible()
			case m.scanning:
				m.scanning = false
				m.logLines = append(m.logLines,
					time.Now().Format("15:04:05")+"  scan dismissed (still running in background)")
				if len(m.logLines) > 200 {
					m.logLines = m.logLines[len(m.logLines)-200:]
				}
			}
			return m, nil
		}

		// Movement: j/k or arrows or pgup/pgdn or g/G.
		switch msg.Type {
		case tea.KeyDown:
			m.cursor++
			m.ensureCursorVisible()
			return m, nil
		case tea.KeyUp:
			m.cursor--
			m.ensureCursorVisible()
			return m, nil
		case tea.KeyPgDown:
			m.cursor += m.devicesViewportHeight()
			m.ensureCursorVisible()
			return m, nil
		case tea.KeyPgUp:
			m.cursor -= m.devicesViewportHeight()
			m.ensureCursorVisible()
			return m, nil
		case tea.KeyHome:
			m.cursor = 0
			m.ensureCursorVisible()
			return m, nil
		case tea.KeyEnd:
			m.cursor = len(m.visibleDevices()) - 1
			m.ensureCursorVisible()
			return m, nil
		}

		if r, ok := keyMatch(msg, "qQ"); ok && (r == 'q' || r == 'Q') {
			return m, tea.Quit
		}
		if _, ok := keyMatch(msg, "jJ"); ok {
			m.cursor++
			m.ensureCursorVisible()
			return m, nil
		}
		if _, ok := keyMatch(msg, "kK"); ok {
			m.cursor--
			m.ensureCursorVisible()
			return m, nil
		}
		if r, ok := keyMatch(msg, "gG"); ok {
			if r == 'G' {
				m.cursor = len(m.visibleDevices()) - 1
			} else {
				m.cursor = 0
			}
			m.ensureCursorVisible()
			return m, nil
		}
		if _, ok := keyMatch(msg, "/"); ok {
			m.filterMode = true
			return m, nil
		}
		if _, ok := keyMatch(msg, "?"); ok {
			m.showHelp = !m.showHelp
			m.ensureCursorVisible()
			return m, nil
		}
		// Policy keys act on the visible (filtered) cursor row.
		if r, ok := keyMatch(msg, "dDtTpPxXcCrR"); ok {
			vis := m.visibleDevices()
			if len(vis) == 0 {
				return m, nil
			}
			actionKey := normalizePolicyKey(r)
			return m, applyPolicyCmd(m.client, vis[m.cursor].ip, actionKey,
				m.defaultRateKbit, m.defaultPcapDir)
		}
		if _, ok := keyMatch(msg, "sS"); ok {
			if m.scanning {
				return m, nil
			}
			m.scanning = true
			m.scanStarted = time.Now()
			return m, tea.Batch(scanCmd(m.client), spinnerTick())
		}

	case devicesLoadedMsg:
		m.devices = msg.rows
		m.ensureCursorVisible()

	case sessionLoadedMsg:
		m.session = msg.session

	case eventMsg:
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
		// Every 3s refresh devices; every 5s also refresh session
		// (poison count + scan diagnostics evolve faster than wifi
		// association which is essentially static for the session).
		if m.tickCount%5 == 0 {
			return m, tea.Batch(tickEverySecond(), refreshDevicesCmd(m.client), refreshSessionCmd(m.client))
		}
		if m.tickCount%3 == 0 {
			return m, tea.Batch(tickEverySecond(), refreshDevicesCmd(m.client))
		}
		return m, tickEverySecond()

	case spinnerTickMsg:
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
		// AP isolation hint: when a wireless scan finds nothing, surface
		// the most likely reason directly in the event log so the
		// operator doesn't need to dig into the SESSION panel to
		// understand why the device list is empty.
		if msg.err == nil && msg.deviceCount == 0 && m.session.Wireless {
			m.logLines = append(m.logLines, time.Now().Format("15:04:05")+
				"  ⚠ no devices found on wifi — guest networks usually have AP isolation enabled (clients can't see each other)")
		}
		return m, tea.Batch(refreshDevicesCmd(m.client), refreshSessionCmd(m.client))

	case disconnectedMsg:
		if !m.reconnecting {
			m.logLines = append(m.logLines, time.Now().Format("15:04:05")+"  ✗ daemon disconnected; reconnecting…")
			m.reconnecting = true
			m.reconnectTry = 0
			return m, reconnectCmd(m.sockPath)
		}
		return m, nil

	case reconnectFailedMsg:
		m.reconnectTry++
		if m.reconnectTry <= 3 {
			m.logLines = append(m.logLines, fmt.Sprintf("%s  reconnect %d failed: %s",
				time.Now().Format("15:04:05"), m.reconnectTry, msg.err))
		}
		delay := time.Second
		switch {
		case m.reconnectTry >= 5:
			delay = 10 * time.Second
		case m.reconnectTry >= 3:
			delay = 5 * time.Second
		case m.reconnectTry >= 2:
			delay = 2 * time.Second
		}
		return m, reconnectAfter(m.sockPath, delay)

	case reconnectedMsg:
		if m.client != nil {
			_ = m.client.Close()
		}
		m.client = msg.client
		m.reconnecting = false
		m.reconnectTry = 0
		m.logLines = append(m.logLines, time.Now().Format("15:04:05")+"  ✓ reconnected to daemon")
		return m, tea.Batch(
			refreshDevicesCmd(m.client),
			refreshSessionCmd(m.client),
			waitForEventCmd(m.client),
		)
	}
	return m, nil
}

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

// === palette ===
//
// The palette is deliberately restrained. Saturated colours at full
// brightness (the previous neon green / hot pink / cyan combo) read as
// "glowy" — eye-catching for screenshots but tiring during a long
// session. These muted tones come from the Tokyo Night family: they
// hold contrast against a dark terminal without screaming. Foreground
// text uses a cool off-white (`mist`) so highlights and selection
// don't have to fight a pure-white baseline.

var (
	sage   = lipgloss.Color("#9ece6a") // muted green: positive, primary accent
	rose   = lipgloss.Color("#e07a83") // muted red: danger / drop
	tan    = lipgloss.Color("#e0af68") // muted yellow-orange: warn / throttle
	steel  = lipgloss.Color("#7aa2f7") // muted blue: info / pcap / accents
	lilac  = lipgloss.Color("#bb9af7") // muted purple: hint / accent text
	mist   = lipgloss.Color("#c0caf5") // primary text — softer than pure white
	slate  = lipgloss.Color("#565f89") // secondary text / dim labels
	shadow = lipgloss.Color("#3b4261") // selection background, panel separators
	depth  = lipgloss.Color("#24283b") // status bar / panel-fill background
	hush   = lipgloss.Color("#414868") // borders, deeper dim
)

var (
	bannerStyle = lipgloss.NewStyle().Foreground(sage)
	subBanner   = lipgloss.NewStyle().Foreground(slate).Italic(true)

	headerCol = lipgloss.NewStyle().Foreground(slate).Bold(true)
	rowDim    = lipgloss.NewStyle().Foreground(slate)
	macStyle  = lipgloss.NewStyle().Foreground(tan)
	ipStyle   = lipgloss.NewStyle().Foreground(steel)
	venStyle  = lipgloss.NewStyle().Foreground(sage)
	hostStyle = lipgloss.NewStyle().Foreground(mist)

	dropTag     = lipgloss.NewStyle().Foreground(rose).Bold(true)
	throttleTag = lipgloss.NewStyle().Foreground(tan).Bold(true)
	pcapTag     = lipgloss.NewStyle().Foreground(steel).Bold(true)
	noPolicy    = lipgloss.NewStyle().Foreground(hush)

	// Selection: foreground stays unchanged from default mist (so the
	// IP/MAC etc. don't lose their colour), only the background
	// switches. No bold — the contrast bump is enough.
	selRowStyle = lipgloss.NewStyle().Background(shadow).Foreground(mist)

	// Key chips: dark fill with a coloured foreground. No glowing
	// black-on-bright chips. Stays readable, doesn't dominate the eye.
	keyChip = lipgloss.NewStyle().
		Foreground(sage).
		Background(depth).
		Bold(true).
		Padding(0, 1)
	keyChipDanger = lipgloss.NewStyle().
			Foreground(rose).
			Background(depth).
			Bold(true).
			Padding(0, 1)
	keyChipWarn = lipgloss.NewStyle().
			Foreground(tan).
			Background(depth).
			Bold(true).
			Padding(0, 1)
	keyChipInfo = lipgloss.NewStyle().
			Foreground(steel).
			Background(depth).
			Bold(true).
			Padding(0, 1)
	keyChipMute = lipgloss.NewStyle().
			Foreground(slate).
			Background(depth).
			Bold(true).
			Padding(0, 1)
	keyDesc = lipgloss.NewStyle().Foreground(mist)

	panelTitle = lipgloss.NewStyle().Foreground(sage).Bold(true)
	panelBox   = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(hush).
			Padding(0, 1)
	statusBar = lipgloss.NewStyle().
			Foreground(mist).
			Background(depth).
			Padding(0, 1)
	statusAccent = lipgloss.NewStyle().Foreground(sage).Bold(true)
	statusDim    = lipgloss.NewStyle().Foreground(slate)

	scanSpinningStyle = lipgloss.NewStyle().Foreground(tan).Bold(true)
	reconnectStyle    = lipgloss.NewStyle().Foreground(rose).Bold(true)
	filterStyle       = lipgloss.NewStyle().Foreground(lilac).Bold(true)
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

type policyKind int

const (
	pkNone policyKind = iota
	pkDrop
	pkThrottle
	pkPcap
)

func classifyPolicy(p string) policyKind {
	switch {
	case p == "" || p == "—":
		return pkNone
	case p == "drop":
		return pkDrop
	case strings.HasPrefix(p, "throttle"):
		return pkThrottle
	case p == "pcap":
		return pkPcap
	}
	return pkNone
}

func policyTag(policy string) string {
	switch classifyPolicy(policy) {
	case pkDrop:
		return dropTag.Render("⊘ DROP")
	case pkThrottle:
		return throttleTag.Render("◐ " + strings.ToUpper(policy))
	case pkPcap:
		return pcapTag.Render("◉ PCAP")
	case pkNone:
		return noPolicy.Render("·")
	}
	return policy
}

// maxRenderWidth was 140 previously — left empty space on ultra-wide
// terminals. The SESSION panel now lives alongside TARGET in the right
// column, so we let the dashboard stretch further before capping.
// 200 cols is the comfortable upper bound: beyond that the device-list
// row gains diminishing returns vs. blank padding inside cells.
const maxRenderWidth = 200

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
	out.WriteString(renderStatusBar(m, totalW))
	out.WriteString("\n\n")

	// Devices on the left; right column stacks TARGET on top of SESSION.
	// The two right-column panels share the same inner width so they
	// align visually.
	rightInner := 36
	if totalW < 110 {
		rightInner = 28
	} else if totalW < 140 {
		rightInner = 32
	}
	rightOuter := rightInner + frameSize
	leftOuter := totalW - rightOuter - 2
	leftInner := leftOuter - frameSize

	left := renderDevicesPanel(m, leftInner)
	right := lipgloss.JoinVertical(lipgloss.Left,
		renderTargetPanel(m, rightInner),
		renderSessionPanel(m, rightInner),
	)
	panels := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
	out.WriteString(panels)
	out.WriteString("\n\n")

	out.WriteString(renderAttackPanel(totalW - frameSize))
	out.WriteString("\n\n")
	out.WriteString(renderLogPanel(m, totalW-frameSize))
	out.WriteString("\n")

	if m.showHelp {
		out.WriteString(renderHelpPanel(totalW - frameSize))
		out.WriteString("\n")
	}
	out.WriteString(renderFooter(m))
	out.WriteString("\n")
	return out.String()
}

// renderStatusBar lays out the top status line. When the operator is
// typing a filter, the bar grows a `/<text>█` segment so the input is
// always visible without stealing space from another panel.
func renderStatusBar(m model, totalW int) string {
	visible := m.visibleDevices()
	policies := 0
	for _, d := range m.devices {
		if d.policy != "" {
			policies++
		}
	}

	pieces := []string{
		fmt.Sprintf(" devices %s", statusAccent.Render(fmt.Sprint(len(visible)))),
	}
	if m.filter != "" || m.filterMode {
		// Distinct from devices: total count of unfiltered list.
		pieces = append(pieces, statusDim.Render(fmt.Sprintf("/ %d", len(m.devices))))
	}
	pieces = append(pieces,
		fmt.Sprintf("policies %s", statusAccent.Render(fmt.Sprint(policies))),
		fmt.Sprintf("clock %s", statusDim.Render(m.lastTick.Format("15:04:05"))),
	)

	if m.filterMode {
		pieces = append(pieces, filterStyle.Render(fmt.Sprintf("/%s█", m.filter)))
	} else if m.filter != "" {
		pieces = append(pieces, filterStyle.Render(fmt.Sprintf("/%s", m.filter)))
	}

	if m.scanning {
		elapsed := time.Since(m.scanStarted).Truncate(time.Second)
		pieces = append(pieces, scanSpinningStyle.Render(
			scanSpinnerFrame(m.tickCount)+fmt.Sprintf(" scanning (%s)", elapsed)))
	} else if m.reconnecting {
		pieces = append(pieces, reconnectStyle.Render(
			scanSpinnerFrame(m.tickCount)+" reconnecting"))
	}

	text := strings.Join(pieces, "    ") + " "
	return statusBar.Width(totalW).Render(text)
}

const (
	colIP     = 15
	colMAC    = 17
	colVendor = 18
	colHost   = 22
	colPolicy = 8
)

func renderDevicesPanel(m model, innerWidth int) string {
	visible := m.visibleDevices()
	body := strings.Builder{}
	title := fmt.Sprintf("┳ DEVICES [%d]", len(visible))
	if m.filter != "" {
		title += statusDim.Render(fmt.Sprintf("  filter:%s", m.filter))
	}
	body.WriteString(panelTitle.Render(title))
	body.WriteString("\n")
	body.WriteString(headerCol.Render(fmt.Sprintf(" %-*s  %-*s  %-*s  %-*s  %-*s",
		colIP, "IP", colMAC, "MAC", colVendor, "VENDOR",
		colHost, "HOSTNAME", colPolicy, "POLICY")))
	body.WriteString("\n")

	if len(visible) == 0 {
		empty := " (no devices yet — press [s] to scan)"
		if m.filter != "" {
			empty = fmt.Sprintf(" (no devices match %q — press [Esc] to clear)", m.filter)
		}
		body.WriteString(rowDim.Render(empty))
		body.WriteString("\n")
		return panelBox.Width(innerWidth).Render(body.String())
	}

	height := m.devicesViewportHeight()
	start := m.viewportOffset
	end := start + height
	if end > len(visible) {
		end = len(visible)
	}
	if start > 0 {
		body.WriteString(rowDim.Render(fmt.Sprintf(" ↑ %d more above", start)))
		body.WriteString("\n")
	}
	for i := start; i < end; i++ {
		d := visible[i]
		vendor := truncate(d.vendor, colVendor)
		if vendor == "" {
			vendor = "—"
		}
		hostname := truncate(d.hostname, colHost)
		if hostname == "" {
			hostname = "—"
		}
		policy := compactPolicyText(d.policy)

		plain := fmt.Sprintf(" %-*s  %-*s  %-*s  %-*s  %-*s",
			colIP, d.ip, colMAC, d.mac,
			colVendor, vendor, colHost, hostname,
			colPolicy, policy)

		if i == m.cursor {
			body.WriteString(selRowStyle.Render("▶" + plain[1:]))
		} else {
			ip := ipStyle.Render(fmt.Sprintf("%-*s", colIP, d.ip))
			mac := macStyle.Render(fmt.Sprintf("%-*s", colMAC, d.mac))
			ven := venStyle.Render(fmt.Sprintf("%-*s", colVendor, vendor))
			host := hostStyle.Render(fmt.Sprintf("%-*s", colHost, hostname))
			tag := compactPolicyTag(d.policy, colPolicy)
			body.WriteString(fmt.Sprintf(" %s  %s  %s  %s  %s", ip, mac, ven, host, tag))
		}
		body.WriteString("\n")
	}
	if end < len(visible) {
		body.WriteString(rowDim.Render(fmt.Sprintf(" ↓ %d more below", len(visible)-end)))
		body.WriteString("\n")
	}
	return panelBox.Width(innerWidth).Render(body.String())
}

func compactPolicyText(p string) string {
	switch classifyPolicy(p) {
	case pkDrop:
		return "⊘ DROP"
	case pkThrottle:
		rest := strings.TrimSpace(strings.TrimPrefix(p, "throttle"))
		rest = strings.TrimSuffix(rest, "bit")
		rest = strings.ToUpper(rest)
		if rest == "" {
			return "◐ THR"
		}
		return "◐ " + rest
	case pkPcap:
		return "◉ PCAP"
	case pkNone:
		return "·"
	}
	return p
}

func compactPolicyTag(p string, width int) string {
	text := compactPolicyText(p)
	if lipglossWidth(text) < width {
		text = text + strings.Repeat(" ", width-lipglossWidth(text))
	}
	switch classifyPolicy(p) {
	case pkDrop:
		return dropTag.Render(text)
	case pkThrottle:
		return throttleTag.Render(text)
	case pkPcap:
		return pcapTag.Render(text)
	}
	return noPolicy.Render(text)
}

func lipglossWidth(s string) int {
	return lipgloss.Width(s)
}

func renderTargetPanel(m model, innerWidth int) string {
	visible := m.visibleDevices()
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ TARGET"))
	body.WriteString("\n")
	if len(visible) > 0 {
		d := visible[m.cursor]
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

// renderSessionPanel shows the operator's connection context — iface,
// IP/CIDR, gateway (with gateway MAC), and on a wireless iface the
// SSID/BSSID/signal/tx-rate/freq. It also exposes scan diagnostics
// (poison count, last scan time, AP-isolation hint) so an operator
// can tell at a glance whether their guest WiFi is silently filtering
// intra-client traffic.
func renderSessionPanel(m model, innerWidth int) string {
	s := m.session
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ SESSION"))
	body.WriteString("\n")

	// "label  " is 8 chars; with padding (0,1) total overhead is 10
	// chars. Anything beyond that is value width — truncate to fit.
	fieldW := innerWidth - 10
	if fieldW < 8 {
		fieldW = 8
	}
	row := func(label, val string, valStyle lipgloss.Style) {
		if val == "" {
			val = "—"
			valStyle = noPolicy
		}
		body.WriteString(rowDim.Render(fmt.Sprintf("%-7s ", label)) +
			valStyle.Render(truncate(val, fieldW)) + "\n")
	}

	row("iface", s.Iface, hostStyle)
	row("ip", s.CIDR, ipStyle)
	row("gw", s.Gateway, ipStyle)
	row("gw mac", s.GwMAC, macStyle)

	if s.Wireless {
		// SSID is the first thing an operator wants to see — confirms
		// they're attached to the network they intended to test.
		row("ssid", s.SSID, venStyle)
		row("bssid", s.BSSID, macStyle)
		if s.SignalDBm != 0 {
			// Signal: dBm closer to 0 = stronger. Colour-code roughly:
			//   ≥ -50  excellent (sage)
			//   ≥ -65  ok        (mist)
			//   <  -65 weak      (tan)
			sig := fmt.Sprintf("%d dBm", s.SignalDBm)
			style := venStyle
			switch {
			case s.SignalDBm <= -65:
				style = throttleTag
			case s.SignalDBm <= -50:
				style = hostStyle
			}
			row("signal", sig, style)
		}
		if s.TxRateMbit > 0 {
			row("tx", fmt.Sprintf("%.1f Mbit/s", s.TxRateMbit), hostStyle)
		}
		if s.FreqMHz > 0 {
			row("freq", fmt.Sprintf("%d MHz", s.FreqMHz), hostStyle)
		}
	}

	body.WriteString(rowDim.Render(fmt.Sprintf("%-7s ", "poisons")) +
		statusAccent.Render(fmt.Sprint(s.PoisonsActive)) + "\n")

	// Diagnostic line: AP isolation is the #1 reason a wireless scan
	// returns nothing useful. Surface it instead of letting the
	// operator wonder why their device list is empty.
	if s.LastScanAt != "" {
		body.WriteString(rowDim.Render("scan    ") +
			hostStyle.Render(fmt.Sprintf("%d replies", s.LastScanReplies)) + "\n")
		if s.Wireless && s.LastScanReplies <= 1 {
			body.WriteString(reconnectStyle.Render("⚠ AP isolation likely") + "\n")
			body.WriteString(rowDim.Render("  guests cannot reach guests") + "\n")
		}
	}
	return panelBox.Width(innerWidth).Render(body.String())
}

func renderAttackPanel(innerWidth int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ ATTACK") + "\n")
	const cellW = 48
	leftD := padCell(keyChipDanger.Render(" D ")+" "+keyDesc.Render("DROP — cut traffic to/from device"), cellW)
	leftP := padCell(keyChipInfo.Render(" P ")+" "+keyDesc.Render("PCAP — passive capture to .pcapng"), cellW)
	rightT := keyChipWarn.Render(" T ") + " " + keyDesc.Render("THROTTLE — rate-limit (default 200kbit)")
	rightC := keyChip.Render(" C ") + " " + keyDesc.Render("CLEAR — restore device, send corrective ARP")
	body.WriteString(" " + leftD + rightT + "\n")
	body.WriteString(" " + leftP + rightC)
	return panelBox.Width(innerWidth).Render(body.String())
}

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

// renderHelpPanel is the [?]-toggled keybinding cheatsheet. Compact
// single-panel form so it doesn't crowd the rest of the dashboard;
// each line groups related shortcuts.
func renderHelpPanel(innerWidth int) string {
	body := strings.Builder{}
	body.WriteString(panelTitle.Render("┳ HELP") + "\n")

	row := func(chip, desc string) string {
		return " " + chip + "  " + keyDesc.Render(desc)
	}
	lines := []string{
		row(keyChip.Render(" J/K ")+" "+keyChip.Render(" ↑/↓ "), "move cursor"),
		row(keyChip.Render(" PgUp ")+" "+keyChip.Render(" PgDn "), "page up/down  ·  Home/End or g/G — first/last"),
		row(keyChipDanger.Render(" D ")+" "+keyChipWarn.Render(" T ")+" "+keyChipInfo.Render(" P "), "apply DROP / THROTTLE / PCAP to selected"),
		row(keyChip.Render(" C/X "), "clear policy on selected (corrective ARP)"),
		row(keyChipMute.Render(" / "), "filter by ip/mac/host/vendor  ·  Esc clears"),
		row(keyChip.Render(" S ")+" "+keyChipMute.Render(" Esc "), "scan  ·  Esc dismisses a stuck spinner"),
		row(keyChipMute.Render(" ? ")+" "+keyChip.Render(" Q "), "toggle help  ·  quit"),
	}
	body.WriteString(strings.Join(lines, "\n"))
	return panelBox.Width(innerWidth).Render(body.String())
}

// renderFooter is the always-visible single-line keybind hint. Compact
// so the help overlay can carry the full cheatsheet on demand.
func renderFooter(m model) string {
	if m.filterMode {
		return " " + filterStyle.Render("filter mode") + "    " +
			keyDesc.Render("type to match  ·  ") +
			keyChipMute.Render(" Esc ") + " " + keyDesc.Render("clear  ·  ") +
			keyChipMute.Render(" Enter ") + " " + keyDesc.Render("apply")
	}
	return " " +
		keyChip.Render(" J/K ") + " " + keyDesc.Render("move") + "    " +
		keyChipMute.Render(" / ") + " " + keyDesc.Render("filter") + "    " +
		keyChip.Render(" S ") + " " + keyDesc.Render("scan") + "    " +
		keyChipMute.Render(" ? ") + " " + keyDesc.Render("help") + "    " +
		keyChip.Render(" Q ") + " " + keyDesc.Render("quit")
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

// sessionLoadedMsg carries the most recent Session.Get response.
type sessionLoadedMsg struct{ session rpc.SessionDTO }

type disconnectedMsg struct{}
type reconnectedMsg struct{ client *rpc.Client }
type reconnectFailedMsg struct{ err error }

type scanCompleteMsg struct {
	err         error
	elapsed     time.Duration
	deviceCount int
}

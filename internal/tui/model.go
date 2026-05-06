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
		m.logLines = append(m.logLines, msg.text)
		if len(m.logLines) > 200 {
			m.logLines = m.logLines[len(m.logLines)-200:]
		}
		next := waitForEventCmd(m.client)
		if msg.refreshDevices {
			return m, tea.Batch(next, refreshDevicesCmd(m.client))
		}
		return m, next
	case disconnectedMsg:
		m.logLines = append(m.logLines, "(daemon disconnected)")
		return m, nil
	}
	return m, nil
}

func (m model) View() string {
	headerStyle := lipgloss.NewStyle().Bold(true)
	left := strings.Builder{}
	left.WriteString(headerStyle.Render(fmt.Sprintf("Devices (%d)", len(m.devices))))
	left.WriteString("\n")
	for i, d := range m.devices {
		marker := "  "
		if i == m.cursor {
			marker = "> "
		}
		policy := d.policy
		if policy == "" {
			policy = "-"
		}
		left.WriteString(fmt.Sprintf("%s%-15s %-12s %-20s [%s]\n", marker, d.ip, d.mac, d.hostname, policy))
	}
	left.WriteString("\n[j/k] move  [s] scan  [q] quit\n")

	right := strings.Builder{}
	right.WriteString(headerStyle.Render("Policy"))
	right.WriteString("\n")
	if len(m.devices) > 0 {
		right.WriteString("Target: " + m.devices[m.cursor].ip + "\n\n")
	}
	right.WriteString("[d] drop  [t] throttle  [p] pcap  [x] clear\n")

	bottom := "Log:\n" + strings.Join(tail(m.logLines, 10), "\n")
	return lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Top, left.String(), "  ", right.String()),
		bottom,
	)
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

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/assert"
)

func TestModelHandlesQuit(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	assert.NotNil(t, cmd)
}

func TestModelMovesSelectionDownUp(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.devices = []deviceRow{{ip: "10.0.0.42"}, {ip: "10.0.0.55"}}
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	assert.Equal(t, 1, m.cursor)
	m, _ = m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	assert.Equal(t, 0, m.cursor)
}

func TestRenderedViewFitsTerminalWidth(t *testing.T) {
	m := newModel(nil, 200, "/var/lib/shardflow/pcap")
	m.width, m.height = 220, 50
	m.devices = []deviceRow{
		{ip: "192.168.1.1", mac: "08:63:32:60:3f:63", vendor: "IEEE Reg. Authority", hostname: "router.local", policy: ""},
		{ip: "192.168.1.6", mac: "22:53:a5:32:06:6b", vendor: "", hostname: "", policy: "drop"},
		{ip: "192.168.1.10", mac: "e4:0d:36:92:84:57", vendor: "Intel Corporate", hostname: "het-laptop.local", policy: "throttle 200kbit"},
	}
	view := m.View()
	t.Logf("\n%s\n", view)
	// Check no line exceeds 130 cols (visible width — strip ANSI for the test).
	for i, line := range strings.Split(view, "\n") {
		visible := stripANSI(line)
		// Dashboard caps at maxRenderWidth (140) regardless of terminal width.
		if w := lipgloss.Width(visible); w > 145 {
			t.Errorf("line %d width %d exceeds 145 (cap is 140): %q", i, w, visible)
		}
	}
}

func stripANSI(s string) string {
	out := []byte{}
	in := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' {
			in = true
			continue
		}
		if in {
			if s[i] == 'm' {
				in = false
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

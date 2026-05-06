package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

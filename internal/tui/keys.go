package tui

import tea "github.com/charmbracelet/bubbletea"

// keyMatch returns true when msg is a runes key matching any rune in s.
func keyMatch(msg tea.Msg, s string) (rune, bool) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return 0, false
	}
	if km.Type != tea.KeyRunes || len(km.Runes) != 1 {
		return 0, false
	}
	r := km.Runes[0]
	for _, want := range s {
		if r == want {
			return r, true
		}
	}
	return 0, false
}

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRootCommandHasExpectedSubcommands(t *testing.T) {
	root := NewRoot()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"scan", "devices", "policy", "stats", "tui"} {
		assert.True(t, names[want], "missing subcommand: "+want)
	}
}

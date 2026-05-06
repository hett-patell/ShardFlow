package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestParseRate(t *testing.T) {
	cases := []struct {
		in        string
		want      int
		wantErr   bool
		errSubstr string
	}{
		{"200kbit", 200, false, ""},
		{"500kbps", 500, false, ""},
		{"1mbit", 1000, false, ""},
		{"2mbps", 2000, false, ""},
		{"  100KBIT  ", 100, false, ""}, // case-insensitive, trims whitespace
		{"-200kbit", 0, true, "must be a positive integer"},
		{"0kbit", 0, true, "must be a positive integer"},
		{"200", 0, true, "expected suffix"},
		{"abc", 0, true, "expected suffix"},
		{"foobit", 0, true, "expected suffix"},
	}
	for _, tc := range cases {
		got, err := parseRate(tc.in)
		if tc.wantErr {
			require.Error(t, err, "input %q", tc.in)
			assert.Contains(t, err.Error(), tc.errSubstr, "input %q", tc.in)
		} else {
			require.NoError(t, err, "input %q", tc.in)
			assert.Equal(t, tc.want, got, "input %q", tc.in)
		}
	}
}

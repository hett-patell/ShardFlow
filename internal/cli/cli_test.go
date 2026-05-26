package cli

import (
	"bytes"
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

func TestDashIfEmpty(t *testing.T) {
	assert.Equal(t, "—", dashIfEmpty(""))
	assert.Equal(t, "Apple", dashIfEmpty("Apple"))
}

func TestTruncStr(t *testing.T) {
	// Short strings pass through.
	assert.Equal(t, "short", truncStr("short", 10))
	// Equal-length strings pass through (no need for ellipsis).
	assert.Equal(t, "1234567890", truncStr("1234567890", 10))
	// Over-long strings get ellipsis (truncStr counts the ellipsis as
	// 1 visible cell, so n=10 yields 9 chars + "…").
	assert.Equal(t, "123456789…", truncStr("1234567890ABC", 10))
	// Pathological n<=1 returns input unchanged (defensive).
	assert.Equal(t, "hello", truncStr("hello", 1))
}

// TestPrintStatsStableOrder: map iteration order is undefined in Go, so
// the previous `json.Encode(map[string]any{...})` produced
// non-deterministic output. printStats sorts keys; verify successive
// renders of the same map produce byte-identical output and keys
// appear in alphabetical order.
func TestPrintStatsStableOrder(t *testing.T) {
	s := map[string]any{
		"poisoned": 3,
		"devices":  42,
		"policies": 5,
	}
	var buf1, buf2 bytes.Buffer
	printStats(&buf1, s)
	printStats(&buf2, s)
	assert.Equal(t, buf1.String(), buf2.String(), "output must be deterministic")

	want := "devices      42\npoisoned     3\npolicies     5\n"
	assert.Equal(t, want, buf1.String())
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

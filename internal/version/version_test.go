package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStringFallsBackToDevel: with no -ldflags injection the package
// defaults are kept (Version="(devel)", Commit="", BuildDate=""), and
// String() should still produce a non-empty banner containing at least
// the version literal and the runtime arch.
func TestStringFallsBackToDevel(t *testing.T) {
	// Snapshot/restore in case other tests touched the package vars.
	prev := Version
	t.Cleanup(func() { Version = prev })
	Version = "(devel)"
	Commit = ""
	BuildDate = ""

	out := String()
	assert.Contains(t, out, "(devel)")
	// Should always include GOOS/GOARCH + go version even with no ldflags.
	assert.Contains(t, out, "go")
	// Sanity: not the literal empty fallback.
	assert.NotEmpty(t, strings.TrimSpace(out))
}

// TestStringIncludesLDFlagFields: when -ldflags has set the fields,
// String() must surface all three (version, commit, build date).
func TestStringIncludesLDFlagFields(t *testing.T) {
	prev, prevC, prevB := Version, Commit, BuildDate
	t.Cleanup(func() {
		Version, Commit, BuildDate = prev, prevC, prevB
	})
	Version = "v1.2.3"
	Commit = "abc1234"
	BuildDate = "2026-01-01T00:00:00Z"

	out := String()
	assert.Contains(t, out, "v1.2.3")
	assert.Contains(t, out, "abc1234")
	assert.Contains(t, out, "2026-01-01T00:00:00Z")
}

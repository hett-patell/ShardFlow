// Package version exposes the build-time version stamp consumed by
// both shardflow (CLI/TUI) and shardflowd (daemon) for their --version
// output. The fields are set via -ldflags at build time:
//
//	go build -ldflags "-X github.com/hett-patell/ShardFlow/internal/version.Version=v0.2.0 \
//	                   -X github.com/hett-patell/ShardFlow/internal/version.Commit=$(git rev-parse --short HEAD) \
//	                   -X github.com/hett-patell/ShardFlow/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
//	          ./cmd/shardflow ./cmd/shardflowd
//
// Defaults are sensible for source-tree builds (`go build`, `go run`)
// so a developer running locally without -ldflags gets "(devel)" instead
// of an empty string — useful when grepping for stale builds in journald.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Defaults are placeholders; release builds override via -ldflags.
var (
	Version   = "(devel)"
	Commit    = ""
	BuildDate = ""
)

// String returns a single-line version banner. Falls back to runtime/debug
// build-info (Go 1.18+ embeds the VCS commit automatically when building
// from a tagged Git checkout), so `go install ./...` without -ldflags
// still produces a useful version string instead of "(devel) unknown".
func String() string {
	v := Version
	commit := Commit
	if commit == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 7 {
					commit = s.Value[:7]
					break
				}
			}
		}
	}
	out := v
	if commit != "" {
		out += " (" + commit + ")"
	}
	if BuildDate != "" {
		out += " built " + BuildDate
	}
	return fmt.Sprintf("%s, %s/%s, %s", out, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

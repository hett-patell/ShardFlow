// Package cli provides the Cobra command tree for the shardflow client.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/version"
)

// DefaultSocket is the default daemon socket path; --sock overrides.
const DefaultSocket = "/run/shardflow/sock"

// NewRoot returns the configured root command.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:     "shardflow",
		Short:   "ShardFlow client (CLI + TUI)",
		Version: version.String(),
	}
	// Use {{.Version}} (the field cobra set above) so --version emits
	// our String() output verbatim. Default cobra template prepends the
	// command name + ' version ' which is redundant for a tool with
	// one binary name.
	root.SetVersionTemplate("shardflow {{.Version}}\n")
	root.PersistentFlags().String("sock", DefaultSocket, "daemon Unix socket path")
	root.PersistentFlags().Bool("json", false, "emit JSON instead of human tables")

	root.AddCommand(scanCmd())
	root.AddCommand(devicesCmd())
	root.AddCommand(policyCmd())
	root.AddCommand(statsCmd())
	root.AddCommand(sessionCmd())
	root.AddCommand(tuiCmd())
	return root
}

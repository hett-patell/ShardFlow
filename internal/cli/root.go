// Package cli provides the Cobra command tree for the shardflow client.
package cli

import (
	"github.com/spf13/cobra"
)

// DefaultSocket is the default daemon socket path; --sock overrides.
const DefaultSocket = "/run/shardflow/sock"

// NewRoot returns the configured root command.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "shardflow",
		Short: "ShardFlow client (CLI + TUI)",
	}
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

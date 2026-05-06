package cli

import (
	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/tui"
)

func tuiCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "tui",
		Short: "Launch the live TUI dashboard.",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			rate, _ := cmd.Flags().GetInt("default-throttle-kbit")
			pcapDir, _ := cmd.Flags().GetString("default-pcap-dir")
			return tui.Run(sock, rate, pcapDir)
		},
	}
	c.Flags().Int("default-throttle-kbit", 200, "rate applied by the [t] shortcut in the TUI")
	c.Flags().String("default-pcap-dir", "/var/lib/shardflow/pcap", "directory used by the [p] shortcut in the TUI")
	return c
}

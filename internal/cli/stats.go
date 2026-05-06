package cli

import (
	"context"
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Print daemon stats once (use TUI for live).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var raw map[string]any
			if err := cli.Call(context.Background(), rpc.MethodStats, nil, &raw); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(raw)
		},
	}
}

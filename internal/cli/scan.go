package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Trigger a one-shot LAN scan (active ARP + mDNS + SSDP).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			c, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var res map[string]string
			if err := c.Call(context.Background(), rpc.MethodScan, nil, &res); err != nil {
				return err
			}
			fmt.Println("scan:", res["status"])
			return nil
		},
	}
}

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func sessionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "session",
		Short: "Show the daemon's connection details (iface, gw, wifi assoc, scan stats).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			emitJSON, _ := cmd.Flags().GetBool("json")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var s rpc.SessionDTO
			if err := cli.Call(context.Background(), rpc.MethodSessionGet, nil, &s); err != nil {
				return err
			}
			if emitJSON {
				return json.NewEncoder(os.Stdout).Encode(s)
			}
			printSession(s)
			return nil
		},
	}
}

// printSession is a compact human form. Mirrors the SESSION panel's
// layout so an operator who has read one can read the other.
func printSession(s rpc.SessionDTO) {
	fmt.Printf("iface     %s\n", or(s.Iface, "—"))
	fmt.Printf("mac       %s\n", or(s.MAC, "—"))
	fmt.Printf("ip        %s\n", or(s.CIDR, s.IP))
	fmt.Printf("gateway   %s (%s)\n", or(s.Gateway, "—"), or(s.GwMAC, "—"))
	if s.Wireless {
		fmt.Printf("ssid      %s\n", or(s.SSID, "(not associated)"))
		if s.SSID != "" {
			fmt.Printf("bssid     %s\n", s.BSSID)
			if s.SignalDBm != 0 {
				fmt.Printf("signal    %d dBm\n", s.SignalDBm)
			}
			if s.TxRateMbit > 0 {
				fmt.Printf("tx-rate   %.1f Mbit/s\n", s.TxRateMbit)
			}
			if s.FreqMHz > 0 {
				fmt.Printf("freq      %d MHz\n", s.FreqMHz)
			}
		}
	} else {
		fmt.Printf("wireless  no\n")
	}
	fmt.Printf("poisons   %d active\n", s.PoisonsActive)
	fmt.Printf("devices   %d known\n", s.DevicesTotal)
	if s.LastScanAt != "" {
		fmt.Printf("last scan %s — %d ARP replies\n", s.LastScanAt, s.LastScanReplies)
		if s.Wireless && s.LastScanReplies <= 1 {
			fmt.Println()
			fmt.Println("⚠ AP isolation likely")
			fmt.Println("  Most guest WiFi networks (and many enterprise SSIDs) enable AP/client")
			fmt.Println("  isolation: the AP refuses to forward frames between connected clients.")
			fmt.Println("  In that mode, ARP/mDNS/SSDP cannot reach other peers, so ShardFlow's")
			fmt.Println("  discovery returns empty and policies cannot be applied to neighbours.")
			fmt.Println("  Switch to a network you control (no client isolation) to proceed.")
		}
	} else {
		fmt.Println("last scan never — run `shardflow scan` first")
	}
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

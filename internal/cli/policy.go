package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func policyCmd() *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "Set, clear, or list per-target policies."}
	c.AddCommand(policySetCmd(), policyClearCmd(), policyListCmd())
	return c
}

func policySetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <target> <kind> [rate|dir]",
		Short: "Apply a policy. Kind ∈ {drop, throttle, pcap}. throttle takes a rate (200kbit); pcap takes a dir.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			p := rpc.PolicySpec{Target: args[0], Kind: rpc.PolicyKind(args[1])}
			switch p.Kind {
			case rpc.PolicyThrottle:
				if len(args) < 3 {
					return fmt.Errorf("throttle requires a rate, e.g. 200kbit")
				}
				p.RateKbit, err = parseRate(args[2])
				if err != nil {
					return err
				}
			case rpc.PolicyPcap:
				if len(args) < 3 {
					return fmt.Errorf("pcap requires a directory")
				}
				p.PcapDir = args[2]
			case rpc.PolicyDrop:
				// no extra args
			default:
				return fmt.Errorf("unknown kind %q (drop|throttle|pcap)", args[1])
			}
			var res map[string]string
			if err := cli.Call(context.Background(), rpc.MethodPolicySet, p, &res); err != nil {
				return err
			}
			fmt.Println("policy:", res["status"])
			return nil
		},
	}
}

func policyClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear <target>",
		Args:  cobra.ExactArgs(1),
		Short: "Clear policy for target (IP or MAC).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var res map[string]string
			err = cli.Call(context.Background(), rpc.MethodPolicyClear, map[string]string{"target": args[0]}, &res)
			if err != nil {
				return err
			}
			fmt.Println("policy:", res["status"])
			return nil
		},
	}
}

func policyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List active policies.",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var entries []rpc.PolicyEntryDTO
			if err := cli.Call(context.Background(), rpc.MethodPolicyList, nil, &entries); err != nil {
				return err
			}
			fmt.Printf("%d active polic(ies)\n", len(entries))
			for _, e := range entries {
				switch e.Kind {
				case "throttle":
					fmt.Printf("  %s → throttle %dkbit\n", e.MAC, e.RateKbit)
				case "pcap":
					fmt.Printf("  %s → pcap %s\n", e.MAC, e.PcapDir)
				default:
					fmt.Printf("  %s → %s\n", e.MAC, e.Kind)
				}
			}
			return nil
		},
	}
}

// parseRate accepts "200kbit", "1mbit", "500kbps" → kbit.
func parseRate(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mul := 1
	num := s
	switch {
	case strings.HasSuffix(s, "kbit"), strings.HasSuffix(s, "kbps"):
		num = s[:len(s)-4]
	case strings.HasSuffix(s, "mbit"), strings.HasSuffix(s, "mbps"):
		num = s[:len(s)-4]
		mul = 1024
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, fmt.Errorf("bad rate %q", s)
	}
	return n * mul, nil
}

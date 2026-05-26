package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func devicesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "devices",
		Short: "List or inspect devices known to the daemon.",
	}
	c.AddCommand(devicesListCmd())
	c.AddCommand(devicesGetCmd())
	return c
}

func devicesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Print the current device list.",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			emitJSON, _ := cmd.Flags().GetBool("json")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var out []rpc.DeviceDTO
			if err := cli.Call(context.Background(), rpc.MethodDevicesList, nil, &out); err != nil {
				return err
			}
			if emitJSON {
				return json.NewEncoder(os.Stdout).Encode(out)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			// Columns extended from v1: POLICY surfaces drop/throttle/pcap
			// state without forcing the operator to either parse --json
			// or open the TUI to see what's active. MODEL is the SSDP
			// SERVER string (e.g. PhilipsHue/1.0) — distinct from VENDOR
			// (which is the OUI silicon maker). Both columns are blank
			// when unavailable so they don't visually shout 'missing'.
			fmt.Fprintln(tw, "IP\tMAC\tHOSTNAME\tVENDOR\tMODEL\tPOLICY\tLAST_SEEN")
			for _, d := range out {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					d.IP, d.MAC, dashIfEmpty(d.Hostname), dashIfEmpty(d.Vendor),
					dashIfEmpty(truncStr(d.Model, 32)), dashIfEmpty(d.Policy), d.LastSeen)
			}
			return tw.Flush()
		},
	}
}

// dashIfEmpty renders blank fields as "—" so the column visually
// aligns and the operator sees "no data" rather than empty whitespace
// (especially when MODEL is rare — most devices don't speak SSDP).
func dashIfEmpty(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// truncStr clips an over-long string with an ellipsis. MODEL strings
// can be 100+ chars on chatty embedded devices ("Linux/3.10 UPnP/1.0
// SSDP/1.6 PhilipsHue/1.0 ...") which would blow up the column.
func truncStr(s string, n int) string {
	if n <= 1 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func devicesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <mac>",
		Short: "Show detail for a device by MAC.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var d rpc.DeviceDTO
			err = cli.Call(context.Background(), rpc.MethodDevicesGet, map[string]string{"mac": args[0]}, &d)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(d)
		},
	}
}

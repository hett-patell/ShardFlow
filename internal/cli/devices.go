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
			fmt.Fprintln(tw, "IP\tMAC\tHOSTNAME\tVENDOR\tLAST_SEEN")
			for _, d := range out {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					d.IP, d.MAC, d.Hostname, d.Vendor, d.LastSeen)
			}
			return tw.Flush()
		},
	}
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

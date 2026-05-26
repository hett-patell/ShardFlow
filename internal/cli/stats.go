package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/hett-patell/ShardFlow/internal/rpc"
)

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Print daemon stats once (use TUI for live).",
		RunE: func(cmd *cobra.Command, args []string) error {
			sock, _ := cmd.Flags().GetString("sock")
			emitJSON, _ := cmd.Flags().GetBool("json")
			cli, err := rpc.Dial(sock)
			if err != nil {
				return err
			}
			defer cli.Close()
			var raw map[string]any
			if err := cli.Call(context.Background(), rpc.MethodStats, nil, &raw); err != nil {
				return err
			}
			if emitJSON {
				return json.NewEncoder(os.Stdout).Encode(raw)
			}
			printStats(os.Stdout, raw)
			return nil
		},
	}
}

// printStats renders the dynamic stats map in `key  value` form. Keys
// are sorted alphabetically so successive runs produce stable output
// (the daemon returns a Go map literal — iteration order is undefined,
// so the previous unconditional JSON output also varied per call).
// New fields appear automatically without code changes here.
//
// Takes an io.Writer so tests can capture the output; production calls
// pass os.Stdout.
func printStats(w io.Writer, s map[string]any) {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%-12s %v\n", k, s[k])
	}
}

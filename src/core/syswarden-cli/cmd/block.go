package cmd

import (
	"errors"
	"fmt"

	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"

	"github.com/spf13/cobra"
)

type blockEntryOperation func(string) error
type blockAlertOperation func(string)

func newBlockCommand(block blockEntryOperation, alert blockAlertOperation) *cobra.Command {
	return &cobra.Command{
		Use:   "block <IP>...",
		Short: "Add addresses or CIDRs to the persistent blocklist",
		Long:  "Records each entry in the persistent blocklist and reapplies firewall policy; success does not independently prove final kernel state.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			failures := make([]error, 0)
			for _, ip := range args {
				if err := block(ip); err != nil {
					failures = append(failures, fmt.Errorf("block %q: %w", ip, err))
					continue
				}
				alert(ip)
			}
			return errors.Join(failures...)
		},
	}
}

var blockCmd = newBlockCommand(firewall.AddToBlocklist, integration.SendBanAlert)

func init() { rootCmd.AddCommand(blockCmd) }

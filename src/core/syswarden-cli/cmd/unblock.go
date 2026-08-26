package cmd

import (
	"errors"
	"fmt"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

type unblockEntryOperation func(string) error

func newUnblockCommand(unblock unblockEntryOperation) *cobra.Command {
	return &cobra.Command{
		Use:   "unblock <IP>...",
		Short: "Remove addresses or CIDRs from the persistent blocklist",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			failures := make([]error, 0)
			for _, ip := range args {
				if err := unblock(ip); err != nil {
					failures = append(failures, fmt.Errorf("unblock %q: %w", ip, err))
				}
			}
			return errors.Join(failures...)
		},
	}
}

var unblockCmd = newUnblockCommand(firewall.RemoveFromBlocklist)

func init() { rootCmd.AddCommand(unblockCmd) }

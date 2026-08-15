package cmd

import (
	"fmt"
	"time"

	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var (
	listHistoricalIPs = firewall.ListIPs
	listHALedgerFile  = network.DefaultHABanLedgerFile
	listNow           = time.Now
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Displays all custom IP registries",
	RunE: func(cmd *cobra.Command, args []string) error {
		listHistoricalIPs()
		bans, err := network.ReadActiveHABans(listHALedgerFile, listNow())
		if err != nil {
			return fmt.Errorf("read HA temporary-ban ledger: %w", err)
		}
		return network.RenderActiveHABans(cmd.OutOrStdout(), bans)
	},
}

func init() { rootCmd.AddCommand(listCmd) }

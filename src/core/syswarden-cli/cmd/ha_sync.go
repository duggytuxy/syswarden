package cmd

import (
	"fmt"
	"os"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var haSyncCmd = &cobra.Command{
	Use:   "ha-sync",
	Short: "Push missing local blocklist entries to configured HA peers",
	Long:  "Compares the local blocklist with each exact configured peer and pushes entries that the peer does not report. TLS 1.3 peer verification uses /etc/syswarden/ha-ca.pem when present and otherwise the system trust roots. CIDR peer entries authorize inbound clients only and are never dialed.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := network.SyncHAPeer(); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] HA Sync failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(haSyncCmd)
}

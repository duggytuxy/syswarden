package cmd

import (
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var runSystemUpgrade = system.UpgradeSystem

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Install a release verified by a signed manifest",
	Long:  "Downloads and installs a release package only after verifying its canonical manifest, Ed25519 signature, platform metadata, size, and SHA-256 digest. The v4.02.8 first upgrade must use a separately verified manual package procedure.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runSystemUpgrade(); err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

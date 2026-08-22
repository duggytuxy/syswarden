package cmd

import (
	"errors"
	"fmt"
	"syswarden-cli/config"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var updateFeedsCmd = &cobra.Command{
	Use:   "update-feeds",
	Short: "Download configured threat-intelligence feeds and reapply firewall policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("[*] Updating Threat Intelligence Feeds...")

		mirrorURL := config.GlobalConfig.CustomURL
		if mirrorURL == "" && config.GlobalConfig.ListChoice != "3" {
			mirrorURL = "https://codeberg.org/"
		}

		return runFeedUpdateGuarded(
			firewall.PreflightConfiguredBackendMutation,
			func() error {
				return network.DownloadFeeds(mirrorURL, config.GlobalConfig.CustomURLIPv6, config.GlobalConfig.CustomHash, config.GlobalConfig.CustomHashIPv6, config.GlobalConfig.ListChoice, config.GlobalConfig.GeoCodes, config.GlobalConfig.ASNList, config.GlobalConfig.GeoAllowed, config.GlobalConfig.ASNAllowed, config.GlobalConfig.LANMode, config.GlobalConfig.UseSpamhaus)
			},
			firewall.ApplyPolicies,
		)
	},
}

func runFeedUpdateGuarded(preflight func() error, download func() error, apply func() error) error {
	if err := preflight(); err != nil {
		return fmt.Errorf("firewall backend preflight failed before feed mutation: %w", err)
	}
	return runFeedUpdate(download, apply)
}

func runFeedUpdate(download func() error, apply func() error) error {
	downloadErr := download()
	if downloadErr == nil {
		fmt.Println("[*] Feeds downloaded successfully. Reloading SYSWARDEN firewall engine in memory...")
	} else {
		fmt.Println("[WARNING] One or more feed updates failed. Reapplying validated last-known-good policy before returning failure...")
	}
	applyErr := apply()
	if downloadErr == nil && applyErr == nil {
		fmt.Println("[SUCCESS] Threat Intelligence successfully updated and applied.")
		return nil
	}
	var failures []error
	if downloadErr != nil {
		failures = append(failures, fmt.Errorf("update threat intelligence feeds: %w", downloadErr))
	}
	if applyErr != nil {
		failures = append(failures, fmt.Errorf("apply updated threat intelligence policy: %w", applyErr))
	}
	return errors.Join(failures...)
}

func init() {
	rootCmd.AddCommand(updateFeedsCmd)
}

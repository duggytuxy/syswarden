package cmd

import (
	"errors"
	"fmt"
	"regexp"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var whitelistCmd = &cobra.Command{
	Use:   "whitelist <IP>... [PORT]",
	Short: "Add addresses or CIDRs to the persistent whitelist",
	Long:  "Records each entry in the persistent whitelist and reapplies firewall policy. Verify the resulting kernel rule before relying on the entry.",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var ips []string
		var failures []error
		port := ""
		portRegex := regexp.MustCompile(`^[0-9]+$`)
		for _, arg := range args {
			// If it's purely numerical, assume it's the port
			if portRegex.MatchString(arg) {
				port = arg
			} else {
				ips = append(ips, arg)
			}
		}

		for _, ip := range ips {
			if err := firewall.AddToWhitelist(ip, port); err != nil {
				failures = append(failures, fmt.Errorf("whitelist %s: %w", ip, err))
			}
		}
		if len(ips) == 0 {
			failures = append(failures, fmt.Errorf("at least one IP address or CIDR is required"))
		}
		return errors.Join(failures...)
	},
}

func init() { rootCmd.AddCommand(whitelistCmd) }

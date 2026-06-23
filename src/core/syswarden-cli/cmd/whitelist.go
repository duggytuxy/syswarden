package cmd

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var whitelistCmd = &cobra.Command{
	Use:   "whitelist <IP>... [PORT]",
	Short: "Grants global VIP access and bypasses the firewall",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var ips []string
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
				fmt.Printf("[ERROR] %s: %v\n", ip, err)
			}
		}
	},
}

func init() { rootCmd.AddCommand(whitelistCmd) }

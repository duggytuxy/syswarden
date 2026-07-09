package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/pkg/nexus"

	"github.com/spf13/cobra"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll [token]",
	Short: "Enroll this node into a SysWarden Nexus fleet",
	Long:  `Securely enroll this server into a centralized SysWarden Nexus management console using a bootstrap token.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		token := args[0]

		fmt.Println("[*] Initiating Zero-Trust mTLS enrollment with SysWarden Nexus...")
		err := nexus.EnrollNode(token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Enrollment failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[SUCCESS] Node successfully enrolled and certificates provisioned.")
		fmt.Println("[*] The 'Sleepy Agent' module will now wake up and synchronize telemetry.")
	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)
}

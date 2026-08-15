//go:build freebsd

package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var packagePFRestoreCmd = &cobra.Command{
	Use:    "package-restore-pf",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		if packagePFRestoreEUID() != 0 {
			return fmt.Errorf("package PF restore must run as root")
		}
		return restorePackagePFPolicy()
	},
}

var (
	packagePFRestoreEUID   = os.Geteuid
	restorePackagePFPolicy = firewall.RestorePersistedPFPolicy
)

func init() {
	degradedConfigAllowlist["package-restore-pf"] = struct{}{}
	rootCmd.AddCommand(packagePFRestoreCmd)
}

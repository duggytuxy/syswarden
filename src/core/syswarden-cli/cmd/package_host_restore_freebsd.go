//go:build freebsd

package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var packageHostRestoreCmd = &cobra.Command{
	Use:    "package-restore-host-state",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		if packageHostRestoreEUID() != 0 {
			return fmt.Errorf("package host-state restore must run as root")
		}
		return restorePackageHostState()
	},
}

var (
	packageHostRestoreEUID  = os.Geteuid
	restorePackageHostState = system.RestoreFreeBSDPackageHostState
)

func init() {
	degradedConfigAllowlist["package-restore-host-state"] = struct{}{}
	rootCmd.AddCommand(packageHostRestoreCmd)
}

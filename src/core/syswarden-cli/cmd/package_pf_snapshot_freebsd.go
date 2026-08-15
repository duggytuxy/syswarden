//go:build freebsd

package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var packagePFLegacyV4028 bool

var packagePFSnapshotCmd = &cobra.Command{
	Use:    "package-capture-pf",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		if packagePFSnapshotEUID() != 0 {
			return fmt.Errorf("package PF snapshot must run as root")
		}
		provenance := firewall.PFSnapshotExactLive
		if packagePFLegacyV4028 {
			provenance = firewall.PFSnapshotLegacyDerived
		}
		return capturePackagePFPolicy(provenance)
	},
}

var (
	packagePFSnapshotEUID  = os.Geteuid
	capturePackagePFPolicy = firewall.CapturePFPolicySnapshot
)

func init() {
	packagePFSnapshotCmd.Flags().BoolVar(
		&packagePFLegacyV4028,
		"legacy-v4-02-8",
		false,
		"capture only the configured PF source after the immutable v4.02.8 transition",
	)
	degradedConfigAllowlist["package-capture-pf"] = struct{}{}
	rootCmd.AddCommand(packagePFSnapshotCmd)
}

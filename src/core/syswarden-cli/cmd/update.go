package cmd

import (
	"errors"
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var runSystemUpgrade = system.UpgradeSystem
var runQualificationBundleUpgrade = system.UpgradeSystemFromQualificationBundle

var (
	qualificationBundlePath string
	qualificationCandidate  string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Install a release verified by a signed manifest",
	Long:  "Downloads and installs a release package only after verifying its canonical manifest, Ed25519 signature, platform metadata, size, and SHA-256 digest. An explicitly selected offline qualification bundle is never discovered on the network and has no network fallback. The v4.02.8 first upgrade must use a separately verified manual package procedure.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if qualificationBundlePath != "" || qualificationCandidate != "" {
			if qualificationBundlePath == "" || qualificationCandidate == "" {
				return fmt.Errorf("update failed: --qualification-bundle and --candidate-version must be provided together")
			}
			if err := runQualificationBundleUpgrade(qualificationBundlePath, qualificationCandidate); err != nil {
				return fmt.Errorf("update failed: %w", err)
			}
			return nil
		}
		if err := runSystemUpgrade(); err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
		return nil
	},
}

func qualificationUpdateSelection(cmd *cobra.Command) (bool, error) {
	topLevel := topLevelCommand(cmd)
	if topLevel == nil || topLevel.Name() != "update" {
		return false, nil
	}
	bundle, bundleErr := topLevel.Flags().GetString("qualification-bundle")
	candidate, candidateErr := topLevel.Flags().GetString("candidate-version")
	if bundleErr != nil || candidateErr != nil {
		return false, errors.New("update qualification flags are unavailable")
	}
	if bundle == "" && candidate == "" {
		return false, nil
	}
	if bundle == "" || candidate == "" {
		return false, errors.New("update failed: --qualification-bundle and --candidate-version must be provided together")
	}
	return true, nil
}

func init() {
	updateCmd.Flags().StringVar(
		&qualificationBundlePath,
		"qualification-bundle",
		"",
		"absolute path to a protected local signed-candidate bundle; disables all network discovery",
	)
	updateCmd.Flags().StringVar(
		&qualificationCandidate,
		"candidate-version",
		"",
		"exact candidate version required from the offline qualification bundle",
	)
	rootCmd.AddCommand(updateCmd)
}

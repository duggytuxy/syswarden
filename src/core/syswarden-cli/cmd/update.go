package cmd

import (
	"errors"
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var runSystemUpgrade = system.UpgradeSystem
var runQualificationBundleUpgrade = system.UpgradeSystemFromQualificationBundle
var reviewStoredAPKPreparation = system.UpgradeSystemWithAPKTransitionApproval

var (
	qualificationBundlePath string
	qualificationCandidate  string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Install a release verified by a signed manifest",
	Long:  "Downloads and installs a release package only after verifying its canonical manifest, Ed25519 signature, platform metadata, size, and SHA-256 digest. An explicitly selected offline qualification bundle is never discovered on the network and has no network fallback. --review-apk-plan records only review of an existing protected APK preparation, without network discovery or package execution; it does not authorize package effects. The v4.02.8 first upgrade must use a separately verified manual package procedure.",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.NoArgs(cmd, args); err != nil {
			return err
		}
		_, err := qualificationUpdateSelection(cmd)
		return err
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		digest, reviewSelected, err := apkPlanReviewSelection(cmd)
		if err != nil {
			return err
		}
		if reviewSelected {
			if ctx := cmd.Context(); ctx != nil {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "This command can record only review of an existing APK preparation. Native execution is unavailable; this review does not authorize package effects.")
			if err := reviewStoredAPKPreparation(digest); err != nil {
				return fmt.Errorf("APK preparation review: %w", err)
			}
			// The current API always refuses execution. A future callback must
			// not turn a preparation-only review into update success.
			return errors.New("APK preparation review returned without execution authority; native execution remains unavailable")
		}
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

func apkPlanReviewSelection(cmd *cobra.Command) (string, bool, error) {
	flag := cmd.Flags().Lookup("review-apk-plan")
	if flag == nil {
		return "", false, errors.New("APK preparation review flag is unavailable")
	}
	digest, err := cmd.Flags().GetString("review-apk-plan")
	if err != nil {
		return "", false, err
	}
	if digest == "" && !flag.Changed {
		return "", false, nil
	}
	for _, name := range []string{"qualification-bundle", "candidate-version"} {
		selector := cmd.Flags().Lookup(name)
		value, err := cmd.Flags().GetString(name)
		if selector == nil || err != nil {
			return "", false, errors.New("update qualification flags are unavailable")
		}
		if selector.Changed || value != "" {
			return "", false, errors.New("--review-apk-plan cannot be combined with --qualification-bundle or --candidate-version, including empty selectors")
		}
	}
	if len(digest) != 64 {
		return "", false, errors.New("--review-apk-plan requires exactly 64 lowercase hexadecimal SHA-256 characters")
	}
	for _, value := range []byte(digest) {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return "", false, errors.New("--review-apk-plan requires exactly 64 lowercase hexadecimal SHA-256 characters")
		}
	}
	return digest, true, nil
}

func qualificationUpdateSelection(cmd *cobra.Command) (bool, error) {
	topLevel := topLevelCommand(cmd)
	if topLevel == nil || topLevel.Name() != "update" {
		return false, nil
	}
	if _, reviewSelected, err := apkPlanReviewSelection(topLevel); err != nil || reviewSelected {
		return false, err
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
	updateCmd.Flags().String("review-apk-plan", "", "record review of an existing protected APK preparation by exact SHA-256; no download or package execution")
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

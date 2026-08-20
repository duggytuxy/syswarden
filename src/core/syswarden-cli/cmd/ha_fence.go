package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

func requireHAFenceAdministrator() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("HA native-sync fence administration requires root")
	}
	return nil
}

func newHAFenceManifestCreateCommand() *cobra.Command {
	var inventoryPath string
	var outputPath string
	var assertComplete bool
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a verified canonical HA fence manifest",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := requireHAFenceAdministrator(); err != nil {
				return err
			}
			manifest, err := network.CreateHAFenceManifest(command.Context(), inventoryPath, outputPath, assertComplete)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "HA fence manifest created: epoch=%s membership_sha256=%s legacy_writer_inventory_sha256=%s\n",
				manifest.Epoch, manifest.MembershipSHA256, manifest.LegacyWriterInventorySHA256)
			return err
		},
	}
	command.Flags().StringVar(&inventoryPath, "inventory", "", "absolute path to the protected operator inventory")
	command.Flags().StringVar(&outputPath, "output", "", "absolute path for the new protected canonical manifest")
	command.Flags().BoolVar(&assertComplete, "assert-complete", false, "attest that the node and legacy-writer inventories are complete")
	_ = command.MarkFlagRequired("inventory")
	_ = command.MarkFlagRequired("output")
	return command
}

func newHAFenceManifestVerifyCommand() *cobra.Command {
	var manifestPath string
	command := &cobra.Command{
		Use:   "verify",
		Short: "Verify a canonical HA fence manifest and both digests",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := requireHAFenceAdministrator(); err != nil {
				return err
			}
			manifest, err := network.VerifyHAFenceManifest(manifestPath)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "HA fence manifest verified: epoch=%s membership_sha256=%s legacy_writer_inventory_sha256=%s\n",
				manifest.Epoch, manifest.MembershipSHA256, manifest.LegacyWriterInventorySHA256)
			return err
		},
	}
	command.Flags().StringVar(&manifestPath, "manifest", "", "absolute path to the protected canonical manifest")
	_ = command.MarkFlagRequired("manifest")
	return command
}

func newHAFenceManifestCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "manifest",
		Short: "Create and verify HA fence manifests",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newHAFenceManifestCreateCommand(), newHAFenceManifestVerifyCommand())
	return command
}

func newHAFenceEngageCommand() *cobra.Command {
	var manifestPath string
	command := &cobra.Command{
		Use:   "engage",
		Short: "Engage and drain a local native-sync fence",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := network.EngageHAFence(manifestPath); err != nil {
				return err
			}
			_, err := fmt.Fprintln(command.OutOrStdout(), "HA native-sync fence engaged and drained")
			return err
		},
	}
	command.Flags().StringVar(&manifestPath, "manifest", "", "absolute path to the protected canonical manifest")
	_ = command.MarkFlagRequired("manifest")
	return command
}

func newHAFenceRecoverCommand() *cobra.Command {
	var manifestPath string
	command := &cobra.Command{
		Use:   "recover",
		Short: "Recover and re-drain an interrupted HA fence campaign",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := network.RecoverHAFence(manifestPath); err != nil {
				return err
			}
			_, err := fmt.Fprintln(command.OutOrStdout(), "HA native-sync fence recovered and drained")
			return err
		},
	}
	command.Flags().StringVar(&manifestPath, "manifest", "", "absolute path to the protected canonical manifest")
	_ = command.MarkFlagRequired("manifest")
	return command
}

func newHAFenceStatusCommand() *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "status",
		Short: "Report the local HA fence state",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if !jsonOutput {
				return fmt.Errorf("HA fence status requires --json")
			}
			status, err := network.ReadLocalHAFenceStatus()
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(status)
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit the local fence state as JSON")
	return command
}

func newHAFenceReleaseCommand() *cobra.Command {
	var manifestPath string
	var closurePath string
	command := &cobra.Command{
		Use:   "release",
		Short: "Release a drained HA fence after durable writer closure",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := network.ReleaseHAFence(manifestPath, closurePath); err != nil {
				return err
			}
			_, err := fmt.Fprintln(command.OutOrStdout(), "HA native-sync fence released")
			return err
		},
	}
	command.Flags().StringVar(&manifestPath, "manifest", "", "absolute path to the protected canonical manifest")
	command.Flags().StringVar(&closurePath, "writer-closure", "", "absolute path to the protected canonical writer closure")
	_ = command.MarkFlagRequired("manifest")
	_ = command.MarkFlagRequired("writer-closure")
	return command
}

func newHAFenceCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "ha-fence",
		Short: "Administer the native-sync migration fence",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(
		newHAFenceManifestCommand(),
		newHAFenceEngageCommand(),
		newHAFenceRecoverCommand(),
		newHAFenceStatusCommand(),
		newHAFenceReleaseCommand(),
	)
	return command
}

func init() {
	rootCmd.AddCommand(newHAFenceCommand())
}

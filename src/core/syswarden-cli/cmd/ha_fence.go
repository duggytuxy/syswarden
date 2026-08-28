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
		Long: `Create a verified canonical HA fence manifest from a protected operator inventory.

The inventory must be a root-owned regular JSON file with mode 0600 and this exact schema:
{
  "schema_version": 1,
  "membership_scope": "one_receiving_api_endpoint_per_syswarden_node",
  "legacy_writer_ids": ["writer-id"],
  "members": [{"address": "203.0.113.10", "port": 62026}]
}

Both paths must be absolute. The inventory must be smaller than one MiB. Use an empty legacy_writer_ids array only when the operator has verified that no legacy writer exists. Writer IDs must match [a-z0-9][a-z0-9._-]{0,63}. Addresses must be canonical IP literals, ports must be in 1..65535, endpoint pairs must be unique, and every receiving SysWarden node must appear exactly once. Unknown or duplicate JSON keys are rejected.`,
		Example: `  syswarden ha-fence manifest create \
    --inventory /root/syswarden-ha-inventory.json \
    --output /root/syswarden-ha-manifest.json \
    --assert-complete`,
		Args: cobra.NoArgs,
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
		Long: `Release a drained HA fence only after every legacy writer has durable terminal evidence.

The writer closure must be a root-owned regular JSON file with mode 0600, canonical indentation and this schema:
{
  "schema_version": 1,
  "epoch": "<manifest epoch>",
  "membership_sha256": "<manifest membership SHA-256>",
  "legacy_writer_inventory_sha256": "<manifest writer inventory SHA-256>",
  "legacy_retry_queue_drained": true,
  "writers": [{
    "id": "writer-id",
    "disposition": "migrated_enriched_only",
    "closure_generation": "operator-evidence-generation",
    "closed_at": "2026-08-28T12:00:00Z",
    "evidence_sha256": "<lowercase evidence SHA-256>"
  }]
}

Writer order and identities must exactly match the manifest. Accepted terminal dispositions are migrated_enriched_only, disabled, credential_revoked and network_quarantined. Use an empty writers array only when the manifest has no legacy writers. Unknown or duplicate JSON keys and noncanonical bytes are rejected.`,
		Example: `  syswarden ha-fence release \
    --manifest /root/syswarden-ha-manifest.json \
    --writer-closure /root/syswarden-ha-writer-closure.json`,
		Args: cobra.NoArgs,
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

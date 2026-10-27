package cmd

import (
	"context"
	"fmt"
	"os"

	"syswarden-cli/config"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/platformpaths"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var cfgFile string

// Pin the actual root after construction without a variable-initialization cycle.
var staticInformationRoot *cobra.Command

var rootCmd = &cobra.Command{
	Use:   "syswarden",
	Short: "SYSWARDEN Security Orchestrator",
	Long:  "SYSWARDEN is a host firewall orchestrator and out-of-band security-log analysis toolkit; it is not an inline WAF.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if staticInformationCommand(cmd) {
			// Usage, the built-in reference and shell completion need no host
			// policy or recovery state, including during incomplete removal.
			return nil
		}
		if sshAccessControllerCommand(cmd) {
			// The independent controller has no target configuration or removal
			// state. Its command validates only approved private exchange files.
			return nil
		}
		if cmd == preparePackageRemovalCmd && retainAPKPayload {
			// APK pre-commit must never load policy or recover firewall state.
			return nil
		}
		if cmd == configCmd || cmd == configPreviewCmd || cmd == configActivateCmd || commandRequiresEarlyFirewallRecovery(cmd) {
			if err := refusePendingModuleEditHook(); err != nil {
				return err
			}
		}
		if err := enforceWireGuardPolicyTransition(cmd); err != nil {
			return err
		}
		if topLevel := topLevelCommand(cmd); topLevel != nil && topLevel.Name() == "uninstall" {
			if err := preflightUninstall(); err != nil {
				return err
			}
		}
		if system.OfflineQualificationPackageInstall() {
			topLevel := topLevelCommand(cmd)
			if topLevel != nil && topLevel.Name() == "install" {
				// The package-script stage must not recover firewall state, load
				// configuration, or activate candidate code before the updater
				// reattests the installed package and fixed CLI.
				return enforceRemovalState(cmd)
			}
		}
		qualificationSelected, qualificationErr := qualificationUpdateSelection(cmd)
		if qualificationErr != nil {
			return qualificationErr
		}
		if qualificationSelected {
			// The candidate CLI must authenticate the protected offline bundle
			// before it runs configuration loading or firewall recovery code.
			// The removal tombstone remains a mandatory read-only safety gate.
			return enforceRemovalState(cmd)
		}
		if cmd == updateCmd {
			// Authentication, native transaction approval and runtime lineage
			// are checked by the updater before candidate replacement.
			return enforceRemovalState(cmd)
		}
		// Reject removal-blocked commands before firewall recovery or config normalization can mutate the host.
		if err := enforceRemovalState(cmd); err != nil {
			return err
		}
		if cmd == configCmd || cmd == configPreviewCmd || cmd == configEditRecoveryCmd {
			if err := refusePendingFirewallTransactionHook(); err != nil {
				return fmt.Errorf("[ERROR] configuration editor requires resolved firewall recovery state: %w", err)
			}
		}
		if topLevel := topLevelCommand(cmd); topLevel != nil && topLevel.Name() == "install" {
			if freshNativePackageInstallation() {
				// First installation stages only validated configuration. It
				// must not observe/prepare services or recover firewall state.
				return nil
			}
			if err := refuseUnapprovedActiveNativeInstall(); err != nil {
				return err
			}
			plan, err := prepareNativeServicesForInstall()
			if err != nil {
				return installStageError("native service-state preflight failed before command preparation", err)
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cmd.SetContext(context.WithValue(ctx, installServicePlanKey{}, plan))
			if plan.Deferred() {
				return nil
			}
			if err := preflightLegacyWireGuardForInstall(); err != nil {
				return installStageError("historical WireGuard conflict detected before command preparation", err)
			}
		}
		if activationOperation(cmd) != "" {
			// New or changed TOML must be approved before any automatic
			// recovery or compatibility normalization can alter the host.
			if err := prepareConfigurationActivationHook(cmd); err != nil {
				return err
			}
			if err := recoverPendingFirewallTransactionHook(); err != nil {
				return fmt.Errorf("approved activation recovery failed before command preparation: %w", err)
			}
			return enforceValidatedConfiguration(cmd)
		}
		approvedOperational := operationalConfigurationApprovalRequired(cmd)
		if approvedOperational {
			if err := consumeApprovedOperationalConfigurationHook(cmd); err != nil {
				return err
			}
		}
		if commandRequiresEarlyFirewallRecovery(cmd) {
			if err := recoverPendingFirewallTransactionHook(); err != nil {
				return fmt.Errorf("[ERROR] authoritative firewall recovery failed before command preparation: %w", err)
			}
		}
		if commandRequiresAutomaticConfigLoad(cmd) && !approvedOperational {
			if configurationInspectionCommand(cmd) {
				initInspectionConfigHook()
			} else {
				initConfigHook()
			}
		}
		return enforceValidatedConfiguration(cmd)
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Default behavior when no subcommand is given
		fmt.Printf("SYSWARDEN %s CLI\n", system.Version)
		fmt.Println("Use 'syswarden manual' for the built-in operator reference, or 'syswarden --help' for command help.")
	},
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd:   false,
		DisableDescriptions: true,
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	staticInformationRoot = rootCmd
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", platformpaths.LegacyConfig, "config file")
}

var refusePendingModuleEditHook = func() error { return config.RefusePendingModuleEdit(configEditorRoot) }
var initConfigHook = initConfig
var initInspectionConfigHook = func() { initConfigUsing(config.ParseConfigForInspection) }

// These operational readers still need validated policy, unlike static help.
// Their configuration load must never persist a compatibility rewrite.
func configurationInspectionCommand(cmd *cobra.Command) bool {
	if cmd == nil || cmd.Parent() != staticInformationRoot {
		return false
	}
	switch cmd.Name() {
	case "audit", "alerts", "check", "list":
		return true
	}
	return false
}

var recoverPendingFirewallTransactionHook = firewall.RecoverPendingAuthoritativeTransaction
var refusePendingFirewallTransactionHook = firewall.RefusePendingAuthoritativeTransaction

var earlyFirewallRecoveryCommands = map[string]struct{}{
	"allow-ssh":               {},
	"block":                   {},
	"ha-sync":                 {},
	"install":                 {},
	"prepare-package-removal": {},
	"reload":                  {},
	"revoke-ssh":              {},
	"tui":                     {},
	"unblock":                 {},
	"runtime-unblock":         {},
	"uninstall":               {},
	"unwhitelist":             {},
	"update":                  {},
	"update-feeds":            {},
	"whitelist":               {},
	"whitelist-infra":         {},
}

func commandRequiresEarlyFirewallRecovery(cmd *cobra.Command) bool {
	if cmd == nil || cmd == configValidateCmd || cmd == configCmd {
		return false
	}
	if cmd == configMigrateCmd || cmd == migrateConfigCmd {
		dryRun, err := cmd.Flags().GetBool("dry-run")
		return err != nil || !dryRun
	}
	topLevel := topLevelCommand(cmd)
	if topLevel == nil || topLevel.Parent() == nil {
		return false
	}
	_, required := earlyFirewallRecoveryCommands[topLevel.Name()]
	return required
}

// Configuration inspection and migration commands load their explicitly
// selected inputs themselves. Opening the editor menu loads no configuration.
// Loading the process-wide runtime configuration first would let compatibility
// normalization modify operator files before a read-only validation or dry-run
// migration starts.
func commandRequiresAutomaticConfigLoad(cmd *cobra.Command) bool {
	if staticInformationCommand(cmd) {
		return false
	}
	if cmd == nil {
		return true
	}
	if cmd == configCmd || cmd == configPreviewCmd || cmd == configActivateCmd || cmd == configEditRecoveryCmd || cmd == configGetCmd || cmd == configValidateCmd || cmd == configMigrateCmd || cmd == migrateConfigCmd {
		return false
	}
	if isolatedSSHPolicyCommand(cmd) {
		return false
	}
	if topLevel := topLevelCommand(cmd); topLevel != nil {
		switch topLevel.Name() {
		case "completion", "recover-wireguard", "recover-removal":
			return false
		}
	}
	return true
}

// Only the actual static entry points bypass host preparation. This does not
// classify operational inspection commands such as audit, alerts or list as
// static, and cannot be extended by renaming an unrelated command's parent.
func staticInformationCommand(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	if cmd == staticInformationRoot || cmd == manualCmd {
		return true
	}
	top := topLevelCommand(cmd)
	if top == nil || top.Parent() != staticInformationRoot {
		return false
	}
	switch top.Name() {
	case "help", "completion", "__complete", "__completeNoDesc":
		return true
	}
	return false
}

var inspectRemovalTombstone = system.InspectRemovalTombstone

var removalStateReadOnlyCommands = map[string]struct{}{
	"alerts":     {},
	"audit":      {},
	"check":      {},
	"completion": {},
	"config-get": {},
	"help":       {},
	"list":       {},
	"manual":     {},
}

func topLevelCommand(cmd *cobra.Command) *cobra.Command {
	if cmd == nil {
		return nil
	}
	topLevel := cmd
	for topLevel.Parent() != nil && topLevel.Parent().Parent() != nil {
		topLevel = topLevel.Parent()
	}
	return topLevel
}

func commandAllowedDuringRemoval(cmd *cobra.Command) bool {
	if readOnlySSHPolicyCommand(cmd) {
		return true
	}
	if cmd != nil && cmd.CommandPath() == "syswarden config validate" {
		return true
	}
	topLevel := topLevelCommand(cmd)
	if topLevel == nil || topLevel.Parent() == nil {
		return true
	}
	switch topLevel.Name() {
	case "prepare-package-removal", "recover-wireguard", "recover-removal", "uninstall":
		return true
	}
	if _, allowed := removalStateReadOnlyCommands[topLevel.Name()]; allowed {
		return true
	}
	if topLevel.Name() != "ha-fence" {
		return false
	}
	path := cmd.CommandPath()
	return path == "syswarden ha-fence status" || path == "syswarden ha-fence manifest verify"
}

func enforceRemovalState(cmd *cobra.Command) error {
	if commandAllowedDuringRemoval(cmd) {
		return nil
	}
	present, err := inspectRemovalTombstone()
	if err != nil {
		return fmt.Errorf("[ERROR] refusing operational mutation while removal state is unsafe: %w", err)
	}
	if !present {
		return nil
	}
	return fmt.Errorf(
		"[ERROR] refusing operational mutation while %s is present; removal is incomplete; inspect WireGuard evidence with 'sudo syswarden recover-wireguard', validate configuration with 'sudo syswarden config validate', then resume 'sudo syswarden uninstall'; retain the barrier and ownership files",
		system.RemovalTombstonePath,
	)
}

var degradedConfigAllowlist = map[string]struct{}{
	"completion":              {},
	"config":                  {},
	"config-get":              {},
	"ha-fence":                {},
	"help":                    {},
	"install":                 {},
	"manual":                  {},
	"migrate-config":          {},
	"prepare-package-removal": {},
	"recover-wireguard":       {},
	"recover-removal":         {},
	"uninstall":               {},
}

func enforceValidatedConfiguration(cmd *cobra.Command) error {
	if isolatedSSHPolicyCommand(cmd) {
		return nil
	}
	if cmd == nil || cmd.Parent() == nil {
		return nil
	}
	topLevel := topLevelCommand(cmd)
	if _, allowed := degradedConfigAllowlist[topLevel.Name()]; allowed {
		return nil
	}
	state := config.CurrentLoadState()
	if !state.Degraded {
		return nil
	}
	return fmt.Errorf(
		"[ERROR] validated configuration is unavailable from %s: %s; repair it with 'syswarden config' or 'syswarden migrate-config'",
		state.Source,
		state.Error,
	)
}

func initConfig() { initConfigUsing(config.ParseConfig) }

func initConfigUsing(parse func(string) error) {
	// Parse config if TOML directory exists, or if legacy conf file exists
	tomlExists := false
	if _, err := os.Stat("/etc/syswarden/config/modules"); err == nil {
		tomlExists = true
	}

	if tomlExists {
		_ = parse("/etc/syswarden/config")
		return
	}

	// ParseConfig records a failed source in CurrentLoadState. Keep startup
	// silent here so root, help, and repair commands retain their process
	// contract; mutating commands surface the recorded failure through the
	// fail-closed PersistentPreRunE guard above.
	_ = parse(cfgFile)
}

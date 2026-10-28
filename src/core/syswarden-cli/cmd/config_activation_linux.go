//go:build linux

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"syswarden-cli/config"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

type activationExecutionKey struct{}

type activationExecution struct {
	command         *cobra.Command
	approval        *config.ActivationApproval
	operation       string
	verifyAuthority func(context.Context) error
	reviewedHost    func(context.Context) error
	phase           configurationActivationPhase
}

type configurationActivationPlan struct {
	Schema                 string
	Operation              string
	NoRestart              bool
	PolicySHA256           string
	PreviousApprovalSHA256 string
	HostSHA256             string
	ObservationSHA256      string
	SSHConnectionSHA256    string
	SSHClientSHA256        string
	ModulePlan             []string
	Effects                []config.ConfigurationEffect
	HostSummary            []string
}

var configActivateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Review and explicitly approve activation of the complete TOML configuration",
	Long:  "Inspects the live target and complete TOML without mutation. A new or changed policy requires the exact displayed --approve-plan digest before install/reload may apply it. Approval does not grant dedicated SSH hardening or prove migration, access or final qualification.",
	Args:  cobra.NoArgs,
	RunE:  func(cmd *cobra.Command, args []string) error { return installCmd.RunE(cmd, args) },
}

var preflightAPKActivation = system.PreflightAPKConfigurationActivation
var captureActivationPolicy = config.CaptureActivationPolicy
var captureActivationHost = system.CaptureActivationHost
var prepareConfigurationActivationHook = prepareConfigurationActivation
var consumeApprovedOperationalConfigurationHook = consumeApprovedOperationalConfiguration

func activationOperation(cmd *cobra.Command) string {
	if cmd == configActivateCmd {
		return "install"
	}
	if cmd == installCmd {
		return "install"
	}
	if cmd == reloadCmd {
		return "reload"
	}
	return ""
}

func activationOperationAllowed(approved, requested string) bool {
	return approved == "install" && (requested == "install" || requested == "reload") || approved == "reload" && requested == "reload"
}

func activationPlanDigest(plan configurationActivationPlan) (string, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func activationEnvironmentDigest(name string) string {
	value, present := os.LookupEnv(name)
	raw, _ := json.Marshal(struct {
		Present bool
		Value   string
	}{present, value})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// This boundary runs before recovery, ParseConfig, dependency installation and
// every lifecycle RunE. Package hooks can consume existing approval but cannot
// mint it. An environment flag, profile, active service or --no-restart never
// supplies approval. The command's successful result is recorded separately.
func prepareConfigurationActivation(cmd *cobra.Command) error {
	operation := activationOperation(cmd)
	if operation == "" {
		return errors.New("configuration activation command is not recognized")
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cmd.SetContext(ctx)
	if err := preflightAPKActivation(ctx); err != nil {
		return err
	}
	if err := preflightWireGuardPolicyTransition(); err != nil {
		return err
	}
	if err := enforceRemovalState(cmd); err != nil {
		return err
	}
	policy, err := captureActivationPolicy(ctx, configEditorRoot)
	if err != nil {
		return fmt.Errorf("capture complete activation policy before mutation: %w", err)
	}
	requested, err := cmd.Flags().GetString("approve-plan")
	if err != nil {
		return err
	}
	if operation == "reload" {
		suppressRestart, flagErr := cmd.Flags().GetBool("no-restart")
		if flagErr != nil {
			return flagErr
		}
		if err := validateActivationApprovalRestartScope(suppressRestart, requested); err != nil {
			return err
		}
	}
	current, err := policy.CurrentApproval(ctx)
	if err != nil {
		return fmt.Errorf("inspect existing activation approval: %w", err)
	}
	if operation == "reload" && requested == "" && current != nil && activationOperationAllowed(current.Review().Operation, operation) {
		if approval, verifyErr := policy.VerifyApproved(ctx); verifyErr == nil {
			return consumeConfigurationActivation(cmd, policy, approval, operation, nil)
		}
	}
	if operation == "reload" {
		suppressRestart, flagErr := cmd.Flags().GetBool("no-restart")
		if flagErr != nil {
			return flagErr
		}
		if suppressRestart {
			return errors.New("reload --no-restart requires exact existing approval; review changed policy with ordinary reload or config activate")
		}
	}
	if os.Getenv("SYSWARDEN_PKG_INSTALL") == "1" {
		return errors.New("native package hooks cannot approve new or changed policy; inspect package and runtime state, then review activation explicitly")
	}
	// New approval cannot silently recover an earlier operation. Existing
	// exact authority may enter its independently guarded recovery in root.
	if err := readonlyConfigurationLifecyclePreflight(cmd); err != nil {
		return err
	}
	review := policy.Review()
	if review.UnknownKeyCount != 0 || review.DeprecatedKeyCount != 0 {
		return errors.New("activation requires TOML without unknown or deprecated entries; inspect config validate and resolve them before approval")
	}
	configuration, err := policy.Configuration(ctx)
	if err != nil {
		return err
	}
	host, err := captureActivationHost(ctx, configuration.FirewallBackend, configuration.HAEnabled)
	if err != nil {
		return fmt.Errorf("inspect live activation prerequisites without changes: %w", err)
	}
	hostSHA256, err := policy.HostSHA256()
	if err != nil {
		return err
	}
	plan := configurationActivationPlan{
		Schema: "syswarden-command-activation-plan-v1", Operation: operation,
		PolicySHA256: review.Digest, HostSHA256: hostSHA256, ObservationSHA256: host.Digest(),
		SSHConnectionSHA256: activationEnvironmentDigest("SSH_CONNECTION"), SSHClientSHA256: activationEnvironmentDigest("SSH_CLIENT"),
		ModulePlan: review.ModulePlan, Effects: review.Effects, HostSummary: host.Summary(),
	}
	if operation == "reload" {
		plan.NoRestart, err = cmd.Flags().GetBool("no-restart")
		if err != nil {
			return err
		}
	}
	if current != nil {
		plan.PreviousApprovalSHA256 = current.Review().SHA256
	}
	digest, err := activationPlanDigest(plan)
	if err != nil {
		return err
	}
	output := cmd.OutOrStdout()
	fmt.Fprintf(output, "Configuration activation plan for %s (%d complete TOML inputs).\n", operation, review.InputCount)
	for _, line := range plan.ModulePlan {
		fmt.Fprintln(output, line)
	}
	fmt.Fprintln(output, "Observed live service, scheduling and interface state:")
	for _, line := range plan.HostSummary {
		fmt.Fprintln(output, "- "+line)
	}
	fmt.Fprintln(output, "Authorized operation effects if this plan is explicitly approved:")
	for _, effect := range plan.Effects {
		fmt.Fprintf(output, "- %s: %s\n", effect.Area, effect.Detail)
	}
	fmt.Fprintln(output, "Independent ownership, kernel transaction and SSH access checks remain mandatory. This plan is not a kernel-rule diff or migration acceptance.")
	fmt.Fprintf(output, "Activation plan SHA256: %s\n", digest)
	if requested == "" {
		return fmt.Errorf("no change applied; review this plan, then repeat %q with --approve-plan %s", cmd.CommandPath(), digest)
	}
	if requested != digest {
		return errors.New("activation approval does not match the current exact plan; no change applied")
	}
	reviewedHost := func(check context.Context) error {
		if err := preflightAPKActivation(check); err != nil {
			return err
		}
		if err := readonlyConfigurationLifecyclePreflight(cmd); err != nil {
			return err
		}
		if plan.SSHConnectionSHA256 != activationEnvironmentDigest("SSH_CONNECTION") || plan.SSHClientSHA256 != activationEnvironmentDigest("SSH_CLIENT") {
			return errors.New("administrator connection context changed after activation review")
		}
		return host.Revalidate(check)
	}
	approval, err := policy.Approve(ctx, config.ActivationApprovalRequest{
		PlanSHA256: digest, ApprovedPlanSHA256: requested, PreviousApprovalSHA256: plan.PreviousApprovalSHA256, Operation: operation,
	}, func() error { return reviewedHost(ctx) })
	if err != nil {
		return fmt.Errorf("activation approval did not authorize host effects: %w", err)
	}
	return consumeConfigurationActivation(cmd, policy, approval, operation, reviewedHost)
}

func consumeConfigurationActivation(cmd *cobra.Command, policy *config.ActivationPolicy, approval *config.ActivationApproval, operation string, reviewedHost func(context.Context) error) error {
	if !activationOperationAllowed(approval.Review().Operation, operation) {
		return errors.New("activation approval does not permit this operation")
	}
	if reviewedHost != nil {
		if err := reviewedHost(cmd.Context()); err != nil {
			return fmt.Errorf("activation host changed before approval consumption: %w", err)
		}
	}
	consumed, err := policy.UseApproved(cmd.Context())
	if err != nil {
		return err
	}
	if consumed.Review().SHA256 != approval.Review().SHA256 {
		return errors.New("activation approval changed before consumption")
	}
	verifyAuthority := func(check context.Context) error {
		if err := preflightAPKActivation(check); err != nil {
			return err
		}
		if err := policy.Revalidate(check); err != nil {
			return err
		}
		return consumed.Revalidate(check)
	}
	if reviewedHost != nil {
		if err := reviewedHost(cmd.Context()); err != nil {
			return fmt.Errorf("activation host changed during approval consumption: %w", err)
		}
	}
	if err := verifyAuthority(cmd.Context()); err != nil {
		return err
	}
	cmd.SetContext(context.WithValue(cmd.Context(), activationExecutionKey{}, &activationExecution{
		command: cmd, approval: consumed, operation: operation,
		verifyAuthority: verifyAuthority, reviewedHost: reviewedHost, phase: activationPrepared,
	}))
	return nil
}

func configurationActivationExecution(cmd *cobra.Command) *activationExecution {
	if cmd == nil || cmd.Context() == nil {
		return nil
	}
	execution, _ := cmd.Context().Value(activationExecutionKey{}).(*activationExecution)
	return execution
}

func revalidateConfigurationActivation(cmd *cobra.Command) error {
	execution := configurationActivationExecution(cmd)
	if execution == nil || execution.verifyAuthority == nil {
		return errors.New("captured activation approval is unavailable")
	}
	if execution.phase == activationFailed || execution.phase == activationFinished {
		return errors.New("activation command execution cannot be reused after failure or completion")
	}
	return execution.verifyAuthority(cmd.Context())
}

func markConfigurationActivationApplied(cmd *cobra.Command) error {
	execution := configurationActivationExecution(cmd)
	if execution == nil || execution.approval == nil || execution.phase != activationApplying {
		return errors.New("cannot record applied configuration before its guarded application phase")
	}
	if err := revalidateConfigurationActivation(cmd); err != nil {
		return err
	}
	// A firewall service reload inside install cannot claim that the parent
	// install completed. Existing applied install approval remains unchanged.
	if execution.operation == "reload" && execution.approval.Review().Operation == "install" {
		execution.phase = activationFinished
		return nil
	}
	if err := execution.approval.MarkApplied(cmd.Context()); err != nil {
		execution.phase = activationFailed
		return err
	}
	execution.phase = activationFinished
	return nil
}

func init() {
	for _, command := range []*cobra.Command{installCmd, reloadCmd, configActivateCmd} {
		command.Flags().String("approve-plan", "", "exact SHA256 of the reviewed current activation plan; never implied by package installation")
	}
	configCmd.AddCommand(configActivateCmd)
}

// Scheduled feeds, HA and interactive runtime mutations consume existing exact
// authority. They cannot turn an edited TOML into a new activation path.
func consumeApprovedOperationalConfiguration(cmd *cobra.Command) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := preflightAPKActivation(ctx); err != nil {
		return err
	}
	policy, err := captureActivationPolicy(ctx, configEditorRoot)
	if err != nil {
		return err
	}
	_, err = policy.UseApproved(ctx)
	if err != nil {
		return fmt.Errorf("runtime command requires exact previously approved TOML; review config activate or reload first: %w", err)
	}
	return nil
}

func operationalConfigurationApprovalRequired(cmd *cobra.Command) bool {
	if !commandRequiresAutomaticConfigLoad(cmd) || configurationInspectionCommand(cmd) {
		return false
	}
	top := topLevelCommand(cmd)
	if top == nil {
		return false
	}
	switch top.Name() {
	case "uninstall", "prepare-package-removal", "recover-removal", "recover-wireguard", "update":
		// Explicit recovery/removal have independent authority and must remain
		// usable when approved configuration has become unavailable.
		return false
	}
	return activationOperation(cmd) == ""
}

func validateActivationApprovalRestartScope(noRestart bool, requested string) error {
	if noRestart && requested != "" {
		return errors.New("--no-restart can only consume existing approval; review new policy with config activate or ordinary reload")
	}
	return nil
}

var inspectActivationServiceManagerState = system.ServiceManagerRuntimeState

// Existing package upgrades may defer entirely when the host manager is
// offline. An active package hook has no candidate-specific activation plan;
// refuse before its service-pair observer can execute a native manager query.
func refuseUnapprovedActiveNativeInstall() error {
	if os.Getenv("SYSWARDEN_PKG_INSTALL") != "1" || os.Getenv("SYSWARDEN_NATIVE_INSTALL_PHASE") != "upgrade" {
		return nil
	}
	state, err := inspectActivationServiceManagerState()
	if err != nil {
		return err
	}
	if state != "OFFLINE" {
		return errors.New("active native package activation requires a candidate-specific reviewed plan; inspect package and runtime state before continuing")
	}
	return nil
}

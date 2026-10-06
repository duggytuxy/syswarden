//go:build linux

package firewall

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"syswarden-cli/config"
)

// PreflightAdministratorPolicyRemoval is read-only and runs before stopping
// product services. Cleanup repeats these checks under its firewall lock.
// WireGuard state is deliberately left for its separate owned removal phase.
func PreflightAdministratorPolicyRemoval() error {
	if firewallCleanupEffectiveUserID() != 0 {
		return fmt.Errorf("administrator policy removal preflight must run as root")
	}
	if err := preflightConfiguredOperatorPolicyRemoval(); err != nil {
		return err
	}
	runner, err := uninstallNFTRunnerFactory()
	if err != nil {
		return fmt.Errorf("prepare read-only administrator policy inspection: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("inspect administrator policy before removal: %w", err)
	}
	document, err := decodeNFTJSON(output)
	if err != nil {
		return fmt.Errorf("decode administrator policy observation: %w", err)
	}
	return preflightLiveOperatorPolicyRemoval(document)
}

// An operator policy remains administrator-owned even though the renderer puts
// it in a product table. Product removal must not erase that protection or its
// source configuration. This check is not proof of ownership for other rules.
func preflightConfiguredOperatorPolicyRemoval() error {
	if config.GlobalConfig == nil {
		return fmt.Errorf("operator policy configuration is unavailable before removal")
	}
	if err := config.ValidateOperatorPolicy(config.GlobalConfig.OperatorPolicy); err != nil {
		return fmt.Errorf("validate operator policy before removal: %w", err)
	}
	if err := config.ReattestOperatorPolicySource(config.GlobalConfig); err != nil {
		return fmt.Errorf("reattest administrator policy source before removal: %w", err)
	}
	if len(config.GlobalConfig.OperatorPolicy.Rules) != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		preservation, err := authorizeNFTOperatorPolicyRemoval(ctx, nil)
		if err != nil {
			return fmt.Errorf("administrator operator policy remains configured without verified independent preservation; preserve its source and runtime rules: %w", err)
		}
		expected, err := compileOperatorPolicy(config.GlobalConfig.OperatorPolicy.Rules)
		if err != nil {
			return err
		}
		actual, err := compileOperatorPolicy(preservation.Rules)
		if err != nil || expected.chain != actual.chain {
			return fmt.Errorf("configured administrator policy differs from the independently preserved policy")
		}
	}
	return nil
}

func preflightLiveOperatorPolicyRemoval(document nftJSONDocument) error {
	embedded := false
	for _, entry := range document.NFTables {
		rule := entry.Rule
		if rule != nil && rule.Family == "inet" && rule.Table == "syswarden" && rule.Chain == operatorPolicyChainName && rule.Comment != operatorPolicyReturnComment {
			embedded = true
		}
	}
	if !embedded {
		return preflightUnpreservedLiveOperatorPolicyRemoval(document)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	preservation, err := authorizeNFTOperatorPolicyRemoval(ctx, nil)
	if err != nil {
		return fmt.Errorf("administrator policy rules remain in a product table without exact independent preservation: %w", err)
	}
	compiled, err := compileOperatorPolicy(preservation.Rules)
	if err != nil {
		return err
	}
	if err := verifyOperatorPolicyNFTState(document, compiled.verification); err != nil {
		return err
	}
	// Analyze a shallow copy only after exact typed verification. Keep raw
	// fields and all other objects so unknown rules and metadata still refuse.
	reduced := document
	reduced.NFTables = nil
	for _, entry := range document.NFTables {
		rule := entry.Rule
		if rule != nil && rule.Family == "inet" && rule.Table == "syswarden" && rule.Chain == operatorPolicyChainName && rule.Comment != operatorPolicyReturnComment {
			continue
		}
		reduced.NFTables = append(reduced.NFTables, entry)
	}
	return preflightUnpreservedLiveOperatorPolicyRemoval(reduced)
}

func preflightUnpreservedLiveOperatorPolicyRemoval(document nftJSONDocument) error {
	chains, returns := 0, 0
	for _, entry := range document.NFTables {
		if chain := entry.Chain; chain != nil && chain.Family == "inet" && chain.Table == "syswarden" && chain.Name == operatorPolicyChainName {
			chains++
			if chains > 1 || chain.Handle == 0 || verifyOperatorPolicyChainEnvelope(chain) != nil {
				return fmt.Errorf("administrator policy chain is ambiguous; preserve the ruleset for verified recovery")
			}
		}
		rule := entry.Rule
		if rule == nil || !isSyswardenNFTTable(nftTableTarget{family: rule.Family, name: rule.Table}) {
			continue
		}
		if strings.HasPrefix(rule.Comment, operatorPolicyCommentPrefix) && rule.Comment != operatorPolicyDispatchComment && rule.Comment != operatorPolicyReturnComment {
			return fmt.Errorf("administrator policy rules remain in a product table; preserve their effective protection before removal")
		}
		if rule.Chain != operatorPolicyChainName {
			continue
		}
		returns++
		if returns > 1 || rule.Handle == 0 || verifyNFTJSONRuleExact(rule, "inet", "syswarden", operatorPolicyChainName, operatorPolicyReturnComment, []any{map[string]any{"return": nil}}) != nil {
			return fmt.Errorf("administrator policy rules or modified policy scaffolding remain; preserve the ruleset and source configuration before removal")
		}
	}
	if returns > 0 && chains != 1 {
		return fmt.Errorf("administrator policy rule has no exact regular chain; preserve the ruleset for recovery")
	}
	return nil
}

// Run before compatibility-wrapper changes and again immediately before the
// native table cleanup. Neither a configured nor a live administrator policy
// may be discarded merely because it uses a SysWarden container.
func preflightNFTablesForUninstall(ctx context.Context, runner nftCommandRunner) error {
	if err := preflightConfiguredOperatorPolicyRemoval(); err != nil {
		return err
	}
	handles, err := listLegacyWireGuardForwardRuleHandles(ctx, runner)
	if err != nil {
		return err
	}
	if len(handles) > 0 {
		values := make([]string, 0, len(handles))
		for _, handle := range handles {
			values = append(values, strconv.FormatUint(handle, 10))
		}
		return fmt.Errorf("refusing to remove unowned legacy WireGuard nftables rules: handles %s; remove or attest them explicitly before retrying", strings.Join(values, ", "))
	}
	return nil
}

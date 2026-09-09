package cmd

import (
	"bytes"
	"errors"
	"strings"
	"syswarden-cli/pkg/network"
	"testing"
)

func commandLegacyWireGuardRecoveryPlan() network.LegacyWireGuardRecoveryPlan {
	return network.LegacyWireGuardRecoveryPlan{
		Schema:              "syswarden-legacy-wireguard-recovery-v1",
		Generation:          "pre-v3.75.7-wg0",
		ServiceManager:      "systemd",
		HistoricalInterface: "wg0",
		Table: network.LegacyWireGuardTableEvidence{
			Family: "inet", Name: "syswarden_wg", Handle: 7,
			PreroutingChainHandle: 8, PostroutingChainHandle: 9,
			MasqueradeRuleHandle: 11, EgressInterface: "ens3",
		},
		ForwardRules: []network.LegacyWireGuardForwardRuleEvidence{},
		Configuration: network.LegacyWireGuardFileEvidence{
			Path: "/etc/wireguard/wg0.conf", SHA256: strings.Repeat("a", 64),
			Mode: 0600, UID: 0, GID: 0, NLink: 1, Device: 8, Inode: 42, Size: 1024,
			Source: "exact-historical-config",
		},
		Ownership: network.LegacyWireGuardOwnershipEvidence{
			State: "no-manifest", SHA256: strings.Repeat("b", 64),
		},
		Service: network.LegacyWireGuardServiceEvidence{
			LoadState: "loaded", Name: "wg-quick@wg0.service",
			ActiveState: "inactive", EnabledState: "disabled",
		},
		SafeToApply: true,
		Blockers:    []string{},
	}
}

func TestRecoverWireGuardDryRunPrintsRedactedPlanAndExactApplyCommand_SW2_WGRECOVERY_001(t *testing.T) {
	previousInspect := inspectLegacyWireGuardRecovery
	previousApply := applyLegacyWireGuardRecovery
	t.Cleanup(func() {
		inspectLegacyWireGuardRecovery = previousInspect
		applyLegacyWireGuardRecovery = previousApply
	})
	plan := commandLegacyWireGuardRecoveryPlan()
	inspectCalls := 0
	inspectLegacyWireGuardRecovery = func() (network.LegacyWireGuardRecoveryPlan, error) {
		inspectCalls++
		return plan, nil
	}
	applyLegacyWireGuardRecovery = func(string) (network.LegacyWireGuardRecoveryPlan, error) {
		t.Fatal("dry run invoked mutation")
		return network.LegacyWireGuardRecoveryPlan{}, nil
	}
	digest, err := network.LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	command := newRecoverWireGuardCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs(nil)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if inspectCalls != 1 || !strings.Contains(output.String(), "Plan SHA-256: "+digest) ||
		!strings.Contains(output.String(), "--apply --plan-sha256 "+digest) {
		t.Fatalf("unexpected dry-run output/calls (%d): %s", inspectCalls, output.String())
	}
}

func TestRecoverWireGuardApplyRequiresAndForwardsExactPlanDigest_SW2_WGRECOVERY_002(t *testing.T) {
	previousApply := applyLegacyWireGuardRecovery
	t.Cleanup(func() { applyLegacyWireGuardRecovery = previousApply })
	plan := commandLegacyWireGuardRecoveryPlan()
	digest, err := network.LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	applyCalls := 0
	applyLegacyWireGuardRecovery = func(got string) (network.LegacyWireGuardRecoveryPlan, error) {
		applyCalls++
		if got != digest {
			t.Fatalf("apply digest = %q, want %q", got, digest)
		}
		return plan, nil
	}

	missing := newRecoverWireGuardCommand()
	missing.SetArgs([]string{"--apply"})
	if err := missing.Execute(); err == nil || !strings.Contains(err.Error(), "requires --plan-sha256") {
		t.Fatalf("missing digest error = %v", err)
	}
	if applyCalls != 0 {
		t.Fatalf("missing digest invoked apply %d times", applyCalls)
	}

	command := newRecoverWireGuardCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"--apply", "--plan-sha256", digest})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 || !strings.Contains(output.String(), "Recovery applied") {
		t.Fatalf("apply calls/output = %d/%q", applyCalls, output.String())
	}
}

func TestRecoverWireGuardPropagatesInspectionFailureWithoutMutation_SW2_WGRECOVERY_003(t *testing.T) {
	previousInspect := inspectLegacyWireGuardRecovery
	previousApply := applyLegacyWireGuardRecovery
	t.Cleanup(func() {
		inspectLegacyWireGuardRecovery = previousInspect
		applyLegacyWireGuardRecovery = previousApply
	})
	sentinel := errors.New("unknown unmarked table")
	inspectLegacyWireGuardRecovery = func() (network.LegacyWireGuardRecoveryPlan, error) {
		return network.LegacyWireGuardRecoveryPlan{}, sentinel
	}
	applyLegacyWireGuardRecovery = func(string) (network.LegacyWireGuardRecoveryPlan, error) {
		t.Fatal("failed inspection invoked mutation")
		return network.LegacyWireGuardRecoveryPlan{}, nil
	}
	command := newRecoverWireGuardCommand()
	command.SetArgs(nil)
	if err := command.Execute(); !errors.Is(err, sentinel) {
		t.Fatalf("inspection error = %v, want sentinel", err)
	}
}

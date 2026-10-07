package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syswarden-cli/pkg/firewall"
	"testing"
)

func TestRecoverOperatorPolicyRequiresExactReviewAndSeparateExport(t *testing.T) {
	oldInspect, oldApply, oldExport := inspectOperatorPolicyPreservation, applyOperatorPolicyPreservation, exportOperatorPolicyReceiver
	t.Cleanup(func() {
		inspectOperatorPolicyPreservation, applyOperatorPolicyPreservation, exportOperatorPolicyReceiver = oldInspect, oldApply, oldExport
	})
	plan := firewall.OperatorPolicyPreservationSummary{PlanSHA256: strings.Repeat("a", 64), RuleCount: 4}
	inspectCalls, applyCalls, exports := 0, 0, 0
	sentinel := errors.New("independent receiver changed")
	inspectOperatorPolicyPreservation = func(context.Context) (firewall.OperatorPolicyPreservationSummary, error) {
		inspectCalls++
		return plan, nil
	}
	applyOperatorPolicyPreservation = func(_ context.Context, digest string) (firewall.OperatorPolicyPreservationSummary, error) {
		applyCalls++
		if digest != plan.PlanSHA256 {
			t.Fatal("review digest changed")
		}
		return plan, sentinel
	}
	source := []byte("table inet operator_preserved_0123456789abcdef0123 {\n}\n")
	exportOperatorPolicyReceiver = func() (firewall.OperatorPolicyReceiverExport, error) {
		exports++
		return firewall.OperatorPolicyReceiverExport{Path: "/etc/nftables.d/operator_preserved_0123456789abcdef0123.nft", Source: source}, nil
	}
	for _, args := range [][]string{
		{"--preserve-operator-policy", "--apply"},
		{"--preserve-operator-policy", "--plan-sha256", plan.PlanSHA256},
		{"--preserve-operator-policy", "--file-plan-sha256", plan.PlanSHA256},
		{"--preserve-operator-policy", "--retain-operator-config"},
		{"--preserve-operator-policy", "--retire-legacy-fail2ban"},
		{"--preserve-operator-policy", "--historical-inputs", "/root/original.json"},
		{"--preserve-operator-policy", "--confirm-historical-inputs"},
		{"--preserve-operator-policy", "--export-operator-policy"},
		{"--export-operator-policy", "--apply", "--plan-sha256", plan.PlanSHA256},
		{"--export-operator-policy", "--file-plan-sha256", plan.PlanSHA256},
	} {
		command := newRecoverRemovalCommand()
		command.SetArgs(args)
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatal("conflicting or incomplete review reached host operations", args)
		}
	}
	if inspectCalls != 0 || applyCalls != 0 || exports != 0 {
		t.Fatal("invalid flags reached host operations")
	}
	command := newRecoverRemovalCommand()
	command.SetArgs([]string{"--preserve-operator-policy"})
	out := &bytes.Buffer{}
	command.SetOut(out)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{plan.PlanSHA256, "do not override drops", "no active file or live rule", "--apply --plan-sha256"} {
		if !strings.Contains(out.String(), required) {
			t.Fatal("dry run omitted a material boundary", required)
		}
	}
	if inspectCalls != 1 || applyCalls != 0 {
		t.Fatal("inspection applied a decision")
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--preserve-operator-policy", "--apply", "--plan-sha256", plan.PlanSHA256})
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); !errors.Is(err, sentinel) || applyCalls != 1 {
		t.Fatal("changed receiver refusal was hidden", err)
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--export-operator-policy"})
	out = &bytes.Buffer{}
	diagnostics := &bytes.Buffer{}
	command.SetOut(out)
	command.SetErr(diagnostics)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if exports != 1 || !bytes.Equal(out.Bytes(), source) || !strings.Contains(diagnostics.String(), "private administrator rule predicates") || !strings.Contains(diagnostics.String(), "mode 0600") {
		t.Fatal("export changed source bytes or mixed instructions into them")
	}
}

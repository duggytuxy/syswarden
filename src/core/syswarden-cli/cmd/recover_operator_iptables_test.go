package cmd

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"syswarden-cli/pkg/firewall"
	"testing"
)

func TestRecoverRemovalOperatorIPTablesRequiresExactExplicitSelection(t *testing.T) {
	oldInspect, oldApply := inspectOperatorIPTablesPreservation, applyOperatorIPTablesPreservation
	t.Cleanup(func() { inspectOperatorIPTablesPreservation, applyOperatorIPTablesPreservation = oldInspect, oldApply })
	digest := strings.Repeat("a", 64)
	plan := firewall.OperatorIPTablesPreservationSummary{Schema: "fixture", PlanSHA256: digest, RuleCount: 2}
	inspections, applications := 0, 0
	inspectOperatorIPTablesPreservation = func(context.Context) (firewall.OperatorIPTablesPreservationSummary, error) {
		inspections++
		return plan, nil
	}
	applyOperatorIPTablesPreservation = func(_ context.Context, value string, confirmed bool) (firewall.OperatorIPTablesPreservationSummary, error) {
		applications++
		if value != digest || !confirmed {
			return plan, fmt.Errorf("wrong approval")
		}
		return plan, nil
	}
	for _, extra := range [][]string{{"--apply"}, {"--apply", "--plan-sha256", digest}, {"--confirm-operator-iptables"}, {"--plan-sha256", digest}, {"--retain-operator-config"}, {"--historical-inputs", "/private/file"}, {"--file-plan-sha256", digest}, {"--confirm-historical-inputs"}} {
		command := newRecoverRemovalCommand()
		command.SetArgs(append([]string{"--preserve-operator-iptables"}, extra...))
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatal("invalid selection reached host operations", extra)
		}
	}
	command := newRecoverRemovalCommand()
	command.SetArgs([]string{"--retain-operator-config", "--confirm-operator-iptables", "--apply", "--plan-sha256", digest})
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); err == nil {
		t.Fatal("unrelated recovery accepted preservation confirmation")
	}
	if inspections != 0 || applications != 0 {
		t.Fatal("invalid approvals reached host operations")
	}
	output := &bytes.Buffer{}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--preserve-operator-iptables"})
	command.SetOut(output)
	if err := command.Execute(); err != nil || inspections != 1 || applications != 0 || !strings.Contains(output.String(), "no deletion authority") {
		t.Fatal("incorrect dry run", err, output.String())
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--preserve-operator-iptables", "--apply", "--confirm-operator-iptables", "--plan-sha256", digest})
	command.SetOut(&bytes.Buffer{})
	if err := command.Execute(); err != nil || applications != 1 {
		t.Fatal("exact confirmed preservation was not applied once", err)
	}
}

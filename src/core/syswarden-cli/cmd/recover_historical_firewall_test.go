package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syswarden-cli/pkg/firewall"
	"testing"
)

func TestRecoverHistoricalFirewallRequiresIndependentInputsAndExactReview(t *testing.T) {
	oldInspect, oldApply := inspectHistoricalFirewallPersistence, applyHistoricalFirewallPersistence
	oldBegin, oldPrepare, oldCron := beginRemoval, prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval
	t.Cleanup(func() {
		inspectHistoricalFirewallPersistence, applyHistoricalFirewallPersistence = oldInspect, oldApply
		beginRemoval, prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval = oldBegin, oldPrepare, oldCron
	})
	const path = "/root/historical-capture/review.json"
	plan := firewall.HistoricalFirewallPersistenceSummary{PlanSHA256: strings.Repeat("a", 64), RequiresOriginalInputReview: true, RequiresAbsentProductTables: true, PreservesSharedService: true}
	inspections, applications := 0, 0
	inspectHistoricalFirewallPersistence = func(_ context.Context, actual string) (firewall.HistoricalFirewallPersistenceSummary, error) {
		if actual != path {
			t.Fatal("input path changed")
		}
		inspections++
		return plan, nil
	}
	failure := errors.New("service preparation refused")
	beginRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { return failure }
	removeOwnedCronStateForRemoval = func() error { t.Fatal("failed preparation changed cron"); return nil }
	applyHistoricalFirewallPersistence = func(_ context.Context, actual, reviewed string, confirmed bool, prepare func() error) (firewall.HistoricalFirewallPersistenceSummary, error) {
		applications++
		if actual != path || reviewed != plan.PlanSHA256 || !confirmed {
			t.Fatal("review authority changed")
		}
		return plan, prepare()
	}
	for _, args := range [][]string{
		{"--retire-legacy-firewall-persistence"},
		{"--retire-legacy-firewall-persistence", "--historical-inputs", path, "--confirm-historical-inputs"},
		{"--retire-legacy-firewall-persistence", "--historical-inputs", path, "--apply", "--plan-sha256", plan.PlanSHA256},
		{"--retire-legacy-firewall-persistence", "--historical-inputs", path, "--apply", "--confirm-historical-inputs"},
		{"--retire-legacy-firewall-persistence", "--historical-inputs", path, "--file-plan-sha256", plan.PlanSHA256},
		{"--retire-legacy-firewall-persistence", "--historical-inputs", path, "--retain-operator-config"},
		{"--retain-legacy-logs", "--historical-inputs", path},
		{"--retain-legacy-logs", "--confirm-historical-inputs"},
	} {
		command := newRecoverRemovalCommand()
		command.SetArgs(args)
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatal("incomplete or conflicting approval reached recovery", args)
		}
	}
	if inspections != 0 || applications != 0 {
		t.Fatal("invalid flags reached host operations")
	}
	command := newRecoverRemovalCommand()
	command.SetArgs([]string{"--retire-legacy-firewall-persistence", "--historical-inputs", path})
	output := &bytes.Buffer{}
	command.SetOut(output)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"do not authenticate", "absent product tables", "never changes live rules", "--confirm-historical-inputs", plan.PlanSHA256} {
		if !strings.Contains(output.String(), text) {
			t.Fatal("dry run omitted a material boundary", text)
		}
	}
	if inspections != 1 || applications != 0 {
		t.Fatal("dry run mutated host state")
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--retire-legacy-firewall-persistence", "--historical-inputs", path, "--apply", "--confirm-historical-inputs", "--plan-sha256", plan.PlanSHA256})
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); !errors.Is(err, failure) || applications != 1 {
		t.Fatal("failed preparation was hidden or repeated", err)
	}
}

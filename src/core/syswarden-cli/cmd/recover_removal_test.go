package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/system"
	"testing"
)

func TestRecoverRemovalRequiresExplicitSelectionAndReviewedDigest(t *testing.T) {
	oldInspect, oldApply := inspectLegacyLogRetention, applyLegacyLogRetention
	t.Cleanup(func() { inspectLegacyLogRetention, applyLegacyLogRetention = oldInspect, oldApply })
	inspections, applications := 0, 0
	plan := system.LegacyLogRetentionPlan{Schema: "syswarden-legacy-log-retention-v1", Directory: "/var/log/syswarden", Authority: "explicit-operator-confirmation-of-exact-legacy-log-retention"}
	digest, err := system.LegacyLogRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	inspectLegacyLogRetention = func() (system.LegacyLogRetentionPlan, error) { inspections++; return plan, nil }
	applyLegacyLogRetention = func(s string) (system.LegacyLogRetentionPlan, string, error) {
		applications++
		if s != digest {
			return plan, "", errors.New("changed plan")
		}
		return plan, "/var/backups/syswarden-retired-v1/private-fixture", nil
	}
	for _, args := range [][]string{nil, {"--apply"}, {"--retain-legacy-lists", "--retain-legacy-ui"}, {"--retain-legacy-logs", "--retain-legacy-ui"}, {"--retire-legacy-cron", "--retain-legacy-lists"}, {"--retire-legacy-cron", "--apply"}, {"--retire-legacy-cron", "--plan-sha256", digest}, {"--retain-legacy-logs", "--apply"}, {"--retain-legacy-logs", "--plan-sha256", digest}} {
		command := newRecoverRemovalCommand()
		command.SetArgs(args)
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatal("incomplete authorization was accepted", args)
		}
	}
	if inspections != 0 || applications != 0 {
		t.Fatal("invalid flags reached host operations")
	}
	output := &bytes.Buffer{}
	command := newRecoverRemovalCommand()
	command.SetArgs([]string{"--retain-legacy-logs"})
	command.SetOut(output)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if inspections != 1 || applications != 0 || !strings.Contains(output.String(), digest) || !strings.Contains(output.String(), "no other producer") {
		t.Fatal("dry run did not expose the bounded confirmation contract", output.String())
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--retain-legacy-logs", "--apply", "--plan-sha256", digest})
	command.SetOut(&bytes.Buffer{})
	if err := command.Execute(); err != nil || applications != 1 {
		t.Fatal("reviewed plan was not delegated exactly once", err)
	}
}

func TestRecoverRemovalSkipsConfigurationAndFirewallMutationDuringPreparation(t *testing.T) {
	oldInit, oldRecovery := initConfigHook, recoverPendingFirewallTransactionHook
	t.Cleanup(func() { initConfigHook, recoverPendingFirewallTransactionHook = oldInit, oldRecovery })
	initConfigHook = func() { t.Fatal("recovery normalized configuration before inspection") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("recovery mutated firewall state before inspection"); return nil }
	if !commandAllowedDuringRemoval(recoverRemovalCmd) {
		t.Fatal("retained removal barrier blocked its recovery command")
	}
	if err := rootCmd.PersistentPreRunE(recoverRemovalCmd, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverRemovalCronRequiresBoundedOperatorReview(t *testing.T) {
	oldInspect, oldApply := inspectLegacyCronRetirement, applyLegacyCronRetirement
	t.Cleanup(func() { inspectLegacyCronRetirement, applyLegacyCronRetirement = oldInspect, oldApply })
	plan := system.LegacyCronRetirementPlan{Schema: "syswarden-legacy-root-cron-retirement-v1", RemovedLines: []int{3}, StopsProduct: true, PreservesOtherJobs: true}
	digest, err := system.LegacyCronRetirementPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	inspections, applications := 0, 0
	inspectLegacyCronRetirement = func() (system.LegacyCronRetirementPlan, error) { inspections++; return plan, nil }
	applyLegacyCronRetirement = func(reviewed string) (system.LegacyCronRetirementPlan, string, error) {
		applications++
		if reviewed != digest {
			return plan, "", errors.New("unreviewed plan")
		}
		return plan, "/var/backups/syswarden-retired-v1/cron-fixture", nil
	}
	output := &bytes.Buffer{}
	command := newRecoverRemovalCommand()
	command.SetArgs([]string{"--retire-legacy-cron"})
	command.SetOut(output)
	if err := command.Execute(); err != nil || inspections != 1 || applications != 0 {
		t.Fatal("dry run mutated the host", err)
	}
	for _, expected := range []string{digest, "stops managed product services", "Other records remain byte-for-byte unchanged"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatal("dry run omitted a material consequence", expected)
		}
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--retire-legacy-cron", "--apply", "--plan-sha256", digest})
	command.SetOut(&bytes.Buffer{})
	if err := command.Execute(); err != nil || inspections != 1 || applications != 1 {
		t.Fatal("reviewed application was not delegated exactly once", err)
	}
}

func TestRecoverRemovalFail2banBindsBothDigestsAndStopsOnPreparationFailure(t *testing.T) {
	oldInspect, oldApply := inspectLegacyFail2banRecovery, applyLegacyFail2banRecovery
	oldBegin, oldPrepare, oldCron := beginRemoval, prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval
	t.Cleanup(func() {
		inspectLegacyFail2banRecovery, applyLegacyFail2banRecovery = oldInspect, oldApply
		beginRemoval, prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval = oldBegin, oldPrepare, oldCron
	})
	plan := firewall.LegacyFail2banRecoverySummary{
		FilePlanSHA256: strings.Repeat("a", 64), PlanSHA256: strings.Repeat("b", 64),
		PreservesSharedService: true, StopsProductServices: true,
	}
	inspections, applications := 0, 0
	inspectLegacyFail2banRecovery = func(context.Context) (firewall.LegacyFail2banRecoverySummary, error) {
		inspections++
		return plan, nil
	}
	preparationFailure := errors.New("product service preparation refused")
	var order []string
	beginRemoval = func() error { order = append(order, "barrier"); return nil }
	prepareFirewallStateForRemoval = func() error { order = append(order, "services"); return preparationFailure }
	removeOwnedCronStateForRemoval = func() error { t.Fatal("failed service preparation reached cron mutation"); return nil }
	applyLegacyFail2banRecovery = func(_ context.Context, fileDigest, runtimeDigest string, prepare func() error) (firewall.LegacyFail2banRecoverySummary, error) {
		applications++
		if fileDigest != plan.FilePlanSHA256 || runtimeDigest != plan.PlanSHA256 {
			t.Fatal("reviewed digests were changed or reversed")
		}
		return plan, prepare()
	}
	run := func(args ...string) (string, error) {
		output := &bytes.Buffer{}
		command := newRecoverRemovalCommand()
		command.SetArgs(args)
		command.SetOut(output)
		command.SetErr(&bytes.Buffer{})
		err := command.Execute()
		return output.String(), err
	}
	for _, args := range [][]string{
		{"--retire-legacy-fail2ban", "--apply", "--plan-sha256", plan.PlanSHA256},
		{"--retire-legacy-fail2ban", "--file-plan-sha256", plan.FilePlanSHA256},
		{"--retire-legacy-fail2ban", "--retire-legacy-cron"},
	} {
		if _, err := run(args...); err == nil {
			t.Fatal("incomplete or mixed recovery authorization accepted")
		}
	}
	if inspections != 0 || applications != 0 || len(order) != 0 {
		t.Fatal("invalid flags reached host operations")
	}
	output, err := run("--retire-legacy-fail2ban")
	if err != nil || inspections != 1 || applications != 0 || len(order) != 0 {
		t.Fatal("dry run changed host state", err)
	}
	for _, expected := range []string{plan.FilePlanSHA256, plan.PlanSHA256, "shared Fail2ban service", "unrelated protections remain active"} {
		if !strings.Contains(output, expected) {
			t.Fatal("dry run omitted the review contract", expected)
		}
	}
	_, err = run("--retire-legacy-fail2ban", "--apply", "--file-plan-sha256", plan.FilePlanSHA256, "--plan-sha256", plan.PlanSHA256)
	if !errors.Is(err, preparationFailure) || applications != 1 || strings.Join(order, ",") != "barrier,services" {
		t.Fatal("failed preparation was not propagated at the exact boundary", err, order)
	}
}

func TestRecoverRemovalFail2banPersistenceRequiresSeparateBoundedReview(t *testing.T) {
	oldInspect, oldApply := inspectLegacyFail2banPersistence, applyLegacyFail2banPersistence
	oldBegin, oldPrepare, oldCron := beginRemoval, prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval
	t.Cleanup(func() {
		inspectLegacyFail2banPersistence, applyLegacyFail2banPersistence = oldInspect, oldApply
		beginRemoval, prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval = oldBegin, oldPrepare, oldCron
	})
	plan := firewall.LegacyFail2banPersistenceSummary{
		FilePlanSHA256: strings.Repeat("a", 64), PlanSHA256: strings.Repeat("b", 64),
		PreservesSharedService: true, StopsProductServices: true,
	}
	inspections, applications := 0, 0
	inspectLegacyFail2banPersistence = func(context.Context) (firewall.LegacyFail2banPersistenceSummary, error) {
		inspections++
		return plan, nil
	}
	preparationFailure := errors.New("product service preparation refused")
	var order []string
	beginRemoval = func() error { order = append(order, "barrier"); return nil }
	prepareFirewallStateForRemoval = func() error { order = append(order, "services"); return preparationFailure }
	removeOwnedCronStateForRemoval = func() error { t.Fatal("failed service preparation reached cron mutation"); return nil }
	applyLegacyFail2banPersistence = func(_ context.Context, fileDigest, runtimeDigest string, prepare func() error) (firewall.LegacyFail2banPersistenceSummary, error) {
		applications++
		if fileDigest != plan.FilePlanSHA256 || runtimeDigest != plan.PlanSHA256 {
			t.Fatal("reviewed digests were changed or reversed")
		}
		return plan, prepare()
	}
	run := func(args ...string) (string, error) {
		output := &bytes.Buffer{}
		command := newRecoverRemovalCommand()
		command.SetArgs(args)
		command.SetOut(output)
		command.SetErr(&bytes.Buffer{})
		err := command.Execute()
		return output.String(), err
	}
	for _, args := range [][]string{
		{"--retire-legacy-fail2ban-persistence", "--apply", "--plan-sha256", plan.PlanSHA256},
		{"--retire-legacy-fail2ban-persistence", "--file-plan-sha256", plan.FilePlanSHA256},
		{"--retire-legacy-fail2ban-persistence", "--retire-legacy-cron"},
		{"--retire-legacy-fail2ban-persistence", "--retire-legacy-fail2ban"},
	} {
		if _, err := run(args...); err == nil {
			t.Fatal("incomplete or mixed recovery authorization accepted")
		}
	}
	if inspections != 0 || applications != 0 || len(order) != 0 {
		t.Fatal("invalid flags reached host operations")
	}
	output, err := run("--retire-legacy-fail2ban-persistence")
	if err != nil || inspections != 1 || applications != 0 || len(order) != 0 {
		t.Fatal("dry run changed host state", err)
	}
	for _, expected := range []string{plan.FilePlanSHA256, plan.PlanSHA256, "shared Fail2ban service", "Administrator entries remain byte-for-byte unchanged"} {
		if !strings.Contains(output, expected) {
			t.Fatal("dry run omitted the review contract", expected)
		}
	}
	_, err = run("--retire-legacy-fail2ban-persistence", "--apply", "--file-plan-sha256", plan.FilePlanSHA256, "--plan-sha256", plan.PlanSHA256)
	if !errors.Is(err, preparationFailure) || applications != 1 || strings.Join(order, ",") != "barrier,services" {
		t.Fatal("failed preparation was not propagated at the exact boundary", err, order)
	}
}

func TestRecoverRemovalLegacyConfigRequiresExplicitReview(t *testing.T) {
	oldInspect, oldApply := inspectLegacyConfigRetention, applyLegacyConfigRetention
	t.Cleanup(func() { inspectLegacyConfigRetention, applyLegacyConfigRetention = oldInspect, oldApply })
	plan := system.LegacyLogRetentionPlan{Schema: "syswarden-inactive-legacy-config-retention-v1", Directory: "/opt/syswarden"}
	digest, err := system.LegacyLogRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	inspections, applications := 0, 0
	inspectLegacyConfigRetention = func() (system.LegacyLogRetentionPlan, error) { inspections++; return plan, nil }
	applyLegacyConfigRetention = func(expected string) (system.LegacyLogRetentionPlan, string, error) {
		applications++
		if expected != digest {
			return plan, "", errors.New("changed digest")
		}
		return plan, "/var/backups/syswarden-retired-v1/legacy-config-fixture", nil
	}
	run := func(args ...string) (string, error) {
		output := &bytes.Buffer{}
		command := newRecoverRemovalCommand()
		command.SetArgs(args)
		command.SetOut(output)
		command.SetErr(output)
		err := command.Execute()
		return output.String(), err
	}
	for _, args := range [][]string{{"--retain-legacy-config", "--retain-operator-config"}, {"--retain-legacy-config", "--apply"}, {"--retain-legacy-config", "--plan-sha256", digest}, {"--retain-legacy-config", "--file-plan-sha256", digest}} {
		if _, err := run(args...); err == nil {
			t.Fatal("incomplete or ambiguous review accepted", args)
		}
	}
	if inspections != 0 || applications != 0 {
		t.Fatal("invalid request reached host operations")
	}
	output, err := run("--retain-legacy-config")
	if err != nil || inspections != 1 || applications != 0 {
		t.Fatal("dry run mutated host", err)
	}
	for _, expected := range []string{digest, "inactive legacy configuration backup", "no other consumer or producer", "without deleting its bytes", "Active configuration remains untouched"} {
		if !strings.Contains(output, expected) {
			t.Fatal("review omitted a material effect", expected)
		}
	}
	if _, err := run("--retain-legacy-config", "--apply", "--plan-sha256", digest); err != nil || applications != 1 {
		t.Fatal("exact reviewed plan not delegated once", err)
	}
}

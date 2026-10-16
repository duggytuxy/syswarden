package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"syswarden-cli/pkg/system"
	"testing"
)

func TestRecoverRemovalHARequiresExclusiveStateConfirmation(t *testing.T) {
	oldInspect, oldApply := inspectHAStateRetention, applyHAStateRetention
	t.Cleanup(func() { inspectHAStateRetention, applyHAStateRetention = oldInspect, oldApply })
	plan := system.LegacyLogRetentionPlan{Schema: "syswarden-ha-state-retention-v1", Directory: "/var/lib/syswarden/ha"}
	digest, err := system.LegacyLogRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	inspections, applications := 0, 0
	inspectHAStateRetention = func() (system.LegacyLogRetentionPlan, error) { inspections++; return plan, nil }
	applyHAStateRetention = func(reviewed string) (system.LegacyLogRetentionPlan, string, error) {
		applications++
		if reviewed != digest {
			return plan, "", fmt.Errorf("changed plan")
		}
		return plan, "/var/backups/syswarden-retired-v1/ha-state-fixture", nil
	}
	for _, args := range [][]string{
		{"--retain-ha-state", "--apply", "--plan-sha256", digest},
		{"--retain-ha-state", "--confirm-exclusive-ha-state"},
		{"--retain-ha-state", "--plan-sha256", digest},
		{"--retain-ha-state", "--retain-legacy-config"},
		{"--retain-ha-state", "--historical-inputs", "/fixture"},
		{"--retain-ha-state", "--file-plan-sha256", digest},
		{"--retain-ha-state", "--confirm-historical-inputs"},
		{"--retain-ha-state", "--confirm-operator-iptables"},
		{"--retain-legacy-logs", "--apply", "--plan-sha256", digest, "--confirm-exclusive-ha-state"},
	} {
		command := newRecoverRemovalCommand()
		command.SetArgs(args)
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatal("incomplete or cross-inventory authorization accepted", args)
		}
	}
	if inspections != 0 || applications != 0 {
		t.Fatal("invalid flags reached the host")
	}
	output := &bytes.Buffer{}
	command := newRecoverRemovalCommand()
	command.SetArgs([]string{"--retain-ha-state"})
	command.SetOut(output)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if inspections != 1 || applications != 0 {
		t.Fatal("dry run changed state")
	}
	for _, expected := range []string{digest, "no other consumer or producer", "including TLS keys", "does not infer ownership", "--confirm-exclusive-ha-state"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatal("missing material consequence", expected)
		}
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--retain-ha-state", "--confirm-exclusive-ha-state", "--apply", "--plan-sha256", digest})
	command.SetOut(&bytes.Buffer{})
	if err := command.Execute(); err != nil || applications != 1 {
		t.Fatal("reviewed application was not delegated exactly once", err)
	}
}

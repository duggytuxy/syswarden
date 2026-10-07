package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"syscall"
	"syswarden-cli/pkg/system"
	"testing"
)

func TestRecoverRemovalOperatorConfigurationRequiresIndependentReviewedSelection(t *testing.T) {
	oldInspect, oldApply := inspectOperatorConfigurationRetention, applyOperatorConfigurationRetention
	t.Cleanup(func() {
		inspectOperatorConfigurationRetention, applyOperatorConfigurationRetention = oldInspect, oldApply
	})
	plan := system.OperatorConfigurationRetentionPlan{
		Schema: "SYSWARDEN_OPERATOR_CONFIGURATION_RETENTION_V1", Authority: "explicit-operator-retention-at-original-paths",
		Files: []system.LegacyLogRetentionFile{{Path: "/etc/syswarden/config/modules/75-custom.toml", Identity: system.LegacyLogRetentionIdentity{Inode: 1, Mode: syscall.S_IFREG | 0600}, SHA256: strings.Repeat("a", 64)}},
	}
	digest, err := system.OperatorConfigurationRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	inspections, applications := 0, 0
	inspectOperatorConfigurationRetention = func() (system.OperatorConfigurationRetentionPlan, error) {
		inspections++
		return plan, nil
	}
	applyOperatorConfigurationRetention = func(value string) (system.OperatorConfigurationRetentionPlan, string, error) {
		applications++
		if value != digest {
			return plan, "", fmt.Errorf("changed fixture decision")
		}
		return plan, "/var/backups/syswarden-retired-v1/operator-configuration/fixture.retention", nil
	}
	for _, extra := range [][]string{{"--apply"}, {"--plan-sha256", digest}, {"--retain-legacy-logs"}, {"--retire-legacy-fail2ban"}, {"--file-plan-sha256", digest}} {
		command := newRecoverRemovalCommand()
		command.SetArgs(append([]string{"--retain-operator-config"}, extra...))
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatal("incomplete or conflicting configuration approval reached recovery")
		}
	}
	if inspections != 0 || applications != 0 {
		t.Fatal("invalid recovery flags reached host operations")
	}
	output := &bytes.Buffer{}
	command := newRecoverRemovalCommand()
	command.SetArgs([]string{"--retain-operator-config"})
	command.SetOut(output)
	if err := command.Execute(); err != nil || inspections != 1 || applications != 0 || !strings.Contains(output.String(), digest) || !strings.Contains(output.String(), "no deletion authority") {
		t.Fatal("dry run did not disclose its bounded preservation effect", err, output.String())
	}
	command = newRecoverRemovalCommand()
	command.SetArgs([]string{"--retain-operator-config", "--apply", "--plan-sha256", digest})
	command.SetOut(&bytes.Buffer{})
	if err := command.Execute(); err != nil || applications != 1 {
		t.Fatal("exact reviewed configuration decision was not delegated once", err)
	}
}

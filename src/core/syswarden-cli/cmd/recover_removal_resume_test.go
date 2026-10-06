package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"syswarden-cli/pkg/firewall"
)

func TestRecoverRemovalUnusedResumeRequiresSeparateCurrentRuntimeReview(t *testing.T) {
	oldInspect, oldApply := inspectUnusedLegacyFail2banResume, applyUnusedLegacyFail2banResume
	t.Cleanup(func() { inspectUnusedLegacyFail2banResume, applyUnusedLegacyFail2banResume = oldInspect, oldApply })
	fileDigest, newDigest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	plan := firewall.LegacyFail2banRecoverySummary{FilePlanSHA256: fileDigest, PlanSHA256: newDigest, FileOnly: true, CurrentRuntimeReviewed: true}
	inspections, applications := 0, 0
	inspectUnusedLegacyFail2banResume = func(_ context.Context, file string) (firewall.LegacyFail2banRecoverySummary, error) {
		inspections++
		if file != fileDigest {
			return plan, errors.New("wrong original file plan")
		}
		return plan, nil
	}
	applyUnusedLegacyFail2banResume = func(_ context.Context, file, reviewed string, prepare func() error) (firewall.LegacyFail2banRecoverySummary, error) {
		applications++
		if file != fileDigest || reviewed != newDigest || prepare == nil {
			return plan, errors.New("wrong resumption authorization")
		}
		return plan, nil
	}
	for _, args := range [][]string{
		{"--resume-unused-fail2ban"},
		{"--resume-unused-fail2ban", "--retire-legacy-fail2ban", "--file-plan-sha256", fileDigest},
		{"--resume-unused-fail2ban", "--retain-legacy-logs", "--file-plan-sha256", fileDigest},
		{"--resume-unused-fail2ban", "--file-plan-sha256", fileDigest, "--apply"},
		{"--resume-unused-fail2ban", "--file-plan-sha256", fileDigest, "--plan-sha256", newDigest},
		{"--resume-unused-fail2ban", "--apply", "--plan-sha256", newDigest},
	} {
		command := newRecoverRemovalCommand()
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		command.SetArgs(args)
		if err := command.Execute(); err == nil {
			t.Fatal("incomplete or conflicting review was accepted", args)
		}
	}
	if inspections != 0 || applications != 0 {
		t.Fatal("invalid resumption flags reached the host adapters")
	}
	command := newRecoverRemovalCommand()
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetArgs([]string{"--resume-unused-fail2ban", "--file-plan-sha256", fileDigest})
	if err := command.Execute(); err != nil || inspections != 1 || applications != 0 {
		t.Fatal("separate current-state review failed or mutated the host", err)
	}
	for _, wanted := range []string{fileDigest, newDigest, "Original files and earlier runtime evidence remain unchanged", "not protection continuity", "shared Fail2ban service remains active"} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatal("resumption review omitted a material boundary", wanted)
		}
	}
	command = newRecoverRemovalCommand()
	command.SetOut(&bytes.Buffer{})
	command.SetArgs([]string{"--resume-unused-fail2ban", "--file-plan-sha256", fileDigest, "--apply", "--plan-sha256", newDigest})
	if err := command.Execute(); err != nil || applications != 1 {
		t.Fatal("reviewed resumption was not delegated exactly once", err)
	}
}

package cmd

import (
	"bytes"
	"errors"
	"strings"
	"syswarden-cli/pkg/network"
	"testing"
)

func TestOwnedWireGuardAssessmentCommandCannotAuthorizeMutation(t *testing.T) {
	previous := inspectOwnedWireGuardPolicy
	t.Cleanup(func() { inspectOwnedWireGuardPolicy = previous })
	calls := 0
	inspectOwnedWireGuardPolicy = func() (network.OwnedWireGuardPolicyAssessment, error) {
		calls++
		return network.OwnedWireGuardPolicyAssessment{
			Schema: "syswarden-owned-wireguard-policy-assessment-v1", ReadOnly: true, State: "v1-transition-required", Blockers: []string{"publication unavailable"},
		}, nil
	}
	var output bytes.Buffer
	command := newRecoverWireGuardCommand()
	command.SetOut(&output)
	command.SetArgs([]string{"--assess-owned-policy"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !strings.Contains(output.String(), "Read-only assessment.") || strings.Contains(output.String(), "--apply") || strings.Contains(output.String(), "Plan SHA-256:") {
		t.Fatal("assessment implies mutation authorization")
	}
	for _, args := range [][]string{
		{"--apply"}, {"--apply", "--plan-sha256", strings.Repeat("a", 64)}, {"--plan-sha256", strings.Repeat("a", 64)},
		{"--retire-legacy-wg0"}, {"--migrate-legacy-wg-syswarden"},
	} {
		command := newRecoverWireGuardCommand()
		command.SilenceErrors = true
		command.SilenceUsage = true
		command.SetArgs(append([]string{"--assess-owned-policy"}, args...))
		if err := command.Execute(); err == nil {
			t.Fatal("accepted assessment with mutation mode", args)
		}
		if calls != 1 {
			t.Fatal("conflicting mode inspected state before refusing")
		}
	}
	sentinel := errors.New("unsafe source")
	inspectOwnedWireGuardPolicy = func() (network.OwnedWireGuardPolicyAssessment, error) {
		return network.OwnedWireGuardPolicyAssessment{}, sentinel
	}
	command = newRecoverWireGuardCommand()
	command.SilenceErrors = true
	command.SilenceUsage = true
	command.SetArgs([]string{"--assess-owned-policy"})
	if err := command.Execute(); !errors.Is(err, sentinel) {
		t.Fatal("inspection failure was hidden", err)
	}
}

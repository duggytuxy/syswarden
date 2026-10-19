package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
)

func TestSSHPolicyPlanCommandIsReadOnly(t *testing.T) {
	for _, args := range [][]string{{"ssh-policy", "plan"}, {"ssh-policy", "plan", "--apply"}, {"ssh-policy", "apply"}, {"ssh-policy", "plan", "extra"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			command := newSSHPolicyCommand(func() (sshpolicy.PlanSummary, error) {
				calls++
				return sshpolicy.PlanSummary{Schema: 1, Operation: "publish"}, nil
			})
			root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
			root.AddCommand(command)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs(args)
			err := root.Execute()
			valid := len(args) == 2 && args[1] == "plan"
			if valid {
				if err != nil || calls != 1 || !strings.Contains(output.String(), `"apply_available": false`) {
					t.Fatalf("unexpected planning result: %v %s", err, output.String())
				}
			} else if err == nil || calls != 0 {
				t.Fatal("unsupported command ran inspection")
			}
		})
	}
}

func TestSSHPolicyPlanSkipsMutatingRootPreparation(t *testing.T) {
	command := newSSHPolicyCommand(nil)
	root := &cobra.Command{Use: "syswarden"}
	root.AddCommand(command)
	plan, _, err := root.Find([]string{"ssh-policy", "plan"})
	if err != nil {
		t.Fatal(err)
	}
	if commandRequiresAutomaticConfigLoad(plan) || commandRequiresEarlyFirewallRecovery(plan) || !commandAllowedDuringRemoval(plan) {
		t.Fatal("plan entered mutation preparation")
	}
	if err := enforceValidatedConfiguration(plan); err != nil {
		t.Fatal(err)
	}
	apply := &cobra.Command{Use: "apply"}
	command.AddCommand(apply)
	if commandAllowedDuringRemoval(apply) || readOnlySSHPolicyCommand(apply) {
		t.Fatal("future apply inherited read-only permission")
	}
}

func TestSSHPolicyPlanPropagatesRefusalWithoutPartialOutput(t *testing.T) {
	want := errors.New("fixture refused")
	command := newSSHPolicyCommand(func() (sshpolicy.PlanSummary, error) { return sshpolicy.PlanSummary{Operation: "publish"}, want })
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"plan"})
	command.SilenceErrors = true
	command.SilenceUsage = true
	if err := command.Execute(); !errors.Is(err, want) {
		t.Fatalf("lost refusal: %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("refusal returned a partial plan")
	}
}

package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"syswarden-cli/config"
	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
)

func TestSSHPolicyPortsCommandDoesNotLoadOrMutateConfiguration(t *testing.T) {
	for _, args := range [][]string{{"ports"}, {"ports", "--apply"}, {"ports", "extra"}, {"ports", "--port", "2222"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			previous := config.GlobalConfig
			config.GlobalConfig = &config.Config{SSHPort: "4400"}
			t.Cleanup(func() { config.GlobalConfig = previous })
			calls := 0
			command := newSSHPolicyCommand(nil, nil, func() (sshpolicy.PortSummary, error) {
				calls++
				return sshpolicy.PortSummary{Schema: 1, ParserVerified: true, ListenPorts: []uint16{2222}}, nil
			})
			root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
			root.AddCommand(command)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs(append([]string{"ssh-policy"}, args...))
			err := root.Execute()
			if len(args) != 1 {
				if err == nil || calls != 0 {
					t.Fatal("unsupported option reached port inspection")
				}
				return
			}
			if err != nil || calls != 1 || config.GlobalConfig.SSHPort != "4400" ||
				!strings.Contains(output.String(), `"runtime_verified": false`) || !strings.Contains(output.String(), `"hardening_applied": false`) {
				t.Fatalf("port observation failed or claimed mutation: %v %s", err, output.String())
			}
			ports, _, err := root.Find([]string{"ssh-policy", "ports"})
			if err != nil || commandRequiresAutomaticConfigLoad(ports) || commandRequiresEarlyFirewallRecovery(ports) || !commandAllowedDuringRemoval(ports) {
				t.Fatal("port observation entered mutating preparation")
			}
			if err := enforceValidatedConfiguration(ports); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSHPolicyPortsRefusalHasNoPartialJSON(t *testing.T) {
	want := errors.New("fixture parser refused")
	command := newSSHPolicyCommand(nil, nil, func() (sshpolicy.PortSummary, error) {
		return sshpolicy.PortSummary{ParserVerified: true, ListenPorts: []uint16{2222}}, want
	})
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"ports"})
	command.SilenceErrors, command.SilenceUsage = true, true
	if err := command.Execute(); !errors.Is(err, want) || output.Len() != 0 {
		t.Fatal("lost refusal or exposed a partial port result")
	}
}

func TestSSHPolicyPlanCommandIsReadOnly(t *testing.T) {
	for _, args := range [][]string{{"ssh-policy", "plan"}, {"ssh-policy", "plan", "--apply"}, {"ssh-policy", "apply"}, {"ssh-policy", "plan", "extra"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			command := newSSHPolicyCommand(func() (sshpolicy.PlanSummary, error) {
				calls++
				return sshpolicy.PlanSummary{Schema: 1, Operation: "publish"}, nil
			}, nil, nil)
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
	command := newSSHPolicyCommand(nil, nil, nil)
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
	command := newSSHPolicyCommand(func() (sshpolicy.PlanSummary, error) { return sshpolicy.PlanSummary{Operation: "publish"}, want }, nil, nil)
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

func TestSSHPolicyVerifyCommandBoundary(t *testing.T) {
	for _, args := range [][]string{{"verify"}, {"verify", "--apply"}, {"verify", "extra"}, {"verify", "--plan-sha256", strings.Repeat("a", 64)}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			command := newSSHPolicyCommand(nil, func() (sshpolicy.VerificationSummary, error) {
				calls++
				return sshpolicy.VerificationSummary{ParserVerified: true}, nil
			}, nil)
			root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
			root.AddCommand(command)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs(append([]string{"ssh-policy"}, args...))
			err := root.Execute()
			if len(args) != 1 {
				if err == nil || calls != 0 {
					t.Fatal("unsupported mutation option ran verification")
				}
				return
			}
			if err != nil || calls != 1 || !strings.Contains(output.String(), `"runtime_activated": false`) || !strings.Contains(output.String(), `"apply_available": false`) {
				t.Fatalf("verification claimed activation or failed: %v %s", err, output.String())
			}
			verify, _, err := root.Find([]string{"ssh-policy", "verify"})
			if err != nil || commandRequiresAutomaticConfigLoad(verify) || commandRequiresEarlyFirewallRecovery(verify) || !commandAllowedDuringRemoval(verify) {
				t.Fatal("verification entered mutating root preparation")
			}
			if err := enforceValidatedConfiguration(verify); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSHPolicyVerifyRefusalHasNoPartialJSON(t *testing.T) {
	want := errors.New("fixture parser refusal")
	command := newSSHPolicyCommand(nil, func() (sshpolicy.VerificationSummary, error) {
		return sshpolicy.VerificationSummary{ParserVerified: true}, want
	}, nil)
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"verify"})
	command.SilenceErrors, command.SilenceUsage = true, true
	if err := command.Execute(); !errors.Is(err, want) || output.Len() != 0 {
		t.Fatal("lost refusal or returned partial verification")
	}
}

func TestSSHPolicyOwnedVerificationBoundary(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, args := range [][]string{
		{"verify-owned", "--plan-sha256", digest},
		{"verify-owned"},
		{"verify-owned", "--plan-sha256", digest, "extra"},
		{"verify-owned", "--plan-sha256", digest, "--apply"},
		{"verify-owned", "--plan-sha256", digest, "--recover"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			previous := config.GlobalConfig
			config.GlobalConfig = &config.Config{SSHPort: "4400"}
			t.Cleanup(func() { config.GlobalConfig = previous })
			calls := 0
			command := newSSHPolicyCommand(nil, nil, nil)
			command.AddCommand(newSSHOwnedCommand(func(approved string) (sshpolicy.OwnedSummary, error) {
				calls++
				if approved != digest {
					t.Fatal("lost original plan identity")
				}
				return sshpolicy.OwnedSummary{Schema: 1, PlanSHA256: approved, OwnershipVerified: true}, nil
			}))
			root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
			root.AddCommand(command)
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs(append([]string{"ssh-policy"}, args...))
			err := root.Execute()
			if len(args) != 3 {
				if err == nil || calls != 0 {
					t.Fatal("unsupported input reached verification")
				}
				return
			}
			if err != nil || calls != 1 || config.GlobalConfig.SSHPort != "4400" ||
				!strings.Contains(output.String(), `"runtime_activated": false`) ||
				!strings.Contains(output.String(), `"access_verified": false`) {
				t.Fatal("verification failed or claimed runtime acceptance", err, output.String())
			}
			owned, _, err := root.Find([]string{"ssh-policy", "verify-owned"})
			if err != nil || commandRequiresAutomaticConfigLoad(owned) || commandRequiresEarlyFirewallRecovery(owned) ||
				!commandAllowedDuringRemoval(owned) || enforceValidatedConfiguration(owned) != nil {
				t.Fatal("owned verification entered mutating preparation")
			}
		})
	}
}

func TestSSHPolicyOwnedRefusalHasNoPartialJSON(t *testing.T) {
	want := errors.New("fixture owned verification refused")
	command := newSSHOwnedCommand(func(string) (sshpolicy.OwnedSummary, error) {
		return sshpolicy.OwnedSummary{OwnershipVerified: true}, want
	})
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"--plan-sha256", strings.Repeat("a", 64)})
	command.SilenceErrors, command.SilenceUsage = true, true
	if err := command.Execute(); !errors.Is(err, want) || output.Len() != 0 {
		t.Fatal("lost refusal or returned partial owned verification")
	}
}

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/sshpolicy"
	"testing"

	"github.com/spf13/cobra"
)

func TestSSHRestorationAssessmentCommandBoundary(t *testing.T) {
	for _, mode := range []string{"observe", "missing-plan", "missing-recovery", "bad-plan", "bad-recovery", "extra", "apply", "config", "error", "output-error"} {
		t.Run(mode, func(t *testing.T) {
			original, recovery := strings.Repeat("a", 64), strings.Repeat("b", 64)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			want := errors.New("fixture assessment failure")
			command := newSSHRestorationAssessmentCommand(func(got context.Context, plan, approved string) (sshpolicy.RecoveryAssessment, error) {
				calls++
				if got != ctx || plan != original || approved != recovery {
					t.Fatal("assessment lost context or digests")
				}
				summary := sshpolicy.RecoveryAssessment{Schema: 1, RecoveryRequired: true, ConfigurationRestored: true}
				if mode == "error" {
					return summary, want
				}
				return summary, nil
			})
			root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
			root.PersistentFlags().String("config", "default", "fixture configuration")
			parent := newSSHPolicyCommand(nil, nil, nil)
			parent.AddCommand(command)
			root.AddCommand(parent)
			args := []string{"ssh-policy", "assess-restoration", "--plan-sha256", original, "--recovery-sha256", recovery}
			switch mode {
			case "missing-plan":
				args = append(args[:2], args[4:]...)
			case "missing-recovery":
				args = args[:4]
			case "bad-plan":
				args[3] = strings.ToUpper(original)
			case "bad-recovery":
				args[5] = strings.ToUpper(recovery)
			case "extra":
				args = append(args, "extra")
			case "apply":
				args = append(args, "--apply")
			case "config":
				args = append(args, "--config", "unused")
			}
			var output bytes.Buffer
			root.SetOut(&output)
			if mode == "output-error" {
				root.SetOut(sshRecoveryFailWriter{})
			}
			root.SetArgs(args)
			err := root.ExecuteContext(ctx)
			invoked := mode == "observe" || mode == "error" || mode == "output-error"
			if (err == nil) != (mode == "observe") || (calls == 1) != invoked {
				t.Fatal("incorrect assessment outcome", calls, err)
			}
			if err != nil && output.Len() != 0 {
				t.Fatal("error exposed partial result")
			}
			if mode == "error" && !errors.Is(err, want) {
				t.Fatal("lost error identity")
			}
			if mode == "observe" {
				for _, field := range []string{`"recovery_required": true`, `"runtime_activated": false`, `"access_verified": false`} {
					if !strings.Contains(output.String(), field) {
						t.Fatal("missing uncertainty", field)
					}
				}
			}
		})
	}
}

func TestSSHRestorationAssessmentBypassesMutationPreparation(t *testing.T) {
	oldInit, oldFirewall, oldRemoval, oldConfig := initConfigHook, recoverPendingFirewallTransactionHook, inspectRemovalTombstone, config.GlobalConfig
	valid := filepath.Join(t.TempDir(), "valid.conf")
	if err := os.WriteFile(valid, []byte("SYSWARDEN_HA_ENABLED=n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		initConfigHook, recoverPendingFirewallTransactionHook, inspectRemovalTombstone = oldInit, oldFirewall, oldRemoval
		_ = config.ParseConfig(valid)
		config.GlobalConfig = oldConfig
	})
	if err := config.ParseConfig(filepath.Join(t.TempDir(), "missing.conf")); err == nil || !config.CurrentLoadState().Degraded {
		t.Fatal("missing degraded fixture")
	}
	config.GlobalConfig = &config.Config{SSHPort: "4400"}
	initConfigHook = func() { t.Fatal("assessment loaded global configuration") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("assessment recovered firewall"); return nil }
	inspectRemovalTombstone = func() (bool, error) {
		t.Fatal("read-only assessment inspected mutation barrier")
		return true, errors.New("unsafe fixture")
	}
	calls := 0
	command := newSSHRestorationAssessmentCommand(func(context.Context, string, string) (sshpolicy.RecoveryAssessment, error) {
		calls++
		return sshpolicy.RecoveryAssessment{RecoveryRequired: true}, nil
	})
	root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true, PersistentPreRunE: rootCmd.PersistentPreRunE}
	parent := newSSHPolicyCommand(nil, nil, nil)
	parent.AddCommand(command)
	root.AddCommand(parent)
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"ssh-policy", "assess-restoration", "--plan-sha256", strings.Repeat("a", 64), "--recovery-sha256", strings.Repeat("b", 64)})
	if err := root.Execute(); err != nil || calls != 1 || config.GlobalConfig.SSHPort != "4400" || !config.CurrentLoadState().Degraded {
		t.Fatal("assessment entered automatic preparation", calls, err)
	}
	if !commandAllowedDuringRemoval(command) || commandRequiresAutomaticConfigLoad(command) || commandRequiresEarlyFirewallRecovery(command) || enforceValidatedConfiguration(command) != nil {
		t.Fatal("assessment acquired mutation preparation")
	}
}

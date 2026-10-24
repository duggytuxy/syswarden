package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/sshpolicy"
	"testing"

	"github.com/spf13/cobra"
)

func TestSSHRestoreOriginalArgumentsAndOutcome(t *testing.T) {
	original, recovery := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, mode := range []string{"inspect", "apply", "missing-original", "bad-original", "extra", "apply-no-approval", "bad-recovery", "approval-no-apply", "config", "unknown", "inspect-error", "apply-error", "write-error", "apply-write-error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			want := errors.New("fixture error")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			apply := mode == "apply" || mode == "apply-error" || mode == "apply-write-error"
			invoke := func(got context.Context, plan, approved string) (sshpolicy.RuntimeRecoverySummary, error) {
				calls++
				if got != ctx || plan != original || (approved != "") != apply || (apply && approved != recovery) {
					t.Fatal("command lost exact inputs or caller context")
				}
				summary := sshpolicy.RuntimeRecoverySummary{Schema: 1, Operation: "restore-original", RecoveryRequired: true,
					ConfigurationRestored: apply, RequestReturned: apply}
				if strings.HasSuffix(mode, "error") && !strings.HasSuffix(mode, "write-error") {
					return summary, want
				}
				return summary, nil
			}
			command := newSSHRestoreOriginalCommand(func(ctx context.Context, plan string) (sshpolicy.RuntimeRecoverySummary, error) {
				return invoke(ctx, plan, "")
			}, invoke)
			root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true}
			root.PersistentFlags().String("config", "default", "fixture config")
			parent := newSSHPolicyCommand(nil, nil, nil)
			parent.AddCommand(command)
			root.AddCommand(parent)
			args := []string{"ssh-policy", "restore-original", "--plan-sha256", original}
			switch mode {
			case "apply", "apply-error", "apply-write-error":
				args = append(args, "--apply", "--recovery-sha256", recovery)
			case "missing-original":
				args = args[:2]
			case "bad-original":
				args[3] = strings.ToUpper(original)
			case "extra":
				args = append(args, "extra")
			case "apply-no-approval":
				args = append(args, "--apply")
			case "bad-recovery":
				args = append(args, "--apply", "--recovery-sha256", strings.ToUpper(recovery))
			case "approval-no-apply":
				args = append(args, "--recovery-sha256", recovery)
			case "config":
				args = append(args, "--config", "unused")
			case "unknown":
				args = append(args, "--force")
			}
			var output bytes.Buffer
			root.SetOut(&output)
			if strings.HasSuffix(mode, "write-error") {
				root.SetOut(sshRecoveryFailWriter{})
			}
			root.SetArgs(args)
			err := root.ExecuteContext(ctx)
			valid := mode == "inspect" || mode == "apply" || mode == "inspect-error" || mode == "apply-error" || mode == "write-error" || mode == "apply-write-error"
			if (calls == 1) != valid || (err == nil) != (mode == "inspect" || mode == "apply") {
				t.Fatal("command boundary failed", calls, err)
			}
			if err == nil {
				for _, field := range []string{`"recovery_required": true`, `"runtime_activated": false`, `"access_verified": false`} {
					if !strings.Contains(output.String(), field) {
						t.Fatal("missing uncertainty field", field, output.String())
					}
				}
			} else if output.Len() != 0 {
				t.Fatal("refusal emitted success JSON", output.String())
			}
			if mode == "apply-write-error" && !strings.Contains(err.Error(), "configuration_restored=true, request_returned=true, recovery_required=true") {
				t.Fatal("output failure discarded partial restoration facts", err)
			}
			if mode == "apply-error" && (!errors.Is(err, want) || !strings.Contains(err.Error(), "configuration_restored=true, request_returned=true, recovery_required=true")) {
				t.Fatal("lost partial failure facts", err)
			}
		})
	}
}

type sshRecoveryFailWriter struct{}

func (sshRecoveryFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture output failure")
}

func TestSSHRestoreOriginalRootPreparationIsolation(t *testing.T) {
	oldInit, oldFirewall, oldRemoval := initConfigHook, recoverPendingFirewallTransactionHook, inspectRemovalTombstone
	oldConfig := config.GlobalConfig
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
		t.Fatal("fixture did not establish degraded configuration", err)
	}
	config.GlobalConfig = &config.Config{SSHPort: "4400"}
	initConfigHook = func() { t.Fatal("recovery loaded or normalized global configuration") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("recovery entered firewall repair"); return nil }
	for _, apply := range []bool{false, true} {
		for _, removal := range []string{"absent", "present", "unreadable"} {
			t.Run(fmt.Sprintf("apply-%v-removal-%s", apply, removal), func(t *testing.T) {
				inspectRemovalTombstone = func() (bool, error) {
					if removal == "unreadable" {
						return false, errors.New("fixture removal state unavailable")
					}
					return removal == "present", nil
				}
				calls := 0
				invoke := func(context.Context, string, string) (sshpolicy.RuntimeRecoverySummary, error) {
					calls++
					return sshpolicy.RuntimeRecoverySummary{RecoveryRequired: true}, nil
				}
				root := &cobra.Command{Use: "syswarden", SilenceErrors: true, SilenceUsage: true, PersistentPreRunE: rootCmd.PersistentPreRunE}
				parent := newSSHPolicyCommand(nil, nil, nil)
				command := newSSHRestoreOriginalCommand(func(ctx context.Context, plan string) (sshpolicy.RuntimeRecoverySummary, error) {
					return invoke(ctx, plan, "")
				}, invoke)
				parent.AddCommand(command)
				root.AddCommand(parent)
				var output bytes.Buffer
				root.SetOut(&output)
				args := []string{"ssh-policy", "restore-original", "--plan-sha256", strings.Repeat("a", 64)}
				if apply {
					args = append(args, "--apply", "--recovery-sha256", strings.Repeat("b", 64))
				}
				root.SetArgs(args)
				err := root.Execute()
				allowed := !apply || removal == "absent"
				if (err == nil) != allowed || (calls == 1) != allowed || config.GlobalConfig.SSHPort != "4400" || !config.CurrentLoadState().Degraded {
					t.Fatal("removal or input isolation failed", calls, err)
				}
				if commandRequiresAutomaticConfigLoad(command) || commandRequiresEarlyFirewallRecovery(command) ||
					enforceValidatedConfiguration(command) != nil || commandAllowedDuringRemoval(command) != !apply {
					t.Fatal("input isolation conferred incorrect mutation authority")
				}
			})
		}
	}
}

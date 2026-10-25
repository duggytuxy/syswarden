package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

type recoveryReviewFixture struct {
	review config.ModuleEditRecoveryReview
	calls  int
}

func (f *recoveryReviewFixture) Review() config.ModuleEditRecoveryReview { return f.review }
func (f *recoveryReviewFixture) Apply(_ context.Context, id string, preflight func() error) error {
	f.calls++
	if id != f.review.ApprovalID {
		return errors.New("wrong approval passed to recovery API")
	}
	return preflight()
}

func TestConfigEditRecoveryReviewRequiresExactPhraseAndLifecycleBarrier(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, choice := range []string{"approve", "cancel", "wrong", "eof", "blocked"} {
		t.Run(choice, func(t *testing.T) {
			preserveConfigMenuPreflightHooks(t)
			preflightWireGuardPolicyTransition = func() error { return nil }
			inspectRemovalTombstone = func() (bool, error) { return false, nil }
			refusePendingFirewallTransactionHook = func() error { return nil }
			fixture := &recoveryReviewFixture{review: config.ModuleEditRecoveryReview{Target: "modules/99-user.toml", State: "published_pending", Action: "restore_original_file", InputsChanged: true, ApprovalID: id, ExpiresAt: time.Now().Add(time.Minute)}}
			input := "recover " + id + "\n"
			switch choice {
			case "cancel":
				input = "\n"
			case "wrong":
				input = "yes\n"
			case "eof":
				input = ""
			case "blocked":
				refusePendingFirewallTransactionHook = func() error { return errors.New("pending firewall recovery") }
			}
			parent := &cobra.Command{Use: "syswarden"}
			group := &cobra.Command{Use: "config"}
			command := &cobra.Command{Use: "recover-edit"}
			parent.AddCommand(group)
			group.AddCommand(command)
			var output bytes.Buffer
			command.SetContext(context.Background())
			command.SetIn(strings.NewReader(input))
			command.SetOut(&output)
			err := reviewModuleEditRecovery(command, fixture)
			wantCall := choice == "approve" || choice == "blocked"
			if (fixture.calls == 1) != wantCall {
				t.Fatal("recovery invocation did not follow exact approval")
			}
			if (err != nil) != (choice == "eof" || choice == "blocked") {
				t.Fatalf("unexpected review result: %v", err)
			}
			if !strings.Contains(output.String(), "restore the recorded original") || !strings.Contains(output.String(), "current reviewed state will be preserved") {
				t.Fatal("review omitted recovery effects")
			}
			if choice != "approve" && strings.Contains(output.String(), "recovery completed") {
				t.Fatal("unapplied recovery reported completion")
			}
		})
	}
}

func TestConfigEditRecoveryCobraPreflightAndAbsentStateAreReadOnly(t *testing.T) {
	preserveConfigMenuPreflightHooks(t)
	root := filepath.Join(t.TempDir(), "config")
	if err := config.InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	configEditorRoot = root
	before := snapshotRegularFiles(t, root)
	global, load := config.GlobalConfig, config.CurrentLoadState()
	var calls []string
	preflightWireGuardPolicyTransition = func() error { calls = append(calls, "wireguard"); return nil }
	inspectRemovalTombstone = func() (bool, error) { calls = append(calls, "removal"); return false, nil }
	refusePendingFirewallTransactionHook = func() error { calls = append(calls, "firewall"); return nil }
	output, err := executeRootCobraLifecycle(t, []string{"config", "recover-edit"}, initConfigHook)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "No pending TOML") || !reflect.DeepEqual(calls, []string{"wireguard", "firewall"}) {
		t.Fatalf("unexpected read-only preflight: %s %v", output, calls)
	}
	if !reflect.DeepEqual(before, snapshotRegularFiles(t, root)) || config.GlobalConfig != global || !reflect.DeepEqual(config.CurrentLoadState(), load) {
		t.Fatal("recovery inspection changed files or runtime")
	}
}

func TestConfigEditRecoveryRefusesPendingRemovalBeforeObservation(t *testing.T) {
	preserveConfigMenuPreflightHooks(t)
	preflightWireGuardPolicyTransition = func() error { return nil }
	inspectRemovalTombstone = func() (bool, error) { return true, nil }
	refusePendingFirewallTransactionHook = func() error { t.Fatal("removal-blocked recovery reached later preflight"); return nil }
	if err := rootCmd.PersistentPreRunE(configEditRecoveryCmd, nil); err == nil || !strings.Contains(err.Error(), "removal is incomplete") {
		t.Fatalf("recovery bypassed removal barrier: %v", err)
	}
}

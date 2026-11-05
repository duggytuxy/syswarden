package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func setAPKReviewSelectors(t *testing.T, values map[string]string) {
	t.Helper()
	for _, name := range []string{"review-apk-plan", "qualification-bundle", "candidate-version"} {
		flag := updateCmd.Flags().Lookup(name)
		previous, changed := flag.Value.String(), flag.Changed
		value, selected := values[name]
		if err := flag.Value.Set(value); err != nil {
			t.Fatal(err)
		}
		flag.Changed = selected
		t.Cleanup(func() {
			_ = flag.Value.Set(previous)
			flag.Changed = changed
		})
	}
}

func TestAPKReviewCommandRoutesOnlyExactStoredPlanAndNeverReportsUpdateSuccess(t *testing.T) {
	for _, outcome := range []string{"refused", "unexpected-nil"} {
		t.Run(outcome, func(t *testing.T) {
			digest := strings.Repeat("1a", 32)
			setAPKReviewSelectors(t, map[string]string{"review-apk-plan": digest})
			originalOnline, originalOffline, originalReview := runSystemUpgrade, runQualificationBundleUpgrade, reviewStoredAPKPreparation
			previousOutput := updateCmd.OutOrStdout()
			var output bytes.Buffer
			updateCmd.SetOut(&output)
			calls, reviews := 0, 0
			runSystemUpgrade = func() error { calls++; return nil }
			runQualificationBundleUpgrade = func(string, string) error { calls++; return nil }
			refusal := errors.New("stored preparation verified; native execution unavailable")
			reviewStoredAPKPreparation = func(selected string) error {
				reviews++
				if selected != digest {
					t.Fatalf("selected plan = %q", selected)
				}
				if outcome == "refused" {
					return refusal
				}
				return nil
			}
			t.Cleanup(func() {
				runSystemUpgrade, runQualificationBundleUpgrade, reviewStoredAPKPreparation = originalOnline, originalOffline, originalReview
				updateCmd.SetOut(previousOutput)
			})
			if err := updateCmd.Args(updateCmd, nil); err != nil {
				t.Fatal(err)
			}
			err := updateCmd.RunE(updateCmd, nil)
			if err == nil || outcome == "refused" && !errors.Is(err, refusal) || calls != 0 || reviews != 1 {
				t.Fatalf("review error=%v online/offline=%d reviews=%d", err, calls, reviews)
			}
			if !strings.Contains(output.String(), "Native execution is unavailable") || !strings.Contains(output.String(), "does not authorize package effects") || strings.Contains(output.String(), "[SUCCESS]") {
				t.Fatalf("misleading review output: %q", output.String())
			}
		})
	}
}

func TestAPKReviewCommandRejectsMalformedOrConflictingSelectorsBeforeDispatch(t *testing.T) {
	digest := strings.Repeat("a", 64)
	cases := []struct {
		name   string
		values map[string]string
	}{
		{"empty", map[string]string{"review-apk-plan": ""}},
		{"short", map[string]string{"review-apk-plan": "abcd"}},
		{"uppercase", map[string]string{"review-apk-plan": strings.Repeat("A", 64)}},
		{"nonhex", map[string]string{"review-apk-plan": strings.Repeat("g", 64)}},
		{"whitespace", map[string]string{"review-apk-plan": digest + "\n"}},
		{"path", map[string]string{"review-apk-plan": "/tmp/" + digest}},
		{"bundle", map[string]string{"review-apk-plan": digest, "qualification-bundle": "/root/bundle"}},
		{"candidate", map[string]string{"review-apk-plan": digest, "candidate-version": "v5.00.0"}},
		{"empty-bundle", map[string]string{"review-apk-plan": digest, "qualification-bundle": ""}},
		{"empty-candidate", map[string]string{"review-apk-plan": digest, "candidate-version": ""}},
		{"offline-pair", map[string]string{"review-apk-plan": digest, "qualification-bundle": "/root/bundle", "candidate-version": "v5.00.0"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			setAPKReviewSelectors(t, test.values)
			originalOnline, originalOffline, originalReview := runSystemUpgrade, runQualificationBundleUpgrade, reviewStoredAPKPreparation
			calls := 0
			runSystemUpgrade = func() error { calls++; return nil }
			runQualificationBundleUpgrade = func(string, string) error { calls++; return nil }
			reviewStoredAPKPreparation = func(string) error { calls++; return nil }
			t.Cleanup(func() {
				runSystemUpgrade, runQualificationBundleUpgrade, reviewStoredAPKPreparation = originalOnline, originalOffline, originalReview
			})
			if err := updateCmd.Args(updateCmd, nil); err == nil {
				t.Fatal("invalid selectors passed command argument validation")
			}
			if _, err := qualificationUpdateSelection(updateCmd); err == nil {
				t.Fatal("invalid selectors passed root selection validation")
			}
			if err := updateCmd.RunE(updateCmd, nil); err == nil || calls != 0 {
				t.Fatalf("invalid selectors error=%v calls=%d", err, calls)
			}
		})
	}
}

func TestAPKReviewPreflightPreservesReadOnlyLifecycleGuards(t *testing.T) {
	setAPKReviewSelectors(t, map[string]string{"review-apk-plan": strings.Repeat("a", 64)})
	originalRecovery, originalInit := recoverPendingFirewallTransactionHook, initConfigHook
	originalRemoval, originalWireGuard := inspectRemovalTombstone, preflightWireGuardPolicyTransition
	mutations, removals, transitions := 0, 0, 0
	recoverPendingFirewallTransactionHook = func() error { mutations++; return nil }
	initConfigHook = func() { mutations++ }
	inspectRemovalTombstone = func() (bool, error) { removals++; return false, nil }
	preflightWireGuardPolicyTransition = func() error { transitions++; return nil }
	t.Cleanup(func() {
		recoverPendingFirewallTransactionHook, initConfigHook = originalRecovery, originalInit
		inspectRemovalTombstone, preflightWireGuardPolicyTransition = originalRemoval, originalWireGuard
	})
	if err := rootCmd.PersistentPreRunE(updateCmd, nil); err != nil {
		t.Fatal(err)
	}
	if mutations != 0 || removals != 1 || transitions != 1 {
		t.Fatalf("mutations=%d removal guards=%d transition guards=%d", mutations, removals, transitions)
	}
	inspectRemovalTombstone = func() (bool, error) { return true, nil }
	if err := rootCmd.PersistentPreRunE(updateCmd, nil); err == nil {
		t.Fatal("stored-plan review bypassed removal refusal")
	}
}

func TestAPKReviewCommandCancellationPrecedesReviewRecord(t *testing.T) {
	setAPKReviewSelectors(t, map[string]string{"review-apk-plan": strings.Repeat("a", 64)})
	previousContext, originalReview := updateCmd.Context(), reviewStoredAPKPreparation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	updateCmd.SetContext(ctx)
	calls := 0
	reviewStoredAPKPreparation = func(string) error { calls++; return nil }
	t.Cleanup(func() {
		updateCmd.SetContext(previousContext)
		reviewStoredAPKPreparation = originalReview
	})
	if err := updateCmd.RunE(updateCmd, nil); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("canceled review error=%v calls=%d", err, calls)
	}
}

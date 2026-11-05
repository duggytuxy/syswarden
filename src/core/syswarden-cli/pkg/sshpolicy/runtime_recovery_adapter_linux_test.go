//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSSHRecoveryAdapterOwnsResourcesAndPreservesPartialFacts(t *testing.T) {
	for _, scenario := range []string{"inspect", "apply", "inspect-close-error", "apply-close-error", "request-error", "open-error", "missing-close", "nil-session"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := runtimeRecoveryFixture(t, false, false)
			calls, leaseCloses, sessionCloses, opens := 0, 0, 0, 0
			bind := runtimeRecoveryBinder(t, journal, &calls, &leaseCloses)
			digest := runtimeRecoveryPlan(t, journal, plan, deps, bind)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := errors.New("fixture recovery failure")
			apply := scenario != "inspect" && scenario != "inspect-close-error"
			if !apply {
				digest = ""
			}
			open := func(got context.Context) (*sshRecoverySession, error) {
				opens++
				if got != ctx {
					t.Fatal("adapter replaced caller cancellation")
				}
				s := &sshRecoverySession{journal, deps.parserDigest, deps.run, deps.checkParser, bind,
					func() error {
						sessionCloses++
						err := journal.Close()
						if strings.HasSuffix(scenario, "close-error") {
							err = errors.Join(err, want)
						}
						return err
					}}
				switch scenario {
				case "open-error":
					return s, want
				case "missing-close":
					s.close = nil
				case "nil-session":
					return nil, nil
				case "request-error":
					s.bind = func(ctx context.Context, guard func() error, anchor *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
						l, err := bind(ctx, guard, anchor)
						if err == nil {
							previous := l.(*activationTestLease).requestFn
							l.(*activationTestLease).requestFn = func(ctx context.Context, guard func() error) error {
								return errors.Join(previous(ctx, guard), want)
							}
						}
						return l, err
					}
				}
				return s, nil
			}
			got, err := runSSHRecoverySession(ctx, plan.summary.PlanSHA256, digest, apply, open)
			if (err == nil) != (scenario == "inspect" || scenario == "apply") || opens != 1 {
				t.Fatal("incorrect adapter outcome", got, err, opens)
			}
			wantClose := 1
			if scenario == "missing-close" || scenario == "nil-session" {
				wantClose = 0
			}
			if sessionCloses != wantClose {
				t.Fatal("lost session ownership", sessionCloses)
			}
			partial := scenario == "apply" || scenario == "apply-close-error" || scenario == "request-error"
			if scenario == "inspect" || partial {
				if got.Schema != 1 || got.Operation != "restore-original" || !got.RecoveryRequired || got.RuntimeActivated || got.AccessVerified {
					t.Fatal("adapter invented acceptance", got)
				}
				if partial && (!got.ConfigurationRestored || !got.IntentDurable || calls != 1 ||
					got.RequestReturned != (scenario != "request-error")) {
					t.Fatal("adapter discarded partial recovery facts", got, calls)
				}
				wire, err := json.Marshal(got)
				if err != nil || strings.Contains(string(wire), "AllowTcpForwarding") || strings.Contains(string(wire), "192.0.2.") {
					t.Fatal("public result disclosed private configuration", err)
				}
			} else if !reflect.DeepEqual(got, RuntimeRecoverySummary{}) || calls != 0 {
				t.Fatal("pre-operation refusal returned facts", got, calls)
			}
			if scenario == "inspect" && (calls != 0 || got.IntentDurable || got.ConfigurationRestored || got.RequestReturned) {
				t.Fatal("inspection mutated state", got)
			}
			if wantClose == 1 {
				reopened := fixtureJournal(t, f)
				if err := reopened.Close(); err != nil {
					t.Fatal("adapter retained journal lock", err)
				}
			}
		})
	}
}

func TestSSHRecoveryAdapterRejectsBeforeOpening(t *testing.T) {
	good := strings.Repeat("a", 64)
	for _, scenario := range []string{"nil-context", "cancelled", "original-empty", "original-uppercase", "recovery-empty", "recovery-uppercase", "inspect-with-approval", "nil-opener"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var input context.Context = ctx
			original, recovery, apply := good, good, true
			open := func(context.Context) (*sshRecoverySession, error) {
				t.Fatal("invalid request opened resources")
				return nil, nil
			}
			switch scenario {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "original-empty":
				original = ""
			case "original-uppercase":
				original = strings.ToUpper(original)
			case "recovery-empty":
				recovery = ""
			case "recovery-uppercase":
				recovery = strings.ToUpper(recovery)
			case "inspect-with-approval":
				apply = false
			case "nil-opener":
				open = nil
			}
			got, err := runSSHRecoverySession(input, original, recovery, apply, open)
			if err == nil || got != (RuntimeRecoverySummary{}) {
				t.Fatal("invalid request accepted", got, err)
			}
		})
	}
	if got, err := RestoreOriginalSystemd(t.Context(), good, ""); err == nil || got != (RuntimeRecoverySummary{}) {
		t.Fatal("application silently inspected without recovery approval", got, err)
	}
	if os.Geteuid() != 0 {
		if _, err := InspectSystemdRecovery(t.Context(), good); err == nil {
			t.Fatal("non-root inspection accepted")
		}
		if _, err := RestoreOriginalSystemd(t.Context(), good, good); err == nil {
			t.Fatal("non-root restoration accepted")
		}
	}
}

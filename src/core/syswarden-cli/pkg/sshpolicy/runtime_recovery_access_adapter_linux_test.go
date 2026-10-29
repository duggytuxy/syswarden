//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSSHRestoredAccessAdaptersRefuseUnapprovedRecoveryBeforeOpen(t *testing.T) {
	good := strings.Repeat("a", 64)
	open := func(context.Context, string, string, string) (*sshAccessSession, error) {
		t.Fatal("invalid approval opened target resources")
		return nil, nil
	}
	for _, scenario := range []string{"nil-context", "cancelled", "empty-plan", "empty-recovery", "uppercase-recovery", "empty-enrollment"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var input context.Context = ctx
			plan, recovery, enrollment := good, good, good
			switch scenario {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "empty-plan":
				plan = ""
			case "empty-recovery":
				recovery = ""
			case "uppercase-recovery":
				recovery = strings.ToUpper(good)
			case "empty-enrollment":
				enrollment = ""
			}
			if _, err := prepareSystemdRestoredAccessRequest(input, plan, recovery, enrollment, open); err == nil {
				t.Fatal("invalid restored request")
			}
			if _, err := issueSystemdRestoredAccessChallenge(input, plan, recovery, enrollment, good, time.Minute, open); err == nil {
				t.Fatal("invalid restored issuance")
			}
			if _, err := recordSystemdRestoredAccessReceipt(input, plan, recovery, enrollment, good, good, []byte("untrusted"), open); err == nil {
				t.Fatal("invalid restored receipt")
			}
			if _, err := inspectSystemdRestoredAccess(input, plan, recovery, enrollment, good, good, "", open); err == nil {
				t.Fatal("invalid restored inspection")
			}
		})
	}
	for _, lifetime := range []time.Duration{0, -time.Second, time.Nanosecond, 301 * time.Second} {
		if _, err := issueSystemdRestoredAccessChallenge(t.Context(), good, good, good, good, lifetime, open); err == nil {
			t.Fatal("invalid lifetime")
		}
	}
	for _, bad := range []string{"", strings.ToUpper(good)} {
		if _, err := recordSystemdRestoredAccessReceipt(t.Context(), good, good, good, good, bad, []byte("untrusted"), open); err == nil {
			t.Fatal("invalid original issuance image")
		}
		if _, err := inspectSystemdRestoredAccess(t.Context(), good, good, good, good, bad, "", open); err == nil {
			t.Fatal("invalid inspected original issuance image")
		}
	}
}

func TestSSHRestoredAccessAdaptersSuppressDeliveryAfterCloseFailure(t *testing.T) {
	for _, operation := range []string{"prepare", "issue", "record", "inspect"} {
		for _, failure := range []string{"error", "cancel"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				x := restoredAccessFixture(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var issued sshAccessIssuanceResult
				var receipt []byte
				if operation == "record" || operation == "inspect" {
					var err error
					issued, err = x.issue(ctx, digestBytes(x.request))
					if err != nil {
						t.Fatal(err)
					}
					if operation == "record" {
						receipt = x.receipt(t, issued)
					}
					x.reopen(t)
				}
				closes := 0
				open := func(_ context.Context, plan, recovery, enrollment string) (*sshAccessSession, error) {
					if plan != x.plan.summary.PlanSHA256 || recovery != x.recovery || enrollment != x.authority.digest {
						t.Fatal("adapter lost independent approvals")
					}
					return issuanceSession(x.sshIssuanceFixture, func() error {
						closes++
						err := x.journal.Close()
						if failure == "cancel" {
							cancel()
							return err
						}
						return errors.Join(err, errors.New("fixture close refused"))
					}), nil
				}
				switch operation {
				case "prepare":
					got, err := prepareSystemdRestoredAccessRequest(ctx, x.plan.summary.PlanSHA256, x.recovery, x.authority.digest, open)
					if err == nil || !reflect.DeepEqual(got, AccessRequestPreview{}) {
						t.Fatal("failed preview exposed bytes", got, err)
					}
				case "issue":
					got, err := issueSystemdRestoredAccessChallenge(ctx, x.plan.summary.PlanSHA256, x.recovery, x.authority.digest, digestBytes(x.request), time.Minute, open)
					if err == nil || !got.IssuanceDurable || !got.RecoveryRequired || len(got.Request) != 0 || len(got.Challenge) != 0 {
						t.Fatal("close failure lost write facts or delivered challenge", got, err)
					}
				case "record":
					got, err := recordSystemdRestoredAccessReceipt(ctx, x.plan.summary.PlanSHA256, x.recovery, x.authority.digest, issued.IssuanceSHA256, issued.IssuanceImageSHA256, receipt, open)
					if err == nil || !got.RecordDurable || !got.RecoveryRequired {
						t.Fatal("close failure lost recorded facts", got, err)
					}
				case "inspect":
					got, err := inspectSystemdRestoredAccess(ctx, x.plan.summary.PlanSHA256, x.recovery, x.authority.digest, issued.IssuanceSHA256, issued.IssuanceImageSHA256, "", open)
					if err == nil || !reflect.DeepEqual(got, RestoredAccessInspection{}) {
						t.Fatal("failed inspection returned claims", got, err)
					}
				}
				if closes != 1 {
					t.Fatal("adapter did not close exactly once", closes)
				}
			})
		}
	}
}

//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func issuanceSession(x *sshIssuanceFixture, close func() error) *sshAccessSession {
	return &sshAccessSession{x.journal, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority, func() time.Time { return x.now }, close}
}

func TestSSHAccessAdapterResourceAndDeliveryBoundaries(t *testing.T) {
	for _, op := range []string{"preview", "issue", "record"} {
		for _, failure := range []string{"none", "open", "close", "authority", "nil-session", "missing-close"} {
			t.Run(op+"/"+failure, func(t *testing.T) {
				x := accessIssuanceFixture(t)
				var issued sshAccessIssuanceResult
				var receipt []byte
				if op == "record" {
					var err error
					issued, err = x.issue(t.Context(), digestBytes(x.request))
					if err != nil {
						t.Fatal(err)
					}
					receipt = x.receipt(t, issued)
					x.reopen(t)
				}
				opens, closes := 0, 0
				want := errors.New("isolated adapter failure")
				open := func(ctx context.Context, plan, enrollment string) (*sshAccessSession, error) {
					opens++
					if ctx != t.Context() || plan != x.plan.summary.PlanSHA256 || enrollment != x.authority.digest {
						t.Fatal("lost independently approved input")
					}
					s := issuanceSession(x, func() error {
						closes++
						err := x.journal.Close()
						if failure == "close" {
							err = errors.Join(err, want)
						}
						return err
					})
					switch failure {
					case "open":
						return s, want
					case "authority":
						s.authority.plan = strings.Repeat("c", 64)
					case "nil-session":
						return nil, nil
					case "missing-close":
						s.close = nil
					}
					return s, nil
				}
				var err error
				switch op {
				case "preview":
					var got AccessRequestPreview
					got, err = prepareSystemdAccessRequest(t.Context(), x.plan.summary.PlanSHA256, x.authority.digest, open)
					if failure == "none" {
						if got.RequestSHA256 != digestBytes(x.request) || !got.RecoveryRequired {
							t.Fatal(got)
						}
					} else if !reflect.DeepEqual(got, AccessRequestPreview{}) {
						t.Fatal("failed preview returned private bytes", got)
					}
				case "issue":
					var got AccessChallengePublication
					got, err = issueSystemdAccessChallenge(t.Context(), x.plan.summary.PlanSHA256, x.authority.digest, digestBytes(x.request), time.Minute, open)
					wrote := failure == "none" || failure == "close"
					if got.IssuanceDurable != wrote || got.RecoveryRequired != wrote {
						t.Fatal("lost issuance facts", got)
					}
					if failure == "none" {
						if len(got.Request) == 0 || len(got.Challenge) == 0 {
							t.Fatal("successful writer lost delivery")
						}
					} else if len(got.Request) != 0 || len(got.Challenge) != 0 {
						t.Fatal("failed writer delivered private payload")
					}
				case "record":
					var got AccessReceiptPublication
					got, err = recordSystemdAccessReceipt(t.Context(), x.plan.summary.PlanSHA256, x.authority.digest, issued.IssuanceSHA256, issued.IssuanceImageSHA256, receipt, open)
					wrote := failure == "none" || failure == "close"
					if got.RecordDurable != wrote || got.RecoveryRequired != wrote {
						t.Fatal("lost recording facts", got)
					}
				}
				wantCloses := 1
				if failure == "nil-session" || failure == "missing-close" {
					wantCloses = 0
				}
				if (err == nil) != (failure == "none") || opens != 1 || closes != wantCloses {
					t.Fatal("resource ownership or error boundary", err, opens, closes)
				}
			})
		}
	}
}

func TestSSHAccessAdapterRefusesInvalidApprovalBeforeOpening(t *testing.T) {
	good := strings.Repeat("a", 64)
	open := func(context.Context, string, string) (*sshAccessSession, error) {
		t.Fatal("invalid operation opened live resources")
		return nil, nil
	}
	for _, scenario := range []string{"nil-context", "cancelled", "empty-plan", "uppercase-plan", "empty-enrollment", "uppercase-enrollment"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var input context.Context = ctx
			plan, enrollment := good, good
			switch scenario {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "empty-plan":
				plan = ""
			case "uppercase-plan":
				plan = strings.ToUpper(plan)
			case "empty-enrollment":
				enrollment = ""
			case "uppercase-enrollment":
				enrollment = strings.ToUpper(enrollment)
			}
			if _, err := prepareSystemdAccessRequest(input, plan, enrollment, open); err == nil {
				t.Fatal("invalid preview")
			}
			if _, err := issueSystemdAccessChallenge(input, plan, enrollment, good, time.Minute, open); err == nil {
				t.Fatal("invalid issuance")
			}
			if _, err := recordSystemdAccessReceipt(input, plan, enrollment, good, good, []byte("untrusted"), open); err == nil {
				t.Fatal("invalid receipt recording")
			}
		})
	}
	for _, ttl := range []time.Duration{0, -time.Second, time.Nanosecond, 301 * time.Second} {
		if _, err := issueSystemdAccessChallenge(t.Context(), good, good, good, ttl, open); err == nil {
			t.Fatal("invalid lifetime")
		}
	}
	if _, err := issueSystemdAccessChallenge(t.Context(), good, good, "", time.Minute, open); err == nil {
		t.Fatal("missing request approval")
	}
	if _, err := recordSystemdAccessReceipt(t.Context(), good, good, "", good, []byte("x"), open); err == nil {
		t.Fatal("missing issuance approval")
	}
	for _, image := range []string{"", strings.ToUpper(good)} {
		if _, err := recordSystemdAccessReceipt(t.Context(), good, good, good, image, []byte("x"), open); err == nil {
			t.Fatal("missing or noncanonical original image approval")
		}
	}
	for _, wire := range [][]byte{nil, make([]byte, maxSSHAccessReceiptBytes+1)} {
		if _, err := recordSystemdAccessReceipt(t.Context(), good, good, good, good, wire, open); err == nil {
			t.Fatal("unbounded receipt")
		}
	}
	if _, err := prepareSystemdAccessRequest(t.Context(), good, good, nil); err == nil {
		t.Fatal("nil opener")
	}
	if os.Geteuid() != 0 {
		if _, err := PrepareSystemdAccessRequest(t.Context(), good, good); err == nil {
			t.Fatal("nonroot preview")
		}
		if _, err := IssueSystemdAccessChallenge(t.Context(), good, good, good, time.Minute); err == nil {
			t.Fatal("nonroot issuance")
		}
		if _, err := RecordSystemdAccessReceipt(t.Context(), good, good, good, good, []byte("untrusted")); err == nil {
			t.Fatal("nonroot recording")
		}
	}
}

//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type sshForwardFixture struct {
	plan, enrollment string
	request          []byte
	migration        sshMigrationResult
	issued           AccessChallengePublication
	recorded         AccessReceiptPublication
	calls            []string
	operations       sshForwardOperations
	exchange         sshForwardAccessExchange
}

func forwardSessionFixture(t *testing.T) *sshForwardFixture {
	t.Helper()
	declaration, err := parseIntent([]byte(validIntentJSON))
	if err != nil {
		t.Fatal(err)
	}
	access := declaration.Contexts[0]
	key := sshProbeSigner(t).PublicKey().Marshal()
	pin := sshAccessPin{net.JoinHostPort(access.LocalAddress, strconv.Itoa(int(access.LocalPort))), access.User, key, key}
	x := &sshForwardFixture{plan: strings.Repeat("a", 64), enrollment: strings.Repeat("b", 64)}
	x.migration = sshMigrationResult{strings.Repeat("c", 64), true, true, true, true}
	x.request, err = json.Marshal(sshAccessRequest{1, sshAccessRequestDomain, x.migration.Transaction, x.plan,
		strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64), []sshAccessRequestRoute{{access, pin, nil}}})
	if err != nil {
		t.Fatal(err)
	}
	x.issued = AccessChallengePublication{Transaction: x.migration.Transaction, IssuanceSHA256: strings.Repeat("d", 64),
		IssuanceImageSHA256: strings.Repeat("e", 64), IssuanceDurable: true, Request: x.request, Challenge: []byte("fixture-challenge"), RecoveryRequired: true}
	x.recorded = AccessReceiptPublication{x.migration.Transaction, strings.Repeat("f", 64), true, true}
	x.operations = sshForwardOperations{
		migrate: func(_ context.Context, plan, enrollment string) (sshMigrationResult, error) {
			x.calls = append(x.calls, "migrate")
			if plan != x.plan || enrollment != x.enrollment {
				t.Fatal("independent plan or enrollment changed")
			}
			return x.migration, nil
		},
		request: func(context.Context, string, string) (AccessRequestPreview, error) {
			x.calls = append(x.calls, "request")
			return AccessRequestPreview{digestBytes(x.request), bytes.Clone(x.request), true}, nil
		},
		issue: func(_ context.Context, _, _, approved string, lifetime time.Duration) (AccessChallengePublication, error) {
			x.calls = append(x.calls, "issue")
			if approved != digestBytes(x.request) || lifetime != 3*time.Minute {
				t.Fatal("issuance changed exact request approval or bounded lifetime")
			}
			return x.issued, nil
		},
		record: func(_ context.Context, _, _, issuance, image string, receipt []byte) (AccessReceiptPublication, error) {
			x.calls = append(x.calls, "record")
			if issuance != x.issued.IssuanceSHA256 || image != x.issued.IssuanceImageSHA256 || string(receipt) != "fixture-signed-receipt" {
				t.Fatal("recording lost exact writer approvals or receipt")
			}
			return x.recorded, nil
		},
	}
	x.exchange = sshForwardAccessExchange{
		review: func(_ context.Context, preview AccessRequestPreview) (string, error) {
			x.calls = append(x.calls, "review")
			if !bytes.Equal(preview.Request, x.request) || preview.RequestSHA256 != digestBytes(x.request) {
				t.Fatal("independent request review received altered bytes")
			}
			return preview.RequestSHA256, nil
		},
		probe: func(_ context.Context, issued AccessChallengePublication) ([]byte, error) {
			x.calls = append(x.calls, "probe")
			if !reflect.DeepEqual(issued, x.issued) {
				t.Fatal("controller received altered durable delivery")
			}
			return []byte("fixture-signed-receipt"), nil
		},
	}
	return x
}

func TestSSHForwardSequenceRetainsRecoveryAfterAccessRecording(t *testing.T) {
	x := forwardSessionFixture(t)
	result, err := runSSHForwardWith(t.Context(), x.plan, x.enrollment, x.exchange, x.operations)
	if err != nil || !result.RecoveryRequired || !result.Migration.RecoveryRequired || !result.IssuanceDurable || !result.RecordDurable ||
		result.RecordSHA256 != x.recorded.RecordSHA256 || !reflect.DeepEqual(x.calls, []string{"migrate", "request", "review", "issue", "probe", "record"}) {
		t.Fatal("forward sequence lost order, partial facts or recovery requirement", result, x.calls, err)
	}
}

func TestSSHForwardSequenceFailuresNeverAdvanceOrReplay(t *testing.T) {
	for _, scenario := range []string{"migration-before-write", "migration-after-write", "migration-incomplete", "request", "request-cancel", "wrong-request-transaction", "wrong-request-approval", "review-private-error", "review-cancel", "issue-uncertain", "issue-close-error", "issue-wrong-request", "issue-wrong-transaction", "probe-private-error", "probe-cancel", "empty-receipt", "oversized-receipt", "record-close-error", "record-wrong-transaction", "record-clears-recovery", "record-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			x := forwardSessionFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("private-controller-credential-context")
			last := "migrate"
			switch scenario {
			case "migration-before-write", "migration-after-write":
				x.operations.migrate = func(context.Context, string, string) (sshMigrationResult, error) {
					x.calls = append(x.calls, "migrate")
					if scenario == "migration-before-write" {
						return sshMigrationResult{}, errors.New("preflight refused")
					}
					return x.migration, errors.New("close failed after reload")
				}
			case "migration-incomplete":
				x.migration.RequestReturned = false
			case "request", "request-cancel", "wrong-request-transaction":
				last = "request"
				original := x.operations.request
				x.operations.request = func(ctx context.Context, plan, enrollment string) (AccessRequestPreview, error) {
					preview, _ := original(ctx, plan, enrollment)
					if scenario == "request" {
						return AccessRequestPreview{}, errors.New("assessment changed")
					}
					if scenario == "request-cancel" {
						cancel()
						return preview, nil
					}
					var request sshAccessRequest
					if err := json.Unmarshal(preview.Request, &request); err != nil {
						t.Fatal(err)
					}
					request.Transaction = strings.Repeat("f", 64)
					preview.Request, _ = json.Marshal(request)
					preview.RequestSHA256 = digestBytes(preview.Request)
					return preview, nil
				}
			case "wrong-request-approval", "review-private-error", "review-cancel":
				last = "review"
				x.exchange.review = func(context.Context, AccessRequestPreview) (string, error) {
					x.calls = append(x.calls, "review")
					if scenario == "review-private-error" {
						return "", failure
					}
					if scenario == "review-cancel" {
						cancel()
						return digestBytes(x.request), nil
					}
					return strings.Repeat("f", 64), nil
				}
			case "issue-uncertain", "issue-close-error", "issue-wrong-request", "issue-wrong-transaction":
				last = "issue"
				x.operations.issue = func(context.Context, string, string, string, time.Duration) (AccessChallengePublication, error) {
					x.calls = append(x.calls, "issue")
					switch scenario {
					case "issue-uncertain":
						return AccessChallengePublication{Transaction: x.migration.Transaction, RecoveryRequired: true}, errors.New("directory sync failed")
					case "issue-close-error":
						return x.issued, errors.New("issuance close failed")
					case "issue-wrong-request":
						x.issued.Request = []byte("different-request")
					case "issue-wrong-transaction":
						x.issued.Transaction = strings.Repeat("f", 64)
					}
					return x.issued, nil
				}
			case "probe-private-error", "probe-cancel", "empty-receipt", "oversized-receipt":
				last = "probe"
				x.exchange.probe = func(context.Context, AccessChallengePublication) ([]byte, error) {
					x.calls = append(x.calls, "probe")
					switch scenario {
					case "probe-private-error":
						return nil, failure
					case "probe-cancel":
						cancel()
						return []byte("fixture-signed-receipt"), nil
					case "oversized-receipt":
						return make([]byte, maxSSHAccessReceiptBytes+1), nil
					}
					return nil, nil
				}
			default:
				last = "record"
				x.operations.record = func(context.Context, string, string, string, string, []byte) (AccessReceiptPublication, error) {
					x.calls = append(x.calls, "record")
					switch scenario {
					case "record-close-error":
						return x.recorded, errors.New("receipt close failed")
					case "record-wrong-transaction":
						x.recorded.Transaction = strings.Repeat("e", 64)
					case "record-clears-recovery":
						x.recorded.RecoveryRequired = false
					case "record-cancel":
						cancel()
					}
					return x.recorded, nil
				}
			}
			result, err := runSSHForwardWith(ctx, x.plan, x.enrollment, x.exchange, x.operations)
			if err == nil || len(x.calls) == 0 || x.calls[len(x.calls)-1] != last || result.RecoveryRequired != (scenario != "migration-before-write") {
				t.Fatal("failed phase advanced or lost recovery facts", result, x.calls, err)
			}
			if strings.Contains(err.Error(), failure.Error()) {
				t.Fatal("independent controller error exposed private context")
			}
			if strings.HasSuffix(scenario, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal("phase cancellation was lost", err)
			}
			if scenario == "issue-close-error" && (!result.IssuanceDurable || result.IssuanceImageSHA256 == "") {
				t.Fatal("uncertain delivery discarded acknowledged issuance")
			}
			if scenario == "record-close-error" && (!result.RecordDurable || result.RecordSHA256 == "") {
				t.Fatal("post-write failure discarded acknowledged receipt")
			}
		})
	}
}

func TestSSHForwardSequenceRefusesMissingAuthorityBeforeEffects(t *testing.T) {
	for _, scenario := range []string{"nil-context", "cancelled", "plan", "enrollment", "review", "probe", "migration", "request", "issue", "record", "opener"} {
		t.Run(scenario, func(t *testing.T) {
			x := forwardSessionFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var parent context.Context = ctx
			switch scenario {
			case "nil-context":
				parent = nil
			case "cancelled":
				cancel()
			case "plan":
				x.plan = ""
			case "enrollment":
				x.enrollment = ""
			case "review":
				x.exchange.review = nil
			case "probe":
				x.exchange.probe = nil
			case "migration":
				x.operations.migrate = nil
			case "request":
				x.operations.request = nil
			case "issue":
				x.operations.issue = nil
			case "record":
				x.operations.record = nil
			case "opener":
				if _, err := runSSHForwardSession(parent, x.plan, x.enrollment, nil, x.exchange); err == nil {
					t.Fatal("missing production opener accepted")
				}
				return
			}
			if result, err := runSSHForwardWith(parent, x.plan, x.enrollment, x.exchange, x.operations); err == nil || len(x.calls) != 0 || result != (sshForwardResult{}) {
				t.Fatal("incomplete authority reached forward effects", result, x.calls, err)
			}
		})
	}
}

func TestSSHForwardSignedFreshAccessNeverAcceptsConsumedPolicy(t *testing.T) {
	for _, scenario := range []string{"recorded", "invalid-signature", "changed-listener-generation", "cancelled-after-authentication"} {
		t.Run(scenario, func(t *testing.T) {
			x := accessIssuanceFixture(t)
			prepared, err := x.journal.read()
			if err != nil {
				t.Fatal(err)
			}
			before, err := observeSSHOwnedRecordSet(x.journal, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := x.journal.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			open := func(context.Context, string, string) (*sshAccessSession, error) {
				x.journal = fixtureJournal(t, x.f)
				return issuanceSession(x, x.journal.Close), nil
			}
			operations := sshForwardOperations{
				migrate: func(context.Context, string, string) (sshMigrationResult, error) {
					// Publication/reload is supplied by this protected fixture;
					// the separate native scenario runs the real migration opener.
					return sshMigrationResult{prepared.Transaction, true, true, true, true}, nil
				},
				request: func(ctx context.Context, plan, enrollment string) (AccessRequestPreview, error) {
					return prepareSystemdAccessRequest(ctx, plan, enrollment, open)
				},
				issue: func(ctx context.Context, plan, enrollment, request string, lifetime time.Duration) (AccessChallengePublication, error) {
					return issueSystemdAccessChallenge(ctx, plan, enrollment, request, lifetime, open)
				},
				record: func(ctx context.Context, plan, enrollment, issuance, image string, receipt []byte) (AccessReceiptPublication, error) {
					return recordSystemdAccessReceipt(ctx, plan, enrollment, issuance, image, receipt, open)
				},
			}
			exchange := sshForwardAccessExchange{
				review: func(_ context.Context, request AccessRequestPreview) (string, error) {
					return digestBytes(request.Request), nil
				},
				probe: func(ctx context.Context, issued AccessChallengePublication) ([]byte, error) {
					receipt, err := probeSSHAccessChallenge(ctx, issued.Request, issued.Challenge, digestBytes(issued.Challenge), x.key, x.credentials, func() time.Time { return x.now }, func() error { return ctx.Err() })
					if err != nil {
						return nil, err
					}
					switch scenario {
					case "invalid-signature":
						receipt[len(receipt)-3] ^= 1
					case "changed-listener-generation":
						previous := x.observe
						x.observe = func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
							summary, err := previous(ctx, expected, guard)
							summary.SocketsSHA256 = strings.Repeat("f", 64)
							return summary, err
						}
					case "cancelled-after-authentication":
						cancel()
					}
					return receipt, nil
				},
			}
			result, err := runSSHForwardWith(ctx, x.plan.summary.PlanSHA256, x.authority.digest, exchange, operations)
			success := scenario == "recorded"
			if (err == nil) != success || !result.RecoveryRequired || !result.IssuanceDurable || result.RecordDurable != success || x.target.signatures.Load() != 2 || x.jump.signatures.Load() != 1 {
				t.Fatal("signed fresh authentication bypassed state or recovery checks", result, err)
			}
			x.reopen(t)
			after, err := observeSSHIssuedRecordMembership(x.journal, true, success, true)
			if err != nil {
				t.Fatal(err)
			}
			for name, digest := range before {
				if after[name] != digest {
					t.Fatal("forward access changed original history", name)
				}
			}
			if len(after) != len(before)+1+map[bool]int{false: 0, true: 1}[success] {
				t.Fatal("forward access created unexpected terminal or recovery history")
			}
		})
	}
}

func TestSSHForwardControllerCannotRewriteRetainedDeliveryInputs(t *testing.T) {
	x := forwardSessionFixture(t)
	request, challenge := bytes.Clone(x.request), bytes.Clone(x.issued.Challenge)
	x.exchange.review = func(_ context.Context, preview AccessRequestPreview) (string, error) {
		approved := preview.RequestSHA256
		clear(preview.Request)
		return approved, nil
	}
	x.exchange.probe = func(_ context.Context, issued AccessChallengePublication) ([]byte, error) {
		if !bytes.Equal(issued.Request, request) || !bytes.Equal(issued.Challenge, challenge) {
			t.Fatal("earlier callback changed the approved delivery")
		}
		clear(issued.Request)
		clear(issued.Challenge)
		return []byte("fixture-signed-receipt"), nil
	}
	result, err := runSSHForwardWith(t.Context(), x.plan, x.enrollment, x.exchange, x.operations)
	if err != nil || !result.RecordDurable || !result.RecoveryRequired || !bytes.Equal(request, x.request) || !bytes.Equal(challenge, x.issued.Challenge) {
		t.Fatal("controller callback rewrote retained coordinator inputs", result, err)
	}
}

//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func receiptController(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func signedAccessFixture(t *testing.T, request []byte, credentials []sshAccessCredentials) (sshAccessReceiptInput, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private := receiptController(t)
	now := time.Now().Truncate(time.Second)
	challenge, err := newSSHAccessChallenge(request, digestBytes(request), public, now, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := probeSSHAccessChallenge(t.Context(), request, challenge, digestBytes(challenge), private, credentials,
		func() time.Time { return now }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return sshAccessReceiptInput{request, challenge, wire, digestBytes(challenge), public}, private, now
}

func rewriteAccessReceipt(t *testing.T, input sshAccessReceiptInput, key ed25519.PrivateKey, mutate func(*sshAccessReceipt)) sshAccessReceiptInput {
	t.Helper()
	var signed sshAccessSignedReceipt
	var receipt sshAccessReceipt
	if err := json.Unmarshal(input.Receipt, &signed); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(signed.Payload, &receipt); err != nil {
		t.Fatal(err)
	}
	mutate(&receipt)
	signed.Payload, _ = json.Marshal(receipt)
	signed.Signature = ed25519.Sign(key, signed.Payload)
	input.Receipt, _ = json.Marshal(signed)
	return input
}

func TestSSHAccessReceiptAuthenticatedRoundTrip(t *testing.T) {
	target := newSSHProbeFixture(t, "success")
	jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
	request, credentials := syntheticAccessRequest(t, target, jump)
	input, key, now := signedAccessFixture(t, request, credentials)
	got, err := verifySSHAccessReceipt(input, now)
	if err != nil || !got.RecoveryRequired || got.ContextsObserved != 2 || got.RequestSHA256 != digestBytes(request) || got.ReceiptSHA256 != digestBytes(input.Receipt) {
		t.Fatal(got, err)
	}
	if target.signatures.Load() != 2 || jump.signatures.Load() != 1 {
		t.Fatal("receipt skipped fresh authentication")
	}
	// Signature is diagnostic evidence, not a consumed one-time activation grant.
	again, err := verifySSHAccessReceipt(input, now.Add(time.Second))
	if err != nil || again != got {
		t.Fatal("read-only appraisal is not repeatable", err)
	}
	next, err := newSSHAccessChallenge(request, digestBytes(request), input.Controller, now, 3*time.Minute)
	if err != nil || bytes.Equal(next, input.Challenge) {
		t.Fatal("challenge nonce reused", err)
	}
	replaced := input
	replaced.Challenge, replaced.ApprovedChallenge = next, digestBytes(next)
	if _, err := verifySSHAccessReceipt(replaced, now); err == nil {
		t.Fatal("old receipt crossed challenge boundary")
	}
	receipt, err := probeSSHAccessChallenge(t.Context(), request, next, digestBytes(next), key, credentials, func() time.Time { return now }, func() error { return nil })
	if err != nil || bytes.Equal(receipt, input.Receipt) || target.signatures.Load() != 4 || jump.signatures.Load() != 2 {
		t.Fatal("challenge reused access", err)
	}
	if bytes.Contains(receipt, key) || bytes.Contains(receipt, []byte("PRIVATE KEY")) {
		t.Fatal("controller secret exposed")
	}
}

func TestSSHAccessReceiptRejectsSignedOrWireConfusion(t *testing.T) {
	target := newSSHProbeFixture(t, "success")
	jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
	request, credentials := syntheticAccessRequest(t, target, jump)
	good, key, now := signedAccessFixture(t, request, credentials)
	mutations := map[string]func(*sshAccessReceipt){
		"schema":             func(r *sshAccessReceipt) { r.Schema++ },
		"domain":             func(r *sshAccessReceipt) { r.Domain = "other" },
		"challenge":          func(r *sshAccessReceipt) { r.Challenge = strings.Repeat("f", 64) },
		"before-issued":      func(r *sshAccessReceipt) { r.StartedAt-- },
		"reverse-time":       func(r *sshAccessReceipt) { r.CompletedAt-- },
		"future-completion":  func(r *sshAccessReceipt) { r.CompletedAt++ },
		"expired-completion": func(r *sshAccessReceipt) { r.CompletedAt += 180 },
		"batch-request":      func(r *sshAccessReceipt) { r.Batch.RequestSHA256 = strings.Repeat("f", 64) },
		"batch-completed":    func(r *sshAccessReceipt) { r.Batch.RecoveryRequired = false },
		"missing-route":      func(r *sshAccessReceipt) { r.Batch.Observations = r.Batch.Observations[:1] },
		"extra-route": func(r *sshAccessReceipt) {
			r.Batch.Observations = append(r.Batch.Observations, r.Batch.Observations[0])
		},
		"reordered-route": func(r *sshAccessReceipt) {
			r.Batch.Observations[0], r.Batch.Observations[1] = r.Batch.Observations[1], r.Batch.Observations[0]
		},
		"wrong-binding":   func(r *sshAccessReceipt) { r.Batch.Observations[0].BindingSHA256 = strings.Repeat("f", 64) },
		"route-completed": func(r *sshAccessReceipt) { r.Batch.Observations[0].RecoveryRequired = false },
		"empty-session":   func(r *sshAccessReceipt) { r.Batch.Observations[0].SessionSHA256 = "" },
		"bad-challenge":   func(r *sshAccessReceipt) { r.Batch.Observations[0].ChallengeSHA256 = "bad" },
		"missing-jump":    func(r *sshAccessReceipt) { r.Batch.Observations[1].JumpSessionSHA256 = "" },
		"unexpected-jump": func(r *sshAccessReceipt) { r.Batch.Observations[0].JumpSessionSHA256 = strings.Repeat("f", 64) },
		"reused-session": func(r *sshAccessReceipt) {
			r.Batch.Observations[1].SessionSHA256 = r.Batch.Observations[0].SessionSHA256
		},
		"reused-challenge": func(r *sshAccessReceipt) {
			r.Batch.Observations[1].ChallengeSHA256 = r.Batch.Observations[0].ChallengeSHA256
		},
		"jump-session-alias": func(r *sshAccessReceipt) {
			r.Batch.Observations[1].JumpSessionSHA256 = r.Batch.Observations[0].SessionSHA256
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			input := rewriteAccessReceipt(t, good, key, mutate)
			if got, err := verifySSHAccessReceipt(input, now); err == nil || got != (sshAccessReceiptAssessment{}) {
				t.Fatal("signed invalid result accepted", got, err)
			}
		})
	}
	for _, scenario := range []string{"wrong-key", "short-key", "wrong-approval", "changed-request", "changed-signature", "unsigned", "unknown-envelope", "duplicate-envelope", "case-folded-envelope", "noncanonical-payload", "duplicate-payload", "unknown-payload", "case-folded-payload", "trailing", "oversized", "expired", "not-issued"} {
		t.Run(scenario, func(t *testing.T) {
			input, err := copySSHAccessReceiptInput(good)
			if err != nil {
				t.Fatal(err)
			}
			instant := now
			var signed sshAccessSignedReceipt
			if err := json.Unmarshal(input.Receipt, &signed); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "wrong-key":
				input.Controller, _ = receiptController(t)
			case "short-key":
				input.Controller = input.Controller[:1]
			case "wrong-approval":
				input.ApprovedChallenge = strings.Repeat("f", 64)
			case "changed-request":
				input.Request = append(input.Request, '\n')
			case "changed-signature":
				signed.Signature[0] ^= 1
				input.Receipt, _ = json.Marshal(signed)
			case "unsigned":
				signed.Signature = nil
				input.Receipt, _ = json.Marshal(signed)
			case "unknown-envelope":
				input.Receipt = bytes.Replace(input.Receipt, []byte("{"), []byte(`{"extra":true,`), 1)
			case "duplicate-envelope":
				input.Receipt = bytes.Replace(input.Receipt, []byte("{"), []byte(`{"payload":"",`), 1)
			case "case-folded-envelope":
				input.Receipt = bytes.Replace(input.Receipt, []byte(`"signature"`), []byte(`"Signature"`), 1)
			case "trailing":
				input.Receipt = append(input.Receipt, '\n')
			case "oversized":
				input.Receipt = bytes.Repeat([]byte("x"), maxSSHAccessReceiptBytes+1)
			case "expired":
				instant = now.Add(3 * time.Minute)
			case "not-issued":
				instant = now.Add(-time.Second)
			default:
				switch scenario {
				case "noncanonical-payload":
					signed.Payload = append(signed.Payload, '\n')
				case "duplicate-payload":
					signed.Payload = bytes.Replace(signed.Payload, []byte("{"), []byte(`{"schema":1,`), 1)
				case "unknown-payload":
					signed.Payload = bytes.Replace(signed.Payload, []byte("{"), []byte(`{"extra":true,`), 1)
				case "case-folded-payload":
					signed.Payload = bytes.Replace(signed.Payload, []byte(`"schema"`), []byte(`"Schema"`), 1)
				}
				signed.Signature = ed25519.Sign(key, signed.Payload)
				input.Receipt, _ = json.Marshal(signed)
			}
			if got, err := verifySSHAccessReceipt(input, instant); err == nil || got != (sshAccessReceiptAssessment{}) {
				t.Fatal("invalid receipt accepted", got, err)
			}
		})
	}
}

func TestSSHAccessChallengeRefusesBeforeNetwork(t *testing.T) {
	for _, scenario := range []string{"request", "approval", "controller", "private-length", "private-halves", "schema", "domain", "nonce", "issued", "expiry", "window", "future", "noncanonical", "unknown", "duplicate", "case-folded", "oversized", "cancelled", "revoked", "nil-clock", "nil-guard", "nil-context"} {
		t.Run(scenario, func(t *testing.T) {
			target := newSSHProbeFixture(t, "success")
			jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
			request, credentials := syntheticAccessRequest(t, target, jump)
			public, private := receiptController(t)
			now := time.Now().Truncate(time.Second)
			wire, err := newSSHAccessChallenge(request, digestBytes(request), public, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			var c sshAccessChallenge
			if err := json.Unmarshal(wire, &c); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "request":
				c.Request = strings.Repeat("f", 64)
			case "controller":
				c.Controller = strings.Repeat("f", 64)
			case "schema":
				c.Schema++
			case "domain":
				c.Domain = "other"
			case "nonce":
				c.Nonce = ""
			case "issued":
				c.IssuedAt = 0
			case "expiry":
				c.ExpiresAt = now.Unix()
			case "window":
				c.ExpiresAt = c.IssuedAt + 301
			case "future":
				c.IssuedAt++
				c.ExpiresAt++
			}
			wire, _ = json.Marshal(c)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var callContext context.Context = ctx
			clock := func() time.Time { return now }
			guard := func() error { return nil }
			switch scenario {
			case "private-length":
				private = private[:1]
			case "private-halves":
				private[len(private)-1] ^= 1
			case "noncanonical":
				wire = append(wire, '\n')
			case "unknown":
				wire = bytes.Replace(wire, []byte("{"), []byte(`{"extra":true,`), 1)
			case "duplicate":
				wire = bytes.Replace(wire, []byte("{"), []byte(`{"schema":1,`), 1)
			case "case-folded":
				wire = bytes.Replace(wire, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "oversized":
				wire = bytes.Repeat([]byte("x"), maxSSHAccessChallengeBytes+1)
			case "cancelled":
				cancel()
			case "revoked":
				guard = func() error { return ErrInventoryChanged }
			case "nil-clock":
				clock = nil
			case "nil-guard":
				guard = nil
			case "nil-context":
				callContext = nil
			}
			approved := digestBytes(wire)
			if scenario == "approval" {
				approved = strings.Repeat("f", 64)
			}
			got, err := probeSSHAccessChallenge(callContext, request, wire, approved, private, credentials, clock, guard)
			if err == nil || got != nil || target.connections.Load() != 0 || jump.connections.Load() != 0 {
				t.Fatal("invalid challenge reached network", err)
			}
		})
	}
}

func TestSSHAccessChallengeLateFailureAndFrozenInputs(t *testing.T) {
	for _, scenario := range []string{"expiry", "clock-backwards", "revoked", "cancelled", "caller-mutation"} {
		t.Run(scenario, func(t *testing.T) {
			target := newSSHProbeFixture(t, "success")
			jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
			request, credentials := syntheticAccessRequest(t, target, jump)
			public, private := receiptController(t)
			now := time.Now().Truncate(time.Second)
			challenge, err := newSSHAccessChallenge(request, digestBytes(request), public, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			originalRequest, originalChallenge := bytes.Clone(request), bytes.Clone(challenge)
			approved := digestBytes(challenge)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			clock := func() time.Time {
				if target.signatures.Load() > 0 {
					if scenario == "expiry" {
						return now.Add(time.Minute)
					}
					if scenario == "clock-backwards" {
						return now.Add(-time.Nanosecond)
					}
				}
				return now
			}
			changed := false
			guard := func() error {
				if target.signatures.Load() > 0 {
					switch scenario {
					case "revoked":
						return ErrInventoryChanged
					case "cancelled":
						cancel()
					case "caller-mutation":
						if !changed {
							changed = true
							clear(request)
							clear(challenge)
							clear(private)
						}
					}
				}
				return nil
			}
			got, err := probeSSHAccessChallenge(ctx, request, challenge, approved, private, credentials, clock, guard)
			if scenario == "caller-mutation" {
				input := sshAccessReceiptInput{originalRequest, originalChallenge, got, approved, public}
				if _, verifyErr := verifySSHAccessReceipt(input, now); err != nil || verifyErr != nil {
					t.Fatal(err, verifyErr)
				}
			} else if err == nil || got != nil {
				t.Fatal("late failure returned receipt", err)
			}
		})
	}
}

func TestSSHProtectedReceiptAssessment(t *testing.T) {
	for _, scenario := range []string{"success", "policy-drift", "intent-replaced", "endpoint-drift", "expiry-during-assessment", "revocation-during-assessment", "late-parser-drift", "late-policy-drift", "clock-backwards", "caller-mutation", "cancel-on-last-guard", "approval", "bad-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal, target, jump, pins, credentials, run, observe := protectedAccessFixture(t)
			request, err := prepareSSHActivationAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, observe, pins)
			if err != nil {
				t.Fatal(err)
			}
			input, _, now := signedAccessFixture(t, request, credentials)
			records, err := observeSSHOwnedRecordSet(journal, true)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := journal.read()
			if err != nil {
				t.Fatal(err)
			}
			before, err := stableSSHRollback(journal, prepared.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			initialConnections := target.connections.Load() + jump.connections.Load()
			journal.syncDirectory = func(*os.File) error { t.Fatal("receipt repaired durability"); return unix.EIO }
			approved := plan.summary.PlanSHA256
			switch scenario {
			case "policy-drift":
				f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "intent-replaced":
				f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
			case "approval":
				approved = strings.Repeat("f", 64)
			case "bad-receipt":
				input.Receipt = []byte("{}")
			}
			observed := false
			mutated := false
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			clock := func() time.Time {
				if observed && scenario == "expiry-during-assessment" {
					return now.Add(3 * time.Minute)
				}
				if observed && scenario == "clock-backwards" {
					return now.Add(-time.Nanosecond)
				}
				return now
			}
			auth := func() error {
				if observed && !mutated {
					mutated = true
					switch scenario {
					case "late-policy-drift":
						f.write(DropInPath, "AllowTcpForwarding yes\n")
					case "caller-mutation":
						clear(input.Request)
						clear(input.Challenge)
						clear(input.Receipt)
						clear(input.Controller)
					case "cancel-on-last-guard":
						cancel()
					}
				}
				if observed && scenario == "revocation-during-assessment" {
					return ErrInventoryChanged
				}
				return nil
			}
			check := func() error {
				if observed && scenario == "late-parser-drift" {
					return ErrInventoryChanged
				}
				return deps.checkParser()
			}
			wrapped := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				competing, err := openSSHJournal(f.root, os.Geteuid())
				if err == nil {
					_ = competing.Close()
					t.Fatal("receipt released protected lock")
				}
				value, err := observe(ctx, expected, guard)
				observed = true
				if scenario == "endpoint-drift" {
					value.SocketsSHA256 = strings.Repeat("f", 64)
				}
				return value, err
			}
			got, err := assessSSHActivationAccessReceipt(ctx, journal, approved, deps.parserDigest, run, check, wrapped, pins, input, clock, auth)
			if scenario != "success" && scenario != "caller-mutation" {
				if err == nil || got != (sshAccessReceiptAssessment{}) {
					t.Fatal("stale receipt accepted", got, err)
				}
				return
			}
			if err != nil || !got.RecoveryRequired || got.ContextsObserved != 2 {
				t.Fatal(got, err)
			}
			if target.connections.Load()+jump.connections.Load() != initialConnections {
				t.Fatal("target appraisal opened network")
			}
			after, err := stableSSHRollback(journal, prepared.Transaction)
			afterRecords, recordsErr := observeSSHOwnedRecordSet(journal, true)
			if err != nil || recordsErr != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, afterRecords) {
				t.Fatal("receipt modified state", err, recordsErr)
			}
			if err := rollbackSSHConfiguration(t.Context(), journal, approved, deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
				t.Fatal("receipt cleared activation fence")
			}
		})
	}
}

func TestSSHAccessChallengeIssuanceBounds(t *testing.T) {
	target := newSSHProbeFixture(t, "success")
	jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
	request, _ := syntheticAccessRequest(t, target, jump)
	public, _ := receiptController(t)
	now := time.Now()
	for _, life := range []time.Duration{0, -time.Second, time.Nanosecond, time.Second + time.Nanosecond, 5*time.Minute + time.Second} {
		if wire, err := newSSHAccessChallenge(request, digestBytes(request), public, now, life); err == nil || wire != nil {
			t.Fatal("invalid lifetime")
		}
	}
	for _, scenario := range []string{"approval", "key", "clock"} {
		approved, key, instant := digestBytes(request), public, now
		switch scenario {
		case "approval":
			approved = ""
		case "key":
			key = nil
		case "clock":
			instant = time.Unix(0, 0)
		}
		if wire, err := newSSHAccessChallenge(request, approved, key, instant, time.Minute); err == nil || wire != nil {
			t.Fatal("invalid authority input")
		}
	}
}

func FuzzSSHAccessChallengeCanonical(f *testing.F) {
	now := time.Unix(1700000000, 0)
	valid, _ := json.Marshal(sshAccessChallenge{1, sshAccessChallengeDomain, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), now.Unix(), now.Unix() + 60})
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maxSSHAccessChallengeBytes {
			return
		}
		value, err := parseSSHAccessChallenge(wire, digestBytes(wire), now)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(value)
		if err != nil || !bytes.Equal(canonical, wire) {
			t.Fatal("noncanonical challenge accepted")
		}
	})
}

func FuzzSSHAccessReceiptCanonical(f *testing.F) {
	now := time.Unix(1700000000, 0)
	controller := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := controller.Public().(ed25519.PublicKey)
	host, err := ssh.NewPublicKey(public)
	if err != nil {
		f.Fatal(err)
	}
	pin := sshAccessPin{"127.0.0.1:22", "administrator", host.Marshal(), host.Marshal()}
	access := accessContext{"administrator", "direct", "administrator", "controller.example", "127.0.0.1", "127.0.0.1", 22}
	request := sshAccessRequest{1, sshAccessRequestDomain, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), []sshAccessRequestRoute{{access, pin, nil}}}
	requestWire, _ := json.Marshal(request)
	challenge, err := newSSHAccessChallenge(requestWire, digestBytes(requestWire), public, now, time.Minute)
	if err != nil {
		f.Fatal(err)
	}
	binding, err := sshAccessBindingDigest(sshAccessBinding{request.Transaction, request.Plan, request.Intent, request.Target, digestBytes(requestWire), access}, sshAccessIdentity{pin.Address, pin.User, digestBytes(pin.HostKey), digestBytes(pin.ClientKey)}, nil)
	if err != nil {
		f.Fatal(err)
	}
	observation := sshAccessObservation{binding, strings.Repeat("1", 64), strings.Repeat("2", 64), "", true}
	receipt := sshAccessReceipt{1, sshAccessReceiptDomain, digestBytes(challenge), now.Unix(), now.Unix(), sshAccessBatchObservation{digestBytes(requestWire), []sshAccessObservation{observation}, true}}
	payload, _ := json.Marshal(receipt)
	valid, _ := json.Marshal(sshAccessSignedReceipt{payload, ed25519.Sign(controller, payload)})
	input := sshAccessReceiptInput{requestWire, challenge, valid, digestBytes(challenge), public}
	if _, err := verifySSHAccessReceipt(input, now); err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maxSSHAccessReceiptBytes {
			return
		}
		candidate := input
		candidate.Receipt = wire
		got, err := verifySSHAccessReceipt(candidate, now)
		if err != nil {
			if got != (sshAccessReceiptAssessment{}) {
				t.Fatal("partial receipt result")
			}
			return
		}
		if !bytes.Equal(wire, valid) || !got.RecoveryRequired || got.ContextsObserved != 1 {
			t.Fatal("changed signed receipt accepted")
		}
	})
}

func TestSSHControllerReceiptFinalGuard(t *testing.T) {
	target := newSSHProbeFixture(t, "success")
	jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
	request, credentials := syntheticAccessRequest(t, target, jump)
	public, private := receiptController(t)
	now := time.Now().Truncate(time.Second)
	challenge, err := newSSHAccessChallenge(request, digestBytes(request), public, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = probeSSHAccessChallenge(t.Context(), request, challenge, digestBytes(challenge), private, credentials, func() time.Time { return now }, func() error { calls++; return nil })
	if err != nil || calls == 0 {
		t.Fatal(err, calls)
	}
	finalCalls := calls
	for _, scenario := range []string{"revoked", "cancelled", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			calls = 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			instant := now
			guard := func() error {
				calls++
				if calls == finalCalls {
					switch scenario {
					case "revoked":
						return ErrInventoryChanged
					case "cancelled":
						cancel()
					case "expired":
						instant = now.Add(time.Minute)
					}
				}
				return nil
			}
			wire, err := probeSSHAccessChallenge(ctx, request, challenge, digestBytes(challenge), private, credentials, func() time.Time { return instant }, guard)
			if err == nil || wire != nil || calls != finalCalls {
				t.Fatal("last controller guard bypassed", calls, err)
			}
		})
	}
}

func TestSSHProtectedReceiptFinalGuard(t *testing.T) {
	f, plan, deps, journal, _, _, pins, credentials, run, observe := protectedAccessFixture(t)
	request, err := prepareSSHActivationAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, observe, pins)
	if err != nil {
		t.Fatal(err)
	}
	input, _, now := signedAccessFixture(t, request, credentials)
	calls := 0
	_, err = assessSSHActivationAccessReceipt(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, observe, pins, input, func() time.Time { return now }, func() error { calls++; return nil })
	if err != nil || calls == 0 {
		t.Fatal(err, calls)
	}
	finalCalls := calls
	for _, scenario := range []string{"revoked", "cancelled", "expired", "policy-drift"} {
		t.Run(scenario, func(t *testing.T) {
			calls = 0
			instant := now
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			guard := func() error {
				calls++
				if calls == finalCalls {
					switch scenario {
					case "revoked":
						return ErrInventoryChanged
					case "cancelled":
						cancel()
					case "expired":
						instant = now.Add(3 * time.Minute)
					case "policy-drift":
						f.write(DropInPath, "AllowTcpForwarding yes\n")
					}
				}
				return nil
			}
			got, err := assessSSHActivationAccessReceipt(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, observe, pins, input, func() time.Time { return instant }, guard)
			if err == nil || got != (sshAccessReceiptAssessment{}) || calls != finalCalls {
				t.Fatal("last protected guard bypassed", got, calls, err)
			}
		})
	}
}

// Independent JSON/SHA-256 vector pins the original transport encoding.
func TestSSHAccessBindingGolden(t *testing.T) {
	access := accessContext{"administrator", "direct", "administrator", "controller.example", "192.0.2.2", "192.0.2.1", 22}
	binding := sshAccessBinding{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), access}
	target := sshAccessIdentity{"192.0.2.1:22", "administrator", strings.Repeat("f", 64), strings.Repeat("1", 64)}
	got, err := sshAccessBindingDigest(binding, target, nil)
	if err != nil || got != "0eeba6b6b74da87fa1cbb63c59dc17c22aa36141e5c581ec32c4ba141a7d58c7" {
		t.Fatal("transport binding encoding changed", got, err)
	}
}

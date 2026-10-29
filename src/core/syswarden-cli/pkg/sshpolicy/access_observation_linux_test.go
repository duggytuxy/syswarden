//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

func recordedAccessFixture(t *testing.T, uncertain bool) (*sshEvidenceFixture, sshAccessEvidenceApproval, []byte) {
	t.Helper()
	x := accessEvidenceFixture(t)
	if uncertain {
		x.journal.syncDirectory = func(*os.File) error { return unix.EIO }
	}
	result, err := x.record(t.Context(), func() time.Time { return x.now }, func() error { return nil })
	if uncertain {
		if err == nil || result.RecordDurable {
			t.Fatal("uncertain record acknowledged", result, err)
		}
	} else if err != nil || !result.RecordDurable {
		t.Fatal(result, err)
	}
	if err := x.journal.Close(); err != nil {
		t.Fatal(err)
	}
	x.journal = fixtureJournal(t, x.f)
	wire, err := x.journal.readRecord(sshAccessEvidenceName)
	if err != nil {
		t.Fatal(err)
	}
	return x, sshAccessEvidenceApproval{digestBytes(wire), x.input.ApprovedChallenge, bytes.Clone(x.input.Controller)}, wire
}

func (x *sshEvidenceFixture) inspect(ctx context.Context, approval sshAccessEvidenceApproval, clock func() time.Time, auth func() error) (sshAccessEvidenceObservation, error) {
	return observeSSHActivationAccessEvidence(ctx, x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.pins, approval, clock, auth)
}

func TestSSHRecordedAccessObservationPreservesUncertainty(t *testing.T) {
	for _, scenario := range []string{"current", "expired", "unknown-durability", "changed-endpoints", "changed-pins"} {
		t.Run(scenario, func(t *testing.T) {
			x, approval, wire := recordedAccessFixture(t, scenario == "unknown-durability")
			records, err := observeSSHRecordMembership(x.journal, true, true)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := x.journal.read()
			if err != nil {
				t.Fatal(err)
			}
			before, err := stableSSHRollback(x.journal, prepared.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			connections := x.target.connections.Load() + x.jump.connections.Load()
			x.journal.syncDirectory = func(*os.File) error { t.Fatal("observer repaired durability"); return unix.EIO }
			now := x.now
			if scenario == "expired" {
				now = now.Add(3 * time.Minute)
			}
			original := x.observe
			x.observe = func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				competing, err := openSSHJournal(x.f.root, os.Geteuid())
				if err == nil {
					_ = competing.Close()
					t.Fatal("observer lost journal lock")
				}
				result, err := original(ctx, expected, guard)
				if scenario == "changed-endpoints" {
					result.SocketsSHA256 = strings.Repeat("f", 64)
				}
				return result, err
			}
			if scenario == "changed-pins" {
				x.pins[0].Target.HostKey = bytes.Clone(x.jump.peer.HostKey)
			}
			got, err := x.inspect(t.Context(), approval, func() time.Time { return now }, func() error { return nil })
			if err != nil || !got.HistoricalSignatureVerified || !got.DurabilityUnknown || !got.RecoveryRequired || got.ContextsRecorded != 2 || got.RecordSHA256 != digestBytes(wire) || got.RequestSHA256 != digestBytes(x.input.Request) || got.AssessedAt != x.now.Unix() {
				t.Fatal(got, err)
			}
			if got.WindowOpen != (scenario != "expired") || got.CurrentRequestMatches != (scenario != "changed-endpoints" && scenario != "changed-pins") {
				t.Fatal("conflated historical and current state", got)
			}
			if x.target.connections.Load()+x.jump.connections.Load() != connections {
				t.Fatal("observer opened SSH network connection")
			}
			afterRecords, err := observeSSHRecordMembership(x.journal, true, true)
			if err != nil || !reflect.DeepEqual(records, afterRecords) {
				t.Fatal("observer changed evidence", err)
			}
			after, err := stableSSHRollback(x.journal, prepared.Transaction)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("observer changed configuration", err)
			}
			if _, err := prepareSSHActivationAccessRequest(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.pins); err == nil {
				t.Fatal("observer reopened fresh request path")
			}
			if _, err := x.record(t.Context(), func() time.Time { return x.now }, func() error { return nil }); err == nil {
				t.Fatal("observer cleared single-use slot")
			}
			if err := rollbackSSHConfiguration(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.run, x.deps.checkParser, sshPublicationDefaults()); err == nil {
				t.Fatal("observer cleared runtime recovery fence")
			}
		})
	}
}

func TestSSHRecordedAccessDecoderRejectsAmbiguousEvidence(t *testing.T) {
	x, approval, wire := recordedAccessFixture(t, false)
	var original sshAccessEvidence
	if err := json.Unmarshal(wire, &original); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*sshAccessEvidence){
		"schema":            func(r *sshAccessEvidence) { r.Schema++ },
		"domain":            func(r *sshAccessEvidence) { r.Domain = "other" },
		"recovery-cleared":  func(r *sshAccessEvidence) { r.RecoveryRequired = false },
		"future-appraisal":  func(r *sshAccessEvidence) { r.AssessedAt = x.now.Unix() + 1 },
		"before-completion": func(r *sshAccessEvidence) { r.AssessedAt = x.now.Unix() - 1 },
		"controller":        func(r *sshAccessEvidence) { r.Controller = strings.Repeat("f", 64) },
		"transaction":       func(r *sshAccessEvidence) { r.Transaction = strings.Repeat("f", 64) },
		"plan":              func(r *sshAccessEvidence) { r.Plan = strings.Repeat("f", 64) },
		"intent":            func(r *sshAccessEvidence) { r.Intent = strings.Repeat("f", 64) },
		"target":            func(r *sshAccessEvidence) { r.Target = strings.Repeat("f", 64) },
		"history-format":    func(r *sshAccessEvidence) { r.Records = "unknown" },
		"parser-format":     func(r *sshAccessEvidence) { r.Parser = "unknown" },
		"request":           func(r *sshAccessEvidence) { r.Request = []byte("{}") },
		"challenge":         func(r *sshAccessEvidence) { r.Challenge = []byte("{}") },
		"receipt":           func(r *sshAccessEvidence) { r.Receipt = []byte("{}") },
		"request-bound":     func(r *sshAccessEvidence) { r.Request = bytes.Repeat([]byte("x"), maxSSHAccessRequestBytes+1) },
		"challenge-bound":   func(r *sshAccessEvidence) { r.Challenge = bytes.Repeat([]byte("x"), maxSSHAccessChallengeBytes+1) },
		"receipt-bound":     func(r *sshAccessEvidence) { r.Receipt = bytes.Repeat([]byte("x"), maxSSHAccessReceiptBytes+1) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			r := original
			change(&r)
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			pin := approval
			pin.EvidenceSHA256 = digestBytes(data)
			if _, _, _, err := decodeSSHAccessEvidence(data, pin, x.now); err == nil {
				t.Fatal("accepted invalid reviewed record")
			}
		})
	}
	for _, scenario := range []string{"empty", "oversized", "unknown-field", "duplicate-field", "case-folded-field", "whitespace", "null", "approval", "key", "challenge-approval"} {
		t.Run(scenario, func(t *testing.T) {
			data := bytes.Clone(wire)
			pin := approval
			switch scenario {
			case "empty":
				data = nil
			case "oversized":
				data = bytes.Repeat([]byte("x"), maxSSHAccessEvidenceBytes+1)
			case "unknown-field":
				data = append([]byte(`{"unknown":0,`), wire[1:]...)
			case "duplicate-field":
				data = append([]byte(`{"schema":1,`), wire[1:]...)
			case "case-folded-field":
				data = bytes.Replace(wire, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "whitespace":
				data = append(data, '\n')
			case "null":
				data = []byte("null")
			case "key":
				pin.Controller, _ = receiptController(t)
			case "challenge-approval":
				pin.ChallengeSHA256 = strings.Repeat("f", 64)
			}
			pin.EvidenceSHA256 = digestBytes(data)
			if scenario == "approval" {
				pin.EvidenceSHA256 = strings.Repeat("f", 64)
			}
			got, verified, challenge, err := decodeSSHAccessEvidence(data, pin, x.now)
			if err == nil || !reflect.DeepEqual(got, sshAccessEvidence{}) || verified != (sshAccessReceiptAssessment{}) || challenge != (sshAccessChallenge{}) {
				t.Fatal("ambiguous evidence returned observation", err)
			}
		})
	}
}

func TestSSHRecordedAccessProtectedHistoryAndFinalGuards(t *testing.T) {
	for _, scenario := range []string{"approval", "history", "parser-binding", "policy-drift", "original-record-replaced", "record-mode", "record-symlink", "extra-entry", "future-clock", "revoked", "cancelled", "late-policy", "late-record", "late-parser", "clock-backwards", "caller-mutation"} {
		t.Run(scenario, func(t *testing.T) {
			x, approval, wire := recordedAccessFixture(t, false)
			observed := false
			mutated := false
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "approval":
				approval.EvidenceSHA256 = strings.Repeat("f", 64)
			case "history", "parser-binding":
				var r sshAccessEvidence
				if err := json.Unmarshal(wire, &r); err != nil {
					t.Fatal(err)
				}
				if scenario == "history" {
					r.Records = strings.Repeat("f", 64)
				} else {
					r.Parser = strings.Repeat("f", 64)
				}
				changed, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				x.f.write(sshJournalDirectory+"/"+sshAccessEvidenceName, string(changed))
				approval.EvidenceSHA256 = digestBytes(changed)
			case "policy-drift":
				x.f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "original-record-replaced":
				replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshPreparedRecord)
			case "record-mode":
				storage, err := os.OpenRoot(x.f.base)
				if err != nil {
					t.Fatal(err)
				}
				defer storage.Close()
				if err := storage.Chmod(strings.TrimPrefix(sshJournalDirectory, "/")+"/"+sshAccessEvidenceName, 0644); err != nil {
					t.Fatal(err)
				} // #nosec G302 -- Deliberately unsafe fixture mode; the read-only observer must refuse it.
			case "record-symlink":
				storage, err := os.OpenRoot(x.f.base)
				if err != nil {
					t.Fatal(err)
				}
				defer storage.Close()
				name := strings.TrimPrefix(sshJournalDirectory, "/") + "/" + sshAccessEvidenceName
				if err := storage.Rename(name, "retained"); err != nil {
					t.Fatal(err)
				}
				if err := storage.Symlink("../../../retained", name); err != nil {
					t.Fatal(err)
				}
			case "extra-entry":
				x.f.write(sshJournalDirectory+"/unowned", "keep")
			case "cancelled":
				cancel()
			}
			originalObserve := x.observe
			x.observe = func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				value, err := originalObserve(ctx, expected, guard)
				observed = true
				return value, err
			}
			parserCheck := x.deps.checkParser
			x.deps.checkParser = func() error {
				if observed && scenario == "late-parser" {
					return ErrInventoryChanged
				}
				return parserCheck()
			}
			clock := func() time.Time {
				if scenario == "future-clock" || observed && scenario == "clock-backwards" {
					return x.now.Add(-time.Second)
				}
				return x.now
			}
			auth := func() error {
				if scenario == "revoked" {
					return ErrInventoryChanged
				}
				if observed && !mutated {
					mutated = true
					switch scenario {
					case "late-policy":
						x.f.write(DropInPath, "AllowTcpForwarding yes\n")
					case "late-record":
						replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshAccessEvidenceName)
					case "caller-mutation":
						clear(approval.Controller)
						clear(x.pins[0].Target.HostKey)
						clear(x.pins[0].Target.ClientKey)
					}
				}
				return nil
			}
			x.journal.syncDirectory = func(*os.File) error { t.Fatal("inspection mutated durability"); return unix.EIO }
			got, err := x.inspect(ctx, approval, clock, auth)
			if scenario == "caller-mutation" {
				if err != nil || !got.CurrentRequestMatches {
					t.Fatal("caller buffers not frozen", got, err)
				}
			} else if err == nil || got != (sshAccessEvidenceObservation{}) {
				t.Fatal("unsafe history accepted", scenario, got, err)
			}
		})
	}
}

func TestSSHRecordedAccessFinalCallback(t *testing.T) {
	x, approval, _ := recordedAccessFixture(t, false)
	calls := 0
	_, err := x.inspect(t.Context(), approval, func() time.Time { return x.now }, func() error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	final := calls
	for _, scenario := range []string{"cancelled", "revoked", "record-replaced", "policy-drift", "expiry", "clock-backwards"} {
		t.Run(scenario, func(t *testing.T) {
			x, approval, _ := recordedAccessFixture(t, false)
			calls := 0
			now := x.now
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			auth := func() error {
				calls++
				if calls == final {
					switch scenario {
					case "cancelled":
						cancel()
					case "revoked":
						return ErrInventoryChanged
					case "record-replaced":
						replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshAccessEvidenceName)
					case "policy-drift":
						x.f.write(DropInPath, "AllowTcpForwarding yes\n")
					case "expiry":
						now = now.Add(3 * time.Minute)
					case "clock-backwards":
						now = now.Add(-time.Nanosecond)
					}
				}
				return nil
			}
			got, err := x.inspect(ctx, approval, func() time.Time { return now }, auth)
			if calls != final {
				t.Fatal("final callback not reached", calls, final)
			}
			if scenario == "expiry" {
				if err != nil || got.WindowOpen || !got.HistoricalSignatureVerified || !got.DurabilityUnknown {
					t.Fatal("historical evidence confused with freshness", got, err)
				}
			} else if err == nil || got != (sshAccessEvidenceObservation{}) {
				t.Fatal("final callback escaped guard", got, err)
			}
		})
	}
}

func TestSSHRecordedAccessRejectsForeignProtectedContext(t *testing.T) {
	x, _, wire := recordedAccessFixture(t, false)
	var record sshAccessEvidence
	if err := json.Unmarshal(wire, &record); err != nil {
		t.Fatal(err)
	}
	request, err := parseSSHAccessRequest(record.Request, digestBytes(record.Request))
	if err != nil {
		t.Fatal(err)
	}
	request.Routes[0].Access.ID = "different-context"
	requestWire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	credentials := make([]sshAccessCredentials, len(request.Routes))
	for index, route := range request.Routes {
		credentials[index] = sshAccessCredentials{ContextID: route.Access.ID, Target: x.target.peer.Identity}
		if route.Jump != nil {
			credentials[index].Jump = x.jump.peer.Identity
		}
	}
	input, _, now := signedAccessFixture(t, requestWire, credentials)
	record.Request, record.Challenge, record.Receipt = input.Request, input.Challenge, input.Receipt
	record.Controller, record.AssessedAt = digestBytes(input.Controller), now.Unix()
	changed, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	approval := sshAccessEvidenceApproval{digestBytes(changed), input.ApprovedChallenge, input.Controller}
	if _, _, _, err := decodeSSHAccessEvidence(changed, approval, now); err != nil {
		t.Fatal("fixture must be valid signed history", err)
	}
	x.f.write(sshJournalDirectory+"/"+sshAccessEvidenceName, string(changed))
	got, err := x.inspect(t.Context(), approval, func() time.Time { return now }, func() error { return nil })
	if err == nil || got != (sshAccessEvidenceObservation{}) {
		t.Fatal("signed context escaped original protected plan", got, err)
	}
}

func FuzzSSHRecordedAccessCanonical(f *testing.F) {
	now := time.Unix(1700000000, 0)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	sshKey, err := ssh.NewPublicKey(public)
	if err != nil {
		f.Fatal(err)
	}
	pin := sshAccessPin{"127.0.0.1:22", "administrator", sshKey.Marshal(), sshKey.Marshal()}
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
	receipt := sshAccessReceipt{1, sshAccessReceiptDomain, digestBytes(challenge), now.Unix(), now.Unix(), sshAccessBatchObservation{digestBytes(requestWire), []sshAccessObservation{{binding, strings.Repeat("1", 64), strings.Repeat("2", 64), "", true}}, true}}
	payload, _ := json.Marshal(receipt)
	signed, _ := json.Marshal(sshAccessSignedReceipt{payload, ed25519.Sign(key, payload)})
	record := sshAccessEvidence{1, sshAccessEvidenceDomain, request.Transaction, request.Plan, strings.Repeat("f", 64), request.Intent, request.Target, strings.Repeat("9", 64), digestBytes(public), now.Unix(), requestWire, challenge, signed, true, ""}
	valid, _ := json.Marshal(record)
	approvedChallenge := digestBytes(challenge)
	if _, _, _, err := decodeSSHAccessEvidence(valid, sshAccessEvidenceApproval{digestBytes(valid), approvedChallenge, public}, now); err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"schema":1,"schema":1}`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maxSSHAccessEvidenceBytes {
			return
		}
		approval := sshAccessEvidenceApproval{digestBytes(wire), approvedChallenge, public}
		got, verified, challenge, err := decodeSSHAccessEvidence(wire, approval, now)
		if err != nil {
			if !reflect.DeepEqual(got, sshAccessEvidence{}) || verified != (sshAccessReceiptAssessment{}) || challenge != (sshAccessChallenge{}) {
				t.Fatal("partial untrusted decode")
			}
			return
		}
		canonical, err := json.Marshal(got)
		if err != nil || !bytes.Equal(canonical, wire) || !verified.RecoveryRequired || !got.RecoveryRequired {
			t.Fatal("noncanonical accepted")
		}
	})
}

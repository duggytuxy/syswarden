//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type sshIssuanceFixture struct {
	f            *inventoryFixture
	plan         migrationPlan
	deps         sshTransactionDependencies
	journal      *sshJournal
	target, jump *sshProbeFixture
	credentials  []sshAccessCredentials
	run          sshParserRun
	observe      sshEndpointObserver
	authority    *sshAccessAuthority
	key          ed25519.PrivateKey
	now          time.Time
	request      []byte
	issuedImage  string
}

func accessIssuanceFixture(t *testing.T) *sshIssuanceFixture {
	t.Helper()
	f, plan, deps, journal, target, jump, pins, credentials, run, observe := protectedAccessFixture(t, func(f *inventoryFixture) { f.write(sshAccessAuthorityPath, "") })
	public, key := receiptController(t)
	now := time.Now().Truncate(time.Second)
	routes := make([]sshAccessAuthorityRoute, len(pins))
	for i, pin := range pins {
		routes[i] = sshAccessAuthorityRoute(pin)
	}
	doc := sshAccessAuthorityDocument{1, sshAccessAuthorityDomain, "activation-access", plan.summary.PlanSHA256, public, routes, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix()}
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f.write(sshAccessAuthorityPath, string(wire))
	x := &sshIssuanceFixture{f: f, plan: plan, deps: deps, journal: journal, target: target, jump: jump, credentials: credentials, run: run, observe: observe, key: key, now: now}
	x.authority, err = openSSHAccessAuthority(f.root, os.Geteuid(), plan.summary.PlanSHA256, digestBytes(wire), func() time.Time { return x.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.authority.Close() })
	x.request, err = prepareSSHActivationAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, observe, x.authority.pins)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *sshIssuanceFixture) issue(ctx context.Context, approved string) (sshAccessIssuanceResult, error) {
	got, err := issueSSHAuthorizedAccessChallenge(ctx, x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority, approved, time.Minute, func() time.Time { return x.now })
	if got.IssuanceImageSHA256 != "" {
		x.issuedImage = got.IssuanceImageSHA256
	}
	return got, err
}
func (x *sshIssuanceFixture) reopen(t *testing.T) {
	t.Helper()
	if err := x.journal.Close(); err != nil {
		t.Fatal(err)
	}
	x.journal = fixtureJournal(t, x.f)
}
func (x *sshIssuanceFixture) receipt(t *testing.T, issued sshAccessIssuanceResult) []byte {
	t.Helper()
	wire, err := probeSSHAccessChallenge(t.Context(), issued.Request, issued.Challenge, digestBytes(issued.Challenge), x.key, x.credentials, func() time.Time { return x.now }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func (x *sshIssuanceFixture) record(t *testing.T, approved string, receipt []byte) (sshAccessEvidenceResult, error) {
	t.Helper()
	return recordSSHAuthorizedAccessEvidence(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority, approved, x.issuedImage, receipt, func() time.Time { return x.now })
}

func TestSSHIssuedAccessProtectedRoundTrip(t *testing.T) {
	x := accessIssuanceFixture(t)
	before, err := observeSSHOwnedRecordSet(x.journal, true)
	if err != nil {
		t.Fatal(err)
	}
	syncs := 0
	x.journal.syncDirectory = func(d *os.File) error { syncs++; return d.Sync() }
	issued, err := x.issue(t.Context(), digestBytes(x.request))
	if err != nil || !issued.IssuanceDurable || !issued.RecoveryRequired || !bytes.Equal(issued.Request, x.request) || !lowerDigest.MatchString(issued.IssuanceSHA256) || syncs != 1 || !x.journal.poisoned {
		t.Fatal(issued, err, syncs)
	}
	if x.target.connections.Load() != 0 || x.jump.connections.Load() != 0 {
		t.Fatal("issuance reached network")
	}
	x.reopen(t)
	image, err := readSSHPrivateChild(x.journal.directory, sshAccessIssuanceName, x.journal.uid, maxSSHAccessIssuanceBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeSSHAccessIssuance(image.data, issued.IssuanceSHA256, x.authority, x.now)
	if err != nil || record.Enrollment != x.authority.digest || record.EnrollmentImage != sshImageDigest(x.authority.image) {
		t.Fatal(record, err)
	}
	for name, hash := range before {
		all, err := observeSSHIssuedRecordMembership(x.journal, true, false, true)
		if err != nil || all[name] != hash {
			t.Fatal("issuance changed original history", name, err)
		}
	}
	if _, err := x.issue(t.Context(), digestBytes(x.request)); err == nil {
		t.Fatal("reopened issuance replay")
	}
	receipt := x.receipt(t, issued)
	connections := x.target.connections.Load() + x.jump.connections.Load()
	result, err := x.record(t, issued.IssuanceSHA256, receipt)
	if err != nil || !result.RecordDurable || !result.RecoveryRequired || !x.journal.poisoned || result.Transaction != issued.Transaction {
		t.Fatal(result, err)
	}
	if x.target.connections.Load()+x.jump.connections.Load() != connections {
		t.Fatal("target recorder authenticated")
	}
	x.reopen(t)
	after, err := observeSSHIssuedRecordMembership(x.journal, true, true, true)
	if err != nil || len(after) != 11 {
		t.Fatal(after, err)
	}
	for name, hash := range before {
		if after[name] != hash {
			t.Fatal("original history changed", name)
		}
	}
	evidence, err := readSSHPrivateChild(x.journal.directory, sshAccessEvidenceName, x.journal.uid, maxSSHAccessEvidenceBytes)
	if err != nil {
		t.Fatal(err)
	}
	var ev sshAccessEvidence
	if err := json.Unmarshal(evidence.data, &ev); err != nil || ev.Issuance != sshImageDigest(image) {
		t.Fatal("evidence lost issuance", err)
	}
	approval := sshAccessEvidenceApproval{result.RecordSHA256, digestBytes(issued.Challenge), x.authority.controller}
	observed, err := observeSSHActivationAccessEvidence(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority.pins, approval, func() time.Time { return x.now }, x.authority.recheck)
	if err != nil || !observed.HistoricalSignatureVerified || !observed.CurrentRequestMatches || !observed.DurabilityUnknown || !observed.RecoveryRequired {
		t.Fatal(observed, err)
	}
	if _, err := x.record(t, issued.IssuanceSHA256, receipt); err == nil {
		t.Fatal("recorded receipt replay")
	}
}

func TestSSHIssuanceRefusesUnauthorizedOrUncertainDelivery(t *testing.T) {
	for _, scenario := range []string{"wrong-request", "wrong-plan", "cancelled", "revoked", "clock-backward", "occupied", "directory-sync", "late-revocation", "late-expiry", "enrollment-window"} {
		t.Run(scenario, func(t *testing.T) {
			x := accessIssuanceFixture(t)
			approved := digestBytes(x.request)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "wrong-request":
				approved = strings.Repeat("f", 64)
			case "wrong-plan":
				x.authority.plan = strings.Repeat("f", 64)
			case "cancelled":
				cancel()
			case "revoked":
				if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
			case "clock-backward":
				x.now = x.now.Add(-time.Second)
			case "occupied":
				if err := x.journal.writeRecord(sshAccessIssuanceName, []byte("interrupted issuance")); err != nil {
					t.Fatal(err)
				}
			case "directory-sync":
				x.journal.syncDirectory = func(*os.File) error { return unix.EIO }
			case "late-revocation":
				x.journal.syncDirectory = func(d *os.File) error { return errors.Join(d.Sync(), os.Remove(x.f.path(sshAccessAuthorityPath))) }
			case "late-expiry":
				x.journal.syncDirectory = func(d *os.File) error { x.now = x.now.Add(2 * time.Minute); return d.Sync() }
			case "enrollment-window":
				x.now = time.Unix(x.authority.expiresAt-30, 0)
			}
			got, err := x.issue(ctx, approved)
			if err == nil || len(got.Request) != 0 || len(got.Challenge) != 0 {
				t.Fatal("failed issuance delivered challenge", got, err)
			}
			written := scenario == "directory-sync" || scenario == "late-revocation" || scenario == "late-expiry"
			if got.RecoveryRequired != written || got.IssuanceDurable != (scenario == "late-revocation" || scenario == "late-expiry") || (written && !x.journal.poisoned) {
				t.Fatal("lost write uncertainty", got, err)
			}
			if x.target.connections.Load() != 0 || x.jump.connections.Load() != 0 {
				t.Fatal("issuance authenticated")
			}
			if scenario == "directory-sync" && (got.IssuanceSHA256 != "" || got.IssuanceImageSHA256 != "") {
				t.Fatal("uncertain write returned an approval", got)
			}
			if written {
				x.reopen(t)
				if scenario == "directory-sync" {
					if result, err := x.record(t, got.IssuanceSHA256, []byte("untrusted receipt")); err == nil || result.RecordDurable {
						t.Fatal("reopening reconstructed writer approval", result, err)
					}
				}
				if _, err := x.journal.readRecord(sshAccessIssuanceName); err != nil {
					t.Fatal("failed write evidence lost", err)
				}
				if _, err := assessSSHActivation(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe); err == nil {
					t.Fatal("uncertain issuance bypassed fence")
				}
			}
		})
	}
}

func TestSSHIssuedReceiptRejectsChangedAuthorityOrEvidence(t *testing.T) {
	for _, scenario := range []string{"wrong-approval", "invalid-signature", "different-challenge", "enrollment-replacement", "enrollment-reopened-replacement", "enrollment-reapproved-key", "enrollment-reapproved-route", "enrollment-revoked", "expired", "original-history-replaced", "issuance-replaced-during-check", "issuance-replaced-before-reopen", "wrong-image", "late-revocation"} {
		t.Run(scenario, func(t *testing.T) {
			x := accessIssuanceFixture(t)
			issued, err := x.issue(t.Context(), digestBytes(x.request))
			if err != nil {
				t.Fatal(err)
			}
			receipt := x.receipt(t, issued)
			x.reopen(t)
			approved := issued.IssuanceSHA256
			switch scenario {
			case "wrong-approval":
				approved = strings.Repeat("e", 64)
			case "invalid-signature":
				receipt[len(receipt)-3] ^= 1
			case "different-challenge":
				other, err := newSSHAccessChallenge(issued.Request, digestBytes(issued.Request), x.authority.controller, x.now, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				altered := issued
				altered.Challenge = other
				receipt = x.receipt(t, altered)
			case "enrollment-replacement":
				wire := bytes.Clone(x.authority.image.data)
				if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
				x.f.write(sshAccessAuthorityPath, string(wire))
			case "enrollment-reopened-replacement", "enrollment-reapproved-key", "enrollment-reapproved-route":
				var doc sshAccessAuthorityDocument
				if err := json.Unmarshal(x.authority.image.data, &doc); err != nil {
					t.Fatal(err)
				}
				if scenario == "enrollment-reapproved-key" {
					doc.Controller, _ = receiptController(t)
				}
				if scenario == "enrollment-reapproved-route" {
					doc.Routes[0].Target.User = "another"
				}
				wire, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := x.authority.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
				x.f.write(sshAccessAuthorityPath, string(wire))
				x.authority, err = openSSHAccessAuthority(x.f.root, os.Geteuid(), x.plan.summary.PlanSHA256, digestBytes(wire), func() time.Time { return x.now })
				if err != nil {
					t.Fatal("new independently approved enrollment did not open", err)
				}
			case "enrollment-revoked":
				if err := os.Remove(x.f.path(sshAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
			case "expired":
				x.now = x.now.Add(2 * time.Minute)
			case "original-history-replaced":
				wire, err := x.journal.readRecord(sshPreparedRecord)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(x.f.path(sshJournalDirectory + "/" + sshPreparedRecord)); err != nil {
					t.Fatal(err)
				}
				x.f.write(sshJournalDirectory+"/"+sshPreparedRecord, string(wire))
			case "wrong-image":
				x.issuedImage = strings.Repeat("f", 64)
			case "issuance-replaced-before-reopen":
				wire, err := x.journal.readRecord(sshAccessIssuanceName)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(x.f.path(sshJournalDirectory + "/" + sshAccessIssuanceName)); err != nil {
					t.Fatal(err)
				}
				x.f.write(sshJournalDirectory+"/"+sshAccessIssuanceName, string(wire))
				x.reopen(t)
			case "issuance-replaced-during-check":
				previous := x.deps.checkParser
				changed := false
				x.deps.checkParser = func() error {
					if !changed {
						changed = true
						wire, err := x.journal.readRecord(sshAccessIssuanceName)
						if err != nil {
							return err
						}
						if err := os.Remove(x.f.path(sshJournalDirectory + "/" + sshAccessIssuanceName)); err != nil {
							return err
						}
						x.f.write(sshJournalDirectory+"/"+sshAccessIssuanceName, string(wire))
					}
					return previous()
				}
			case "late-revocation":
				x.journal.syncDirectory = func(d *os.File) error { return errors.Join(d.Sync(), os.Remove(x.f.path(sshAccessAuthorityPath))) }
			}
			got, err := x.record(t, approved, receipt)
			if err == nil {
				t.Fatal("changed evidence accepted", got)
			}
			if scenario == "late-revocation" {
				if !got.RecordDurable || !got.RecoveryRequired || !x.journal.poisoned {
					t.Fatal("lost late write facts", got)
				}
			} else if !reflect.DeepEqual(got, sshAccessEvidenceResult{}) {
				t.Fatal("rejection invented write", got)
			}
		})
	}
}

func TestSSHIssuanceOpaqueRecoveryRetainsAllSeventeenRecords(t *testing.T) {
	f, plan, deps, journal := runtimeRecoveryFixture(t, true, false)
	// Malformed/expired/revoked issuance is opaque history during restoration.
	opaque := []byte("uncertain issuance, never authority")
	if err := journal.writeRecord(sshAccessIssuanceName, opaque); err != nil {
		t.Fatal(err)
	}
	before, err := observeSSHRuntimeRecoveryRecords(journal)
	if err != nil || len(before) != 11 {
		t.Fatal(before, err)
	}
	calls, closes := 0, 0
	bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
	approval := runtimeRecoveryPlan(t, journal, plan, deps, bind)
	got, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approval, deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if err != nil || !got.ConfigurationRestored || !got.RequestReturned || !got.RecoveryRequired || calls != 1 {
		t.Fatal(got, err, calls)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	after, err := observeSSHRuntimeRecoveryRecords(journal)
	if err != nil || len(after) != 17 {
		t.Fatal(after, err)
	}
	for name, hash := range before {
		if after[name] != hash {
			t.Fatal("restoration changed historical evidence", name)
		}
	}
	retained, err := journal.readRecord(sshAccessIssuanceName)
	if err != nil || !bytes.Equal(retained, opaque) {
		t.Fatal(err)
	}
}

func TestSSHIssuanceDecoderCanonicalCrossBindings(t *testing.T) {
	x := accessIssuanceFixture(t)
	_, err := x.issue(t.Context(), digestBytes(x.request))
	if err != nil {
		t.Fatal(err)
	}
	x.reopen(t)
	wire, err := x.journal.readRecord(sshAccessIssuanceName)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"schema", "domain", "transaction", "plan", "parser", "intent", "target", "records", "enrollment", "enrollment-image", "recovery", "request", "challenge-request", "challenge-controller", "challenge-expired", "unknown", "duplicate", "case-folded", "whitespace", "trailing", "oversized", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			var record sshAccessIssuance
			if err := json.Unmarshal(wire, &record); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "schema":
				record.Schema++
			case "domain":
				record.Domain = "foreign"
			case "transaction":
				record.Transaction = strings.Repeat("f", 64)
			case "plan":
				record.Plan = strings.Repeat("f", 64)
			case "parser":
				record.Parser = "invalid"
			case "intent":
				record.Intent = strings.Repeat("f", 64)
			case "target":
				record.Target = strings.Repeat("f", 64)
			case "records":
				record.Records = "invalid"
			case "enrollment":
				record.Enrollment = strings.Repeat("f", 64)
			case "enrollment-image":
				record.EnrollmentImage = strings.Repeat("f", 64)
			case "recovery":
				record.RecoveryRequired = false
			case "request":
				record.Request = []byte("{}")
			case "challenge-request", "challenge-controller", "challenge-expired":
				var challenge sshAccessChallenge
				if err := json.Unmarshal(record.Challenge, &challenge); err != nil {
					t.Fatal(err)
				}
				if scenario == "challenge-request" {
					challenge.Request = strings.Repeat("f", 64)
				}
				if scenario == "challenge-controller" {
					challenge.Controller = strings.Repeat("f", 64)
				}
				if scenario == "challenge-expired" {
					challenge.IssuedAt = x.now.Unix() - 60
					challenge.ExpiresAt = x.now.Unix()
				}
				record.Challenge, err = json.Marshal(challenge)
				if err != nil {
					t.Fatal(err)
				}
			}
			changed, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unknown":
				changed = bytes.Replace(changed, []byte("{"), []byte(`{"unknown":true,`), 1)
			case "duplicate":
				changed = bytes.Replace(changed, []byte("{"), []byte(`{"schema":1,`), 1)
			case "case-folded":
				changed = bytes.Replace(changed, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "whitespace":
				changed = append(changed, '\n')
			case "trailing":
				changed = append(changed, []byte("{}")...)
			case "oversized":
				changed = bytes.Repeat([]byte("x"), maxSSHAccessIssuanceBytes+1)
			case "empty":
				changed = nil
			}
			got, err := decodeSSHAccessIssuance(changed, digestBytes(changed), x.authority, x.now)
			if err == nil || !reflect.DeepEqual(got, sshAccessIssuance{}) {
				t.Fatal("independently approved malformed issuance accepted", scenario, err)
			}
		})
	}
}

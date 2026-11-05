//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type restoredAccessFixtureState struct {
	*sshIssuanceFixture
	recovery          string
	activationRequest []byte
	history           map[string]string
}

func restoredAccessFixture(t *testing.T) *restoredAccessFixtureState {
	t.Helper()
	f, plan, deps, journal, target, jump, pins, credentials, run, observe := protectedAccessFixture(t, func(f *inventoryFixture) {
		f.write(sshAccessAuthorityPath, "")
		f.write(sshRestoredAccessAuthorityPath, "")
	})
	activationRequest, err := prepareSSHActivationAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, observe, pins)
	if err != nil {
		t.Fatal(err)
	}
	// Restoration preserves arbitrary previous observations without promoting
	// their text, their age or their signatures into new access authority.
	for name, data := range map[string][]byte{sshAccessIssuanceName: []byte("opaque old issuance"), sshAccessEvidenceName: []byte(`{"historical":"not authority"}`)} {
		if err := journal.writeRecord(name, data); err != nil {
			t.Fatal(err)
		}
	}
	calls, closes := 0, 0
	bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
	recovery := runtimeRecoveryPlan(t, journal, plan, deps, bind)
	restored, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, recovery, deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if err != nil || !restored.ConfigurationRestored || !restored.RecoveryRequired || calls != 1 {
		t.Fatal("restored fixture", restored, calls, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	history, err := observeSSHRuntimeRecoveryRecords(journal)
	if err != nil || len(history) != 17 {
		t.Fatal("restored fixture history", len(history), err)
	}
	public, key := receiptController(t)
	now := time.Now().Truncate(time.Second)
	routes := make([]sshAccessAuthorityRoute, len(pins))
	for i, pin := range pins {
		routes[i] = sshAccessAuthorityRoute(pin)
	}
	doc := sshRestoredAccessAuthorityDocument{Schema: 1, Domain: sshRestoredAccessAuthorityDomain, Scope: "restoration-access", PlanSHA256: plan.summary.PlanSHA256, RecoverySHA256: recovery, Controller: public, Routes: routes, NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f.write(sshRestoredAccessAuthorityPath, string(wire))
	x := &restoredAccessFixtureState{sshIssuanceFixture: &sshIssuanceFixture{f: f, plan: plan, deps: deps, journal: journal, target: target, jump: jump, credentials: credentials, run: run, observe: observe, key: key, now: now}, recovery: recovery, activationRequest: activationRequest, history: history}
	x.authority, err = openSSHRestoredAccessAuthority(f.root, os.Geteuid(), plan.summary.PlanSHA256, recovery, digestBytes(wire), func() time.Time { return x.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.authority.Close(); clear(key) })
	x.request, err = prepareSSHRestoredAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, recovery, deps.parserDigest, run, deps.checkParser, observe, pins)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *restoredAccessFixtureState) issue(ctx context.Context, approved string) (sshAccessIssuanceResult, error) {
	got, err := issueSSHAuthorizedRestoredAccessChallenge(ctx, x.journal, x.plan.summary.PlanSHA256, x.recovery, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority, approved, time.Minute, func() time.Time { return x.now })
	if got.IssuanceImageSHA256 != "" {
		x.issuedImage = got.IssuanceImageSHA256
	}
	return got, err
}
func (x *restoredAccessFixtureState) receipt(t *testing.T, issued sshAccessIssuanceResult) []byte {
	t.Helper()
	wire, err := probeSSHAccessChallengeWithParser(t.Context(), issued.Request, issued.Challenge, digestBytes(issued.Challenge), x.key, x.credentials, func() time.Time { return x.now }, func() error { return nil }, normalizedSSHRestoredAccessRequest)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func (x *restoredAccessFixtureState) record(ctx context.Context, approved string, receipt []byte) (sshAccessEvidenceResult, error) {
	return recordSSHAuthorizedRestoredAccessEvidence(ctx, x.journal, x.plan.summary.PlanSHA256, x.recovery, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority, approved, x.issuedImage, receipt, func() time.Time { return x.now })
}
func (x *restoredAccessFixtureState) inspect(ctx context.Context, issued sshAccessIssuanceResult, record string) (RestoredAccessInspection, error) {
	return inspectSSHAuthorizedRestoredAccess(ctx, x.journal, x.plan.summary.PlanSHA256, x.recovery, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority, issued.IssuanceSHA256, x.issuedImage, record, func() time.Time { return x.now })
}
func (x *restoredAccessFixtureState) assertHistory(t *testing.T) {
	t.Helper()
	for name, want := range x.history {
		image, err := readSSHPrivateChild(x.journal.directory, name, x.journal.uid, maxSSHJournalBytes)
		if err != nil || sshImageDigest(image) != want {
			t.Fatal("restored exchange changed old history", name, err)
		}
	}
}

func TestSSHRestoredAccessProtectedRoundTripAndPurposeIsolation(t *testing.T) {
	x := restoredAccessFixture(t)
	if !bytes.Contains(x.request, []byte(`"domain":"syswarden-ssh-restoration-access-request-v1"`)) || !bytes.Contains(x.request, []byte(x.recovery)) {
		t.Fatal("restored request lost explicit purpose/recovery binding")
	}
	if _, err := parseSSHAccessRequest(x.request, digestBytes(x.request)); err == nil {
		t.Fatal("activation accepted restoration request")
	}
	if _, err := parseSSHRestoredAccessRequest(x.activationRequest, digestBytes(x.activationRequest)); err == nil {
		t.Fatal("restoration accepted activation request")
	}
	activationChallenge, err := newSSHAccessChallenge(x.activationRequest, digestBytes(x.activationRequest), x.authority.controller, x.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probeSSHAccessChallengeWithParser(t.Context(), x.activationRequest, activationChallenge, digestBytes(activationChallenge), x.key, x.credentials, func() time.Time { return x.now }, func() error { return nil }, normalizedSSHRestoredAccessRequest); err == nil {
		t.Fatal("activation challenge crossed into restoration")
	}
	issued, err := x.issue(t.Context(), digestBytes(x.request))
	if err != nil || !issued.IssuanceDurable || !issued.RecoveryRequired || !x.journal.poisoned {
		t.Fatal(issued, err)
	}
	if x.target.connections.Load() != 0 || x.jump.connections.Load() != 0 {
		t.Fatal("target issuance authenticated")
	}
	if _, err := probeSSHAccessChallenge(t.Context(), issued.Request, issued.Challenge, digestBytes(issued.Challenge), x.key, x.credentials, func() time.Time { return x.now }, func() error { return nil }); err == nil {
		t.Fatal("restoration challenge crossed into activation")
	}
	x.reopen(t)
	if _, err := x.issue(t.Context(), digestBytes(x.request)); err == nil {
		t.Fatal("issuance replay after reopening")
	}
	x.journal.syncDirectory = func(*os.File) error { t.Fatal("read-only inspection synced journal"); return unix.EIO }
	inspected, err := x.inspect(t.Context(), issued, "")
	if err != nil || !inspected.IssuanceObserved || inspected.ReceiptObserved || !inspected.RecoveryRequired {
		t.Fatal(inspected, err)
	}
	x.reopen(t)
	activationReceipt, err := probeSSHAccessChallenge(t.Context(), x.activationRequest, activationChallenge, digestBytes(activationChallenge), x.key, x.credentials, func() time.Time { return x.now }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if result, err := x.record(t.Context(), issued.IssuanceSHA256, activationReceipt); err == nil || result.RecordDurable {
		t.Fatal("activation receipt authorized restored access", result, err)
	}
	receipt := x.receipt(t, issued)
	if result, err := recordSSHAuthorizedAccessEvidence(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority, issued.IssuanceSHA256, x.issuedImage, receipt, func() time.Time { return x.now }); err == nil || result.RecordDurable {
		t.Fatal("restored receipt authorized activation access", result, err)
	}
	connections := x.target.connections.Load() + x.jump.connections.Load()
	if connections == 0 {
		t.Fatal("controller never authenticated")
	}
	recorded, err := x.record(t.Context(), issued.IssuanceSHA256, receipt)
	if err != nil || !recorded.RecordDurable || !recorded.RecoveryRequired || !x.journal.poisoned {
		t.Fatal(recorded, err)
	}
	if connections != x.target.connections.Load()+x.jump.connections.Load() {
		t.Fatal("target recorder authenticated")
	}
	x.reopen(t)
	x.assertHistory(t)
	x.journal.syncDirectory = func(*os.File) error { t.Fatal("inspection repaired durability"); return unix.EIO }
	inspected, err = x.inspect(t.Context(), issued, recorded.RecordSHA256)
	if err != nil || !inspected.IssuanceObserved || !inspected.ReceiptObserved || !inspected.RecoveryRequired || inspected.RecordSHA256 != recorded.RecordSHA256 {
		t.Fatal(inspected, err)
	}
	if _, err := x.inspect(t.Context(), issued, ""); err == nil {
		t.Fatal("issuance-only inspection ignored occupied receipt slot")
	}
	if _, err := x.record(t.Context(), issued.IssuanceSHA256, receipt); err == nil {
		t.Fatal("receipt replay accepted")
	}
	if _, err := assessSSHRuntimeRecovery(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.recovery, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe); err == nil {
		t.Fatal("old recovery observer silently adopted new access records")
	}
	for _, name := range []string{sshRestoredAccessIssuanceName, sshRestoredAccessEvidenceName} {
		wire, err := x.journal.readRecord(name)
		if err != nil || !bytes.Contains(wire, []byte(`"recovery_required":true`)) || bytes.Contains(wire, []byte("PRIVATE KEY")) {
			t.Fatal("restored record lost uncertainty or leaked credentials", name, err)
		}
	}
}

func TestSSHRestoredAccessAuthorityRequiresIndependentPurpose(t *testing.T) {
	x := restoredAccessFixture(t)
	original := bytes.Clone(x.authority.image.data)
	for _, scenario := range []string{"activation-domain", "activation-scope", "wrong-plan", "wrong-recovery", "empty-recovery", "extra-field", "duplicate-field", "unapproved", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			var doc sshRestoredAccessAuthorityDocument
			if err := json.Unmarshal(original, &doc); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "activation-domain":
				doc.Domain = sshAccessAuthorityDomain
			case "activation-scope":
				doc.Scope = "activation-access"
			case "wrong-plan":
				doc.PlanSHA256 = strings.Repeat("f", 64)
			case "wrong-recovery":
				doc.RecoverySHA256 = strings.Repeat("f", 64)
			case "empty-recovery":
				doc.RecoverySHA256 = ""
			case "expired":
				doc.ExpiresAt = x.now.Add(-time.Second).Unix()
			}
			wire, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "extra-field" {
				wire = append(wire[:len(wire)-1], []byte(`,"extra":true}`)...)
			}
			if scenario == "duplicate-field" {
				wire = append(wire[:len(wire)-1], []byte(`,"schema":1}`)...)
			}
			x.f.write(sshRestoredAccessAuthorityPath, string(wire))
			approved := digestBytes(wire)
			if scenario == "unapproved" {
				approved = strings.Repeat("f", 64)
			}
			authority, err := openSSHRestoredAccessAuthority(x.f.root, os.Geteuid(), x.plan.summary.PlanSHA256, x.recovery, approved, func() time.Time { return x.now })
			if err == nil {
				_ = authority.Close()
				t.Fatal("invalid restored authority accepted")
			}
		})
	}
	// Exact restoration bytes cannot be relabeled as activation enrollment.
	x.f.write(sshAccessAuthorityPath, string(original))
	authority, err := openSSHAccessAuthority(x.f.root, os.Geteuid(), x.plan.summary.PlanSHA256, digestBytes(original), func() time.Time { return x.now })
	if err == nil {
		_ = authority.Close()
		t.Fatal("restoration enrollment authorized activation")
	}
}

func TestSSHRestoredIssuanceRefusesChangedGraphAndLostDelivery(t *testing.T) {
	for _, scenario := range []string{"wrong-request", "wrong-plan", "wrong-recovery", "wrong-parser", "cancelled", "revoked", "expired", "occupied", "orphan-evidence", "missing-completion", "changed-reload", "old-history-image", "late-main-drift", "late-cancel", "directory-sync", "late-revocation", "late-expiry", "late-endpoint"} {
		t.Run(scenario, func(t *testing.T) {
			x := restoredAccessFixture(t)
			approved := digestBytes(x.request)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "wrong-request":
				approved = strings.Repeat("e", 64)
			case "wrong-plan":
				x.plan.summary.PlanSHA256 = strings.Repeat("e", 64)
			case "wrong-recovery":
				x.recovery = strings.Repeat("e", 64)
			case "wrong-parser":
				x.deps.parserDigest = strings.Repeat("e", 64)
			case "cancelled":
				cancel()
			case "revoked":
				if err := os.Remove(x.f.path(sshRestoredAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
			case "expired":
				x.now = x.now.Add(2 * time.Hour)
			case "occupied":
				if err := x.journal.writeRecord(sshRestoredAccessIssuanceName, []byte("interrupted issuance")); err != nil {
					t.Fatal(err)
				}
			case "orphan-evidence":
				if err := x.journal.writeRecord(sshRestoredAccessEvidenceName, []byte("orphan receipt")); err != nil {
					t.Fatal(err)
				}
			case "missing-completion":
				if err := os.Remove(x.f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryPhase(2, true))); err != nil {
					t.Fatal(err)
				}
			case "changed-reload":
				x.f.write(sshJournalDirectory+"/"+sshRuntimeRecoveryReloadName, `{"schema":1}`)
			case "old-history-image":
				replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshPreparedRecord)
			case "late-main-drift", "late-cancel":
				previous := x.observe
				x.observe = func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
					got, err := previous(ctx, expected, guard)
					if scenario == "late-cancel" {
						cancel()
					} else {
						x.f.write(MainPath, "changed after assessment\n")
					}
					return got, err
				}
			case "late-endpoint":
				drift := false
				original := x.observe
				x.observe = func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
					got, err := original(ctx, expected, guard)
					if drift {
						got.SocketsSHA256 = strings.Repeat("c", 64)
					}
					return got, err
				}
				x.journal.syncDirectory = func(d *os.File) error { err := d.Sync(); drift = true; return err }
			case "directory-sync":
				x.journal.syncDirectory = func(*os.File) error { return unix.EIO }
			case "late-revocation":
				x.journal.syncDirectory = func(d *os.File) error {
					return errors.Join(d.Sync(), os.Remove(x.f.path(sshRestoredAccessAuthorityPath)))
				}
			case "late-expiry":
				x.journal.syncDirectory = func(d *os.File) error { x.now = x.now.Add(2 * time.Minute); return d.Sync() }
			}
			got, err := x.issue(ctx, approved)
			if err == nil || len(got.Request) != 0 || len(got.Challenge) != 0 {
				t.Fatal("unsafe issuance delivered challenge", got, err)
			}
			wrote := scenario == "directory-sync" || scenario == "late-revocation" || scenario == "late-expiry" || scenario == "late-endpoint"
			durable := scenario == "late-revocation" || scenario == "late-expiry" || scenario == "late-endpoint"
			if got.RecoveryRequired != wrote || got.IssuanceDurable != durable || wrote && !x.journal.poisoned {
				t.Fatal("lost issuance write facts", got, err)
			}
			if x.target.connections.Load() != 0 || x.jump.connections.Load() != 0 {
				t.Fatal("rejected target issuance authenticated")
			}
			if wrote {
				x.reopen(t)
				image, err := readSSHPrivateChild(x.journal.directory, sshRestoredAccessIssuanceName, x.journal.uid, maxSSHAccessIssuanceBytes)
				if err != nil || len(image.data) == 0 {
					t.Fatal("uncertain evidence removed", err)
				}
				if _, err := x.issue(t.Context(), approved); err == nil {
					t.Fatal("lost delivery reused issuance slot")
				}
				if scenario == "directory-sync" && (got.IssuanceSHA256 != "" || got.IssuanceImageSHA256 != "") {
					t.Fatal("uncertain sync invented writer approval")
				}
				x.assertHistory(t)
			}
		})
	}
}

func TestSSHRestoredReceiptRejectsRebindingAndLateUncertainty(t *testing.T) {
	for _, scenario := range []string{"wrong-issuance", "wrong-image", "invalid-signature", "cancelled", "expired", "revoked", "enrollment-image", "issuance-image", "history-image", "directory-sync", "late-revocation", "late-cancel", "late-endpoint"} {
		t.Run(scenario, func(t *testing.T) {
			x := restoredAccessFixture(t)
			issued, err := x.issue(t.Context(), digestBytes(x.request))
			if err != nil {
				t.Fatal(err)
			}
			receipt := x.receipt(t, issued)
			x.reopen(t)
			approved := issued.IssuanceSHA256
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "wrong-issuance":
				approved = strings.Repeat("e", 64)
			case "wrong-image":
				x.issuedImage = strings.Repeat("e", 64)
			case "invalid-signature":
				receipt[len(receipt)-3] ^= 1
			case "cancelled":
				cancel()
			case "expired":
				x.now = x.now.Add(2 * time.Minute)
			case "revoked":
				if err := os.Remove(x.f.path(sshRestoredAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
			case "enrollment-image":
				wire := bytes.Clone(x.authority.image.data)
				if err := os.Remove(x.f.path(sshRestoredAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
				x.f.write(sshRestoredAccessAuthorityPath, string(wire))
			case "issuance-image":
				replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshRestoredAccessIssuanceName)
			case "history-image":
				replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshPreparedRecord)
			case "late-endpoint":
				drift := false
				original := x.observe
				x.observe = func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
					got, err := original(ctx, expected, guard)
					if drift {
						got.SocketsSHA256 = strings.Repeat("c", 64)
					}
					return got, err
				}
				x.journal.syncDirectory = func(d *os.File) error { err := d.Sync(); drift = true; return err }
			case "directory-sync":
				x.journal.syncDirectory = func(*os.File) error { return unix.EIO }
			case "late-revocation":
				x.journal.syncDirectory = func(d *os.File) error {
					return errors.Join(d.Sync(), os.Remove(x.f.path(sshRestoredAccessAuthorityPath)))
				}
			case "late-cancel":
				x.journal.syncDirectory = func(d *os.File) error { cancel(); return d.Sync() }
			}
			got, err := x.record(ctx, approved, receipt)
			if err == nil {
				t.Fatal("changed restored receipt accepted", got)
			}
			wrote := scenario == "directory-sync" || scenario == "late-revocation" || scenario == "late-cancel" || scenario == "late-endpoint"
			if got.RecoveryRequired != wrote || got.RecordDurable != (wrote && scenario != "directory-sync") {
				t.Fatal("lost receipt uncertainty", got, err)
			}
			if wrote {
				x.reopen(t)
				if _, err := x.journal.readRecord(sshRestoredAccessEvidenceName); err != nil {
					t.Fatal("failed receipt evidence erased", err)
				}
				if _, err := x.record(t.Context(), approved, receipt); err == nil {
					t.Fatal("uncertain receipt reused slot")
				}
				x.assertHistory(t)
			}
		})
	}
}

func TestSSHRestoredAccessInspectionRejectsChangedEvidenceWithoutMutation(t *testing.T) {
	for _, scenario := range []string{"missing-record-approval", "wrong-record", "wrong-image", "expired", "revoked", "late-endpoint", "late-history", "invalid-signature", "wrong-binding"} {
		t.Run(scenario, func(t *testing.T) {
			x := restoredAccessFixture(t)
			issued, err := x.issue(t.Context(), digestBytes(x.request))
			if err != nil {
				t.Fatal(err)
			}
			receipt := x.receipt(t, issued)
			x.reopen(t)
			recorded, err := x.record(t.Context(), issued.IssuanceSHA256, receipt)
			if err != nil {
				t.Fatal(err)
			}
			x.reopen(t)
			approved := recorded.RecordSHA256
			switch scenario {
			case "missing-record-approval":
				approved = ""
			case "wrong-record":
				approved = strings.Repeat("c", 64)
			case "wrong-image":
				x.issuedImage = strings.Repeat("c", 64)
			case "expired":
				x.now = x.now.Add(2 * time.Minute)
			case "revoked":
				if err := os.Remove(x.f.path(sshRestoredAccessAuthorityPath)); err != nil {
					t.Fatal(err)
				}
			case "late-endpoint", "late-history":
				original := x.observe
				observations := 0
				x.observe = func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
					got, err := original(ctx, expected, guard)
					observations++
					if scenario == "late-endpoint" && observations > 1 {
						got.SocketsSHA256 = strings.Repeat("c", 64)
					}
					if scenario == "late-history" && observations == 1 {
						replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshPreparedRecord)
					}
					return got, err
				}
			case "invalid-signature", "wrong-binding":
				wire, err := x.journal.readRecord(sshRestoredAccessEvidenceName)
				if err != nil {
					t.Fatal(err)
				}
				var evidence sshRestoredAccessEvidence
				if err := json.Unmarshal(wire, &evidence); err != nil {
					t.Fatal(err)
				}
				if scenario == "invalid-signature" {
					evidence.Receipt[len(evidence.Receipt)-3] ^= 1
				} else {
					evidence.Restored = strings.Repeat("c", 64)
				}
				wire, err = json.Marshal(evidence)
				if err != nil {
					t.Fatal(err)
				}
				x.f.write(sshJournalDirectory+"/"+sshRestoredAccessEvidenceName, string(wire))
				approved = digestBytes(wire)
			}
			x.journal.syncDirectory = func(*os.File) error { t.Fatal("inspection attempted durability repair"); return unix.EIO }
			connections := x.target.connections.Load() + x.jump.connections.Load()
			got, err := x.inspect(t.Context(), issued, approved)
			if err == nil || got.IssuanceObserved || got.ReceiptObserved {
				t.Fatal("changed inspection returned claims", got, err)
			}
			if connections != x.target.connections.Load()+x.jump.connections.Load() {
				t.Fatal("inspection authenticated")
			}
			if scenario != "late-history" {
				x.assertHistory(t)
			}
		})
	}
}

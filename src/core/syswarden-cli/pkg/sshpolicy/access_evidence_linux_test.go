//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type sshEvidenceFixture struct {
	f            *inventoryFixture
	plan         migrationPlan
	deps         sshTransactionDependencies
	journal      *sshJournal
	target, jump *sshProbeFixture
	pins         []sshAccessRoutePins
	run          sshParserRun
	observe      sshEndpointObserver
	input        sshAccessReceiptInput
	now          time.Time
}

func accessEvidenceFixture(t *testing.T) *sshEvidenceFixture {
	t.Helper()
	f, plan, deps, journal, target, jump, pins, credentials, run, observe := protectedAccessFixture(t)
	request, err := prepareSSHActivationAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, observe, pins)
	if err != nil {
		t.Fatal(err)
	}
	input, _, now := signedAccessFixture(t, request, credentials)
	return &sshEvidenceFixture{f, plan, deps, journal, target, jump, pins, run, observe, input, now}
}

func (x *sshEvidenceFixture) record(ctx context.Context, clock func() time.Time, auth func() error) (sshAccessEvidenceResult, error) {
	return recordSSHActivationAccessEvidence(ctx, x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.pins, x.input, clock, auth)
}

func TestSSHAccessEvidenceDurableAndSingleUse(t *testing.T) {
	x := accessEvidenceFixture(t)
	history, err := observeSSHOwnedRecordSet(x.journal, true)
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
	syncs := 0
	x.journal.syncDirectory = func(d *os.File) error {
		syncs++
		competing, err := openSSHJournal(x.f.root, os.Geteuid())
		if err == nil {
			_ = competing.Close()
			t.Fatal("writer lost journal lock")
		}
		return d.Sync()
	}
	got, err := x.record(t.Context(), func() time.Time { return x.now }, func() error { return nil })
	if err != nil || !got.RecordDurable || !got.RecoveryRequired || got.Transaction != prepared.Transaction || syncs != 1 {
		t.Fatal(got, err, syncs)
	}
	if !x.journal.poisoned {
		t.Fatal("successful writer remained reusable")
	}
	storage, err := os.OpenRoot(x.f.base)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	name := strings.TrimPrefix(sshJournalDirectory, "/") + "/" + sshAccessEvidenceName
	wire, err := storage.ReadFile(name)
	if err != nil || digestBytes(wire) != got.RecordSHA256 {
		t.Fatal(err)
	}
	var record sshAccessEvidence
	if err := json.Unmarshal(wire, &record); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(record)
	original := make(map[string]string)
	for name, digest := range history {
		if name != sshActivationIntentName {
			original[name] = digest
		}
	}
	originalDigest, err2 := sshActivationDigest(original)
	if err != nil || err2 != nil || !bytes.Equal(canonical, wire) || record.Schema != 1 || record.Domain != sshAccessEvidenceDomain ||
		record.Transaction != prepared.Transaction || record.Plan != x.plan.summary.PlanSHA256 || record.Parser != x.deps.parserDigest ||
		record.Records != originalDigest || record.Controller != digestBytes(x.input.Controller) || record.AssessedAt != x.now.Unix() || !record.RecoveryRequired ||
		!bytes.Equal(record.Request, x.input.Request) || !bytes.Equal(record.Challenge, x.input.Challenge) || !bytes.Equal(record.Receipt, x.input.Receipt) {
		t.Fatal("lost original private observation", err, err2)
	}
	if x.target.connections.Load()+x.jump.connections.Load() != connections {
		t.Fatal("evidence writer opened network")
	}
	info, err := storage.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe evidence mode", err)
	}
	if _, err := x.record(t.Context(), func() time.Time { return x.now }, func() error { return nil }); err == nil {
		t.Fatal("same-handle replay")
	}
	if err := x.journal.Close(); err != nil {
		t.Fatal(err)
	}
	x.journal = fixtureJournal(t, x.f)
	observed, err := observeSSHRecordMembership(x.journal, true, true)
	if err != nil || len(observed) != 10 {
		t.Fatal(err)
	}
	for name, digest := range history {
		if observed[name] != digest {
			t.Fatal("original record changed", name)
		}
	}
	after, err := stableSSHRollback(x.journal, prepared.Transaction)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("configuration changed", err)
	}
	x.journal.syncDirectory = func(*os.File) error { t.Fatal("reopened evidence repaired or overwritten"); return unix.EIO }
	if replay, err := x.record(t.Context(), func() time.Time { return x.now }, func() error { return nil }); err == nil || replay != (sshAccessEvidenceResult{}) {
		t.Fatal("reopened receipt replay", replay, err)
	}
	if _, err := assessSSHActivationAccessReceipt(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.pins, x.input, func() time.Time { return x.now }, func() error { return nil }); err == nil {
		t.Fatal("reopened recorded receipt appraised as new")
	}
	if err := rollbackSSHConfiguration(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.deps.run, x.deps.checkParser, sshPublicationDefaults()); err == nil {
		t.Fatal("evidence cleared runtime recovery fence")
	}
	unchanged, err := storage.ReadFile(name)
	if err != nil || !bytes.Equal(wire, unchanged) {
		t.Fatal("evidence overwritten", err)
	}
	if err := x.journal.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "-test.run=^TestSSHAccessEvidenceSeparateProcess$", "-test.count=1")
	cmd.Env = []string{"SYSWARDEN_ACCESS_EVIDENCE_FIXTURE=yes", "SYSWARDEN_ACCESS_EVIDENCE_DIGEST=" + got.RecordSHA256, "GOMAXPROCS=2"}
	cmd.ExtraFiles = []*os.File{x.f.root}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("new process did not retain replay fence: %v %s", err, output)
	}
}

func TestSSHAccessEvidenceSeparateProcess(t *testing.T) {
	if os.Getenv("SYSWARDEN_ACCESS_EVIDENCE_FIXTURE") != "yes" {
		return
	}
	// Only the parent's disposable fixture root is inherited, never its journal
	// handle, locks or in-memory assessment. Open the journal afresh below.
	root := os.NewFile(3, "isolated-fixture-root")
	if root == nil {
		t.Fatal("missing inherited fixture root")
	}
	defer root.Close()
	journal, err := openSSHJournal(root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	wire, err := journal.readRecord(sshAccessEvidenceName)
	if err != nil || digestBytes(wire) != os.Getenv("SYSWARDEN_ACCESS_EVIDENCE_DIGEST") {
		t.Fatal("lost persisted evidence", err)
	}
	journal.syncDirectory = func(*os.File) error { t.Fatal("read-only reopen synced evidence"); return unix.EIO }
	if _, err := observeSSHOwnedRecordSet(journal, true); err == nil {
		t.Fatal("new process accepted consumed history")
	}
	if err := journal.requireNoSSHActivation(); err == nil {
		t.Fatal("new process lost activation fence")
	}
}

func TestSSHAccessEvidenceFailureBoundaries(t *testing.T) {
	scenarios := []string{"sync-failure", "same-byte-replacement", "hardlink", "mode", "policy-drift", "original-record-replaced", "unknown-entry", "expired", "clock-backwards", "revoked", "cancelled", "caller-mutation"}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			x := accessEvidenceFixture(t)
			original, _ := copySSHAccessReceiptInput(x.input)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			synced := false
			x.journal.syncDirectory = func(d *os.File) error {
				synced = true
				path := x.f.path(sshJournalDirectory + "/" + sshAccessEvidenceName)
				switch scenario {
				case "sync-failure":
					return unix.EIO
				case "same-byte-replacement":
					storage, err := os.OpenRoot(x.f.base)
					if err != nil {
						return err
					}
					defer storage.Close()
					name := strings.TrimPrefix(sshJournalDirectory, "/") + "/" + sshAccessEvidenceName
					content, err := storage.ReadFile(name)
					if err != nil {
						return err
					}
					if err := storage.Rename(name, "saved-evidence"); err != nil {
						return err
					}
					if err := storage.WriteFile(name, content, 0600); err != nil {
						return err
					}
				case "hardlink":
					if err := os.Link(path, x.f.path("/linked-evidence")); err != nil {
						return err
					}
				case "mode":
					if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- Intentionally unsafe isolated fixture mode; the writer must refuse its acknowledgement.
						return err
					}
				case "policy-drift":
					x.f.write(DropInPath, "AllowTcpForwarding yes\n")
				case "original-record-replaced":
					replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshActivationIntentName)
				case "unknown-entry":
					x.f.write(sshJournalDirectory+"/unexpected", "unowned")
				case "cancelled":
					cancel()
				case "caller-mutation":
					clear(x.input.Request)
					clear(x.input.Challenge)
					clear(x.input.Receipt)
					clear(x.input.Controller)
				}
				return d.Sync()
			}
			clock := func() time.Time {
				if synced {
					if scenario == "expired" {
						return x.now.Add(3 * time.Minute)
					}
					if scenario == "clock-backwards" {
						return x.now.Add(-time.Nanosecond)
					}
				}
				return x.now
			}
			auth := func() error {
				if synced && scenario == "revoked" {
					return ErrInventoryChanged
				}
				return nil
			}
			got, err := x.record(ctx, clock, auth)
			if scenario == "caller-mutation" {
				if err != nil || !got.RecordDurable {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("late failure claimed success", got)
			}
			if !synced || !got.RecoveryRequired || !x.journal.poisoned {
				t.Fatal("lost uncertain recovery", got)
			}
			unknownDurability := scenario == "sync-failure" || scenario == "same-byte-replacement" || scenario == "hardlink" || scenario == "mode"
			if got.RecordDurable == unknownDurability {
				t.Fatal("incorrect durability acknowledgement", scenario, got)
			}
			wire, readErr := os.ReadFile(x.f.path(sshJournalDirectory + "/" + sshAccessEvidenceName))
			if readErr != nil {
				t.Fatal("removed uncertain evidence", readErr)
			}
			var record sshAccessEvidence
			if err := json.Unmarshal(wire, &record); err != nil || !bytes.Equal(record.Request, original.Request) || !bytes.Equal(record.Challenge, original.Challenge) || !bytes.Equal(record.Receipt, original.Receipt) {
				t.Fatal("changed frozen evidence", err)
			}
			if err := x.journal.Close(); err != nil {
				t.Fatal(err)
			}
			x.journal = fixtureJournal(t, x.f)
			x.input = original
			if replay, err := x.record(t.Context(), func() time.Time { return x.now }, func() error { return nil }); err == nil || replay != (sshAccessEvidenceResult{}) {
				t.Fatal("replayed uncertain evidence", replay, err)
			}
		})
	}
}

func TestSSHAccessEvidenceRefusesBeforeWrite(t *testing.T) {
	for _, scenario := range []string{"bad-receipt", "wrong-key", "wrong-approval", "expired", "revoked", "cancelled", "policy-drift", "existing-empty", "existing-malformed", "existing-directory", "existing-symlink"} {
		t.Run(scenario, func(t *testing.T) {
			x := accessEvidenceFixture(t)
			path := x.f.path(sshJournalDirectory + "/" + sshAccessEvidenceName)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "bad-receipt":
				x.input.Receipt = []byte("{}")
			case "wrong-key":
				x.input.Controller, _ = receiptController(t)
			case "wrong-approval":
				x.input.ApprovedChallenge = strings.Repeat("f", 64)
			case "expired":
				x.now = x.now.Add(3 * time.Minute)
			case "cancelled":
				cancel()
			case "policy-drift":
				x.f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "existing-empty":
				x.f.write(sshJournalDirectory+"/"+sshAccessEvidenceName, "")
			case "existing-malformed":
				x.f.write(sshJournalDirectory+"/"+sshAccessEvidenceName, "uncertain")
			case "existing-directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "existing-symlink":
				if err := os.Symlink(x.f.path(MainPath), path); err != nil {
					t.Fatal(err)
				}
			}
			x.journal.syncDirectory = func(*os.File) error { t.Fatal("invalid input reached durable write"); return unix.EIO }
			auth := func() error {
				if scenario == "revoked" {
					return ErrInventoryChanged
				}
				return nil
			}
			got, err := x.record(ctx, func() time.Time { return x.now }, auth)
			if err == nil || got != (sshAccessEvidenceResult{}) {
				t.Fatal("invalid input accepted", got, err)
			}
			_, err = os.Lstat(path)
			if strings.HasPrefix(scenario, "existing-") {
				if err != nil {
					t.Fatal("deleted occupied evidence", err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid input wrote record", err)
			}
		})
	}
}

func TestSSHAccessEvidenceFinalGuard(t *testing.T) {
	calls := 0
	x := accessEvidenceFixture(t)
	if _, err := x.record(t.Context(), func() time.Time { return x.now }, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	final := calls
	for _, scenario := range []string{"policy-drift", "intent-replaced", "record-replaced", "cancelled", "revoked", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			x := accessEvidenceFixture(t)
			calls := 0
			now := x.now
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			auth := func() error {
				calls++
				if calls == final {
					switch scenario {
					case "policy-drift":
						x.f.write(DropInPath, "AllowTcpForwarding yes\n")
					case "intent-replaced":
						replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshActivationIntentName)
					case "record-replaced":
						replaceRestoredFixtureRecord(t, x.f, sshJournalDirectory+"/"+sshAccessEvidenceName)
					case "cancelled":
						cancel()
					case "revoked":
						return ErrInventoryChanged
					case "expired":
						now = x.now.Add(3 * time.Minute)
					}
				}
				return nil
			}
			got, err := x.record(ctx, func() time.Time { return now }, auth)
			if err == nil || calls != final || !got.RecordDurable || !got.RecoveryRequired || !x.journal.poisoned {
				t.Fatal("late callback escaped final guards", scenario, calls, final, got, err)
			}
		})
	}
}

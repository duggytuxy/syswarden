//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"

	"golang.org/x/sys/unix"
)

func transactionFixture(t *testing.T) (*inventoryFixture, migrationPlan, sshTransactionDependencies) {
	t.Helper()
	f := planFixture(t, includeDropIns+"PasswordAuthentication no\n")
	f.write(sshselection.Path, "[ssh]\nhardening = \"forwarding\"\n")
	if err := os.MkdirAll(f.path(sshStateParent), 0700); err != nil {
		t.Fatal(err)
	}
	return f, f.plan(), transactionFixtureDependencies(f)
}

func transactionFixtureDependencies(f *inventoryFixture) sshTransactionDependencies {
	return sshTransactionDependencies{
		parserDigest: strings.Repeat("a", 64), run: publicationFixtureParser(f),
		checkParser: func() error { return nil },
		resolveLabel: func(_ context.Context, snapshot inventorySnapshot) (*sshTargetLabel, error) {
			// Fixture files live under a temporary path, not the production
			// SELinux target. Retain its kernel-assigned fixture label only.
			attrs := make(map[string][]byte)
			if label, exists := snapshot.attributes[MainPath]["security.selinux"]; exists {
				attrs["security.selinux"] = bytes.Clone(label)
			}
			return &sshTargetLabel{attrs, func(context.Context) error { return nil }, func() error { return nil }}, nil
		},
		provision: sshProvisionDefaults(), publication: sshPublicationDefaults(),
	}
}

func TestSSHTransactionProductionEntryRejectsMissingAuthorization(t *testing.T) {
	if _, err := applySSHTransaction(context.Background(), ""); err == nil {
		t.Fatal("accepted missing explicit approval")
	}
}

func TestSSHTransactionPublishesAndExplicitlyRestores(t *testing.T) {
	f, plan, deps := transactionFixture(t)
	original := fixtureMainImage(t, f)
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err != nil || !result.Published || result.RecoveryRequired || !result.Verification.ParserVerified ||
		result.Verification.RuntimeActivated || result.Transaction == "" {
		t.Fatal("configuration transaction failed", result, err)
	}
	journal := fixtureJournal(t, f)
	record, err := journal.read()
	if err != nil || record.DropIn.Mode&0777 != 0600 || int64(record.DropIn.GID) != int64(os.Geteuid()) {
		t.Fatal("wrong private drop-in permissions", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256,
		deps.parserDigest, deps.run, deps.checkParser, sshPublicationDefaults())
	if err != nil || !result.Restored || result.RecoveryRequired || result.Published {
		t.Fatal("explicit recovery failed", result, err)
	}
	restored := fixtureMainImage(t, f)
	if restored.state.ino != original.state.ino || !bytes.Equal(restored.data, original.data) ||
		!reflect.DeepEqual(restored.attrs, original.attrs) {
		t.Fatal("lost original file or metadata")
	}
	if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("active policy remains after rollback")
	}
}

func TestSSHTransactionExternalOwnerDoesNotProvisionOrResolveLabels(t *testing.T) {
	f, _, deps := transactionFixture(t)
	declaration, err := parseIntent([]byte(validIntentJSON))
	if err != nil {
		t.Fatal(err)
	}
	f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
	declaration.Owner = "external"
	declaration.Profile = "observe"
	f.intent(declaration)
	plan := f.plan()
	deps.resolveLabel = func(context.Context, inventorySnapshot) (*sshTargetLabel, error) {
		t.Fatal("external observation resolved a publication label")
		return nil, unix.EIO
	}
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err != nil || !result.Verification.ParserVerified || result.Published || result.Transaction != "" {
		t.Fatal("external observation failed", result, err)
	}
	if _, err := os.Lstat(f.path(sshJournalDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("external observation created state")
	}
}

func TestSSHTransactionRefusesBeforeStateCreation(t *testing.T) {
	for _, scenario := range []string{"approval", "parser", "label", "context", "changed input"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps := transactionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			approval := plan.summary.PlanSHA256
			switch scenario {
			case "approval":
				approval = strings.Repeat("b", 64)
			case "parser":
				deps.checkParser = func() error { return unix.EIO }
			case "label":
				deps.resolveLabel = func(context.Context, inventorySnapshot) (*sshTargetLabel, error) { return nil, unix.EIO }
			case "context":
				cancel()
			case "changed input":
				f.write(MainPath, includeDropIns+"Port 2223\n")
			}
			if result, err := executeSSHTransaction(ctx, f.root, os.Geteuid(), approval, deps); err == nil || result.Published {
				t.Fatal("accepted invalid prerequisite")
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("created state before valid authorization and preflight")
			}
			if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published a drop-in despite failed preflight")
			}
		})
	}
}

func TestSSHTransactionRetainsInterruptedEvidenceAndBindsRecoveryParser(t *testing.T) {
	f, plan, deps := transactionFixture(t)
	deps.publication.link = func(a int, b string, c int, d string, flags int) error {
		if d == "00-syswarden-hardening.conf" {
			return unix.EIO
		}
		return unix.Linkat(a, b, c, d, flags)
	}
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err == nil || result.Published || !result.RecoveryRequired || result.Transaction == "" {
		t.Fatal("claimed success after interrupted publication", result, err)
	}
	if _, err := recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256,
		strings.Repeat("b", 64), deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
		t.Fatal("allowed recovery with a different installed parser")
	}
	result, err = recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256,
		deps.parserDigest, deps.run, deps.checkParser, sshPublicationDefaults())
	if err != nil || !result.Restored || result.RecoveryRequired {
		t.Fatal("cannot recover exact interrupted configuration", result, err)
	}
}

func TestSSHTransactionRefusesExistingJournalContentsWithoutAdoption(t *testing.T) {
	for _, name := range []string{"operator-note", sshPreparedRecord, "publish-01-intent.json"} {
		t.Run(name, func(t *testing.T) {
			f, plan, deps := transactionFixture(t)
			before := fixtureMainImage(t, f)
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
				t.Fatal(err)
			}
			const evidence = "unreviewed existing evidence\n"
			f.write(sshJournalDirectory+"/"+name, evidence)
			result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
			if err == nil || result.Published || result.Transaction != "" {
				t.Fatal("adopted an existing journal", result, err)
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
				t.Fatal("changed SSH configuration after ambiguous journal")
			}
			data, err := os.ReadFile(f.path(sshJournalDirectory + "/" + name))
			if err != nil || string(data) != evidence {
				t.Fatal("changed existing evidence", err)
			}
			if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published policy after ambiguous journal")
			}
		})
	}
}

func TestSSHTransactionStopsOnChangedDependenciesDuringPublication(t *testing.T) {
	for _, scenario := range []string{"parser", "target label", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps := transactionFixture(t)
			before := fixtureMainImage(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := false
			check := func() error {
				if changed {
					return ErrInventoryChanged
				}
				return nil
			}
			if scenario == "parser" {
				deps.checkParser = check
			}
			resolve := deps.resolveLabel
			deps.resolveLabel = func(ctx context.Context, inventory inventorySnapshot) (*sshTargetLabel, error) {
				label, err := resolve(ctx, inventory)
				if err == nil && scenario == "target label" {
					label.recheck = func(context.Context) error { return check() }
				}
				return label, err
			}
			links := 0
			deps.publication.link = func(a int, b string, c int, d string, flags int) error {
				if err := unix.Linkat(a, b, c, d, flags); err != nil {
					return err
				}
				links++
				changed = true
				if scenario == "cancelled" {
					cancel()
				}
				return nil
			}
			result, err := executeSSHTransaction(ctx, f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
			if err == nil || result.Published || !result.RecoveryRequired || result.Transaction == "" || links != 1 {
				t.Fatal("continued after a changed publication prerequisite", result, links, err)
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
				t.Fatal("changed active main after prerequisite failure")
			}
			if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published policy after prerequisite failure")
			}
			// A new invocation with the original, independently rechecked parser
			// can restore this interrupted stage. No cancelled-context retry.
			result, err = recoverSSHTransaction(context.Background(), f.root, os.Geteuid(),
				plan.summary.PlanSHA256, deps.parserDigest, deps.run, func() error { return nil }, sshPublicationDefaults())
			if err != nil || !result.Restored || result.RecoveryRequired {
				t.Fatal("lost recoverable interruption evidence", result, err)
			}
		})
	}
}

func TestSSHTransactionRefusesRepeatApplicationAndChangedRecoveryPlan(t *testing.T) {
	f, plan, deps := transactionFixture(t)
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err != nil || !result.Published {
		t.Fatal(result, err)
	}
	before := fixtureMainImage(t, f)
	drop, err := os.ReadFile(f.path(DropInPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps); err == nil {
		t.Fatal("replayed the original approval over published state")
	}
	result, err = recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), strings.Repeat("b", 64),
		deps.parserDigest, deps.run, deps.checkParser, sshPublicationDefaults())
	if err == nil || result.Restored {
		t.Fatal("recovered without the original approved plan")
	}
	after, err := os.ReadFile(f.path(DropInPath))
	if err != nil || !bytes.Equal(drop, after) || !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
		t.Fatal("refused recovery changed active configuration", err)
	}
}

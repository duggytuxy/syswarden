//go:build linux

package sshpolicy

import (
	"context"
	"os"
	"strings"
	"testing"

	"syswarden-cli/pkg/sshselection"
)

func TestSSHTransactionRequiresMatchingTOMLSelection(t *testing.T) {
	for _, content := range []string{"", "[ssh]\n", "[ssh]\nhardening = \"disabled\"\n", "[ssh]\nhardening = \"cis\"\n"} {
		t.Run(content, func(t *testing.T) {
			f, _, deps := transactionFixture(t)
			f.write(sshselection.Path, content)
			plan := f.plan()
			deps.run = func(context.Context, *parserImage, string, string) ([]byte, error) {
				t.Fatal("unselected SSH hardening invoked the parser")
				return nil, nil
			}
			result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
			if err == nil || result.Published || result.Transaction != "" || result.RecoveryRequired {
				t.Fatal("accepted undeclared, disabled or mismatched hardening", result, err)
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory)); !os.IsNotExist(err) {
				t.Fatal("unselected hardening created a journal")
			}
			if _, err := os.Lstat(f.path(DropInPath)); !os.IsNotExist(err) {
				t.Fatal("unselected hardening created an active policy")
			}
		})
	}
}

func TestSSHAbsentSelectionDoesNotInferConsentFromLegacyCore(t *testing.T) {
	f := planFixture(t, includeDropIns)
	f.write("/etc/syswarden/config/modules/00-core.toml", "[core]\nhardening_enabled = true\ncis_l2_hardening = true\n")
	plan := f.plan()
	if plan.summary.SSHHardening != "disabled" || plan.summary.SSHSelectionDeclared {
		t.Fatal("legacy OS/CIS settings granted SSH consent", plan.summary)
	}
	if err := plan.selection.Authorize(plan.intent.Owner, plan.intent.Profile); err == nil {
		t.Fatal("missing module authorized publication")
	}
	f.write(sshselection.Path, "[ssh]\nhardening = \"forwarding\"\n")
	if next := f.plan(); next.summary.PlanSHA256 == plan.summary.PlanSHA256 || !next.summary.SSHSelectionDeclared {
		t.Fatal("new explicit selection did not invalidate approval")
	}
}

func TestSSHSelectionRecheckedBeforeAndDuringTransaction(t *testing.T) {
	for _, phase := range []string{"before", "parser", "label"} {
		t.Run(phase, func(t *testing.T) {
			f, plan, deps := transactionFixture(t)
			mutate := func() { f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n") }
			switch phase {
			case "before":
				mutate()
			case "parser":
				run := deps.run
				deps.run = func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
					mutate()
					return run(ctx, image, mode, access)
				}
			case "label":
				resolve := deps.resolveLabel
				deps.resolveLabel = func(ctx context.Context, snapshot inventorySnapshot) (*sshTargetLabel, error) {
					mutate()
					return resolve(ctx, snapshot)
				}
			}
			result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
			if err == nil || result.Published || result.Transaction != "" {
				t.Fatal("changed consent was accepted", result, err)
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory)); !os.IsNotExist(err) {
				t.Fatal("changed consent created a journal")
			}
		})
	}
}

func TestSSHSelectionStorageAndDigestAreAttested(t *testing.T) {
	for _, scenario := range []string{"mode", "symlink", "hardlink", "writable parent", "oversize", "invalid", "replace", "comment", "remove"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, _ := transactionFixture(t)
			switch scenario {
			case "mode":
				if err := f.chmod(sshselection.Path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(f.path(sshselection.Path)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.path(IntentPath), f.path(sshselection.Path)); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(sshselection.Path), f.path("/etc/syswarden/config/modules/alias")); err != nil {
					t.Fatal(err)
				}
			case "writable parent":
				if err := f.chmod("/etc/syswarden/config/modules", 0777); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				f.write(sshselection.Path, strings.Repeat("#", sshselection.MaxBytes+1))
			case "invalid":
				f.write(sshselection.Path, "[ssh]\nhardening = true\n")
			case "replace", "remove":
				if err := os.Remove(f.path(sshselection.Path)); err != nil {
					t.Fatal(err)
				}
				if scenario == "replace" {
					f.write(sshselection.Path, "[ssh]\nhardening = \"forwarding\"\n")
				}
			case "comment":
				f.write(sshselection.Path, "[ssh]\nhardening = \"forwarding\"\n# reviewed again\n")
			}
			next, err := inspectPlan(f.root, os.Geteuid())
			switch scenario {
			case "replace", "comment", "remove":
				if err != nil || next.summary.PlanSHA256 == plan.summary.PlanSHA256 {
					t.Fatal("changed selection did not invalidate plan", err)
				}
			default:
				if err == nil {
					t.Fatal("accepted unsafe selection storage")
				}
			}
		})
	}
}

func TestSSHSelectionChangeDuringPublicationRetainsRecoveryEvidence(t *testing.T) {
	f, plan, deps := transactionFixture(t)
	link := deps.publication.link
	deps.publication.link = func(oldFD int, oldPath string, newFD int, newPath string, flags int) error {
		err := link(oldFD, oldPath, newFD, newPath, flags)
		if err == nil {
			f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
		}
		return err
	}
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err == nil || result.Published || !result.RecoveryRequired || result.Transaction == "" {
		t.Fatal("changed consent during publication lost recovery status", result, err)
	}
	if _, err := os.Lstat(f.path(DropInPath)); !os.IsNotExist(err) {
		t.Fatal("published active policy despite changed consent")
	}
	journal := fixtureJournal(t, f)
	record, err := journal.read()
	if err != nil || record.PlanSHA256 != plan.summary.PlanSHA256 {
		t.Fatal("lost original approval evidence", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSSHObservationAndPortInspectionDoNotRequireSelection(t *testing.T) {
	f := planFixture(t, includeDropIns)
	declaration, err := parseIntent([]byte(validIntentJSON))
	if err != nil {
		t.Fatal(err)
	}
	declaration.Owner, declaration.Profile = "external", "observe"
	f.intent(declaration)
	plan := f.plan()
	if err := plan.selection.Authorize("external", "observe"); err != nil {
		t.Fatal("observation required hardening opt-in", err)
	}
	f.write(sshselection.Path, "[ssh]\nhardening = true\n")
	inventory, err := openInventory(f.root, os.Geteuid())
	if err != nil {
		t.Fatal("plain SSH inventory should not depend on migration selection", err)
	}
	if err := inventory.Close(); err != nil {
		t.Fatal(err)
	}
}

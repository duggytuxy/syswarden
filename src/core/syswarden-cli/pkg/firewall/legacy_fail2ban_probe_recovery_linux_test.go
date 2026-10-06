//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyFail2banRecoveryViewsRejectChangedEvaluation(t *testing.T) {
	_, host, plan := fixtureLegacyFail2banJournal(t)
	fixture := fixtureLegacyFail2banPlanProbe(t)
	if err := revalidateLegacyFail2banPlanViews(host, plan.binding, fixture); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"parser", "enabled", "all", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			probe := func(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
				view, err := fixture(inventory, retiring)
				switch kind {
				case "parser":
					view.parserSHA256 = sha256.Sum256([]byte("different parser"))
				case "enabled":
					view.enabled = append(bytes.Clone(view.enabled), []byte("['set', 'loglevel', 'DEBUG']\n")...)
				case "all":
					view.allJails = append(bytes.Clone(view.allJails), []byte("['set', 'loglevel', 'DEBUG']\n")...)
				case "unavailable":
					err = errors.New("parser unavailable")
				}
				return view, err
			}
			if err := revalidateLegacyFail2banPlanViews(host, plan.binding, probe); err == nil {
				t.Fatal("changed evaluation accepted")
			}
		})
	}
}

func fixtureLegacyFail2banVerifiedFilePlan(t *testing.T) (string, nftPersistenceFilesystem, legacyFail2banRetirementPlan) {
	t.Helper()
	root, host := fixtureLegacyFail2banInstalledParser(t)
	if err := os.MkdirAll(filepath.Join(root, "var/backups"), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
		t.Fatal(err)
	}
	paths := []string{"/etc/fail2ban/action.d/syswarden-nft.conf"}
	for _, name := range []string{"syswarden-webhook", "syswarden-persistence"} {
		path := "/etc/fail2ban/action.d/" + name + ".conf"
		writeNFTPersistenceFixture(t, root, path, string(readLegacyFail2banFixture(t, name+".conf")))
		paths = append(paths, path)
	}
	probe, err := newLegacyFail2banConfigurationProbe(host)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareLegacyFail2banRetirement(host, paths, probe)
	if err != nil {
		t.Fatal(err)
	}
	return root, host, plan
}

func TestLegacyFail2banVerifiedFilePlanRecoversWithInstalledParser(t *testing.T) {
	for _, profile := range []string{"complete", "interrupted", "changed_parser", "changed_admin", "guard_refusal", "nil_guard"} {
		t.Run(profile, func(t *testing.T) {
			root, host, plan := fixtureLegacyFail2banVerifiedFilePlan(t)
			guard := acceptLegacyFail2banJournalFixture
			if profile == "guard_refusal" {
				guard = func() error { return errors.New("live protection cannot be attested") }
			}
			if profile == "nil_guard" {
				guard = nil
			}
			err := publishVerifiedLegacyFail2banFilePlan(host, plan, guard, defaultLegacyRetirementFileOps())
			if profile == "guard_refusal" || profile == "nil_guard" {
				if err == nil {
					t.Fatal("missing live guard accepted")
				}
				if _, err := host.snapshot(legacyFail2banPlanPath(plan.sha256) + "/plan.json"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("published despite invalid live guard")
				}
				return
			}
			if err != nil {
				t.Fatal("publish", err)
			}
			if profile != "complete" {
				interrupted := errors.New("synthetic interruption")
				ops := defaultLegacyRetirementFileOps()
				ops.checkpoint = func(phase string) error {
					if phase == "source-retired" {
						return interrupted
					}
					return nil
				}
				if err := resumeVerifiedLegacyFail2banFilePlan(host, plan.sha256, guard, ops); !errors.Is(err, interrupted) {
					t.Fatal("interruption not observed", err)
				}
				state, err := inspectLegacyFail2banPlanState(host, plan.binding)
				if err != nil || len(state.retired) != 1 {
					t.Fatal("interruption state not durable", err)
				}
			}
			if profile == "changed_parser" {
				path := filepath.Join(root, legacyFail2banLibrary, "version.py")
				content, err := os.ReadFile(path) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(content, []byte("\n# Parser changed after publication.\n")...), 0600); err != nil { // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
					t.Fatal(err)
				}
			}
			if profile == "changed_admin" {
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/admin.conf", "[administrator-active]\nenabled = true\nbantime = 987\n")
			}
			err = resumeVerifiedLegacyFail2banFilePlan(host, plan.sha256, guard, defaultLegacyRetirementFileOps())
			if profile == "changed_parser" || profile == "changed_admin" {
				if err == nil {
					t.Fatal("changed evidence accepted")
				}
				existing := 0
				for _, path := range plan.binding.Targets {
					if _, err := host.snapshot(path); err == nil {
						existing++
					}
				}
				if existing != 2 {
					t.Fatal("recovery moved more targets despite changed evidence")
				}
				return
			}
			if err != nil {
				t.Fatal("resume", err)
			}
			assertLegacyFail2banJournalComplete(t, host, plan)
			if err := resumeVerifiedLegacyFail2banFilePlan(host, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("completed file retirement was not idempotent", err)
			}
		})
	}
}

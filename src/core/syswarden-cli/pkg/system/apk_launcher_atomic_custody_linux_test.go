//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func apkAtomicCustodyInstalled(t *testing.T) (apkLauncherFixture, *APKLauncherCustody, string) {
	t.Helper()
	fixture := newAPKLauncherFixture(t, "absent")
	h := fixture.prepare(t)
	if err := h.CreateAbsent(); err != nil {
		t.Fatal(err)
	}
	digest, err := h.Commit()
	if err != nil {
		t.Fatal(err)
	}
	fixture.barrier(t)
	return fixture, h, digest
}

func TestAPKLauncherAtomicCustodyResumesExactQuarantine(t *testing.T) {
	for _, path := range apkLauncherPaths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			fixture, h, digest := apkAtomicCustodyInstalled(t)
			injected := errors.New("interrupted after durable alias quarantine")
			h.fault = func(point string) error {
				if point == "after-quarantine-"+filepath.Base(path) {
					return injected
				}
				return nil
			}
			if err := h.RetireOwned(); !errors.Is(err, injected) {
				t.Fatalf("quarantine seam not reached: %v", err)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			h = fixture.reopen(t, digest)
			if err := h.AttestTerminal(); err == nil {
				t.Fatal("quarantine counted as terminal removal")
			}
			if err := h.RetireOwned(); err != nil {
				t.Fatal(err)
			}
			if err := h.AttestTerminal(); err != nil {
				t.Fatal(err)
			}
			for i := range apkLauncherPaths {
				record, exists, err := h.readQuarantine(i)
				if err != nil || !exists {
					t.Fatal("retirement quarantine evidence lost")
				}
				if _, err := h.aliases.Lstat(record.Name); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("retired quarantine remains")
				}
			}
		})
	}
}

func TestAPKLauncherAtomicCustodyPreservesConcurrentEntries(t *testing.T) {
	for _, mutation := range []string{"before-rename", "quarantine", "live-conflict", "ancestor"} {
		t.Run(mutation, func(t *testing.T) {
			fixture, h, digest := apkAtomicCustodyInstalled(t)
			aliasPath := filepath.Join(fixture.host, apkLauncherPaths[0])
			point := "before-quarantine-" + filepath.Base(aliasPath)
			if mutation == "quarantine" || mutation == "live-conflict" {
				point = "after-quarantine-" + filepath.Base(aliasPath)
			}
			changed := false
			var preserved os.FileInfo
			var quarantine string
			h.fault = func(phase string) error {
				if changed || phase != point {
					return nil
				}
				changed = true
				switch mutation {
				case "ancestor":
					if err := os.Rename(filepath.Join(fixture.host, "usr/local"), filepath.Join(fixture.host, "usr/local.held")); err != nil {
						return err
					}
					if err := fixture.root.MkdirAll("usr/local/bin", 0700); err != nil {
						return err
					}
				case "before-rename":
					if err := os.Rename(aliasPath, aliasPath+".held"); err != nil {
						return err
					}
				case "quarantine":
					record, exists, err := h.readQuarantine(0)
					if err != nil || !exists {
						return errors.New("quarantine intent unavailable")
					}
					quarantine = filepath.Join(filepath.Dir(aliasPath), record.Name)
					if err := os.Rename(quarantine, quarantine+".held"); err != nil {
						return err
					}
					if err := os.Symlink("/administrator", quarantine); err != nil {
						return err
					}
					preserved, err = os.Lstat(quarantine)
					return err
				case "live-conflict":
					record, exists, err := h.readQuarantine(0)
					if err != nil || !exists {
						return errors.New("quarantine intent unavailable")
					}
					quarantine = filepath.Join(filepath.Dir(aliasPath), record.Name)
				}
				if err := os.Symlink("/administrator", aliasPath); err != nil {
					return err
				}
				var err error
				preserved, err = os.Lstat(aliasPath)
				return err
			}
			if err := h.RetireOwned(); err == nil || !changed {
				t.Fatalf("concurrent mutation accepted: %v", err)
			}
			actual, err := os.Lstat(aliasPath)
			if err != nil || !os.SameFile(preserved, actual) {
				t.Fatal("administrator entry was deleted or overwritten")
			}
			if mutation == "live-conflict" {
				target, err := os.Readlink(quarantine)
				if err != nil || target != apkLauncherTargets[0] {
					t.Fatal("conflicting quarantine was lost")
				}
			}
			if mutation == "ancestor" {
				if _, err := os.Lstat(filepath.Join(fixture.host, "usr/local.held/bin/syswarden")); err != nil {
					t.Fatal("original entry lost from displaced ancestor")
				}
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := inspectAPKLaunchersForRemovalAt(t.Context(), fixture.host, fixture.binding.PlanSHA256, digest)
			if opened != nil {
				_ = opened.Close()
			}
			if err == nil {
				t.Fatal("ambiguous recovery became accepted custody")
			}
		})
	}
}

func TestAPKLauncherAtomicCustodyRequiresPerAliasRetirementIntent(t *testing.T) {
	fixture, h, digest := apkAtomicCustodyInstalled(t)
	h.fault = func(point string) error {
		if point == "after-unlink-syswarden" {
			return errors.New("interrupted")
		}
		return nil
	}
	if err := h.RetireOwned(); err == nil {
		t.Fatal("retirement fault ignored")
	}
	if err := h.journal.Remove(apkLauncherQuarantineName(0)); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := inspectAPKLaunchersForRemovalAt(t.Context(), fixture.host, fixture.binding.PlanSHA256, digest)
	if opened != nil {
		_ = opened.Close()
	}
	if err == nil {
		t.Fatal("absence without per-alias quarantine custody accepted")
	}
}

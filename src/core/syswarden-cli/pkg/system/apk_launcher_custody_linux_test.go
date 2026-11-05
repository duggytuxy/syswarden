//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type apkLauncherFixture struct {
	host, transaction string
	root              *os.Root
	binding           apkLauncherCustodyBinding
	original          []apkTransitionHostEntry
}

func newAPKLauncherFixture(t *testing.T, kind string) apkLauncherFixture {
	t.Helper()
	host := t.TempDir()
	root, err := os.OpenRoot(host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	binding := apkLauncherCustodyBinding{PlanSHA256: strings.Repeat("1", 64), ApprovalSHA256: strings.Repeat("2", 64),
		CandidateSHA256: strings.Repeat("3", 64), CandidateCLISHA256: strings.Repeat("4", 64),
		CandidateCapabilitySHA256: strings.Repeat("5", 64), InventorySHA256: strings.Repeat("6", 64)}
	transaction := strings.TrimPrefix(apkTransitionRoot, "/") + "/execution-" + binding.PlanSHA256
	for _, path := range []string{"usr/local/bin", "var/lib/syswarden", transaction} {
		if err := root.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	switch kind {
	case "retained", "mixed":
		// The interpreter-looking bytes are opaque fixture data, never executed.
		if err := root.WriteFile(apkLauncherPaths[0], []byte("#!/bin/sh\nprintf changed > sentinel\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if kind == "retained" {
			if err := root.Symlink("/opt/administrator-tool", apkLauncherPaths[1]); err != nil {
				t.Fatal(err)
			}
		}
	case "product-link":
		if err := root.Symlink(apkLauncherTargets[0], apkLauncherPaths[0]); err != nil {
			t.Fatal(err)
		}
	case "empty":
		if err := root.WriteFile(apkLauncherPaths[0], nil, 0600); err != nil {
			t.Fatal(err)
		}
	case "absent":
	default:
		t.Fatal("unknown fixture kind")
	}
	original, err := captureAPKLauncherCustodyAt(t.Context(), host)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := apkLauncherCanonical(original)
	if err != nil {
		t.Fatal(err)
	}
	binding.OriginalSnapshotSHA256 = apkTransitionDigest(raw)
	return apkLauncherFixture{host, filepath.Join(host, transaction), root, binding, original}
}

func (fixture apkLauncherFixture) prepare(t *testing.T) *APKLauncherCustody {
	t.Helper()
	h, err := prepareAPKLauncherCustodyAt(t.Context(), fixture.host, fixture.transaction, fixture.binding, fixture.original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func (fixture apkLauncherFixture) barrier(t *testing.T) {
	t.Helper()
	if err := fixture.root.WriteFile(strings.TrimPrefix(RemovalTombstonePath, "/"), []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
}

func (fixture apkLauncherFixture) reopen(t *testing.T, digest string) *APKLauncherCustody {
	t.Helper()
	h, err := inspectAPKLaunchersForRemovalAt(t.Context(), fixture.host, fixture.binding.PlanSHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func TestAPKLauncherCustodyPreservesInheritedEntriesWithoutExecution(t *testing.T) {
	for _, kind := range []string{"retained", "empty", "absent"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newAPKLauncherFixture(t, kind)
			first, err := captureAPKLauncherCustodyAt(t.Context(), fixture.host)
			if err != nil || !reflect.DeepEqual(first, fixture.original) {
				t.Fatal("read-only planning changed original evidence", err)
			}
			h := fixture.prepare(t)
			digest, err := h.Commit()
			if err != nil || !validSHA256(digest) {
				t.Fatal("custody publication failed", err)
			}
			if _, err := h.Commit(); err == nil {
				t.Fatal("duplicate commitment accepted")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			h = fixture.reopen(t, digest)
			if err := h.RetireOwned(); err == nil {
				t.Fatal("retirement without removal barrier accepted")
			}
			fixture.barrier(t)
			if err := h.RetireOwned(); err != nil {
				t.Fatal(err)
			}
			if err := h.AttestTerminal(); err != nil {
				t.Fatal(err)
			}
			after, err := captureAPKLauncherCustodyAt(t.Context(), fixture.host)
			if err != nil || !reflect.DeepEqual(first, after) {
				t.Fatal("retained alias bytes or metadata changed", err)
			}
			if _, err := fixture.root.Lstat("sentinel"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("opaque wrapper executed", err)
			}
		})
	}
}

func TestAPKLauncherCustodyExclusiveCreationAndIndependentRetirement(t *testing.T) {
	for _, kind := range []string{"absent", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newAPKLauncherFixture(t, kind)
			h := fixture.prepare(t)
			if err := h.CreateAbsent(); err != nil {
				t.Fatal(err)
			}
			digest, err := h.Commit()
			if err != nil {
				t.Fatal(err)
			}
			if err := h.AttestTerminal(); err == nil {
				t.Fatal("created alias accepted as already retired")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			h = fixture.reopen(t, digest)
			fixture.barrier(t)
			if err := h.RetireOwned(); err != nil {
				t.Fatal(err)
			}
			if err := h.RetireOwned(); err != nil {
				t.Fatal("exact retry failed", err)
			}
			if len(h.parents) > 12 {
				t.Fatal("repeated retirement leaked parent descriptors")
			}
			for i, path := range apkLauncherPaths {
				actual, err := readAPKLauncherEntry(fixture.root, path)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "mixed" && i == 0 {
					if apkLauncherEntryEvidence(actual) != apkLauncherEntryEvidence(fixture.original[4]) {
						t.Fatal("retained sibling changed during owned unlink")
					}
				} else if !actual.Absent {
					t.Fatal("owned launcher remains")
				}
			}
		})
	}
}

func TestAPKLauncherCustodyRefusesProductTargetBehaviorDependency(t *testing.T) {
	for _, target := range []string{apkLauncherTargets[0], "/opt/syswarden", "../../../opt/syswarden/bin/syswarden-cli"} {
		t.Run(target, func(t *testing.T) {
			fixture := newAPKLauncherFixture(t, "absent")
			if err := fixture.root.Symlink(target, apkLauncherPaths[0]); err != nil {
				t.Fatal(err)
			}
			var err error
			fixture.original, err = captureAPKLauncherCustodyAt(t.Context(), fixture.host)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := apkLauncherCanonical(fixture.original)
			if err != nil {
				t.Fatal(err)
			}
			fixture.binding.OriginalSnapshotSHA256 = apkTransitionDigest(raw)
			h := fixture.prepare(t)
			if err := h.Revalidate(); err != nil {
				t.Fatal("metadata-only observation failed", err)
			}
			if err := h.RefuseProductTargetDependencies(); err == nil {
				t.Fatal("retained product-target behavior accepted")
			}
			if digest, err := h.Commit(); err == nil || digest != "" {
				t.Fatal("unresolved product target committed")
			}
			if err := h.CreateAbsent(); err == nil {
				t.Fatal("creation proceeded beside unresolved inherited alias")
			}
			actual, err := readAPKLauncherEntry(fixture.root, apkLauncherPaths[0])
			if err != nil || apkLauncherEntryEvidence(actual) != apkLauncherEntryEvidence(fixture.original[4]) {
				t.Fatal("inherited product-shaped link was adopted or changed", err)
			}
		})
	}
}

func TestAPKLauncherCustodyRejectsChangedSnapshotAndBindings(t *testing.T) {
	for _, kind := range []string{"snapshot", "plan", "approval", "capability", "inventory", "candidate", "path"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newAPKLauncherFixture(t, "retained")
			switch kind {
			case "snapshot":
				fixture.original[4].Content = []byte("substitution")
			case "plan":
				fixture.binding.PlanSHA256 = strings.Repeat("a", 64)
			case "approval":
				fixture.binding.ApprovalSHA256 = ""
			case "capability":
				fixture.binding.CandidateCapabilitySHA256 = ""
			case "inventory":
				fixture.binding.InventorySHA256 = ""
			case "candidate":
				fixture.binding.CandidateSHA256 = ""
			case "path":
				fixture.transaction += "/../" + filepath.Base(fixture.transaction)
			}
			h, err := prepareAPKLauncherCustodyAt(t.Context(), fixture.host, fixture.transaction, fixture.binding, fixture.original)
			if h != nil {
				if closeErr := h.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err == nil {
				t.Fatal("unbound custody prepared")
			}
		})
	}
}

func TestAPKLauncherCustodyRevalidationRejectsAliasAndParentDrift(t *testing.T) {
	for _, kind := range []string{"content", "replacement", "mode", "same-target-link", "parent", "parent-mode", "prepared", "cancellation"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newAPKLauncherFixture(t, "retained")
			h := fixture.prepare(t)
			var err error
			switch kind {
			case "content":
				err = fixture.root.WriteFile(apkLauncherPaths[0], []byte("changed"), 0600)
			case "replacement":
				if err = fixture.root.Rename(apkLauncherPaths[0], apkLauncherPaths[0]+"-old"); err == nil {
					err = fixture.root.WriteFile(apkLauncherPaths[0], fixture.original[4].Content, 0700)
				}
			case "mode":
				err = fixture.root.Chmod(apkLauncherPaths[0], 0600)
			case "same-target-link":
				if err = fixture.root.Remove(apkLauncherPaths[1]); err == nil {
					err = fixture.root.Symlink(fixture.original[5].LinkTarget, apkLauncherPaths[1])
				}
			case "parent":
				if err = fixture.root.Rename("usr/local/bin", "usr/local/old-bin"); err == nil {
					err = fixture.root.Mkdir("usr/local/bin", 0700)
				}
			case "parent-mode":
				err = fixture.root.Chmod("usr/local/bin", 0750)
			case "prepared":
				err = h.journal.WriteFile("launcher-prepared.json", append(append([]byte(nil), h.prepared...), ' '), 0600)
			case "cancellation":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				h.ctx = ctx
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := h.Revalidate(); err == nil {
				t.Fatal("changed custody accepted")
			}
			if digest, err := h.Commit(); err == nil || digest != "" {
				t.Fatal("changed custody committed")
			}
		})
	}
}

func TestAPKLauncherCustodyPublicationFailureCannotBePromoted(t *testing.T) {
	for _, point := range []string{"before-launcher-custody.json", "after-launcher-custody.json", "before-launcher-created-cli.json", "after-launcher-created-cli.json"} {
		t.Run(point, func(t *testing.T) {
			fixture := newAPKLauncherFixture(t, "absent")
			h := fixture.prepare(t)
			h.fault = func(observed string) error {
				if observed == point {
					return errors.New("injected publication failure")
				}
				return nil
			}
			if strings.Contains(point, "created") {
				if err := h.CreateAbsent(); err == nil {
					t.Fatal("creation publication fault ignored")
				}
			} else if digest, err := h.Commit(); err == nil || digest != "" {
				t.Fatal("commit publication fault ignored")
			}
			if digest, err := h.Commit(); err == nil || digest != "" {
				t.Fatal("uncertain publication promoted on retry")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			if next, err := prepareAPKLauncherCustodyAt(t.Context(), fixture.host, fixture.transaction, fixture.binding, fixture.original); err == nil {
				if closeErr := next.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				t.Fatal("existing preparation was backfilled")
			}
		})
	}
}

func TestAPKLauncherCustodyRetirementResumesOnlyExactOwnedAbsence(t *testing.T) {
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
	h.fault = func(point string) error {
		if point == "after-unlink-syswarden" {
			return errors.New("interrupted")
		}
		return nil
	}
	if err := h.RetireOwned(); err == nil {
		t.Fatal("interruption ignored")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = fixture.reopen(t, digest)
	if err := h.RetireOwned(); err != nil {
		t.Fatal("exact partial unlink could not resume", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = fixture.reopen(t, digest)
	if err := h.AttestTerminal(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.root.Symlink(apkLauncherTargets[0], apkLauncherPaths[0]); err != nil {
		t.Fatal(err)
	}
	if err := h.RetireOwned(); err == nil {
		t.Fatal("same-target replacement adopted after retirement")
	}
}

func TestAPKLauncherCustodyRejectsUnjournaledAbsenceAndMissingCreationIntent(t *testing.T) {
	for _, kind := range []string{"absence", "creation-intent", "wrong-receipt", "noncanonical", "unknown-record"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newAPKLauncherFixture(t, "absent")
			h := fixture.prepare(t)
			if err := h.CreateAbsent(); err != nil {
				t.Fatal(err)
			}
			digest, err := h.Commit()
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "absence":
				err = fixture.root.Remove(apkLauncherPaths[0])
			case "creation-intent":
				err = h.journal.Remove("intent-" + apkLauncherCreationName(0))
			case "unknown-record":
				err = h.journal.WriteFile("launcher-unknown.json", []byte("{}\n"), 0600)
			case "wrong-receipt":
				digest = strings.Repeat("a", 64)
			case "noncanonical":
				raw := append(append([]byte(nil), h.receipt...), ' ')
				err = h.journal.WriteFile("launcher-custody.json", raw, 0600)
				digest = apkTransitionDigest(raw)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := inspectAPKLaunchersForRemovalAt(t.Context(), fixture.host, fixture.binding.PlanSHA256, digest)
			if opened != nil {
				if closeErr := opened.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err == nil {
				t.Fatal("unproven custody accepted")
			}
		})
	}
}

func TestAPKLauncherCustodyReleasesExclusiveLock(t *testing.T) {
	fixture := newAPKLauncherFixture(t, "retained")
	h := fixture.prepare(t)
	digest, err := h.Commit()
	if err != nil {
		t.Fatal(err)
	}
	other, err := inspectAPKLaunchersForRemovalAt(t.Context(), fixture.host, fixture.binding.PlanSHA256, digest)
	if other != nil {
		if closeErr := other.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	if err == nil {
		t.Fatal("simultaneous custody accepted")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Revalidate(); err == nil {
		t.Fatal("closed custody reused")
	}
	fixture.reopen(t, digest)
}

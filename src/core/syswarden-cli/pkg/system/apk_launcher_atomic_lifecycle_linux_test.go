//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func freshAPKAtomicInstalled(t *testing.T, parents bool) string {
	t.Helper()
	root := freshAPKFixture(t, parents)
	if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	freshAPKFixtureCommit(t, root, false)
	if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err != nil {
		t.Fatal(err)
	}
	return root
}

func freshAPKAtomicForgetNative(t *testing.T, root string) {
	t.Helper()
	freshAPKFixtureWrite(t, root, "lib/apk/db/installed", []byte("P:base\nV:1.0-r0\nA:x86_64\n\n"), 0644)
}

func freshAPKAtomicRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned fixture evidence
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func freshAPKAtomicReference(t *testing.T, root string) (apkLauncherLifecycleReference, string) {
	t.Helper()
	path := filepath.Join(root, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "current.json")
	var reference apkLauncherLifecycleReference
	if err := decodeAPKTransitionJSON(freshAPKAtomicRead(t, path), &reference); err != nil {
		t.Fatal(err)
	}
	return reference, path
}

func TestFreshAPKAtomicReinstallPreservesTerminalLineage(t *testing.T) {
	for _, parents := range []bool{false, true} {
		t.Run(fmt.Sprint(parents), func(t *testing.T) {
			root := freshAPKAtomicInstalled(t, parents)
			for generation := 0; generation < 3; generation++ {
				freshAPKFixtureBarrier(t, root)
				if err := retireAPKLaunchersForRemovalAt(context.Background(), root); err != nil {
					t.Fatal(err)
				}
				oldReference, currentPath := freshAPKAtomicReference(t, root)
				previous := freshAPKAtomicRead(t, currentPath)
				oldInfo, err := os.Lstat(currentPath)
				if err != nil {
					t.Fatal(err)
				}
				oldJournal := filepath.Join(filepath.Dir(currentPath), "fresh-"+oldReference.PlanSHA256)
				terminal := freshAPKAtomicRead(t, filepath.Join(oldJournal, "terminal.json"))
				freshAPKAtomicForgetNative(t, root)
				if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(previous, freshAPKAtomicRead(t, currentPath)) {
					t.Fatal("staging changed terminal lineage")
				}
				freshAPKFixtureCommit(t, root, false)
				if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err != nil {
					t.Fatal(err)
				}
				current, _ := freshAPKAtomicReference(t, root)
				if current.PlanSHA256 == oldReference.PlanSHA256 {
					t.Fatal("reinstall did not advance lineage")
				}
				journal := filepath.Join(filepath.Dir(currentPath), "fresh-"+current.PlanSHA256)
				displaced := filepath.Join(journal, "displaced-current.json")
				info, err := os.Lstat(displaced)
				if err != nil || !os.SameFile(oldInfo, info) || !bytes.Equal(previous, freshAPKAtomicRead(t, displaced)) {
					t.Fatal("previous reference identity was not retained")
				}
				if !bytes.Equal(terminal, freshAPKAtomicRead(t, filepath.Join(oldJournal, "terminal.json"))) {
					t.Fatal("prior terminal evidence changed")
				}
				if err := preflightAPKLauncherRemovalAt(context.Background(), root); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFreshAPKAtomicReinstallRefusesActiveLineage(t *testing.T) {
	root := freshAPKAtomicInstalled(t, true)
	_, currentPath := freshAPKAtomicReference(t, root)
	before := freshAPKAtomicRead(t, currentPath)
	freshAPKAtomicForgetNative(t, root)
	if err := stageFreshAPKLaunchersAt(context.Background(), root); err == nil {
		t.Fatal("accepted nonterminal prior lineage")
	}
	if !bytes.Equal(before, freshAPKAtomicRead(t, currentPath)) {
		t.Fatal("changed active lineage")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(currentPath), "pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published pending intent for active lineage")
	}
}

func TestFreshAPKAtomicReinstallRefusesLineageDrift(t *testing.T) {
	for _, phase := range []string{"before-completion", "before-current-swap", "at-current-swap", "terminal-evidence"} {
		t.Run(phase, func(t *testing.T) {
			root := freshAPKAtomicInstalled(t, true)
			freshAPKFixtureBarrier(t, root)
			if err := retireAPKLaunchersForRemovalAt(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			previous, currentPath := freshAPKAtomicReference(t, root)
			raw := freshAPKAtomicRead(t, currentPath)
			freshAPKAtomicForgetNative(t, root)
			if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			freshAPKFixtureCommit(t, root, false)
			changed := false
			var replacement os.FileInfo
			mutate := func() error {
				changed = true
				if phase == "terminal-evidence" {
					return os.WriteFile(filepath.Join(filepath.Dir(currentPath), "fresh-"+previous.PlanSHA256, "terminal.json"), []byte("changed\n"), 0600) // #nosec G306 -- deliberately invalid test-owned evidence
				}
				if err := os.Rename(currentPath, currentPath+".held"); err != nil {
					return err
				}
				if err := os.WriteFile(currentPath, raw, 0600); err != nil {
					return err
				} // #nosec G306 -- deliberate same-byte inode substitution
				var err error
				replacement, err = os.Lstat(currentPath)
				return err
			}
			if phase == "before-completion" || phase == "terminal-evidence" {
				if err := mutate(); err != nil {
					t.Fatal(err)
				}
			}
			err := completeFreshAPKLaunchersAt(context.Background(), root, func(point string) error {
				if point == phase {
					return mutate()
				}
				return nil
			})
			if err == nil || !changed {
				t.Fatalf("lineage drift accepted: %v", err)
			}
			if phase != "terminal-evidence" {
				after, err := os.Lstat(currentPath)
				if err != nil || !os.SameFile(replacement, after) {
					t.Fatal("concurrent lineage replacement was lost")
				}
			}
			if _, err := os.Lstat(filepath.Join(filepath.Dir(currentPath), "pending.json")); err != nil {
				t.Fatal("pending recovery intent lost")
			}
		})
	}
}

func TestFreshAPKAtomicRemovalResumesDurableQuarantine(t *testing.T) {
	for _, path := range []string{apkLauncherPaths[0], apkLauncherPaths[1], apkLauncherParents[3], apkLauncherParents[2]} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			root := freshAPKAtomicInstalled(t, false)
			freshAPKFixtureBarrier(t, root)
			h, err := inspectAPKLauncherLifecycleRemovalAt(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("interrupted after durable quarantine")
			h.store.fault = func(phase string) error {
				if phase == "after-quarantine-"+path {
					return injected
				}
				return nil
			}
			err = errors.Join(h.retire(), h.close())
			if !errors.Is(err, injected) {
				t.Fatalf("fault not reached: %v", err)
			}
			if err := retireAPKLaunchersForRemovalAt(context.Background(), root); err != nil {
				t.Fatalf("quarantine recovery failed: %v", err)
			}
			h, err = inspectAPKLauncherLifecycleRemovalAt(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(h.attestTerminal(), h.close()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(root, "usr/local")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("owned parents remain after quarantine recovery")
			}
		})
	}
}

func TestFreshAPKAtomicRemovalPreservesBoundaryReplacements(t *testing.T) {
	for _, target := range []string{"alias", "directory", "ancestor"} {
		t.Run(target, func(t *testing.T) {
			root := freshAPKAtomicInstalled(t, false)
			freshAPKFixtureBarrier(t, root)
			h, err := inspectAPKLauncherLifecycleRemovalAt(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			path := apkLauncherPaths[0]
			if target == "directory" {
				path = apkLauncherParents[3]
			}
			changed := false
			var replacement os.FileInfo
			preservedPath := filepath.Join(root, path)
			h.store.fault = func(phase string) error {
				if changed || phase != "before-quarantine-"+path {
					return nil
				}
				changed = true
				if target == "ancestor" {
					if err := os.Rename(filepath.Join(root, "usr/local"), filepath.Join(root, "usr/local.held")); err != nil {
						return err
					}
					freshAPKFixtureWrite(t, root, "usr/local/bin/admin", []byte("preserve administrator\n"), 0755)
					return os.Symlink("/administrator", preservedPath)
				}
				if err := os.Rename(preservedPath, preservedPath+".held"); err != nil {
					return err
				}
				if target == "directory" {
					freshAPKFixtureWrite(t, root, filepath.Join(path, "admin"), []byte("preserve administrator\n"), 0755)
				} else if err := os.Symlink("/administrator", preservedPath); err != nil {
					return err
				}
				var err error
				replacement, err = os.Lstat(preservedPath)
				return err
			}
			err = errors.Join(h.retire(), h.close())
			if err == nil || !changed {
				t.Fatalf("replacement race accepted: %v", err)
			}
			if target == "ancestor" {
				link, err := os.Readlink(preservedPath)
				if err != nil || link != "/administrator" {
					t.Fatal("replacement ancestor alias changed")
				}
				if _, err := os.Lstat(filepath.Join(root, "usr/local.held/bin/syswarden")); err != nil {
					t.Fatal("original alias lost from displaced ancestor")
				}
			} else {
				actual, err := os.Lstat(preservedPath)
				if err != nil || !os.SameFile(replacement, actual) {
					t.Fatal("administrator replacement was not restored intact")
				}
				if target == "directory" && string(freshAPKAtomicRead(t, filepath.Join(preservedPath, "admin"))) != "preserve administrator\n" {
					t.Fatal("administrator entry lost")
				}
			}
			if err := preflightAPKLauncherRemovalAt(context.Background(), root); err == nil {
				t.Fatal("ambiguous replacement became accepted ownership")
			}
		})
	}
}

func TestFreshAPKAtomicExecutionPublicationRequiresExactCompleteProof(t *testing.T) {
	for _, mutation := range []string{"none", "missing-publication", "same-byte-current", "unknown-evidence", "proposal"} {
		t.Run(mutation, func(t *testing.T) {
			root := freshAPKFixture(t, true)
			s, err := openAPKLauncherLifecycleStore(context.Background(), root, true)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.close(); err != nil {
					t.Error(err)
				}
			}()
			reference := apkLauncherLifecycleReference{apkFreshLauncherSchema, "execution", apkTransitionDigest([]byte("plan")), apkTransitionDigest([]byte("receipt"))}
			if err := s.openJournal(reference.PlanSHA256, true); err != nil {
				t.Fatal(err)
			}
			intent := apkLauncherLineagePublicationIntent{apkFreshLauncherSchema, "terminal-execution-lineage-publication", apkLauncherLineageProposal{Absent: true}, reference}
			raw, err := s.publish(s.journal, "publication-intent.json", intent)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.publishCurrent(reference, intent.Proposal); err != nil {
				t.Fatal(err)
			}
			current, err := s.captureLineageProposal()
			if err != nil {
				t.Fatal(err)
			}
			if mutation != "missing-publication" {
				if _, err := s.publish(s.journal, "publication.json", apkLauncherLineagePublication{apkFreshLauncherSchema, "execution-lineage-published", apkTransitionDigest(raw), current.Identity}); err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "same-byte-current":
				currentPath := filepath.Join(root, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "current.json")
				contents := freshAPKAtomicRead(t, currentPath)
				if err := os.Rename(currentPath, currentPath+".held"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(currentPath, contents, 0600); err != nil {
					t.Fatal(err)
				} // #nosec G306 -- deliberate same-byte inode replacement
			case "unknown-evidence":
				if err := writeAPKTransitionBytes(s.journal, "unresolved.json", []byte("recovery\n")); err != nil {
					t.Fatal(err)
				}
			case "proposal":
				intent.Proposal.Absent = false
			}
			err = s.attestPublishedLineage(intent)
			if mutation == "none" && err != nil {
				t.Fatal(err)
			}
			if mutation != "none" && err == nil {
				t.Fatal("incomplete or substituted publication proof accepted")
			}
		})
	}
}

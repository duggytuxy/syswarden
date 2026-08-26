//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRemovalTombstonePath(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	uid, gid := systemTestIdentity(t)
	return filepath.Join(t.TempDir(), "syswarden", removalTombstoneName), uid, gid
}

func TestRemovalTombstoneGrammarAndAtomicIdempotentPublication_SW2_FWBACKEND_001(t *testing.T) {
	if len(RemovalTombstoneRecord) != 39 || strings.ContainsAny(RemovalTombstoneRecord, "\r\x00") ||
		RemovalTombstoneRecord != "SYSWARDEN_REMOVAL_V1\nstate=in-progress\n" {
		t.Fatalf("unexpected removal tombstone grammar: %q", RemovalTombstoneRecord)
	}
	path, uid, gid := testRemovalTombstonePath(t)
	present, err := inspectRemovalTombstoneAt(path, uid, gid)
	if err != nil || present {
		t.Fatalf("inspect absent state directory: present=%t err=%v", present, err)
	}
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatalf("idempotent exact publication: %v", err)
	}
	content, err := os.ReadFile(path) // #nosec G304 -- path is produced by the private tombstone fixture helper
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != RemovalTombstoneRecord || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("published tombstone content=%q mode=%04o", content, info.Mode().Perm())
	}
	present, err = inspectRemovalTombstoneAt(path, uid, gid)
	if err != nil || !present {
		t.Fatalf("inspect exact tombstone: present=%t err=%v", present, err)
	}
}

func TestRemovalFinalizingBarrierBlocksWhenInternalStateIsAbsent_SW2_PKG_001(t *testing.T) {
	if RemovalFinalizingRecord != RemovalTombstoneRecord || len(RemovalFinalizingRecord) != 39 {
		t.Fatalf("finalizing barrier record does not match the cross-runtime removal record")
	}
	path, uid, gid := testRemovalTombstonePath(t)
	finalizingPath := removalFinalizingPathFor(path)
	if err := ensureRemovalFinalizingAt(finalizingPath, uid, gid); err != nil {
		t.Fatal(err)
	}
	present, err := inspectRemovalBarrierAt(path, finalizingPath, uid, gid)
	if err != nil || !present {
		t.Fatalf("inspect external finalizing barrier: present=%t err=%v", present, err)
	}
	if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("external barrier unexpectedly created internal state: %v", err)
	}
}

func TestRemovalBarrierInspectionCannotMissAtomicFinalizingRename_SW2_PKG_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	finalizingPath := removalFinalizingPathFor(path)
	renameRequest := make(chan struct{})
	renameResult := make(chan error, 1)
	go func() {
		<-renameRequest
		directory, err := openExistingRemovalStateDirectory(filepath.Dir(path), uid, gid)
		if err != nil {
			renameResult <- err
			return
		}
		defer directory.close()
		renameResult <- transitionRemovalTombstoneToFinalizing(
			directory, finalizingPath, uid, gid, func(string) {},
		)
	}()
	present, err := inspectRemovalBarrierAtUsing(
		path,
		finalizingPath,
		uid,
		gid,
		func() error {
			close(renameRequest)
			return <-renameResult
		},
	)
	if err != nil || !present {
		t.Fatalf("atomic finalizing rename was missed: present=%t err=%v", present, err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("atomic finalizing rename left internal source: %v", statErr)
	}
	if finalizing, inspectErr := inspectRemovalFinalizingAt(finalizingPath, uid, gid); inspectErr != nil || !finalizing {
		t.Fatalf("atomic finalizing destination: present=%t err=%v", finalizing, inspectErr)
	}
}

func TestRemovalBarrierInspectionFailsClosedBeforeHookForUnsafeInternalRecord_SW2_PKG_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	modified := "SYSWARDEN_REMOVAL_V1\nstate=xn-progress\n"
	if len(modified) != len(RemovalTombstoneRecord) {
		t.Fatalf("test record length = %d", len(modified))
	}
	if err := os.WriteFile(path, []byte(modified), 0600); err != nil {
		t.Fatal(err)
	}
	hookCalls := 0
	present, err := inspectRemovalBarrierAtUsing(
		path,
		removalFinalizingPathFor(path),
		uid,
		gid,
		func() error {
			hookCalls++
			return nil
		},
	)
	if err == nil || !present || hookCalls != 0 {
		t.Fatalf("unsafe internal barrier result: present=%t err=%v hook_calls=%d", present, err, hookCalls)
	}
}

func TestRemovalTombstoneRejectsModifiedHardlinkedAndSymlinkedEvidence_SW2_FWBACKEND_001(t *testing.T) {
	t.Run("modified record", func(t *testing.T) {
		path, uid, gid := testRemovalTombstonePath(t)
		if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		modified := "SYSWARDEN_REMOVAL_V1\nstate=xn-progress\n"
		if len(modified) != len(RemovalTombstoneRecord) {
			t.Fatalf("test record length = %d", len(modified))
		}
		if err := os.WriteFile(path, []byte(modified), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ensureRemovalTombstoneAt(path, uid, gid); err == nil {
			t.Fatal("modified existing record was accepted")
		}
		content, err := os.ReadFile(path) // #nosec G304 -- path is produced by the private tombstone fixture helper
		if err != nil || string(content) != modified {
			t.Fatalf("modified evidence was overwritten: content=%q err=%v", content, err)
		}
		present, err := inspectRemovalTombstoneAt(path, uid, gid)
		if err == nil || !present {
			t.Fatalf("modified evidence inspection: present=%t err=%v", present, err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		path, uid, gid := testRemovalTombstonePath(t)
		if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, filepath.Join(filepath.Dir(path), "operator-link")); err != nil {
			t.Fatal(err)
		}
		present, err := inspectRemovalTombstoneAt(path, uid, gid)
		if err == nil || !present {
			t.Fatalf("hardlinked evidence inspection: present=%t err=%v", present, err)
		}
	})

	t.Run("symlinked state root", func(t *testing.T) {
		root := t.TempDir()
		operator := filepath.Join(root, "operator")
		if err := os.Mkdir(operator, 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(operator, "keep")
		if err := os.WriteFile(marker, []byte("operator"), 0600); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(root, "syswarden")
		if err := os.Symlink(operator, state); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(state, removalTombstoneName)
		uid, gid := systemTestIdentity(t)
		if err := ensureRemovalTombstoneAt(path, uid, gid); err == nil {
			t.Fatal("symlinked state root was accepted")
		}
		present, inspectErr := inspectRemovalTombstoneAt(
			path, uid, gid,
		)
		if inspectErr == nil || !present {
			t.Fatalf("symlinked state root inspection: present=%t err=%v", present, inspectErr)
		}
		content, err := os.ReadFile(marker) // #nosec G304 -- marker is confined to the private symlink-adversary fixture
		if err != nil || string(content) != "operator" {
			t.Fatalf("operator target changed: content=%q err=%v", content, err)
		}
	})
}

func TestRemovalRecordAttestationRejectsMetadataChangeBetweenSnapshots_SW2_PKG_001(t *testing.T) {
	for _, test := range []struct {
		name         string
		requiresRoot bool
		mutate       func(string) error
	}{
		{
			name: "mode",
			mutate: func(path string) error {
				return os.Chmod(path, 0666) // #nosec G302 -- adversarial mode is applied only to a private tombstone fixture that t.TempDir removes
			},
		},
		{
			name: "hardlink",
			mutate: func(path string) error {
				return os.Link(path, path+".operator-link")
			},
		},
		{
			name:         "owner",
			requiresRoot: true,
			mutate: func(path string) error {
				return os.Chown(path, 1, 1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.requiresRoot && os.Geteuid() != 0 {
				t.Skip("owner mutation requires root")
			}
			path, uid, gid := testRemovalTombstonePath(t)
			if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
				t.Fatal(err)
			}
			directory, err := openExistingRemovalStateDirectory(filepath.Dir(path), uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.close()
			_, err = attestExactRemovalRecordUsing(
				directory,
				removalTombstoneName,
				RemovalTombstoneRecord,
				uid,
				gid,
				func() {
					if mutateErr := test.mutate(path); mutateErr != nil {
						t.Fatalf("mutate removal record metadata: %v", mutateErr)
					}
				},
			)
			if err == nil {
				t.Fatal("metadata change between snapshots was accepted")
			}
			if _, statErr := os.Lstat(path); statErr != nil {
				t.Fatalf("metadata race removed the record: %v", statErr)
			}
		})
	}
}

func TestRemovalTombstoneFinalizationRequiresAbsentExecutablesAndEmptyState_SW2_FWBACKEND_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(filepath.Dir(filepath.Dir(path)), "syswarden-cli")
	if err := os.WriteFile(executable, []byte("binary"), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for this finalization fixture
		t.Fatal(err)
	}
	if err := finalizeRemovalTombstoneAt(path, uid, gid, []string{executable}); err == nil ||
		!strings.Contains(err.Error(), "executable path remains") {
		t.Fatalf("present executable finalization = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("executable refusal lost evidence: %v", err)
	}
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	residual := filepath.Join(filepath.Dir(path), "operator-neighbor")
	if err := os.WriteFile(residual, []byte("preserve until explicit cleanup"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := finalizeRemovalTombstoneAt(path, uid, gid, []string{executable}); err == nil ||
		!strings.Contains(err.Error(), "residual") {
		t.Fatalf("residual finalization = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("residual refusal lost evidence: %v", err)
	}
	if err := os.Remove(residual); err != nil {
		t.Fatal(err)
	}
	if err := finalizeRemovalTombstoneAt(path, uid, gid, []string{executable}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory remains after finalization: %v", err)
	}
}

func TestRemovalTombstoneFinalizationCrashRetryKeepsDurableExternalBarrier_SW2_PKG_001(t *testing.T) {
	for _, fault := range []string{
		"after-finalizing-rename",
		"after-finalizing-barrier",
		"after-internal-tombstone",
		"after-state-directory",
	} {
		t.Run(fault, func(t *testing.T) {
			path, uid, gid := testRemovalTombstonePath(t)
			if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
				t.Fatal(err)
			}
			finalizingPath := removalFinalizingPathFor(path)
			panicValue := "simulated worker crash at " + fault
			func() {
				defer func() {
					if recovered := recover(); recovered != panicValue {
						t.Fatalf("recovered crash = %v, want %q", recovered, panicValue)
					}
				}()
				err := finalizeRemovalTombstoneAtUsing(
					path,
					uid,
					gid,
					nil,
					func(point string) {
						if point == fault {
							panic(panicValue)
						}
					},
				)
				if err != nil {
					t.Fatalf("finalization before injected crash: %v", err)
				}
			}()

			present, inspectErr := inspectRemovalBarrierAt(path, finalizingPath, uid, gid)
			if inspectErr != nil || !present {
				t.Fatalf("crash lost removal barrier: present=%t err=%v", present, inspectErr)
			}
			if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("crash left simultaneous internal and external barriers: %v", statErr)
			}
			content, readErr := os.ReadFile(finalizingPath) // #nosec G304 -- finalizingPath is confined to the private crash fixture
			if readErr != nil || string(content) != RemovalFinalizingRecord {
				t.Fatalf("external barrier after crash: content=%q err=%v", content, readErr)
			}

			if err := finalizeRemovalTombstoneAt(path, uid, gid, nil); err != nil {
				t.Fatalf("resume finalization after crash: %v", err)
			}
			if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("resumed finalization left state directory: %v", err)
			}
			if _, err := os.Lstat(finalizingPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("resumed finalization left external barrier: %v", err)
			}
		})
	}
}

func TestRemovalTombstoneFinalizationRejectsStateRootMetadataRace_SW2_PKG_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	directoryPath := filepath.Dir(path)
	err := finalizeRemovalTombstoneAtUsing(
		path,
		uid,
		gid,
		nil,
		func(point string) {
			if point == "before-state-root-recheck" {
				if chmodErr := os.Chmod(directoryPath, 0777); chmodErr != nil { // #nosec G302 -- adversarial mode is confined to the private state-root fixture and restored below
					t.Fatalf("mutate state root metadata: %v", chmodErr)
				}
			}
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed before final deletion") {
		t.Fatalf("state-root metadata race = %v", err)
	}
	if _, statErr := os.Lstat(directoryPath); statErr != nil {
		t.Fatalf("metadata-raced state root was removed: %v", statErr)
	}
	finalizingPath := removalFinalizingPathFor(path)
	if present, inspectErr := inspectRemovalFinalizingAt(finalizingPath, uid, gid); inspectErr != nil || !present {
		t.Fatalf("metadata race lost external barrier: present=%t err=%v", present, inspectErr)
	}
	if err := os.Chmod(directoryPath, 0700); err != nil { // #nosec G302 -- owner-only directory mode restores the private state-root fixture after the adversarial mutation
		t.Fatal(err)
	}
	if err := finalizeRemovalTombstoneAt(path, uid, gid, nil); err != nil {
		t.Fatalf("retry after restoring state-root metadata: %v", err)
	}
}

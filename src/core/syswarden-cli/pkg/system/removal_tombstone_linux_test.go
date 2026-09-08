//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	if _, err := os.Lstat(path + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("idempotent publication left a temporary record: %v", err)
	}
}

func TestExactRemovalRecordRejectsSpecialModeBits_SW2_PKG_001(t *testing.T) {
	t.Parallel()
	for _, bit := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		bit := bit
		t.Run(bit.String(), func(t *testing.T) {
			t.Parallel()
			path, uid, gid := testRemovalTombstonePath(t)
			if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(RemovalTombstoneRecord), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0600|bit); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&bit == 0 {
				t.Skipf("filesystem did not retain special mode bit %v", bit)
			}
			directory, err := openExistingRemovalStateDirectory(filepath.Dir(path), uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			_, attestErr := attestRemovalTombstone(directory, uid, gid)
			directory.close()
			if attestErr == nil {
				t.Fatalf("exact removal record accepted special mode bit %v", bit)
			}
			if err := ensureRemovalTombstoneAt(path, uid, gid); err == nil {
				t.Fatalf("publication accepted existing record with special mode bit %v", bit)
			}
		})
	}
}

func TestExactRemovalRecordPublicationOverridesRestrictiveUmask_SW2_PKG_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	oldUmask := syscall.Umask(0777)
	defer syscall.Umask(oldUmask)
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("published tombstone mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestExactRemovalRecordPublicationRecoversOnlyExactPrefixTemporaries_SW2_PKG_001(t *testing.T) {
	record := "SYSWARDEN_TEST_REMOVAL_V1\nstate=in-progress\n"

	prepare := func(t *testing.T) (string, uint32, uint32) {
		t.Helper()
		uid, gid := systemTestIdentity(t)
		directory := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directory, 0750); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(directory, "record-v1"), uid, gid
	}
	assertPublished := func(t *testing.T, path string) {
		t.Helper()
		content, err := os.ReadFile(path) // #nosec G304 -- path is confined to the private publication fixture
		if err != nil || string(content) != record {
			t.Fatalf("published record content=%q err=%v", content, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
			info.Mode().Perm() != 0600 || stat.Nlink != 1 {
			t.Fatalf("published record metadata is not exact: mode=%v stat=%#v", info.Mode(), stat)
		}
		if _, err := os.Lstat(path + ".new"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("publication left a temporary record: %v", err)
		}
	}

	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "empty interrupted write", content: ""},
		{name: "partial interrupted write", content: record[:17]},
		{name: "complete interrupted write", content: record},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, uid, gid := prepare(t)
			if err := os.WriteFile(path+".new", []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := publishExactRemovalRecordAt(path, record, uid, gid); err != nil {
				t.Fatalf("recover interrupted publication: %v", err)
			}
			assertPublished(t, path)
		})
	}

	t.Run("exact final removes redundant safe temporary", func(t *testing.T) {
		path, uid, gid := prepare(t)
		if err := publishExactRemovalRecordAt(path, record, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".new", []byte(record[:9]), 0600); err != nil {
			t.Fatal(err)
		}
		if err := publishExactRemovalRecordAt(path, record, uid, gid); err != nil {
			t.Fatalf("clean redundant temporary: %v", err)
		}
		assertPublished(t, path)
	})
}

func TestExactRemovalRecordPublicationRepairsRestrictiveTemporaryModes_SW2_PKG_001(t *testing.T) {
	record := "SYSWARDEN_TEST_REMOVAL_V1\nstate=in-progress\n"
	contents := []struct {
		name    string
		content string
	}{
		{name: "empty", content: ""},
		{name: "partial", content: record[:17]},
		{name: "complete", content: record},
	}
	for _, mode := range []os.FileMode{0000, 0200, 0400} {
		mode := mode
		for _, content := range contents {
			content := content
			t.Run(fmt.Sprintf("mode-%04o-%s", mode, content.name), func(t *testing.T) {
				uid, gid := systemTestIdentity(t)
				directoryPath := filepath.Join(t.TempDir(), "state")
				if err := os.Mkdir(directoryPath, 0750); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(directoryPath, "record-v1")
				temporaryPath := path + ".new"
				if err := os.WriteFile(temporaryPath, []byte(content.content), 0600); err != nil {
					t.Fatal(err)
				}

				// Production recovery runs as root and can open a 0000 file. Keep a
				// descriptor opened before chmod so a non-root test process can cover
				// the same descriptor-bound repair logic.
				var preopened *os.File
				if mode == 0000 && os.Geteuid() != 0 {
					var err error
					preopened, err = os.OpenFile(temporaryPath, os.O_RDWR|syscall.O_NOFOLLOW, 0) // #nosec G304 -- private test fixture
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chmod(temporaryPath, mode); err != nil { // #nosec G302 -- restrictive crash mode is the test subject
					if preopened != nil {
						_ = preopened.Close()
					}
					t.Fatal(err)
				}
				if preopened != nil {
					directory, err := openExistingRemovalStateDirectory(directoryPath, uid, gid)
					if err != nil {
						_ = preopened.Close()
						t.Fatal(err)
					}
					used := false
					_, complete, repairErr := attestRecoverableRemovalRecordForPublicationUsing(
						directory,
						filepath.Base(temporaryPath),
						record,
						uid,
						gid,
						func(int) (*os.File, error) {
							if used {
								return nil, fmt.Errorf("preopened test descriptor was requested twice")
							}
							used = true
							return preopened, nil
						},
						func() {},
					)
					directory.close()
					preopened = nil // the repair helper owns and closes the descriptor
					if repairErr != nil || complete != (len(content.content) == len(record)) {
						t.Fatalf("repair restrictive temporary: complete=%t err=%v", complete, repairErr)
					}
				}
				if err := publishExactRemovalRecordAt(path, record, uid, gid); err != nil {
					t.Fatalf("publish after restrictive temporary recovery: %v", err)
				}
				final, err := os.ReadFile(path) // #nosec G304 -- private test fixture
				if err != nil || string(final) != record {
					t.Fatalf("published record content=%q err=%v", final, err)
				}
				info, err := os.Lstat(path)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("published record mode=%v err=%v", info, err)
				}
				if _, err := os.Lstat(temporaryPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("restrictive temporary remains after publication: %v", err)
				}
			})
		}
	}

	t.Run("exact final removes restrictive redundant temporary", func(t *testing.T) {
		uid, gid := systemTestIdentity(t)
		directoryPath := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directoryPath, 0750); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directoryPath, "record-v1")
		if err := publishExactRemovalRecordAt(path, record, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".new", []byte(record[:9]), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+".new", 0400); err != nil { // #nosec G302 -- restrictive crash mode is the test subject
			t.Fatal(err)
		}
		if err := publishExactRemovalRecordAt(path, record, uid, gid); err != nil {
			t.Fatalf("clean restrictive redundant temporary: %v", err)
		}
		if _, err := os.Lstat(path + ".new"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restrictive redundant temporary remains: %v", err)
		}
	})
}

func TestExactRemovalRecordPublicationRejectsUnsafeTemporary_SW2_PKG_001(t *testing.T) {
	record := "SYSWARDEN_TEST_REMOVAL_V1\nstate=in-progress\n"
	withMode := func(mode os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(record), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil { // #nosec G302 -- adversarial mode is the test subject
				t.Fatal(err)
			}
		}
	}

	for _, test := range []struct {
		name   string
		create func(t *testing.T, path string)
	}{
		{
			name: "wrong prefix",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("X"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(record+"X"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong mode",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(record), 0640); err != nil { // #nosec G306 -- adversarial fixture intentionally creates a group-readable recovery record
					t.Fatal(err)
				}
			},
		},
		{name: "other execute mode 0001", create: withMode(0001)},
		{name: "group execute mode 0010", create: withMode(0010)},
		{name: "group read mode 0040", create: withMode(0040)},
		{
			name: "symlink",
			create: func(t *testing.T, path string) {
				t.Helper()
				target := path + ".operator"
				if err := os.WriteFile(target, []byte(record), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			create: func(t *testing.T, path string) {
				t.Helper()
				operator := path + ".operator"
				if err := os.WriteFile(operator, []byte(record), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(operator, path); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			uid, gid := systemTestIdentity(t)
			directory := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(directory, 0750); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "record-v1")
			temporary := path + ".new"
			test.create(t, temporary)
			beforeInfo, err := os.Lstat(temporary)
			if err != nil {
				t.Fatal(err)
			}
			beforeIdentity, err := exactRemovalArtifactIdentity(beforeInfo)
			if err != nil {
				t.Fatal(err)
			}
			if err := publishExactRemovalRecordAt(path, record, uid, gid); err == nil {
				t.Fatal("unsafe interrupted publication was accepted")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe temporary unexpectedly published a final record: %v", err)
			}
			afterInfo, err := os.Lstat(temporary)
			if err != nil {
				t.Fatalf("unsafe temporary was modified or removed: %v", err)
			}
			afterIdentity, err := exactRemovalArtifactIdentity(afterInfo)
			if err != nil || beforeIdentity != afterIdentity {
				t.Fatalf("unsafe temporary identity changed: before=%#v after=%#v err=%v", beforeIdentity, afterIdentity, err)
			}
		})
	}

	t.Run("exact final does not hide unsafe temporary", func(t *testing.T) {
		uid, gid := systemTestIdentity(t)
		directory := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directory, 0750); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "record-v1")
		if err := publishExactRemovalRecordAt(path, record, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".new", []byte("unsafe"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := publishExactRemovalRecordAt(path, record, uid, gid); err == nil {
			t.Fatal("unsafe redundant temporary was hidden by the exact final record")
		}
		content, err := os.ReadFile(path) // #nosec G304 -- path is confined to the private publication fixture
		if err != nil || string(content) != record {
			t.Fatalf("exact final record changed after refusal: content=%q err=%v", content, err)
		}
		if _, err := os.Lstat(path + ".new"); err != nil {
			t.Fatalf("unsafe redundant temporary was removed: %v", err)
		}
	})
}

func TestRecoverableRemovalRecordAttestationRejectsOwnerAndSubstitution_SW2_PKG_001(t *testing.T) {
	record := "SYSWARDEN_TEST_REMOVAL_V1\nstate=in-progress\n"
	uid, gid := systemTestIdentity(t)

	t.Run("wrong owner identity", func(t *testing.T) {
		directoryPath := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directoryPath, 0750); err != nil {
			t.Fatal(err)
		}
		name := "record-v1.new"
		if err := os.WriteFile(filepath.Join(directoryPath, name), []byte(record), 0600); err != nil {
			t.Fatal(err)
		}
		directory, err := openExistingRemovalStateDirectory(directoryPath, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.close()
		if _, _, err := attestRecoverableRemovalRecord(directory, name, record, uid^1, gid); err == nil {
			t.Fatal("recoverable record with a different expected owner was accepted")
		}
	})

	t.Run("inode substitution", func(t *testing.T) {
		directoryPath := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directoryPath, 0750); err != nil {
			t.Fatal(err)
		}
		name := "record-v1.new"
		path := filepath.Join(directoryPath, name)
		replacement := filepath.Join(directoryPath, "replacement")
		if err := os.WriteFile(path, []byte(record), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(replacement, []byte(record), 0600); err != nil {
			t.Fatal(err)
		}
		directory, err := openExistingRemovalStateDirectory(directoryPath, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.close()
		_, _, err = attestRecoverableRemovalRecordUsing(
			directory,
			name,
			record,
			uid,
			gid,
			func() {
				if renameErr := os.Rename(replacement, path); renameErr != nil {
					t.Fatalf("substitute recoverable record: %v", renameErr)
				}
			},
		)
		if err == nil {
			t.Fatal("recoverable record inode substitution was accepted")
		}
	})

	t.Run("restrictive mode substitution after open", func(t *testing.T) {
		directoryPath := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directoryPath, 0750); err != nil {
			t.Fatal(err)
		}
		name := "record-v1.new"
		path := filepath.Join(directoryPath, name)
		displaced := filepath.Join(directoryPath, "displaced")
		replacement := filepath.Join(directoryPath, "replacement")
		for _, candidate := range []string{path, replacement} {
			if err := os.WriteFile(candidate, []byte(record), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(candidate, 0400); err != nil { // #nosec G302 -- restrictive crash mode is the test subject
				t.Fatal(err)
			}
		}
		replacementBefore, err := os.Lstat(replacement)
		if err != nil {
			t.Fatal(err)
		}
		replacementIdentity, err := exactRemovalArtifactIdentity(replacementBefore)
		if err != nil {
			t.Fatal(err)
		}
		directory, err := openExistingRemovalStateDirectory(directoryPath, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.close()
		_, _, err = attestRecoverableRemovalRecordForPublicationUsing(
			directory,
			name,
			record,
			uid,
			gid,
			func(flags int) (*os.File, error) {
				return directory.root.OpenFile(name, flags, 0)
			},
			func() {
				if renameErr := os.Rename(path, displaced); renameErr != nil {
					t.Fatalf("displace opened restrictive temporary: %v", renameErr)
				}
				if renameErr := os.Rename(replacement, path); renameErr != nil {
					t.Fatalf("substitute opened restrictive temporary: %v", renameErr)
				}
			},
		)
		if err == nil {
			t.Fatal("restrictive temporary substitution was accepted")
		}
		current, statErr := os.Lstat(path)
		currentIdentity, identityErr := exactRemovalArtifactIdentity(current)
		if statErr != nil || identityErr != nil || currentIdentity.ino != replacementIdentity.ino ||
			current.Mode().Perm() != 0400 {
			t.Fatalf("replacement was changed by descriptor-bound repair: info=%v err=%v identity_err=%v", current, statErr, identityErr)
		}
		displacedInfo, statErr := os.Lstat(displaced)
		if statErr != nil || displacedInfo.Mode().Perm() != 0600 {
			t.Fatalf("pinned original was not repaired through its descriptor: info=%v err=%v", displacedInfo, statErr)
		}
	})
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
	if _, err := os.Lstat(finalizingPath + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("finalizing publication left a temporary barrier: %v", err)
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

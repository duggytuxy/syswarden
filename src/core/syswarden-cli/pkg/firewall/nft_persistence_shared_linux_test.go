//go:build linux

package firewall

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const nftSharedFixturePath = "/etc/nftables.conf"

func fixtureNFTPersistenceShared(t *testing.T) (nftPersistenceFilesystem, []byte, []byte, string) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	before := []byte("#!/usr/sbin/nft -f\n# Administrator policy stays byte-for-byte intact.\ntable inet administrator { chain input { type filter hook input priority 0; policy drop; } }\n" + legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\ninclude \"/etc/nftables.d/administrator.nft\"\n")
	if err := host.root.WriteFile(nftSharedFixturePath[1:], before, 0640); err != nil {
		t.Fatal(err)
	}
	file, err := host.root.Open(nftSharedFixturePath[1:])
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"user.administrator": []byte("preserve me"), "user.binary": {0, 255, 2}, "user.empty": {}} {
		if err := unix.Fsetxattr(int(file.Fd()), name, value, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Linux POSIX ACL xattr version 2, with a named read-only fixture user.
	// The effective mask preserves the source's existing 0640 permissions.
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, entry := range []struct {
		tag         uint16
		permissions uint16
		id          uint32
	}{{1, 6, 0xffffffff}, {2, 4, 12345}, {4, 4, 0xffffffff}, {16, 4, 0xffffffff}, {32, 0, 0xffffffff}} {
		acl = binary.LittleEndian.AppendUint16(acl, entry.tag)
		acl = binary.LittleEndian.AppendUint16(acl, entry.permissions)
		acl = binary.LittleEndian.AppendUint32(acl, entry.id)
	}
	if err := unix.Fsetxattr(int(file.Fd()), "system.posix_acl_access", acl, 0); err != nil {
		t.Fatal("fixture filesystem must support a named POSIX access ACL", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	edit, err := planLegacyNFTIncludeRetirement(before)
	if err != nil {
		t.Fatal(err)
	}
	return host, before, edit.content, strings.Repeat("a", 64)
}

func fixtureNFTPersistenceSharedGuard(host nftPersistenceFilesystem, before, after []byte) func(bool) error {
	return func(edited bool) error {
		expected := before
		if edited {
			expected = after
		}
		current, err := host.snapshot(nftSharedFixturePath)
		if err != nil || !bytes.Equal(current.content, expected) {
			return fmt.Errorf("shared fixture source changed")
		}
		return nil
	}
}

func TestNFTPersistenceSharedEditPreservesAdministratorBytesAndMetadata(t *testing.T) {
	host, before, after, review := fixtureNFTPersistenceShared(t)
	guard := fixtureNFTPersistenceSharedGuard(host, before, after)
	original, attrs, err := snapshotNFTPersistenceMetadata(host, nftSharedFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	record, err := prepareNFTPersistenceSharedEdit(host, nftSharedFixturePath, review, func() error { return guard(false) }, defaultLegacyRetirementFileOps())
	if err != nil {
		t.Fatal(err)
	}
	if err := guard(false); err != nil {
		t.Fatal("preparation edited the active shared file", err)
	}
	if err := applyNFTPersistenceSharedEdit(host, record, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	if err := applyNFTPersistenceSharedEdit(host, record, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal("completed edit was not idempotent", err)
	}
	state, err := inspectNFTPersistenceSharedState(host, record)
	if err != nil || state.phase != 2 || !bytes.Equal(state.original.content, before) || !bytes.Equal(state.replacement.content, after) {
		t.Fatal("shared edit is incomplete", err)
	}
	backup, backupAttrs, err := snapshotNFTPersistenceMetadata(host, nftPersistenceSharedDirectory(record)+"/original")
	if err != nil || !os.SameFile(original.identity, backup.identity) || nftPersistenceXattrDigest(backupAttrs) != nftPersistenceXattrDigest(attrs) {
		t.Fatal("original inode or metadata was not retained", err)
	}
	active, activeAttrs, err := snapshotNFTPersistenceMetadata(host, nftSharedFixturePath)
	if err != nil || active.identity.Mode().Perm() != original.identity.Mode().Perm() || nftPersistenceXattrDigest(activeAttrs) != nftPersistenceXattrDigest(attrs) {
		t.Fatal("replacement lost active-file permissions or metadata", err)
	}
}

func TestNFTPersistenceSharedEditResumesEveryDurabilityBoundary(t *testing.T) {
	for _, phase := range []string{"edit-staged", "shared-edit-intent-durable", "shared-edit-exchanged", "shared-edit-original-retained", "shared-edit-durable", "lost-exchange-ack", "sync"} {
		t.Run(phase, func(t *testing.T) {
			host, before, after, review := fixtureNFTPersistenceShared(t)
			guard := fixtureNFTPersistenceSharedGuard(host, before, after)
			interrupted := fmt.Errorf("injected shared-file interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(point string) error {
				if point == phase {
					return interrupted
				}
				return nil
			}
			prepareOps := defaultLegacyRetirementFileOps()
			if phase == "edit-staged" || phase == "shared-edit-intent-durable" {
				prepareOps = ops
			}
			record, err := prepareNFTPersistenceSharedEdit(host, nftSharedFixturePath, review, func() error { return guard(false) }, prepareOps)
			if phase == "edit-staged" || phase == "shared-edit-intent-durable" {
				if !errors.Is(err, interrupted) {
					t.Fatal("private preparation interruption was not observed", err)
				}
				record, err = prepareNFTPersistenceSharedEdit(host, nftSharedFixturePath, review, func() error { return guard(false) }, defaultLegacyRetirementFileOps())
				if err != nil {
					t.Fatal("private preparation did not resume", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if phase == "sync" {
					ops.sync = func(*os.File) error { return interrupted }
				}
				if phase == "lost-exchange-ack" {
					rename := ops.rename
					ops.rename = func(oldFD int, old string, newFD int, next string, flags uint) error {
						if err := rename(oldFD, old, newFD, next, flags); err != nil {
							return err
						}
						if flags == unix.RENAME_EXCHANGE {
							return interrupted
						}
						return nil
					}
				}
				if err := applyNFTPersistenceSharedEdit(host, record, guard, ops); !errors.Is(err, interrupted) {
					t.Fatal("shared edit interruption was not observed", err)
				}
			}
			loaded, err := readNFTPersistenceSharedRecord(host, nftSharedFixturePath, review)
			if err != nil || loaded != record {
				t.Fatal("private shared edit evidence changed", err)
			}
			if err := applyNFTPersistenceSharedEdit(host, loaded, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("interrupted shared edit did not resume", err)
			}
			state, err := inspectNFTPersistenceSharedState(host, loaded)
			if err != nil || state.phase != 2 {
				t.Fatal("resumed edit was not exactly complete", err)
			}
		})
	}
}

func TestNFTPersistenceSharedEditRejectsChangedSourcesAndIntent(t *testing.T) {
	for _, mutation := range []string{"source", "stage", "xattr", "mode", "intent", "unbound-payload", "guard", "missing-guard"} {
		t.Run(mutation, func(t *testing.T) {
			host, before, after, review := fixtureNFTPersistenceShared(t)
			guard := fixtureNFTPersistenceSharedGuard(host, before, after)
			record, err := prepareNFTPersistenceSharedEdit(host, nftSharedFixturePath, review, func() error { return guard(false) }, defaultLegacyRetirementFileOps())
			if err != nil {
				t.Fatal(err)
			}
			directory := nftPersistenceSharedDirectory(record)
			switch mutation {
			case "source":
				err = host.root.WriteFile(nftSharedFixturePath[1:], []byte("changed administrator policy"), 0600)
			case "stage":
				err = host.root.WriteFile(directory[1:]+"/"+record.Stage, []byte("unreviewed replacement"), 0600)
			case "mode":
				err = host.root.Chmod(nftSharedFixturePath[1:], 0600)
			case "xattr":
				file, openErr := host.root.Open(nftSharedFixturePath[1:])
				if openErr != nil {
					t.Fatal(openErr)
				}
				err = unix.Fsetxattr(int(file.Fd()), "user.administrator", []byte("changed"), 0)
				_ = file.Close()
			case "intent":
				err = host.root.WriteFile(directory[1:]+"/edit.json", []byte("{}"), 0600)
			case "unbound-payload":
				record.Replacement.Source.SHA256 = strings.Repeat("f", 64)
			case "guard":
				guard = func(bool) error { return fmt.Errorf("dependency changed") }
			case "missing-guard":
				guard = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			current, err := host.snapshot(nftSharedFixturePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := applyNFTPersistenceSharedEdit(host, record, guard, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("changed shared-file evidence authorized an exchange", mutation)
			}
			retained, err := host.snapshot(nftSharedFixturePath)
			if err != nil || !sameLegacyFail2banSource(current, retained) {
				t.Fatal("refused edit modified the active shared file", err)
			}
		})
	}
}

func TestNFTPersistenceSharedEditRestoresAnUnexpectedExchangeSource(t *testing.T) {
	host, before, after, review := fixtureNFTPersistenceShared(t)
	guard := fixtureNFTPersistenceSharedGuard(host, before, after)
	record, err := prepareNFTPersistenceSharedEdit(host, nftSharedFixturePath, review, func() error { return guard(false) }, defaultLegacyRetirementFileOps())
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("# Concurrent administrator policy must remain active.\n")
	ops := defaultLegacyRetirementFileOps()
	rename, injected := ops.rename, false
	ops.rename = func(oldFD int, old string, newFD int, next string, flags uint) error {
		if flags == unix.RENAME_EXCHANGE && !injected {
			injected = true
			if err := host.root.WriteFile(nftSharedFixturePath[1:], changed, 0640); err != nil {
				return err
			}
		}
		return rename(oldFD, old, newFD, next, flags)
	}
	if err := applyNFTPersistenceSharedEdit(host, record, guard, ops); err == nil {
		t.Fatal("concurrent administrator change was accepted as product evidence")
	}
	active, err := host.root.ReadFile(nftSharedFixturePath[1:])
	if err != nil || !bytes.Equal(active, changed) {
		t.Fatal("concurrent administrator content was not restored to its active path", err)
	}
}

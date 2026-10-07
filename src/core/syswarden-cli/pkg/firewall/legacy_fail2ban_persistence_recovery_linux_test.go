//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func fixtureLegacyFail2banPersistence(t *testing.T) (nftPersistenceFilesystem, legacyFail2banPersistenceRecord, string) {
	t.Helper()
	host, _, _, _ := fixtureNFTPersistenceShared(t)
	_, _, kernel := fixtureLegacyFail2banNFTJournal(t, true)
	if err := host.root.WriteFile("etc/nftables.conf", []byte(legacyFail2banPersistenceFixture), 0640); err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile("etc/administrator.nft", []byte("table inet administrator { chain input { type filter hook input priority 0; policy accept; } }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loader := &nftPersistenceLoaderInspection{digest: strings.Repeat("a", 64), status: nftPersistenceLoaderStatus{entries: []string{"/etc/nftables.conf"}}}
	record, review, err := prepareLegacyFail2banPersistence(host, loader, kernel.Quiescence.FilePlan, kernel)
	if err != nil {
		t.Fatal(err)
	}
	return host, record, review
}

func TestLegacyFail2banPersistenceResumesExactSharedEdits(t *testing.T) {
	for _, phase := range []string{"none", "shared-edit-intent-durable", "shared-edit-exchanged", "shared-edit-original-retained", "shared-edit-durable"} {
		t.Run(phase, func(t *testing.T) {
			host, record, review := fixtureLegacyFail2banPersistence(t)
			original, attrs, err := snapshotNFTPersistenceMetadata(host, nftSharedFixturePath)
			if err != nil {
				t.Fatal(err)
			}
			guard := func() error { _, err := inspectLegacyFail2banPersistenceState(host, record, review); return err }
			planner := func(content []byte) (nftPersistenceEdit, error) {
				return planLegacyFail2banPersistence(content, record.Kernel)
			}
			interrupted := errors.New("injected persistent retirement interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(current string) error {
				if current == phase {
					return interrupted
				}
				return nil
			}
			shared, err := prepareNFTPersistenceSharedEditUsing(host, nftSharedFixturePath, review, guard, ops, planner)
			if phase == "shared-edit-intent-durable" {
				if !errors.Is(err, interrupted) {
					t.Fatal("preparation interruption was not reached", err)
				}
				shared, err = prepareNFTPersistenceSharedEditUsing(host, nftSharedFixturePath, review, guard, defaultLegacyRetirementFileOps(), planner)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = applyNFTPersistenceSharedEditUsing(host, shared, func(bool) error { return guard() }, ops, planner)
			if phase == "none" || phase == "shared-edit-intent-durable" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, interrupted) {
				t.Fatal("exchange interruption was not reached", err)
			}
			if err := applyNFTPersistenceSharedEditUsing(host, shared, func(bool) error { return guard() }, defaultLegacyRetirementFileOps(), planner); err != nil {
				t.Fatal("exact durable edit could not resume", err)
			}
			edited, err := inspectLegacyFail2banPersistenceState(host, record, review)
			if err != nil || !edited[nftSharedFixturePath] || len(edited) != 1 {
				t.Fatal("shared edit was not completely retained", err)
			}
			backup, backupAttrs, err := snapshotNFTPersistenceMetadata(host, nftPersistenceSharedDirectory(shared)+"/original")
			if err != nil || !os.SameFile(backup.identity, original.identity) || !bytes.Equal(backup.content, original.content) || nftPersistenceXattrDigest(attrs) != nftPersistenceXattrDigest(backupAttrs) {
				t.Fatal("original bytes, inode or access control metadata changed", err)
			}
			if _, err := inspectNFTPersistenceSharedState(host, shared); err == nil {
				t.Fatal("an include-only coordinator accepted a different edit authority")
			}
		})
	}
}

func TestLegacyFail2banPersistenceBindsDependenciesAndOriginalAuthority(t *testing.T) {
	for _, change := range []string{"content", "inode", "mode", "include", "absent-entry", "intent", "claim", "loader", "missing-source"} {
		t.Run(change, func(t *testing.T) {
			host, record, review := fixtureLegacyFail2banPersistence(t)
			var err error
			switch change {
			case "content":
				err = host.root.WriteFile("etc/administrator.nft", []byte("table inet administrator { }\n"), 0600)
			case "inode":
				original, readErr := host.read(nftSharedFixturePath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				err = host.root.Rename("etc/nftables.conf", "etc/operator-saved.nft")
				if err == nil {
					err = host.root.WriteFile("etc/nftables.conf", original, 0640)
				}
			case "mode":
				err = host.root.Chmod("etc/administrator.nft", 0644)
			case "include":
				err = host.root.WriteFile("etc/administrator.nft", []byte("include \"/etc/additional.nft\"\n"), 0600)
			case "absent-entry":
				if len(record.Absent) == 0 {
					t.Fatal("fixture has no absent entry")
				}
				path := record.Absent[0]
				parent := path[:strings.LastIndex(path, "/")]
				err = host.root.MkdirAll(strings.TrimPrefix(parent, "/"), 0700)
				if err == nil {
					err = host.root.WriteFile(path[1:], []byte("# newly installed loader entry\n"), 0600)
				}
			case "intent":
				record.Sources[0].EditedSHA256 = strings.Repeat("f", 64)
			case "claim":
				record.Kernel.Quiescence.FilePlan = strings.Repeat("f", 64)
			case "loader":
				record.Loader = strings.Repeat("f", 64)
			case "missing-source":
				err = host.root.Remove("etc/administrator.nft")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inspectLegacyFail2banPersistenceState(host, record, review); err == nil {
				t.Fatalf("changed %s was accepted", change)
			}
		})
	}
}

func TestLegacyFail2banPersistenceReviewReusesOnlyExactOriginalIntent(t *testing.T) {
	for _, change := range []string{"none", "content", "mode", "guard"} {
		t.Run(change, func(t *testing.T) {
			host, record, review := fixtureLegacyFail2banPersistence(t)
			guard := func() error { _, err := inspectLegacyFail2banPersistenceState(host, record, review); return err }
			wire, err := persistLegacyFail2banPersistenceReview(host, record, review, guard, defaultLegacyRetirementFileOps())
			if err != nil {
				t.Fatal(err)
			}
			path := legacyFail2banPersistencePath(record.FilePlan, review) + "/intent.json"
			before, err := host.snapshot(path)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "content":
				err = host.root.WriteFile(path[1:], append(bytes.Clone(wire), '\n'), 0600)
			case "mode":
				err = host.root.Chmod(path[1:], 0644)
			case "guard":
				guard = func() error { return errors.New("independent producer changed") }
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = persistLegacyFail2banPersistenceReview(host, record, review, guard, defaultLegacyRetirementFileOps())
			if (err == nil) != (change == "none") {
				t.Fatal("incorrect exact-intent resumption", change, err)
			}
			after, err := host.snapshot(path)
			if err != nil || !os.SameFile(before.identity, after.identity) {
				t.Fatal("resumption replaced original evidence", err)
			}
			if change == "none" && !bytes.Equal(after.content, wire) {
				t.Fatal("resumption rewrote original evidence")
			}
		})
	}
}

//go:build linux

package firewall

import (
	"crypto/sha256"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureNFTPersistenceGraphRecord(t *testing.T) (nftPersistenceFilesystem, map[string]string, []nftPersistenceRetiredSource) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	if err := host.root.MkdirAll("root", 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"/etc/nftables.conf":                   "include \"/etc/nftables.d/*.nft\"\n" + legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n",
		"/etc/nftables.d/10-administrator.nft": "include \"/root/operator-policy.nft\"\n",
		"/root/operator-policy.nft":            "table inet administrator { chain input { type filter hook input priority 0; policy drop; } }\n",
		legacyNFTIncludePath:                   "table inet syswarden_table { }\n",
	}
	for path, content := range files {
		if err := host.root.WriteFile(path[1:], []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return host, files, []nftPersistenceRetiredSource{{legacyNFTIncludePath, sha256.Sum256([]byte(files[legacyNFTIncludePath]))}}
}

func TestNFTPersistenceGraphRecordBindsEverySourceWithoutMutation(t *testing.T) {
	host, files, retiring := fixtureNFTPersistenceGraphRecord(t)
	record, digest, err := prepareNFTPersistenceGraphRecord(host, []string{nftSharedFixturePath}, retiring, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil || len(record.Sources) != len(files) || !validLegacyRetirementDigest(digest) {
		t.Fatal("complete source graph was not bound", err)
	}
	var outside, edited bool
	for _, source := range record.Sources {
		outside = outside || source.Artifact.Path == "/root/operator-policy.nft"
		if source.Artifact.Path == nftSharedFixturePath {
			edited = source.EditedSHA256 != source.Artifact.SHA256
		}
	}
	if !outside || !edited || len(record.Expansions) != 1 || !reflect.DeepEqual(record.Retiring, []string{legacyNFTIncludePath}) {
		t.Fatal("graph lost a retained external file or its bounded edit")
	}
	for path, content := range files {
		actual, err := host.root.ReadFile(path[1:])
		if err != nil || string(actual) != content {
			t.Fatal("read-only graph preparation changed a source", err)
		}
	}
	if _, err := host.root.Stat("var/backups"); !os.IsNotExist(err) {
		t.Fatal("read-only graph preparation wrote private staging")
	}
}

func TestNFTPersistenceGraphRecordRejectsDetachedAdministratorDependencies(t *testing.T) {
	host, files, retiring := fixtureNFTPersistenceGraphRecord(t)
	files[legacyNFTIncludePath] += "include \"/root/detached-administrator.nft\"\n"
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(files[legacyNFTIncludePath]), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile("root/detached-administrator.nft", []byte("table inet retained { }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	retiring[0].sha256 = sha256.Sum256([]byte(files[legacyNFTIncludePath]))
	if record, digest, err := prepareNFTPersistenceGraphRecord(host, []string{nftSharedFixturePath}, retiring, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil || digest != "" || record.Schema != "" {
		t.Fatal("graph retirement detached administrator configuration")
	}
}

func TestNFTPersistenceGraphRecordChangesWhenMetadataOrWildcardsChange(t *testing.T) {
	for _, kind := range []string{"xattr", "wildcard", "ownership", "producer"} {
		t.Run(kind, func(t *testing.T) {
			host, _, retiring := fixtureNFTPersistenceGraphRecord(t)
			ownership, producer := strings.Repeat("a", 64), strings.Repeat("b", 64)
			_, before, err := prepareNFTPersistenceGraphRecord(host, []string{nftSharedFixturePath}, retiring, ownership, producer)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "xattr":
				file, err := host.root.Open("root/operator-policy.nft")
				if err != nil {
					t.Fatal(err)
				}
				err = unix.Fsetxattr(int(file.Fd()), "user.administrator", []byte("changed"), 0)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "wildcard":
				if err := host.root.WriteFile("etc/nftables.d/20-administrator.nft", []byte("table inet extra { }\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "ownership":
				ownership = strings.Repeat("c", 64)
			case "producer":
				producer = strings.Repeat("d", 64)
			}
			_, after, err := prepareNFTPersistenceGraphRecord(host, []string{nftSharedFixturePath}, retiring, ownership, producer)
			if err != nil || before == after {
				t.Fatal("changed graph evidence retained the reviewed digest", kind, err)
			}
		})
	}
}

func TestNFTPersistenceGraphRecordRejectsIncompleteOrAmbiguousBindings(t *testing.T) {
	for _, kind := range []string{"empty-ownership", "empty-producer", "duplicate-source", "duplicate-entry", "duplicate-target", "retired-entry", "missing-parent", "writable-source", "symlink-mode", "invalid-fs", "bad-edit", "unbounded-size", "duplicate-pattern", "unbound-expansion"} {
		t.Run(kind, func(t *testing.T) {
			host, _, retiring := fixtureNFTPersistenceGraphRecord(t)
			record, _, err := prepareNFTPersistenceGraphRecord(host, []string{nftSharedFixturePath}, retiring, strings.Repeat("a", 64), strings.Repeat("b", 64))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "empty-ownership":
				record.Ownership = strings.Repeat("0", 64)
			case "empty-producer":
				record.Producers = ""
			case "duplicate-source":
				record.Sources = append(record.Sources, record.Sources[0])
			case "duplicate-entry":
				record.Entries = append(record.Entries, record.Entries[0])
			case "duplicate-target":
				record.Retiring = append(record.Retiring, record.Retiring[0])
			case "retired-entry":
				record.Retiring = []string{nftSharedFixturePath}
			case "missing-parent":
				record.Directories = nil
			case "writable-source":
				record.Sources[0].Artifact.Mode = 0666
			case "symlink-mode":
				record.Sources[0].Artifact.Mode = 0120777
			case "invalid-fs":
				record.Sources[0].Artifact.FilesystemUUID = "invalid"
			case "bad-edit":
				record.Sources[0].EditedSHA256 = "invalid"
			case "unbounded-size":
				record.Sources[0].Size = maximumNFTPersistenceBytes + 1
			case "duplicate-pattern":
				record.Expansions = append(record.Expansions, record.Expansions[0])
			case "unbound-expansion":
				record.Expansions[0].Paths = []string{"/etc/nftables.d/not-inspected.nft"}
			}
			if content, digest, err := encodeNFTPersistenceGraphRecord(record, host); err == nil || content != nil || digest != "" {
				t.Fatal("incomplete graph binding was accepted", kind)
			}
		})
	}
}

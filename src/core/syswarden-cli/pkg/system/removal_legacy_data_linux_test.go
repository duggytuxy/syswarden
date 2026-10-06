//go:build linux

package system

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func legacyDataFixture(t *testing.T, kind string) (string, string, legacyRetentionProfile) {
	t.Helper()
	profile, err := legacyDataProfile(kind)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	parent, backups := filepath.Join(base, "active"), filepath.Join(base, "backups")
	for _, path := range []string{parent, backups, filepath.Join(parent, filepath.Base(profile.directory))} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, kind := range profile.names {
		content := "private synthetic data\n"
		if kind == "blocklist-pair" {
			content = "SYSWARDEN_PERSISTENT_BLOCKLIST_PAIR_V1\n"
		} else if kind == "whitelist-pair" {
			content = "SYSWARDEN_PERSISTENT_WHITELIST_PAIR_V1\n"
		}
		if err := os.WriteFile(filepath.Join(parent, filepath.Base(profile.directory), name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return parent, backups, profile
}

func TestLegacyDataRetentionKeepsExactBytesInodesAndRetry(t *testing.T) {
	for _, kind := range []string{"lists", "ui"} {
		t.Run(kind, func(t *testing.T) {
			parent, backups, profile := legacyDataFixture(t, kind)
			active := filepath.Join(parent, filepath.Base(profile.directory))
			directory, err := openExistingPinnedServiceDirectory(active)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, plan, err := inspectLegacyDataDirectory(directory, false, profile)
			directory.close()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(plan)
			if err != nil || strings.Contains(string(wire), "private synthetic data") {
				t.Fatal("plan disclosed raw content", err)
			}
			if _, _, err := applyLegacyRetention(parent, backups, strings.Repeat("0", 64), func() error { return nil }, unix.Renameat2, profile); err == nil {
				t.Fatal("unreviewed inventory was moved")
			}
			originals := map[string]os.FileInfo{}
			contents := map[string][]byte{}
			originalRoot, err := os.OpenRoot(active)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = originalRoot.Close() }()
			for name := range profile.names {
				originals[name], err = os.Stat(filepath.Join(active, name))
				if err != nil {
					t.Fatal(err)
				}
				contents[name], err = originalRoot.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, backup, err := applyLegacyRetention(parent, backups, snapshot.digest, func() error { return nil }, unix.Renameat2, profile)
			if err != nil {
				t.Fatal(err)
			}
			savedRoot, err := os.OpenRoot(backup)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = savedRoot.Close() }()
			for name, original := range originals {
				info, err := os.Stat(filepath.Join(backup, name))
				if err != nil || !os.SameFile(original, info) {
					t.Fatal("original inode changed", err)
				}
				content, err := savedRoot.ReadFile(name)
				if err != nil || string(content) != string(contents[name]) {
					t.Fatal("original data changed", err)
				}
			}
			_, resumed, err := applyLegacyRetention(parent, backups, snapshot.digest, func() error { return nil }, unix.Renameat2, profile)
			if err != nil || resumed != backup {
				t.Fatal("exact completed operation did not resume", err)
			}
		})
	}
}

func TestLegacyDataRetentionRejectsModifiedSharedAndUnrelatedEntries(t *testing.T) {
	for _, kind := range []string{"lists", "ui"} {
		for _, mutation := range []string{"changed", "extra", "hardlink", "symlink", "marker", "guard"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				parent, backups, profile := legacyDataFixture(t, kind)
				active := filepath.Join(parent, filepath.Base(profile.directory))
				name, attribute := "data.json", productSnapshotOriginAttribute
				if kind == "lists" {
					name, attribute = "syswarden_whitelist.ipv4", generatedListOriginAttribute
				}
				path := filepath.Join(active, name)
				directory, err := openExistingPinnedServiceDirectory(active)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, _, err := inspectLegacyDataDirectory(directory, false, profile)
				directory.close()
				if err != nil {
					t.Fatal(err)
				}
				guard := func() error { return nil }
				switch mutation {
				case "changed":
					err = os.WriteFile(path, []byte("changed private input"), 0600)
				case "extra":
					err = os.WriteFile(filepath.Join(active, "administrator.conf"), []byte("preserve"), 0600)
				case "hardlink":
					err = os.Link(path, filepath.Join(parent, "shared"))
				case "symlink":
					if err = os.Remove(path); err == nil {
						err = os.Symlink("../../external", path)
					}
				case "marker":
					err = unix.Setxattr(path, attribute, []byte("invalid copied marker"), 0)
				case "guard":
					guard = func() error { return os.ErrPermission }
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := applyLegacyRetention(parent, backups, snapshot.digest, guard, unix.Renameat2, profile); err == nil {
					t.Fatal("ambiguous data was moved")
				}
				if _, err := os.Lstat(path); err != nil {
					t.Fatal("refusal lost active evidence", err)
				}
			})
		}
	}
}

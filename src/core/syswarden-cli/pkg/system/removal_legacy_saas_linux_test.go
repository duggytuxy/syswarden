//go:build linux

package system

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func legacySaaSFixture(t *testing.T, names []string) (string, string, legacyRetentionProfile) {
	t.Helper()
	parent, backups, _ := generatedListRetirementFixture(t)
	profile, err := legacyDataProfile("lists")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(parent, "lists", name), []byte("private historical cache bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return parent, backups, profile
}

func TestLegacySaaSRetentionRequiresReviewAndPreservesOriginals(t *testing.T) {
	for _, names := range [][]string{
		{"syswarden_saas_monitors.ipv4"},
		{"syswarden_saas_monitors.ipv4", "syswarden_saas_monitors.ipv6"},
		{"syswarden_saas_monitors.ipv4", "syswarden_saas_monitors.ipv6", "syswarden_saas_monitors.pair"},
		{"syswarden_saas_monitors.pair"},
	} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			parent, backups, profile := legacySaaSFixture(t, names)
			active := filepath.Join(parent, "lists")
			directory, err := openExistingPinnedServiceDirectory(active)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.close()
			if _, err := inspectGeneratedListDirectory(directory); err == nil {
				t.Fatal("unmarked SaaS cache acquired automatic retirement authority")
			}
			snapshot, plan, err := inspectLegacyDataDirectory(directory, false, profile)
			if err != nil || len(plan.Files) != 6+len(names) {
				t.Fatal("historical inventory was not inspectable", err)
			}
			wire, err := json.Marshal(plan)
			if err != nil || bytes.Contains(wire, []byte("private historical cache bytes")) {
				t.Fatal("plan disclosed cache content", err)
			}
			originals := map[string]os.FileInfo{}
			content := map[string][]byte{}
			for _, file := range plan.Files {
				name := filepath.Base(file.Path)
				originals[name], err = os.Stat(filepath.Join(active, name))
				if err != nil {
					t.Fatal(err)
				}
				content[name], err = os.ReadFile(filepath.Join(active, name))
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(name, "syswarden_saas_") && file.CreationProvenance {
					t.Fatal("cache name or pair manifest acquired ownership")
				}
			}
			if _, _, err := applyLegacyRetention(parent, backups, strings.Repeat("0", 64), func() error { return nil }, unix.Renameat2, profile); err == nil {
				t.Fatal("unreviewed cache inventory was moved")
			}
			_, backup, err := applyLegacyRetention(parent, backups, snapshot.digest, func() error { return nil }, unix.Renameat2, profile)
			if err != nil {
				t.Fatal(err)
			}
			for name, before := range originals {
				path := filepath.Join(backup, name)
				after, err := os.Stat(path)
				if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
					t.Fatal("original cache inode or metadata changed", name, err)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, content[name]) {
					t.Fatal("original cache content changed", name, err)
				}
			}
			_, repeated, err := applyLegacyRetention(parent, backups, snapshot.digest, func() error { return nil }, unix.Renameat2, profile)
			if err != nil || repeated != backup {
				t.Fatal("exact completed cache retention did not resume", err)
			}
		})
	}
}

func TestLegacySaaSRetentionRejectsChangesAndAmbiguity(t *testing.T) {
	for _, name := range []string{"syswarden_saas_monitors.ipv4", "syswarden_saas_monitors.ipv6", "syswarden_saas_monitors.pair"} {
		for _, mutation := range []string{"content", "replace", "permissions", "hardlink", "symlink", "origin", "extra", "guard"} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				parent, backups, profile := legacySaaSFixture(t, []string{name})
				active := filepath.Join(parent, "lists")
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
				case "content":
					err = os.WriteFile(path, []byte("changed administrator input\n"), 0600)
				case "replace":
					err = os.Rename(path, filepath.Join(parent, "original"))
					if err == nil {
						err = os.WriteFile(path, []byte("private historical cache bytes\n"), 0600)
					}
				case "permissions":
					err = os.Chmod(path, 0640)
				case "hardlink":
					err = os.Link(path, filepath.Join(parent, "shared"))
				case "symlink":
					err = os.Rename(path, filepath.Join(parent, "original"))
					if err == nil {
						err = os.Symlink("../original", path)
					}
				case "origin":
					err = unix.Setxattr(path, generatedListOriginAttribute, []byte("unrecognized marker"), 0)
				case "extra":
					err = os.WriteFile(filepath.Join(active, "administrator.list"), []byte("preserve\n"), 0600)
				case "guard":
					guard = func() error { return os.ErrPermission }
				}
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := applyLegacyRetention(parent, backups, snapshot.digest, guard, unix.Renameat2, profile); err == nil {
					t.Fatal("changed or ambiguous cache was retired")
				}
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("refusal changed active evidence", err)
				}
			})
		}
	}
}

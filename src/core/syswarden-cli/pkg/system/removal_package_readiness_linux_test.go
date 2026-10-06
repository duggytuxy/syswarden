//go:build linux

package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageRuntimeRetirementRejectsUnretiredFilesWithoutMutation(t *testing.T) {
	for _, logical := range hostRemovalMountRoots {
		t.Run(logical, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "product")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, ".administrator.conf"), []byte("keep effective configuration\n"), 0600); err != nil {
				t.Fatal(err)
			}
			err := attestRuntimeRetirementRoot(path, logical, systemTestUID(t), systemTestGID(t), nil)
			if err == nil || !strings.Contains(err.Error(), "unretired artifact") {
				t.Fatal("native erase admitted an unresolved file", err)
			}
			root, err := os.OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			content, err := root.ReadFile(".administrator.conf")
			if err != nil || string(content) != "keep effective configuration\n" {
				t.Fatal("read-only retirement check changed the administrator file", err)
			}
		})
	}
}

func TestPackageRuntimeRetirementAcceptsOnlyEmptyRuntimeSkeleton(t *testing.T) {
	for _, logical := range []string{"/etc/syswarden", "/var/log/syswarden", "/var/lib/syswarden"} {
		t.Run(logical, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "product")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			directories, _ := packageRetirementChildren(logical)
			for _, name := range directories {
				if err := os.Mkdir(filepath.Join(path, name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := attestRuntimeRetirementRoot(path, logical, systemTestUID(t), systemTestGID(t), nil); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(path, "administrator"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := attestRuntimeRetirementRoot(path, logical, systemTestUID(t), systemTestGID(t), nil); err == nil {
				t.Fatal("an empty administrator directory was adopted")
			}
		})
	}
}

func TestPackageRuntimeRetirementRefusesNestedAndConcurrentRemainders(t *testing.T) {
	for _, phase := range []string{"before", "after", "replacement"} {
		t.Run(phase, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "product")
			modules := filepath.Join(path, "config", "modules")
			if err := os.MkdirAll(modules, 0700); err != nil {
				t.Fatal(err)
			}
			change := func() {
				if phase == "replacement" {
					if err := os.Rename(modules, filepath.Join(base, "retained-modules")); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(modules, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(filepath.Join(modules, "operator.toml"), []byte("private configuration\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var hook func()
			if phase == "before" {
				change()
			} else {
				hook = change
			}
			if err := attestRuntimeRetirementRoot(path, "/etc/syswarden", systemTestUID(t), systemTestGID(t), hook); err == nil {
				t.Fatal("nested or concurrent remainder allowed native erase")
			}
		})
	}
}

func TestPackageRuntimeRetirementDoesNotFollowSkeletonLinks(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "product")
	outside := filepath.Join(base, "administrator")
	for _, directory := range []string{path, outside} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(path, "config")); err != nil {
		t.Fatal(err)
	}
	if err := attestRuntimeRetirementRoot(path, "/etc/syswarden", systemTestUID(t), systemTestGID(t), nil); err == nil {
		t.Fatal("symlinked skeleton accepted")
	}
	if _, err := os.Lstat(outside); err != nil {
		t.Fatal("external directory was changed", err)
	}
}

//go:build linux

package system

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStandalonePayloadRetainsPackagedAndHardenedDirectoryModes(t *testing.T) {
	for _, outer := range []os.FileMode{0750, 0755} {
		for _, inner := range []os.FileMode{0750, 0755} {
			t.Run(fmt.Sprintf("%04o/%04o", outer, inner), func(t *testing.T) {
				base, root, expected := standalonePayloadFixture(t)
				before := map[string]os.FileInfo{}
				for name, mode := range map[string]os.FileMode{"syswarden": outer, "syswarden/bin": inner} {
					if err := root.Chmod(name, mode); err != nil {
						t.Fatal(err)
					}
					info, err := root.Stat(name)
					if err != nil {
						t.Fatal(err)
					}
					before[name] = info
				}
				inspect := func(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
					return inspectStandalonePayload(directory, expected)
				}
				backup, err := retireAttestedDirectory(base, "syswarden", filepath.Join(base, "backups"), "standalone-payload", func() error { return nil }, inspect, unix.Renameat2)
				if err != nil {
					t.Fatal(err)
				}
				for name, original := range before {
					path := backup
					if name == "syswarden/bin" {
						path = filepath.Join(backup, "bin")
					}
					retained, err := os.Stat(path)
					if err != nil || !os.SameFile(original, retained) || original.Mode() != retained.Mode() {
						t.Fatal("packaged directory identity or mode changed", err)
					}
				}
				saved, err := openExistingPinnedServiceDirectory(backup)
				if err != nil {
					t.Fatal(err)
				}
				defer saved.close()
				if _, err := inspect(saved); err != nil {
					t.Fatal("retained payload cannot be reattested", err)
				}
			})
		}
	}
}

func TestStandalonePayloadRefusesUnsafeDirectoryMetadata(t *testing.T) {
	for _, name := range []string{"syswarden", "syswarden/bin"} {
		for _, mode := range []os.FileMode{0770, 0775, 0777, 0751, os.ModeSetgid | 0750, os.ModeSticky | 0755} {
			t.Run(fmt.Sprintf("%s/%v", name, mode), func(t *testing.T) {
				base, root, expected := standalonePayloadFixture(t)
				if err := root.Chmod(name, mode); err != nil {
					t.Fatal(err)
				}
				before, err := root.Stat(name)
				if err != nil {
					t.Fatal(err)
				}
				inspect := func(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
					return inspectStandalonePayload(directory, expected)
				}
				if _, err := retireAttestedDirectory(base, "syswarden", filepath.Join(base, "backups"), "standalone-payload", func() error { return nil }, inspect, unix.Renameat2); err == nil {
					t.Fatal("unsafe or unrecognized directory metadata was accepted")
				}
				after, err := root.Stat(name)
				if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
					t.Fatal("refusal changed payload evidence", err)
				}
			})
		}
	}
}

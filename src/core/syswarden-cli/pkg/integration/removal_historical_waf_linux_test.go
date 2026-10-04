//go:build linux

package integration

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syswarden-cli/config"
	"testing"
)

func TestHistoricalV4028WAFRemovalMatchesFrozenOfficialGenerator(t *testing.T) {
	for _, test := range []struct{ pattern, digest string }{
		{"", "98c9de720872b5e4664fb220eb0df40bdb329e84bff8eead26139455ba5da577"},
		{"/var/log/modsec/*.log", "820c6eb76b0183fda8c4d3eefbc41ae48ccabe5d288e0c1956a3a1790566b475"},
	} {
		got, err := renderHistoricalV4028WAFForRemoval(test.pattern)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256([]byte(got))) != test.digest {
			t.Fatalf("official historical generator bytes changed: %v", err)
		}
	}
	for _, pattern := range []string{"relative.log", "/var/../log/*.log", "/var/log/[", "/var/log/a\n", "/var/log/\"a", "/var/log/\\a", " /var/log/a", "/var/log/a  /var/log/b", "/var/log/a /var/log/a"} {
		if _, err := renderHistoricalV4028WAFForRemoval(pattern); err == nil {
			t.Fatalf("unsafe historical pattern was accepted: %q", pattern)
		}
	}
}

func TestHistoricalV4028WAFRemovalPreservesOwnershipAndRestartBarrier(t *testing.T) {
	for _, scenario := range []string{"exact", "modified", "configuration drift", "symlink", "hardlink", "restart failure"} {
		t.Run(scenario, func(t *testing.T) {
			parent, name, uid, gid := newOwnedArtifactRemovalFixture(t)
			directory := filepath.Join(parent, wafRsyslogDirectoryName)
			if err := os.Rename(filepath.Join(parent, name), directory); err != nil {
				t.Fatal(err)
			}
			active := config.NewFailSafeConfig()
			// This private glob has no match. Removal reconstructs the old bytes
			// without creating or opening a log input.
			active.ModsecLogs = filepath.Join(parent, "missing", "*.log")
			content, err := renderHistoricalV4028WAFForRemoval(active.ModsecLogs)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "modified" {
				content += "# operator customization\n"
			}
			path := filepath.Join(directory, wafRsyslogConfigName)
			writeOwnedArtifactFixture(t, path, []byte(content), 0600)
			readPath := path
			switch scenario {
			case "configuration drift":
				active.ModsecLogs = filepath.Join(parent, "different", "*.log")
			case "symlink":
				readPath = filepath.Join(parent, "operator.conf")
				if err := os.Rename(path, readPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(readPath, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(parent, "operator.conf")); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			sentinel := errors.New("historical bridge restart failure")
			err = removeOwnedRsyslogArtifactsForPackageRemovalAtUsing(
				active, parent, uid, gid, defaultExactOwnedArtifactRemovalOptions(),
				func(bool) error {
					calls++
					if scenario == "restart failure" {
						return sentinel
					}
					return nil
				},
			)
			if scenario == "exact" {
				if err != nil || calls == 0 {
					t.Fatalf("exact historical bridge removal: calls=%d error=%v", calls, err)
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("historical socket producer remains: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("unproven historical bridge removal succeeded")
			}
			if scenario == "restart failure" {
				if !errors.Is(err, sentinel) || calls != 2 {
					t.Fatalf("historical rollback barrier: calls=%d error=%v", calls, err)
				}
			} else if calls != 0 {
				t.Fatal("unrecognized artifact triggered rsyslog restart")
			}
			got, readErr := os.ReadFile(readPath) // #nosec G304 -- readPath is an owned private fixture or its explicit private symlink target
			if readErr != nil || string(got) != content {
				t.Fatalf("preserved historical bridge changed: %v", readErr)
			}
		})
	}
}

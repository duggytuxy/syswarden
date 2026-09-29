package firewall

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func whitelistPairTargets(directory string) []approvedListFile {
	return []approvedListFile{{directory: directory, name: "syswarden_whitelist.ipv4"}, {directory: directory, name: "syswarden_whitelist.ipv6"}}
}

// Reproduce the native image: only the operator's IPv4 policy was seeded.
func TestWhitelistPairPreservesImageOwnerPolicyAndCreatesEmptyFamily(t *testing.T) {
	t.Parallel()
	for _, seeded := range []string{"", "syswarden_whitelist.ipv4", "syswarden_whitelist.ipv6"} {
		t.Run("seed="+seeded, func(t *testing.T) {
			directory := t.TempDir()
			targets := whitelistPairTargets(directory)
			var before os.FileInfo
			content := "192.0.2.44\n"
			if strings.HasSuffix(seeded, "ipv6") {
				content = "2001:db8::44\n"
			}
			if seeded != "" {
				path := filepath.Join(directory, seeded)
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				// #nosec G302 -- Test-only 0640 image-owner policy under t.TempDir verifies preservation of the supported group-readable mode.
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
				var err error
				before, err = os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			for repeat := 0; repeat < 2; repeat++ {
				if err := ensurePersistentWhitelistPairAt(targets, nil); err != nil {
					t.Fatal(err)
				}
			}
			for _, target := range targets {
				path := filepath.Join(directory, target.name)
				wire, err := os.ReadFile(path) // #nosec G304 -- fixed policy names under t.TempDir
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if target.name == seeded {
					if string(wire) != content || !os.SameFile(before, info) || info.Mode() != before.Mode() || !info.ModTime().Equal(before.ModTime()) {
						t.Fatal("image-owner policy or metadata changed")
					}
				} else if len(wire) != 0 || info.Mode() != 0600 {
					t.Fatalf("missing family was not initialized privately: %q %v", wire, info.Mode())
				}
			}
			marker, err := os.ReadFile(filepath.Join(directory, persistentWhitelistPairMarkerName)) // #nosec G304 -- fixed marker under t.TempDir
			if err != nil || string(marker) != persistentWhitelistPairMarkerBytes {
				t.Fatalf("marker %q: %v", marker, err)
			}
		})
	}
}

func TestWhitelistPairRefusesLossAfterInitialization(t *testing.T) {
	t.Parallel()
	for _, missing := range []string{"syswarden_whitelist.ipv4", "syswarden_whitelist.ipv6"} {
		t.Run(missing, func(t *testing.T) {
			directory := t.TempDir()
			targets := whitelistPairTargets(directory)
			if err := ensurePersistentWhitelistPairAt(targets, nil); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, missing)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := ensurePersistentWhitelistPairAt(targets, nil); err == nil || !strings.Contains(err.Error(), "unexpectedly missing") {
				t.Fatalf("missing policy accepted: %v", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("lost whitelist was silently recreated")
			}
		})
	}
}

func TestWhitelistPairRefusesUnsafeSecondFamilyBeforeCreatingFirst(t *testing.T) {
	t.Parallel()
	for _, fixture := range []string{"symlink", "hardlink", "directory", "writable", "foreign-owner", "oversized"} {
		t.Run(fixture, func(t *testing.T) {
			directory := t.TempDir()
			targets := whitelistPairTargets(directory)
			second := filepath.Join(directory, targets[1].name)
			other := filepath.Join(directory, "operator-file")
			if err := os.WriteFile(other, []byte("2001:db8::44\n"), 0600); err != nil {
				t.Fatal(err)
			}
			switch fixture {
			case "symlink":
				if err := os.Symlink(other, second); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(other, second); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(second, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(second, nil, 0600); err != nil {
					t.Fatal(err)
				}
				switch fixture {
				case "writable":
					if err := os.Chmod(second, 0660); err != nil {
						t.Fatal(err)
					} // #nosec G302 -- adversarial writable policy
				case "foreign-owner":
					if os.Geteuid() != 0 {
						t.Skip("requires root to construct foreign ownership")
					}
					if err := os.Chown(second, 1, 1); err != nil {
						t.Fatal(err)
					}
				case "oversized":
					if err := os.Truncate(second, maximumPersistentBlocklistEvidenceBytes+1); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := ensurePersistentWhitelistPairAt(targets, nil); err == nil {
				t.Fatal("unsafe policy accepted")
			}
			for _, name := range []string{targets[0].name, persistentWhitelistPairMarkerName} {
				if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("unsafe second family caused publication of %s", name)
				}
			}
			wire, err := os.ReadFile(other) // #nosec G304 -- t.TempDir fixture
			if err != nil || string(wire) != "2001:db8::44\n" {
				t.Fatal("operator target modified")
			}
		})
	}
}

func TestWhitelistPairSerializesCreationAndRejectsSubstitution(t *testing.T) {
	t.Parallel()
	t.Run("concurrent", func(t *testing.T) {
		directory := t.TempDir()
		targets := whitelistPairTargets(directory)
		var wg sync.WaitGroup
		results := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); results <- ensurePersistentWhitelistPairAt(targets, nil) }()
		}
		wg.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("exclusive create", func(t *testing.T) {
		directory := t.TempDir()
		targets := whitelistPairTargets(directory)
		err := ensurePersistentWhitelistPairAt(targets, func(target approvedListFile) error {
			return os.WriteFile(filepath.Join(directory, target.name), []byte("operator-race\n"), 0600)
		})
		if err == nil {
			t.Fatal("substituted policy accepted")
		}
		wire, err := os.ReadFile(filepath.Join(directory, targets[0].name)) // #nosec G304 -- fixed policy under t.TempDir
		if err != nil || string(wire) != "operator-race\n" {
			t.Fatal("substituted file overwritten")
		}
	})
	t.Run("marker identity", func(t *testing.T) {
		directory := t.TempDir()
		targets := whitelistPairTargets(directory)
		if err := os.WriteFile(filepath.Join(directory, persistentWhitelistPairMarkerName), []byte(persistentBlocklistPairMarkerBytes), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ensurePersistentWhitelistPairAt(targets, nil); err == nil {
			t.Fatal("blocklist marker accepted as whitelist authority")
		}
		if _, err := os.Lstat(filepath.Join(directory, targets[0].name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("invalid marker caused policy creation")
		}
	})
	t.Run("wrong inventory", func(t *testing.T) {
		directory := t.TempDir()
		if err := ensurePersistentWhitelistPairAt(persistentBlocklistTargetsForTest(directory), nil); err == nil {
			t.Fatal("blocklist inventory accepted for whitelist initialization")
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatal("wrong inventory caused mutation")
		}
	})
}

func TestWhitelistPairRefusesDisappearanceBeforeMarkerPublication(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	targets := whitelistPairTargets(directory)
	err := ensurePersistentWhitelistPairAt(targets, func(target approvedListFile) error {
		if target.name == persistentWhitelistPairMarkerName {
			return os.Remove(filepath.Join(directory, targets[0].name))
		}
		return nil
	})
	if err == nil {
		t.Fatal("missing family accepted during publication")
	}
	if _, err := os.Lstat(filepath.Join(directory, persistentWhitelistPairMarkerName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("incomplete policy was marked initialized")
	}
}

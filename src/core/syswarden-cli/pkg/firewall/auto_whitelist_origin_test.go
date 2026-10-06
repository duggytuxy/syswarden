package firewall

import (
	"crypto/sha256"
	"os"
	"strings"
	"syswarden-cli/pkg/system"
	"testing"
)

func TestAutomaticWhitelistPreservesOnlyExactGeneratedOrigin(t *testing.T) {
	for _, kind := range []string{"generated", "legacy", "group-readable", "modified", "manual-command"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			targets := []approvedListFile{{path, "syswarden_whitelist.ipv4"}, {path, "syswarden_whitelist.ipv6"}}
			root, err := os.OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			if kind == "legacy" || kind == "group-readable" {
				if err := root.WriteFile(targets[0].name, []byte("192.0.2.10\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "group-readable" {
					if err := root.Chmod(targets[0].name, 0640); err != nil { // #nosec G302 -- verifies preservation of the supported group-readable operator list.
						t.Fatal(err)
					}
				}
			}
			if err := ensurePersistentWhitelistPairAt(targets, nil); err != nil {
				t.Fatal(err)
			}
			if kind == "modified" {
				if err := root.WriteFile(targets[0].name, []byte("192.0.2.10\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if kind == "manual-command" {
				if err := writeListFileAt(targets[0], []byte("192.0.2.10\n")); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				added, err := appendAutomaticWhitelist(targets[0], []string{"192.0.2.1"})
				if err != nil || len(added) != 1-attempt {
					t.Fatal("automatic append or idempotence failed", added, err)
				}
				content, err := root.ReadFile(targets[0].name)
				if err != nil {
					t.Fatal(err)
				}
				if kind != "generated" && !strings.HasPrefix(string(content), "192.0.2.10\n") {
					t.Fatal("existing administrator line changed")
				}
				if !strings.HasSuffix(string(content), "192.0.2.1\n") {
					t.Fatal("whole-address duplicate check lost the new address")
				}
				file, err := root.Open(targets[0].name)
				if err != nil {
					t.Fatal(err)
				}
				owned, originErr := system.HasGeneratedListOrigin(file, targets[0].name, sha256.Sum256(content))
				_ = file.Close()
				if originErr != nil || owned != (kind == "generated") {
					t.Fatal("automatic append adopted existing administrator input", owned, originErr)
				}
				if kind == "group-readable" {
					info, err := root.Stat(targets[0].name)
					if err != nil || info.Mode().Perm() != 0640 {
						t.Fatal("automatic append changed administrator reader access", err)
					}
				}
			}
		})
	}
}

func TestAutomaticWhitelistRejectsWrongFamilyWithoutChangingInput(t *testing.T) {
	path := t.TempDir()
	targets := []approvedListFile{{path, "syswarden_whitelist.ipv4"}, {path, "syswarden_whitelist.ipv6"}}
	if err := ensurePersistentWhitelistPairAt(targets, nil); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{"2001:db8::1", "192.0.2.1\n192.0.2.2", "invalid", "192.0.2.1/24"} {
		if _, err := appendAutomaticWhitelist(targets[0], []string{candidate}); err == nil {
			t.Fatal("invalid automatic input accepted", candidate)
		}
	}
	content, err := readListFileAt(targets[0])
	if err != nil || len(content) != 0 {
		t.Fatal("refused input changed the list", err)
	}
}

//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

func assertHAPeerListOrigin(t *testing.T, root *os.Root, name string, wantContent []byte, wantOrigin bool) {
	t.Helper()
	content, err := root.ReadFile(name)
	if err != nil || !bytes.Equal(content, wantContent) {
		t.Fatalf("list content = %q, want %q: %v", content, wantContent, err)
	}
	file, err := root.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	owned, err := system.HasGeneratedListOrigin(file, name, sha256.Sum256(content))
	if err != nil || owned != wantOrigin {
		t.Fatalf("generated origin = %t, want %t: %v", owned, wantOrigin, err)
	}
}

func TestAutomaticHAPeerOriginAndPolicyFailureBoundaries_SW_HA_001(t *testing.T) {
	for _, peer := range []string{"192.0.2.9/32", "2001:db8::9/128"} {
		for _, kind := range []string{"generated", "legacy", "modified", "manual", "group-readable"} {
			for _, outcome := range []string{"success", "precommit-error", "committed-error"} {
				t.Run(peer+"/"+kind+"/"+outcome, func(t *testing.T) {
					path := t.TempDir()
					targets := []approvedListFile{{path, "syswarden_whitelist.ipv4"}, {path, "syswarden_whitelist.ipv6"}}
					entry, err := newCanonicalListEntry(peer, "62026")
					if err != nil {
						t.Fatal(err)
					}
					target, other := targets[0], targets[1]
					if !entry.isIPv4 {
						target, other = other, target
					}
					root, err := os.OpenRoot(path)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = root.Close() }()
					var original []byte
					if kind != "generated" {
						original = []byte("# administrator input without a final newline")
					}
					if kind == "legacy" || kind == "group-readable" {
						if err := root.WriteFile(target.name, original, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if err := ensurePersistentWhitelistPairAt(targets, nil); err != nil {
						t.Fatal(err)
					}
					switch kind {
					case "modified":
						if err := root.WriteFile(target.name, original, 0600); err != nil {
							t.Fatal(err)
						}
					case "manual":
						if err := writeListFileAt(target, original); err != nil {
							t.Fatal(err)
						}
					case "group-readable":
						// The operator grants read access; automatic updates must retain it.
						if err := root.Chmod(target.name, 0640); err != nil { // #nosec G302 -- controlled fixture verifies preservation of administrator reader access.
							t.Fatal(err)
						}
					}
					cause := errors.New("injected firewall failure")
					applyCalls := 0
					apply := func() error {
						applyCalls++
						if outcome == "precommit-error" {
							return cause
						}
						if outcome == "committed-error" {
							return committedWrapperReconciliationError("0123456789abcdef", cause)
						}
						return nil
					}
					want := bytes.Clone(original)
					if outcome != "precommit-error" {
						if len(want) != 0 {
							want = append(want, '\n')
						}
						want = append(want, []byte(entry.String()+"\n")...)
					}
					for attempt := 0; attempt < 2; attempt++ {
						err := allowHAPeerAt(entry, target, apply)
						if (outcome == "success" && err != nil) || (outcome != "success" && !errors.Is(err, cause)) {
							t.Fatalf("unexpected policy result: %v", err)
						}
						assertHAPeerListOrigin(t, root, target.name, want, kind == "generated")
						assertHAPeerListOrigin(t, root, other.name, nil, true)
						info, err := root.Stat(target.name)
						mode := os.FileMode(0600)
						if kind == "group-readable" {
							mode = 0640
						}
						if err != nil || info.Mode().Perm() != mode {
							t.Fatalf("administrator permissions changed: %v", err)
						}
					}
					if applyCalls != 2 {
						t.Fatalf("retries must reapply policy: calls=%d", applyCalls)
					}
				})
			}
		}
	}
}

func TestAutomaticHAPeerRejectsUnconfiguredAccessBeforeBackend_SW_HA_001(t *testing.T) {
	previous, previousPreflight := config.GlobalConfig, firewallBackendPreflight
	t.Cleanup(func() { config.GlobalConfig, firewallBackendPreflight = previous, previousPreflight })
	boundary := errors.New("validated backend boundary")
	calls := 0
	firewallBackendPreflight = func(string) error { calls++; return boundary }
	for _, v2 := range []bool{false, true} {
		config.GlobalConfig = &config.Config{HAEnabled: true, HAV2Enabled: v2, HAPeerIP: "192.0.2.9/32,2001:db8::9", HAPeerPort: "62026", FirewallBackend: "nftables"}
		for _, peer := range []string{"192.0.2.9/32", "2001:db8::9"} {
			if err := AllowConfiguredHAPeer(peer, "62026"); !errors.Is(err, boundary) {
				t.Fatalf("configured peer entered the unban fence or failed validation: %v", err)
			}
		}
	}
	for _, test := range []struct{ peer, port, configured, configuredPort string }{
		{"192.0.2.9/32", "", "192.0.2.9/32", "62026"},
		{"192.0.2.9/32", "443", "192.0.2.9/32", "62026"},
		{"192.0.2.10/32", "62026", "192.0.2.9/32", "62026"},
		{"192.0.2.0/24", "62026", "192.0.2.9/32", "62026"},
		{"192.0.2.9/32", "062026", "192.0.2.9/32", "062026"},
		{"192.0.2.9/32", "62026", "192.0.2.9/32 invalid", "62026"},
		{"192.0.2.9/24", "62026", "192.0.2.9/24", "62026"},
		{"192.0.2.9\n192.0.2.10", "62026", "192.0.2.9", "62026"},
	} {
		config.GlobalConfig = &config.Config{HAEnabled: true, HAPeerIP: test.configured, HAPeerPort: test.configuredPort}
		if err := AllowConfiguredHAPeer(test.peer, test.port); err == nil || errors.Is(err, boundary) {
			t.Fatalf("invalid automatic peer reached the backend: %+v: %v", test, err)
		}
	}
	for _, value := range []*config.Config{nil, {HAPeerIP: "192.0.2.9/32", HAPeerPort: "62026"}} {
		config.GlobalConfig = value
		if err := AllowConfiguredHAPeer("192.0.2.9/32", "62026"); err == nil {
			t.Fatal("absent or disabled HA allowed an automatic mutation")
		}
	}
	if calls != 4 {
		t.Fatalf("invalid automatic peer reached the backend: calls=%d", calls)
	}
}

func TestAutomaticHAPeerRollbackPreservesConcurrentAdministratorEdit_SW_HA_001(t *testing.T) {
	path := t.TempDir()
	targets := []approvedListFile{{path, "syswarden_whitelist.ipv4"}, {path, "syswarden_whitelist.ipv6"}}
	if err := ensurePersistentWhitelistPairAt(targets, nil); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	entry, err := newCanonicalListEntry("192.0.2.9", "62026")
	if err != nil {
		t.Fatal(err)
	}
	operator := []byte("192.0.2.99:443\n")
	err = allowHAPeerAt(entry, targets[0], func() error {
		if err := root.WriteFile(targets[0].name, operator, 0600); err != nil {
			t.Fatal(err)
		}
		return errors.New("injected precommit failure")
	})
	if err == nil || !strings.Contains(err.Error(), "changed before rollback") {
		t.Fatalf("concurrent edit was not retained: %v", err)
	}
	assertHAPeerListOrigin(t, root, targets[0].name, operator, false)
}

func TestManualWhitelistStillInvalidatesGeneratedOrigin_SW_HA_001(t *testing.T) {
	path := t.TempDir()
	targets := []approvedListFile{{path, "syswarden_whitelist.ipv4"}, {path, "syswarden_whitelist.ipv6"}}
	if err := ensurePersistentWhitelistPairAt(targets, nil); err != nil {
		t.Fatal(err)
	}
	entry, err := newCanonicalListEntry("192.0.2.9", "62026")
	if err != nil {
		t.Fatal(err)
	}
	err = addToWhitelistAt(entry, targets[0], approvedListFile{}, io.Discard, func() error { return nil }, func(string) error {
		t.Fatal("port-scoped entry attempted a global unban")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	assertHAPeerListOrigin(t, root, targets[0].name, []byte(entry.String()+"\n"), false)
}

//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func retiredRHELDirectoryFixture(t *testing.T) (string, rhelPackageOwnedAttestationHost) {
	t.Helper()
	root := t.TempDir()
	installTestRHELPackageOwnedProfile(t, root)
	host := testRHELPackageOwnedHost(t, root)
	for _, path := range rhelRetirableRuntimeDirectories {
		if err := os.Remove(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/syswarden", removalTombstoneName), []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	host.removalBarrier = func() error {
		state, err := openExistingRemovalStateDirectory(filepath.Join(root, "var/lib/syswarden"), host.expectedUID, host.expectedGID)
		if err != nil {
			return err
		}
		defer state.close()
		_, err = attestRemovalTombstone(state, host.expectedUID, host.expectedGID)
		return err
	}
	host.verifyInstalledPayload = func() ([]byte, error) {
		var wire strings.Builder
		for _, path := range rhelRetirableRuntimeDirectories {
			if info, err := os.Lstat(filepath.Join(root, path)); errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(&wire, "missing     %s\n", path)
			} else if err == nil && info.Mode().Perm() == 0700 {
				fmt.Fprintf(&wire, ".M.......    %s\n", path)
			}
		}
		if wire.Len() == 0 {
			return nil, nil
		}
		return []byte(wire.String()), fakeFirewallRemovalExitError(1)
	}
	return root, host
}

func TestRHELRetiredDirectoriesRequireRemovalAuthority(t *testing.T) {
	for _, kind := range []string{"valid", "activation", "no barrier", "changed barrier", "linked barrier", "wrong owner", "unknown missing", "modified payload", "late replacement", "late barrier removal"} {
		t.Run(kind, func(t *testing.T) {
			root, host := retiredRHELDirectoryFixture(t)
			barrier := filepath.Join(root, "var/lib/syswarden", removalTombstoneName)
			switch kind {
			case "activation":
				host.removalBarrier = nil
			case "no barrier":
				if err := os.Remove(barrier); err != nil {
					t.Fatal(err)
				}
			case "changed barrier":
				if err := os.WriteFile(barrier, []byte("changed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "linked barrier":
				if err := os.Link(barrier, filepath.Join(root, "outside")); err != nil {
					t.Fatal(err)
				}
			case "wrong owner":
				host.queryFileOwner = func(path string) ([]byte, error) {
					if path == "/etc/syswarden/lists" {
						return []byte("another-package\n"), nil
					}
					return testRHELPackageOwnedIdentity(), nil
				}
			case "unknown missing":
				if err := os.Remove(filepath.Join(root, "etc/syswarden/tls")); err != nil {
					t.Fatal(err)
				}
			case "modified payload":
				host.verifyInstalledPayload = func() ([]byte, error) {
					return []byte("S.5....T.  /opt/syswarden/bin/syswarden-cli\n"), fakeFirewallRemovalExitError(1)
				}
			case "late replacement", "late barrier removal":
				verify := host.verifyInstalledPayload
				host.verifyInstalledPayload = func() ([]byte, error) {
					wire, err := verify()
					if kind == "late replacement" {
						if e := os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "etc/syswarden/lists")); e != nil {
							t.Fatal(e)
						}
					} else {
						if e := os.Remove(barrier); e != nil {
							t.Fatal(e)
						}
					}
					return wire, err
				}
			}
			present, err := host.attest()
			if kind == "valid" {
				if err != nil || !present {
					t.Fatal(present, err)
				}
			} else if err == nil {
				t.Fatal("unsafe or activation state was accepted")
			}
			if _, err := os.Lstat(filepath.Join(root, "var/log/syswarden")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("read-only attestation recreated a directory", err)
			}
		})
	}
}

func TestRHELRetiredDirectoryRPMVerificationRejectsAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		code       error
		retired    map[string]string
		valid      bool
	}{
		{"exact", "missing     /etc/syswarden/lists\n", fakeFirewallRemovalExitError(1), map[string]string{"/etc/syswarden/lists": "missing"}, true},
		{"unexpected success", "missing     /etc/syswarden/lists\n", nil, map[string]string{"/etc/syswarden/lists": "missing"}, false},
		{"unknown status", "missing     /etc/syswarden/lists\n", errors.New("query failed"), map[string]string{"/etc/syswarden/lists": "missing"}, false},
		{"truncated", "missing     /etc/syswarden/lists", fakeFirewallRemovalExitError(1), map[string]string{"/etc/syswarden/lists": "missing"}, false},
		{"duplicate", "missing     /etc/syswarden/lists\nmissing     /etc/syswarden/lists\n", fakeFirewallRemovalExitError(1), map[string]string{"/etc/syswarden/lists": "missing"}, false},
		{"extra", "missing     /etc/syswarden/lists\nmissing     /etc/syswarden/tls\n", fakeFirewallRemovalExitError(1), map[string]string{"/etc/syswarden/lists": "missing"}, false},
		{"omitted", "missing     /etc/syswarden/lists\n", fakeFirewallRemovalExitError(1), map[string]string{"/etc/syswarden/lists": "missing", "/var/log/syswarden": "missing"}, false},
		{"unapproved", "missing     /opt/syswarden/bin/syswarden-cli\n", fakeFirewallRemovalExitError(1), map[string]string{"/opt/syswarden/bin/syswarden-cli": "missing"}, false},
		{"strict failure", "", fakeFirewallRemovalExitError(1), nil, false},
		{"strict success", "", nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := attestRHELPackageOwnedVerification([]byte(tc.wire), tc.code, tc.retired); (err == nil) != tc.valid {
				t.Fatalf("accept=%t, error=%v", tc.valid, err)
			}
		})
	}
}

func TestRHELRetiredDirectoryRestorationResumesAfterPartialCreation(t *testing.T) {
	root, host := retiredRHELDirectoryFixture(t)
	uid, gid := host.expectedUID, host.expectedGID
	cli := filepath.Join(root, "opt/syswarden/bin/syswarden-cli")
	before, err := os.Stat(cli)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	sentinel := errors.New("interrupted payload attestation")
	attest := func() error {
		calls++
		if calls == 2 {
			return sentinel
		}
		present, err := host.attest()
		if !present && err == nil {
			return errors.New("missing profile")
		}
		return err
	}
	if err := restoreRetiredRHELPackageOwnedDirectories(root, uid, gid, attest); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	first, err := os.Stat(filepath.Join(root, "etc/syswarden/lists"))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := restoreRetiredRHELPackageOwnedDirectories(root, uid, gid, attest); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat(filepath.Join(root, "etc/syswarden/lists"))
	if err != nil || !os.SameFile(first, after) {
		t.Fatal("retry replaced an existing directory", err)
	}
	after, err = os.Stat(cli)
	if err != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		t.Fatal("restoration modified RPM payload", err)
	}
	if present, err := host.attest(); err != nil || !present {
		t.Fatal(present, err)
	}
	for _, path := range rhelRetirableRuntimeDirectories {
		entries, err := os.ReadDir(filepath.Join(root, path))
		if err != nil || len(entries) != 0 {
			t.Fatal("restoration populated runtime state", err)
		}
	}
}

func TestRHELRetiredDirectoryRestorationRejectsLostAuthority(t *testing.T) {
	for _, kind := range []string{"nil", "payload", "barrier", "parent", "replacement"} {
		t.Run(kind, func(t *testing.T) {
			root, host := retiredRHELDirectoryFixture(t)
			attest := func() error {
				switch kind {
				case "payload":
					return errors.New("modified payload")
				case "barrier":
					return os.Remove(filepath.Join(root, "var/lib/syswarden", removalTombstoneName))
				case "parent":
					return os.Chmod(filepath.Join(root, "etc/syswarden"), 0777) // #nosec G302 -- adversarial private fixture checks writable-parent refusal
				case "replacement":
					return os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "etc/syswarden/lists"))
				}
				return nil
			}
			if kind == "nil" {
				attest = nil
			}
			if err := restoreRetiredRHELPackageOwnedDirectories(root, host.expectedUID, host.expectedGID, attest); err == nil {
				t.Fatal("lost authority allowed skeleton recreation")
			}
			if _, err := os.Lstat(filepath.Join(root, "var/lib/syswarden/ui")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal recreated subsequent directory", err)
			}
		})
	}
}

func TestRHELRetiredDirectoryRestrictiveUmask(t *testing.T) {
	if os.Getenv("SYSWARDEN_RHEL_UMASK_CHILD") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G204 G702 -- only the current test executable and a fixed test name run in the private umask subprocess
		cmd := exec.Command(executable, "-test.run=^TestRHELRetiredDirectoryRestrictiveUmask$")
		cmd.Env = append(os.Environ(), "SYSWARDEN_RHEL_UMASK_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("private umask subprocess: %v: %s", err, output)
		}
		return
	}
	root, host := retiredRHELDirectoryFixture(t)
	syscall.Umask(0077)
	if err := os.Mkdir(filepath.Join(root, "etc/syswarden/lists"), 0700); err != nil {
		t.Fatal(err)
	}
	attest := func() error {
		present, err := host.attest()
		if !present && err == nil {
			return errors.New("profile absent")
		}
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := restoreRetiredRHELPackageOwnedDirectories(root, host.expectedUID, host.expectedGID, attest); err != nil {
			t.Fatal(err)
		}
	}
	for _, logical := range rhelRetirableRuntimeDirectories {
		info, err := os.Stat(filepath.Join(root, logical))
		if err != nil || info.Mode().Perm() != 0750 {
			t.Fatal("RPM mode depends on caller umask", err)
		}
	}
}

func TestRHELRetiredRestrictiveSkeletonRefusesUnexpectedContent(t *testing.T) {
	for _, kind := range []string{"empty", "content", "wide mode", "linked"} {
		t.Run(kind, func(t *testing.T) {
			root, host := retiredRHELDirectoryFixture(t)
			path := filepath.Join(root, "etc/syswarden/lists")
			if kind == "linked" {
				if err := os.Symlink(filepath.Join(root, "outside"), path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "content" {
				if err := os.WriteFile(filepath.Join(path, "administrator"), []byte("keep\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "wide mode" {
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			} // #nosec G302 -- adversarial private fixture checks unapproved skeleton mode
			present, err := host.attest()
			if kind == "empty" {
				if err != nil || !present {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unapproved skeleton accepted")
			}
			if kind == "content" {
				wire, err := os.ReadFile(filepath.Join(path, "administrator")) // #nosec G304 -- fixed sentinel below the private t.TempDir fixture, with no external path input
				if err != nil || string(wire) != "keep\n" {
					t.Fatal("administrator content changed", err)
				}
			}
		})
	}
}

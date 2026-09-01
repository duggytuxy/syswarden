//go:build linux

package security

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func writeCISRemovalFixture(
	t *testing.T,
	host hardeningHost,
	logical string,
	content []byte,
	mode fs.FileMode,
) string {
	t.Helper()
	physical, err := host.path(logical)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeHardeningFixtureFile(physical, content, mode); err != nil {
		t.Fatal(err)
	}
	return physical
}

func TestRemoveExactCISHardeningPoliciesForRemovalRemovesManagedPolicies(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	policies := cisRemovalPolicies()
	for _, policy := range policies {
		writeCISRemovalFixture(t, host, policy.path, policy.expectedContent[0], 0600)
	}

	if err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2); err != nil {
		t.Fatal(err)
	}
	for _, policy := range policies {
		for _, logical := range []string{policy.path, policy.quarantinePath} {
			physical, err := host.path(logical)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(physical); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("managed CIS policy artifact remains after removal: %s: %v", logical, err)
			}
		}
	}
}

func TestCISRemovalQuarantinePathsAreFixedInactiveNames(t *testing.T) {
	want := map[string]string{
		cisFilesystemPolicyPath: "/etc/modprobe.d/.syswarden-cis-fs.conf.syswarden-removal-v1",
		cisNetworkPolicyPath:    "/etc/modprobe.d/.syswarden-cis-net.conf.syswarden-removal-v1",
		cisSysctlPolicyPath:     "/etc/sysctl.d/.99-syswarden-cis-level2.conf.syswarden-removal-v1",
		cisLimitsPolicyPath:     "/etc/security/limits.d/.99-syswarden-cis.conf.syswarden-removal-v1",
		cisCoredumpPolicyPath:   "/etc/systemd/coredump.conf.d/.99-syswarden.conf.syswarden-removal-v1",
	}
	policies := cisRemovalPolicies()
	if len(policies) != len(want) {
		t.Fatalf("CIS removal policy count=%d, want %d", len(policies), len(want))
	}
	for _, policy := range policies {
		if got := policy.quarantinePath; got != want[policy.path] {
			t.Fatalf("CIS quarantine path for %s=%q, want %q", policy.path, got, want[policy.path])
		}
		if strings.HasSuffix(policy.quarantinePath, ".conf") {
			t.Fatalf("CIS quarantine path remains an active configuration filename: %s", policy.quarantinePath)
		}
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalIsIdempotentWhenAbsent(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	for attempt := 0; attempt < 2; attempt++ {
		if err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2); err != nil {
			t.Fatalf("attempt %d: %v", attempt+1, err)
		}
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalPreflightsSecondArtifactBeforeMutation(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	first := writeCISRemovalFixture(
		t,
		host,
		cisFilesystemPolicyPath,
		[]byte(cisFilesystemPolicy),
		0600,
	)
	second := writeCISRemovalFixture(
		t,
		host,
		cisNetworkPolicyPath,
		make([]byte, hardeningMaximumFileSize+1),
		0600,
	)

	err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2)
	if err == nil || !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), cisNetworkPolicyPath) {
		t.Fatalf("second-artifact preflight result: %v", err)
	}
	for _, physical := range []string{first, second} {
		if _, statErr := os.Lstat(physical); statErr != nil {
			t.Fatalf("global preflight mutated artifact %s: %v", physical, statErr)
		}
	}
	firstQuarantine, err := host.path(cisRemovalQuarantinePath(cisFilesystemPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(firstQuarantine); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("global preflight created first quarantine: %v", err)
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalRecoversDeterministicQuarantineAfterCrash(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	policy := cisRemovalPolicies()[0]
	canonical := writeCISRemovalFixture(t, host, policy.path, policy.expectedContent[0], 0600)
	quarantine, err := host.path(policy.quarantinePath)
	if err != nil {
		t.Fatal(err)
	}

	panicked := false
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if err := unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags); err != nil {
			return err
		}
		panic("synthetic CIS removal crash after rename")
	}
	func() {
		defer func() { panicked = recover() != nil }()
		_ = removeExactCISHardeningPoliciesForRemovalOn(host, rename)
	}()
	if !panicked {
		t.Fatal("synthetic CIS removal crash boundary was not reached")
	}
	if _, err := os.Lstat(canonical); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("canonical CIS policy after crash: %v", err)
	}
	if content, err := os.ReadFile(quarantine); err != nil || string(content) != string(policy.expectedContent[0]) { // #nosec G304 -- quarantine is confined to the private hardening fixture root
		t.Fatalf("durable CIS quarantine after crash=%q error=%v", content, err)
	}

	if err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2); err != nil {
		t.Fatalf("CIS removal crash retry: %v", err)
	}
	for _, physical := range []string{canonical, quarantine} {
		if _, err := os.Lstat(physical); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("CIS removal crash retry left %s: %v", physical, err)
		}
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalRejectsCanonicalQuarantineCollision(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	policy := cisRemovalPolicies()[0]
	canonical := writeCISRemovalFixture(t, host, policy.path, policy.expectedContent[0], 0600)
	quarantine := writeCISRemovalFixture(t, host, policy.quarantinePath, policy.expectedContent[0], 0600)

	err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2)
	if err == nil || !strings.Contains(err.Error(), "both canonical") {
		t.Fatalf("canonical/quarantine collision result: %v", err)
	}
	for _, physical := range []string{canonical, quarantine} {
		if _, statErr := os.Lstat(physical); statErr != nil {
			t.Fatalf("collision did not preserve %s: %v", physical, statErr)
		}
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalRejectsLateQuarantineCollision(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	policy := cisRemovalPolicies()[0]
	canonical := writeCISRemovalFixture(t, host, policy.path, policy.expectedContent[0], 0600)
	quarantine, err := host.path(policy.quarantinePath)
	if err != nil {
		t.Fatal(err)
	}
	operatorContent := []byte("operator quarantine\n")
	injected := false
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if !injected {
			injected = true
			if err := writeHardeningFixtureFile(quarantine, operatorContent, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}

	err = removeExactCISHardeningPoliciesForRemovalOn(host, rename)
	if err == nil || !errors.Is(err, unix.EEXIST) {
		t.Fatalf("late quarantine collision result: %v", err)
	}
	if content, readErr := os.ReadFile(canonical); readErr != nil || // #nosec G304 -- canonical is confined to the private hardening fixture root
		string(content) != string(policy.expectedContent[0]) {
		t.Fatalf("late collision changed canonical policy: %q, %v", content, readErr)
	}
	if content, readErr := os.ReadFile(quarantine); readErr != nil || // #nosec G304 -- quarantine is confined to the private hardening fixture root
		string(content) != string(operatorContent) {
		t.Fatalf("late collision changed operator quarantine: %q, %v", content, readErr)
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalPreservesAmbiguousQuarantine(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	policy := cisRemovalPolicies()[0]
	quarantine := writeCISRemovalFixture(
		t,
		host,
		policy.quarantinePath,
		[]byte(cisFilesystemPolicy+"# operator quarantine\n"),
		0600,
	)

	err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2)
	if err == nil || !strings.Contains(err.Error(), "ambiguous deterministic") {
		t.Fatalf("ambiguous quarantine result: %v", err)
	}
	if content, readErr := os.ReadFile(quarantine); readErr != nil || // #nosec G304 -- quarantine is confined to the private hardening fixture root
		string(content) != cisFilesystemPolicy+"# operator quarantine\n" {
		t.Fatalf("ambiguous quarantine was not preserved: %q, %v", content, readErr)
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalAcceptsEveryManagedSysctlVariant(t *testing.T) {
	variants := cisSysctlRemovalContent()
	if len(variants) != 12 {
		t.Fatalf("managed sysctl variant count=%d, want 12", len(variants))
	}
	unique := make(map[string]struct{}, len(variants))
	for _, content := range variants {
		unique[string(content)] = struct{}{}
	}
	if len(unique) != len(variants) {
		t.Fatalf("managed sysctl variants are not unique: %d/%d", len(unique), len(variants))
	}

	for index, content := range variants {
		t.Run(fmt.Sprintf("variant-%02d", index+1), func(t *testing.T) {
			host := hardeningTestHost(t, hardeningExecutor{
				run: func(name string, args ...string) error {
					return fmt.Errorf("runtime command must not run during policy removal: %s %v", name, args)
				},
			})
			physical := writeCISRemovalFixture(t, host, cisSysctlPolicyPath, content, 0600)
			if err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(physical); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("managed sysctl policy remains: %v", err)
			}
		})
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalPreservesAmbiguousArtifacts(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, hardeningHost) string
	}{
		{
			name: "modified content",
			setup: func(t *testing.T, host hardeningHost) string {
				return writeCISRemovalFixture(
					t,
					host,
					cisFilesystemPolicyPath,
					[]byte(cisFilesystemPolicy+"# operator policy\n"),
					0600,
				)
			},
		},
		{
			name: "wrong mode",
			setup: func(t *testing.T, host hardeningHost) string {
				return writeCISRemovalFixture(t, host, cisFilesystemPolicyPath, []byte(cisFilesystemPolicy), 0640)
			},
		},
		{
			name: "hard link",
			setup: func(t *testing.T, host hardeningHost) string {
				physical := writeCISRemovalFixture(t, host, cisFilesystemPolicyPath, []byte(cisFilesystemPolicy), 0600)
				if err := os.Link(physical, physical+".operator-link"); err != nil {
					t.Fatal(err)
				}
				return physical
			},
		},
		{
			name: "symbolic link",
			setup: func(t *testing.T, host hardeningHost) string {
				physical, err := host.path(cisFilesystemPolicyPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
					t.Fatal(err)
				}
				target := physical + ".operator"
				if err := writeHardeningFixtureFile(target, []byte(cisFilesystemPolicy), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(target), physical); err != nil {
					t.Fatal(err)
				}
				return physical
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, host hardeningHost) string {
				physical, err := host.path(cisFilesystemPolicyPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(physical, 0750); err != nil {
					t.Fatal(err)
				}
				return physical
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host := hardeningTestHost(t, hardeningExecutor{})
			physical := test.setup(t, host)
			if err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(physical); err != nil {
				t.Fatalf("ambiguous artifact was not preserved: %v", err)
			}
		})
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalContinuesAfterPreservation(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	modified := writeCISRemovalFixture(
		t,
		host,
		cisFilesystemPolicyPath,
		[]byte(cisFilesystemPolicy+"# operator policy\n"),
		0600,
	)
	exact := writeCISRemovalFixture(t, host, cisNetworkPolicyPath, []byte(cisNetworkPolicy), 0600)

	if err := removeExactCISHardeningPoliciesForRemovalOn(host, unix.Renameat2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(modified); err != nil {
		t.Fatalf("modified policy was not preserved: %v", err)
	}
	if _, err := os.Lstat(exact); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("exact policy remains after an earlier preservation: %v", err)
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalRejectsConcurrentSubstitution(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	physical := writeCISRemovalFixture(t, host, cisFilesystemPolicyPath, []byte(cisFilesystemPolicy), 0600)
	var replacement fs.FileInfo
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(physical); err != nil {
				t.Fatal(err)
			}
			if err := writeHardeningFixtureFile(physical, []byte(cisFilesystemPolicy), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			replacement, err = os.Lstat(physical)
			if err != nil {
				t.Fatal(err)
			}
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}

	err := removeExactCISHardeningPoliciesForRemovalOn(host, rename)
	if err == nil || !strings.Contains(err.Error(), "changed before removal") {
		t.Fatalf("concurrent substitution result: %v", err)
	}
	restored, statErr := os.Lstat(physical)
	if statErr != nil || !os.SameFile(replacement, restored) {
		t.Fatalf("concurrent replacement was not preserved: info=%v error=%v", restored, statErr)
	}
}

func TestRemoveExactCISHardeningPoliciesForRemovalPropagatesRenameFailure(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	physical := writeCISRemovalFixture(t, host, cisFilesystemPolicyPath, []byte(cisFilesystemPolicy), 0600)
	injected := errors.New("injected rename failure")
	rename := func(int, string, int, string, uint) error { return injected }

	err := removeExactCISHardeningPoliciesForRemovalOn(host, rename)
	if !errors.Is(err, injected) {
		t.Fatalf("rename failure was not propagated: %v", err)
	}
	if _, err := os.Lstat(physical); err != nil {
		t.Fatalf("policy was not preserved after rename failure: %v", err)
	}
}

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineQualificationDependenciesAreAttestedWithoutInstallation(t *testing.T) {
	lookups := make([]string, 0)
	validations := make([]string, 0)
	err := attestOfflineQualificationDependenciesWith(
		func(name string) (string, error) {
			lookups = append(lookups, name)
			if name == "apt-get" {
				return "/usr/bin/apt-get", nil
			}
			return "/usr/bin/" + name, nil
		},
		func(path string) error {
			validations = append(validations, path)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("offline dependency attestation failed: %v", err)
	}
	if len(validations) == 0 || lookups[0] != "apt-get" {
		t.Fatalf("dependency lookups=%#v validations=%#v", lookups, validations)
	}
	for _, lookup := range lookups {
		if lookup == "apt-get update" || strings.Contains(lookup, "install") {
			t.Fatalf("offline dependency attestation attempted installation: %q", lookup)
		}
	}
}

func TestOfflineQualificationDependenciesFailClosedWhenRequiredBinaryIsMissing(t *testing.T) {
	err := attestOfflineQualificationDependenciesWith(
		func(name string) (string, error) {
			switch name {
			case "apt-get":
				return "/usr/bin/apt-get", nil
			case "nft":
				return "", os.ErrNotExist
			default:
				return "/usr/bin/" + name, nil
			}
		},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), `required dependency "nft" is unavailable`) {
		t.Fatalf("missing dependency error = %v", err)
	}
}

func TestOfflineQualificationDependencyValidatorRejectsUntrustedPath(t *testing.T) {
	if err := validateOfflineQualificationDependency("relative", os.Geteuid()); err == nil {
		t.Fatal("dependency validator accepted a relative path")
	}
	if err := validateOfflineQualificationDependency("/tmp/tool", os.Geteuid()); err == nil {
		t.Fatal("dependency validator accepted an untrusted path")
	}
}

func TestNativeDependencyParentFailureStopsOtherwiseTrustedBinary(t *testing.T) {
	canonical, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	denied := errors.New("private parent observation refused")
	called := 0
	err = validateDependencyWithParentAttestation("/bin/sh", 0, func(path string) error {
		called++
		if path != filepath.Dir(canonical) {
			t.Fatalf("parent attestation used a different canonical path: %q", path)
		}
		return denied
	})
	if !errors.Is(err, denied) || called != 1 {
		t.Fatal("trusted executable bypassed failed directory attestation", err)
	}
}

func TestNativeDependencyParentCheckCannotAuthorizeUnsafeFile(t *testing.T) {
	for _, path := range []string{"relative", "/tmp/tool", "/bin/../bin/sh", "/usr/bin"} {
		if err := validateDependencyWithParentAttestation(path, 0, func(string) error {
			t.Fatal("unsafe file reached parent acceptance")
			return nil
		}); err == nil {
			t.Fatal("unsafe file accepted")
		}
	}
	if err := validateDependencyWithParentAttestation("/bin/sh", 0, nil); err == nil {
		t.Fatal("missing parent observer accepted")
	}
	if err := validateDependencyWithParentAttestation("/bin/sh", -1, func(string) error { return nil }); err == nil {
		t.Fatal("invalid owner accepted")
	}
}

// The optional expected-refusal value is used only by the isolated native
// fixture, which changes its own container directory modes. This test itself
// performs no writes, starts no commands and never modifies host directories.
func TestNativeDependencyProductionParentObservation(t *testing.T) {
	expectation := os.Getenv("SYSWARDEN_TEST_DEPENDENCY_PARENT")
	if expectation != "" && expectation != "protected" && expectation != "unsafe" && expectation != "intermediate" && expectation != "alternatives" {
		t.Fatal("invalid private fixture selection")
	}
	path := "/bin/sh"
	if expectation == "intermediate" || expectation == "alternatives" {
		path = "/usr/bin/syswarden-dependency-probe"
	}
	err := validateOfflineQualificationDependency(path, 0)
	if (err != nil) != (expectation == "unsafe" || expectation == "intermediate") {
		t.Fatal("unexpected production parent observation", err)
	}
}

func TestNativeDependencyRefusesUntrustedAliasToTrustedExecutable(t *testing.T) {
	alias := filepath.Join(t.TempDir(), "sh")
	if err := os.Symlink("/bin/sh", alias); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDependencyWithParentAttestation(alias, 0, func(string) error {
		t.Fatal("untrusted lookup alias reached canonical parent attestation")
		return nil
	}); err == nil {
		t.Fatal("untrusted alias to trusted binary was accepted")
	}
	after, err := os.Lstat(alias)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("refusal changed the lookup alias")
	}
	target, err := os.Readlink(alias)
	if err != nil || target != "/bin/sh" {
		t.Fatal("refusal rewrote the administrator alias")
	}
}

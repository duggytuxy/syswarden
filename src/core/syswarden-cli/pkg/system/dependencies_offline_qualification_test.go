package system

import (
	"os"
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

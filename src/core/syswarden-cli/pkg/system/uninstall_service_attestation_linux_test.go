//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type firewallRemovalPackageCall struct {
	name      string
	arguments []string
}

const (
	wireGuardUnitFixture         = "vendor unit\n"
	wireGuardUnitFixtureChecksum = "771a9ec17f327f42dc17c3d2e936ebad"
)

func dpkgChecksumMetadata(path string, checksum string) []byte {
	return []byte(checksum + "  " + strings.TrimPrefix(path, string(filepath.Separator)) + "\n")
}

func dpkgMissingVerification(paths ...string) []byte {
	var output strings.Builder
	for _, path := range paths {
		output.WriteString("missing     ")
		output.WriteString(path)
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

func testFirewallRemovalPackageExecutor(
	t *testing.T,
	names []string,
	output func(string, ...string) ([]byte, error),
) firewallManagerExecutor {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string, len(names))
	for _, name := range names {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil { // #nosec G306 -- executable fixture
			t.Fatal(err)
		}
		paths[name] = path
	}
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			path, exists := paths[name]
			if !exists {
				return "", fmt.Errorf("%s: %w", name, exec.ErrNotFound)
			}
			return path, nil
		},
		validate: func(string) error { return nil },
		output:   output,
	}
}

func TestSystemdWireGuardPackageAttestationAcceptsPristineDebianAndUbuntuUnits(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		fragment   string
		listedPath string
		version    string
		verify     []byte
	}{
		{
			name:       "Debian",
			fragment:   "/usr/lib/systemd/system/wg-quick@.service",
			listedPath: "/usr/lib/systemd/system/wg-quick@.service",
			version:    "1.0.20210914-1+b1",
			verify: dpkgMissingVerification(
				"/usr/share/doc/wireguard-tools/NEWS.Debian.gz",
				"/usr/share/doc/wireguard-tools/examples/highlighter/highlight.c",
				"/usr/share/lintian/overrides/wireguard-tools",
				"/usr/share/man/man8/wg-quick.8.gz",
				"/usr/share/man/man8/wg.8.gz",
			),
		},
		{
			name:       "Ubuntu usrmerge alias",
			fragment:   "/usr/lib/systemd/system/wg-quick@.service",
			listedPath: "/lib/systemd/system/wg-quick@.service",
			version:    "1.0.20210914-1ubuntu4",
			verify: dpkgMissingVerification(
				"/usr/share/doc/wireguard-tools/README.Debian",
				"/usr/share/doc/wireguard-tools/examples/reresolve-dns/reresolve-dns.sh",
				"/usr/share/man/man8/wg-quick.8.gz",
				"/usr/share/man/man8/wg.8.gz",
			),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var calls []firewallRemovalPackageCall
			executor := testFirewallRemovalPackageExecutor(
				t, []string{"dpkg-query", "dpkg"},
				func(path string, arguments ...string) ([]byte, error) {
					calls = append(calls, firewallRemovalPackageCall{
						name: filepath.Base(path), arguments: append([]string(nil), arguments...),
					})
					switch {
					case filepath.Base(path) == "dpkg-query" && reflect.DeepEqual(arguments, []string{
						"--show", "--showformat=" + dpkgWireGuardStatusQueryFormat, systemdWireGuardPackageName,
					}):
						return []byte("install ok installed\t" + systemdWireGuardPackageName + "\t" + testCase.version + "\n"), nil
					case filepath.Base(path) == "dpkg-query" && reflect.DeepEqual(arguments, []string{
						"--listfiles", systemdWireGuardPackageName,
					}):
						return []byte("/.\n" + testCase.listedPath + "\n/usr/bin/wg-quick\n"), nil
					case filepath.Base(path) == "dpkg-query" && reflect.DeepEqual(arguments, []string{
						"--control-show", systemdWireGuardPackageName, "md5sums",
					}):
						return dpkgChecksumMetadata(testCase.listedPath, wireGuardUnitFixtureChecksum), nil
					case filepath.Base(path) == "dpkg" && reflect.DeepEqual(arguments, []string{
						"--verify", "--verify-format=rpm", systemdWireGuardPackageName,
					}):
						return testCase.verify, nil
					default:
						return nil, errors.New("unexpected package attestation command")
					}
				},
			)
			canonicalize := func(path string) (string, error) {
				if path == testCase.fragment || path == testCase.listedPath {
					return "/canonical/wg-quick@.service", nil
				}
				return filepath.Clean(path), nil
			}
			if err := attestSystemdWireGuardPackageWith(
				executor, testCase.fragment, canonicalize, []byte(wireGuardUnitFixture),
			); err != nil {
				t.Fatal(err)
			}
			if len(calls) != 4 {
				t.Fatalf("package attestation calls = %#v", calls)
			}
		})
	}
}

func TestSystemdWireGuardDPKGAttestationFailsClosed(t *testing.T) {
	const fragment = "/usr/lib/systemd/system/wg-quick@.service"
	for _, testCase := range []struct {
		name         string
		status       []byte
		files        []byte
		verification []byte
		checksums    []byte
		checksumErr  error
		verifyErr    error
	}{
		{
			name:         "modified package file",
			status:       []byte("install ok installed\twireguard-tools\t1.0.20210914-1\n"),
			files:        []byte(fragment + "\n"),
			verification: []byte("??5??????  " + fragment + "\n"),
		},
		{
			name:      "diverted package file",
			status:    []byte("install ok installed\twireguard-tools\t1.0.20210914-1\n"),
			files:     []byte(fragment + "\nlocally diverted to: /operator/wg-quick@.service\n"),
			verifyErr: errors.New("should not reach verify"),
		},
		{
			name:      "wrong package status",
			status:    []byte("deinstall ok config-files\twireguard-tools\t1.0.20210914-1\n"),
			files:     []byte(fragment + "\n"),
			verifyErr: errors.New("should not reach verify"),
		},
		{
			name:      "verification failure",
			status:    []byte("install ok installed\twireguard-tools\t1.0.20210914-1\n"),
			files:     []byte(fragment + "\n"),
			verifyErr: errors.New("dpkg verify failed"),
		},
		{
			name:         "missing target checksum",
			status:       []byte("install ok installed\twireguard-tools\t1.0.20210914-1\n"),
			files:        []byte(fragment + "\n"),
			checksums:    dpkgChecksumMetadata("/usr/bin/wg-quick", wireGuardUnitFixtureChecksum),
			verification: nil,
		},
		{
			name:         "snapshot checksum mismatch",
			status:       []byte("install ok installed\twireguard-tools\t1.0.20210914-1\n"),
			files:        []byte(fragment + "\n"),
			checksums:    dpkgChecksumMetadata(fragment, "00000000000000000000000000000000"),
			verification: nil,
		},
		{
			name:        "checksum metadata query failure",
			status:      []byte("install ok installed\twireguard-tools\t1.0.20210914-1\n"),
			files:       []byte(fragment + "\n"),
			checksumErr: errors.New("md5sums is unavailable"),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			checksumMetadata := testCase.checksums
			if checksumMetadata == nil {
				checksumMetadata = dpkgChecksumMetadata(fragment, wireGuardUnitFixtureChecksum)
			}
			executor := testFirewallRemovalPackageExecutor(
				t, []string{"dpkg-query", "dpkg"},
				func(path string, arguments ...string) ([]byte, error) {
					switch {
					case filepath.Base(path) == "dpkg-query" && arguments[0] == "--show":
						return testCase.status, nil
					case filepath.Base(path) == "dpkg-query" && arguments[0] == "--listfiles":
						return testCase.files, nil
					case filepath.Base(path) == "dpkg-query" && arguments[0] == "--control-show":
						return checksumMetadata, testCase.checksumErr
					case filepath.Base(path) == "dpkg":
						return testCase.verification, testCase.verifyErr
					default:
						return nil, errors.New("unexpected package attestation command")
					}
				},
			)
			if err := attestSystemdWireGuardPackageWith(
				executor, fragment, func(path string) (string, error) { return path, nil },
				[]byte(wireGuardUnitFixture),
			); err == nil {
				t.Fatal("unverified dpkg WireGuard unit was accepted")
			}
		})
	}
}

func TestDPKGWireGuardVerificationAcceptsOnlyLiveSlimExclusions(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		output []byte
	}{
		{name: "empty", output: nil},
		{
			name: "Debian slim live output",
			output: dpkgMissingVerification(
				"/usr/share/doc/wireguard-tools/NEWS.Debian.gz",
				"/usr/share/doc/wireguard-tools/README.Debian",
				"/usr/share/doc/wireguard-tools/changelog.Debian.gz",
				"/usr/share/doc/wireguard-tools/examples/embeddable-wg-library/wireguard.c",
				"/usr/share/doc/wireguard-tools/examples/highlighter/gui/highlight.cpp",
				"/usr/share/doc/wireguard-tools/examples/reresolve-dns/reresolve-dns.sh",
				"/usr/share/lintian/overrides/wireguard-tools",
				"/usr/share/man/man8/wg-quick.8.gz",
				"/usr/share/man/man8/wg.8.gz",
			),
		},
		{
			name: "Ubuntu slim live output",
			output: dpkgMissingVerification(
				"/usr/share/doc/wireguard-tools/NEWS.Debian.gz",
				"/usr/share/doc/wireguard-tools/README.Debian",
				"/usr/share/doc/wireguard-tools/examples/dns-hatchet/apply.sh",
				"/usr/share/doc/wireguard-tools/examples/extract-keys/extract-keys.c",
				"/usr/share/doc/wireguard-tools/examples/ncat-client-server/server.sh",
				"/usr/share/man/man8/wg-quick.8.gz",
				"/usr/share/man/man8/wg.8.gz",
			),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := attestDPKGWireGuardVerification(testCase.output); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDPKGWireGuardChecksumMetadataIsUniqueCanonicalAndFailClosed(t *testing.T) {
	const fragment = "/usr/lib/systemd/system/wg-quick@.service"
	canonicalize := func(path string) (string, error) { return path, nil }
	valid := dpkgChecksumMetadata(fragment, strings.ToUpper(wireGuardUnitFixtureChecksum))
	checksum, err := attestDPKGWireGuardChecksumMetadata(valid, fragment, canonicalize)
	if err != nil {
		t.Fatal(err)
	}
	if checksum != wireGuardUnitFixtureChecksum {
		t.Fatalf("checksum = %q, want %q", checksum, wireGuardUnitFixtureChecksum)
	}

	for _, testCase := range []struct {
		name   string
		output []byte
	}{
		{name: "empty", output: nil},
		{name: "missing target", output: dpkgChecksumMetadata("/usr/bin/wg-quick", wireGuardUnitFixtureChecksum)},
		{name: "duplicate target", output: append(append([]byte(nil), valid...), valid...)},
		{name: "malformed digest", output: dpkgChecksumMetadata(fragment, "z0000000000000000000000000000000")},
		{name: "short digest", output: []byte("0000  usr/lib/systemd/system/wg-quick@.service\n")},
		{name: "one separator", output: []byte(wireGuardUnitFixtureChecksum + " usr/lib/systemd/system/wg-quick@.service\n")},
		{name: "absolute metadata path", output: []byte(wireGuardUnitFixtureChecksum + "  " + fragment + "\n")},
		{name: "traversal", output: dpkgChecksumMetadata("/usr/lib/systemd/../operator", wireGuardUnitFixtureChecksum)},
		{name: "double slash", output: []byte(wireGuardUnitFixtureChecksum + "  usr/lib//systemd/wg-quick@.service\n")},
		{name: "blank record", output: append(append([]byte(nil), valid...), '\n')},
		{name: "missing terminal LF", output: valid[:len(valid)-1]},
		{name: "NUL", output: append(append([]byte(nil), valid...), 0)},
		{name: "CR", output: append(append([]byte(nil), valid[:len(valid)-1]...), '\r', '\n')},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := attestDPKGWireGuardChecksumMetadata(testCase.output, fragment, canonicalize); err == nil {
				t.Fatal("unsafe dpkg checksum metadata was accepted")
			}
		})
	}

	canonicalAlias := func(path string) (string, error) {
		switch path {
		case "/usr/lib/systemd/system/wg-quick@.service", "/lib/systemd/system/wg-quick@.service":
			return "/canonical/wg-quick@.service", nil
		default:
			return path, nil
		}
	}
	duplicatedCanonicalTarget := append(
		dpkgChecksumMetadata(fragment, wireGuardUnitFixtureChecksum),
		dpkgChecksumMetadata("/lib/systemd/system/wg-quick@.service", wireGuardUnitFixtureChecksum)...,
	)
	if _, err := attestDPKGWireGuardChecksumMetadata(
		duplicatedCanonicalTarget, fragment, canonicalAlias,
	); err == nil {
		t.Fatal("duplicate canonical dpkg checksum records were accepted")
	}
}

func TestDPKGWireGuardVerificationRejectsUnapprovedOrMalformedDrift(t *testing.T) {
	allowed := "/usr/share/doc/wireguard-tools/NEWS.Debian.gz"
	for _, testCase := range []struct {
		name   string
		output []byte
	}{
		{name: "checksum drift", output: []byte("??5??????  /usr/lib/systemd/system/wg-quick@.service\n")},
		{name: "missing unit", output: dpkgMissingVerification("/usr/lib/systemd/system/wg-quick@.service")},
		{name: "missing executable", output: dpkgMissingVerification("/usr/bin/wg-quick")},
		{name: "unknown path", output: dpkgMissingVerification("/usr/share/locale/en/wireguard-tools.mo")},
		{name: "doc root", output: dpkgMissingVerification("/usr/share/doc/wireguard-tools")},
		{name: "unknown manpage", output: dpkgMissingVerification("/usr/share/man/man8/operator.8.gz")},
		{name: "relative path", output: []byte("missing     usr/share/doc/wireguard-tools/NEWS.Debian.gz\n")},
		{name: "path traversal", output: dpkgMissingVerification("/usr/share/doc/wireguard-tools/../operator")},
		{name: "noncanonical path", output: dpkgMissingVerification("/usr/share/doc/wireguard-tools//NEWS.Debian.gz")},
		{name: "malformed prefix", output: []byte("missing " + allowed + "\n")},
		{name: "blank line", output: []byte("missing     " + allowed + "\n\n")},
		{name: "missing terminal LF", output: []byte("missing     " + allowed)},
		{name: "NUL", output: append(dpkgMissingVerification(allowed), 0)},
		{name: "CR", output: []byte("missing     " + allowed + "\r\n")},
		{name: "duplicate", output: dpkgMissingVerification(allowed, allowed)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := attestDPKGWireGuardVerification(testCase.output); err == nil {
				t.Fatal("unsafe dpkg verification output was accepted")
			}
		})
	}
}

func TestSystemdWireGuardRPMAttestationUsesExactOwnershipAndIntegrityCommands(t *testing.T) {
	const (
		fragment = "/usr/lib/systemd/system/wg-quick@.service"
		version  = "1.0.20250521-1.el10"
	)
	var calls []firewallRemovalPackageCall
	executor := testFirewallRemovalPackageExecutor(t, []string{"rpm"}, func(path string, arguments ...string) ([]byte, error) {
		calls = append(calls, firewallRemovalPackageCall{
			name: filepath.Base(path), arguments: append([]string(nil), arguments...),
		})
		switch {
		case reflect.DeepEqual(arguments, []string{
			"--query", "--file", fragment, "--queryformat", rpmWireGuardOwnerQueryFormat,
		}):
			return []byte(systemdWireGuardPackageName + "\t" + version + "\n"), nil
		case reflect.DeepEqual(arguments, []string{"--verify", "--file", fragment, "--noscripts"}):
			return nil, nil
		default:
			return nil, errors.New("unexpected RPM package attestation command")
		}
	})
	if err := attestSystemdWireGuardPackageWith(
		executor, fragment, filepath.EvalSymlinks, []byte(wireGuardUnitFixture),
	); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("RPM package attestation calls = %#v", calls)
	}

	for _, testCase := range []struct {
		name         string
		owner        []byte
		verification []byte
		verifyErr    error
	}{
		{name: "wrong owner", owner: []byte("operator-package\t" + version + "\n")},
		{
			name:         "modified file",
			owner:        []byte(systemdWireGuardPackageName + "\t" + version + "\n"),
			verification: []byte("S.5....T.  " + fragment + "\n"),
		},
		{
			name:      "verification failure",
			owner:     []byte(systemdWireGuardPackageName + "\t" + version + "\n"),
			verifyErr: errors.New("rpm verify failed"),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			executor := testFirewallRemovalPackageExecutor(t, []string{"rpm"}, func(_ string, arguments ...string) ([]byte, error) {
				if arguments[0] == "--query" {
					return testCase.owner, nil
				}
				return testCase.verification, testCase.verifyErr
			})
			if err := attestSystemdWireGuardPackageWith(
				executor, fragment, filepath.EvalSymlinks, []byte(wireGuardUnitFixture),
			); err == nil {
				t.Fatal("unverified RPM WireGuard unit was accepted")
			}
		})
	}
}

func TestSystemdWireGuardPackageAttestationRejectsConflictingAuthorities(t *testing.T) {
	const fragment = "/usr/lib/systemd/system/wg-quick@.service"
	for _, testCase := range []struct {
		name        string
		dpkgMode    string
		rpmMode     string
		wantFailure bool
	}{
		{name: "two valid authorities", dpkgMode: "valid", rpmMode: "valid", wantFailure: true},
		{name: "valid dpkg and drifting rpm claimant", dpkgMode: "valid", rpmMode: "drift", wantFailure: true},
		{name: "mismatched dpkg claimant and valid rpm", dpkgMode: "checksum-mismatch", rpmMode: "valid", wantFailure: true},
		{name: "valid dpkg and unexpected rpm owner", dpkgMode: "valid", rpmMode: "wrong-owner", wantFailure: true},
		{name: "valid dpkg and ambiguous rpm owners", dpkgMode: "valid", rpmMode: "multi-owner", wantFailure: true},
		{name: "ambiguous dpkg status and valid rpm", dpkgMode: "ambiguous-status", rpmMode: "valid", wantFailure: true},
		{name: "valid dpkg and rpm non-owner", dpkgMode: "valid", rpmMode: "non-owner"},
		{name: "dpkg non-owner and valid rpm", dpkgMode: "non-owner", rpmMode: "valid"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			executor := testFirewallRemovalPackageExecutor(
				t, []string{"dpkg-query", "dpkg", "rpm"},
				func(path string, arguments ...string) ([]byte, error) {
					switch filepath.Base(path) {
					case "dpkg-query":
						switch arguments[0] {
						case "--show":
							if testCase.dpkgMode == "non-owner" {
								return nil, errors.New("wireguard-tools is not installed")
							}
							if testCase.dpkgMode == "ambiguous-status" {
								return []byte("deinstall ok config-files\twireguard-tools\t1.0.20210914-1\n"), nil
							}
							return []byte("install ok installed\twireguard-tools\t1.0.20210914-1\n"), nil
						case "--listfiles":
							return []byte(fragment + "\n"), nil
						case "--control-show":
							checksum := wireGuardUnitFixtureChecksum
							if testCase.dpkgMode == "checksum-mismatch" {
								checksum = "00000000000000000000000000000000"
							}
							return dpkgChecksumMetadata(fragment, checksum), nil
						}
					case "dpkg":
						return nil, nil
					case "rpm":
						if arguments[0] == "--query" {
							if testCase.rpmMode == "non-owner" {
								return nil, errors.New("file is not owned by any package")
							}
							if testCase.rpmMode == "wrong-owner" {
								return []byte("operator-package\t1.0\n"), nil
							}
							if testCase.rpmMode == "multi-owner" {
								return []byte("wireguard-tools\t1.0\noperator-package\t1.0\n"), nil
							}
							return []byte("wireguard-tools\t1.0.20210914-4.el9\n"), nil
						}
						if testCase.rpmMode == "drift" {
							return []byte("S.5....T.  " + fragment + "\n"), nil
						}
						return nil, nil
					}
					return nil, errors.New("unexpected package attestation command")
				},
			)
			err := attestSystemdWireGuardPackageWith(
				executor, fragment, func(path string) (string, error) { return path, nil },
				[]byte(wireGuardUnitFixture),
			)
			if testCase.wantFailure && err == nil {
				t.Fatal("conflicting package authorities were accepted")
			}
			if !testCase.wantFailure && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStableSystemdWireGuardPackageAttestationRejectsEvidenceAndFileDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg-quick@.service")
	if err := os.WriteFile(path, []byte(wireGuardUnitFixture), 0644); err != nil { // #nosec G306 -- immutable test fixture
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	baseSnapshot := firewallRemovalFileSnapshot{
		identity: info,
		content:  []byte(wireGuardUnitFixture),
	}

	readCalls := 0
	proofCalls := 0
	if err := attestStablePackageOwnedSystemdWireGuardUnit(
		path,
		func(string, os.FileMode) (firewallRemovalFileSnapshot, error) {
			readCalls++
			return baseSnapshot, nil
		},
		func([]byte) (string, error) {
			proofCalls++
			return "dpkg@1.0#771a9ec17f327f42dc17c3d2e936ebad", nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if readCalls != 2 || proofCalls != 2 {
		t.Fatalf("read/proof calls = %d/%d, want 2/2", readCalls, proofCalls)
	}

	proofCalls = 0
	if err := attestStablePackageOwnedSystemdWireGuardUnit(
		path,
		func(string, os.FileMode) (firewallRemovalFileSnapshot, error) { return baseSnapshot, nil },
		func([]byte) (string, error) {
			proofCalls++
			return fmt.Sprintf("dpkg@1.0#%d", proofCalls), nil
		},
	); err == nil {
		t.Fatal("package evidence drift was accepted")
	}

	readCalls = 0
	if err := attestStablePackageOwnedSystemdWireGuardUnit(
		path,
		func(string, os.FileMode) (firewallRemovalFileSnapshot, error) {
			readCalls++
			snapshot := baseSnapshot
			if readCalls == 2 {
				snapshot.content = []byte("operator mutation\n")
			}
			return snapshot, nil
		},
		func([]byte) (string, error) { return "dpkg@1.0#stable", nil },
	); err == nil {
		t.Fatal("WireGuard unit content drift was accepted")
	}

	if err := attestStablePackageOwnedSystemdWireGuardUnit(path, nil, nil); err == nil {
		t.Fatal("missing package attestation dependencies were accepted")
	}
}

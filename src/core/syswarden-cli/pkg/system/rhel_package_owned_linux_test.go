//go:build linux

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func testRHELPackageOwnedIdentity() []byte {
	return []byte("syswarden\t0\t4.10.0\t1.rhelpo\tx86_64\n")
}

func testRHELPackageOwnedOwner(t *testing.T, root string) (uint32, uint32) {
	t.Helper()
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("stat private RHEL package-owned fixture root: %v", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("private RHEL package-owned fixture root is not an exact directory: %v", info.Mode())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("private RHEL package-owned fixture root has no Linux stat identity")
	}
	return stat.Uid, stat.Gid
}

func TestCompiledRHELPackageOwnedProfileMatchesReviewedPayload(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		rhelPackageOwnedCoreUnitPath:               "cfc30f12ea66548dce4322d2cde38a62cbc257d93be3e82218434a848051dbd7",
		rhelPackageOwnedFirewallUnitPath:           "989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1",
		systemdFirewallWireGuardOrderingDropInPath: "8c4b31f25436882197beec8c8bff5a7599389e564593bd7c353aa99ef3854483",
		rhelPackageOwnedPresetPath:                 "0f6e058dc43d09ed101799ee444015918d28127186c9f0cbc78231906b955354",
		rhelPackageOwnedProfilePath:                "06b0aa821553e322f58641767ac96385c1ad5210bf4d074d735d4bfe06365ac5",
	}
	for _, file := range rhelPackageOwnedFiles {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(file.content)))
		if digest != want[file.path] {
			t.Fatalf("compiled RHEL package-owned payload %s digest = %s, want %s", file.path, digest, want[file.path])
		}
	}
}

func installTestRHELPackageOwnedProfile(t *testing.T, root string) {
	t.Helper()
	for _, directory := range rhelPackageOwnedRequiredDirectories {
		path := filepath.Join(root, strings.TrimPrefix(directory.path, "/"))
		if err := os.MkdirAll(path, directory.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range rhelPackageOwnedFiles {
		path := filepath.Join(root, strings.TrimPrefix(file.path, "/"))
		if err := os.WriteFile(path, []byte(file.content), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		"/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt":  "geoip license\n",
		"/usr/share/doc/syswarden/LICENSE.txt":             "license\n",
		"/usr/libexec/syswarden/rhelpo-postun-recovery-v1": "#!/bin/sh\nexit 0\n",
	} {
		candidate := filepath.Join(root, strings.TrimPrefix(path, "/"))
		mode := os.FileMode(0644)
		if strings.HasPrefix(path, "/usr/libexec/") {
			mode = 0755
		}
		if err := os.WriteFile(candidate, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	installTestRHELPackageOwnedProductSkeleton(t, root)
	completion := filepath.Join(root, "usr/share/bash-completion/completions/syswarden")
	if err := os.WriteFile(completion, []byte("completion\n"), 0644); err != nil { // #nosec G306 -- fixture reproduces the reviewed root-owned 0644 RPM completion payload
		t.Fatal(err)
	}
	for _, link := range rhelPackageOwnedAdditionalOwnedPayloadLinks {
		path := filepath.Join(root, strings.TrimPrefix(link.path, "/"))
		if err := os.Symlink(link.target, path); err != nil {
			t.Fatal(err)
		}
	}
}

func testRHELPackageOwnedHost(t *testing.T, root string) rhelPackageOwnedAttestationHost {
	t.Helper()
	uid, gid := testRHELPackageOwnedOwner(t, root)
	return rhelPackageOwnedAttestationHost{
		root:        root,
		expectedUID: uid,
		expectedGID: gid,
		queryInstalled: func() ([]byte, error) {
			return testRHELPackageOwnedIdentity(), nil
		},
		queryFileOwner: func(string) ([]byte, error) {
			return testRHELPackageOwnedIdentity(), nil
		},
		verifyInstalledPayload: func() ([]byte, error) {
			return nil, nil
		},
		attestRecoveryTemporary: attestRestrictiveRecoverableRemovalRecord,
	}
}

func testSuccessfulRHELPackagePayloadAttestation() error {
	return nil
}

func TestRHELPackageOwnedDistributionLibraryDirectoryModes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		path string
		mode os.FileMode
		want bool
	}{
		{name: "native read-only library parent", path: "usr/lib", mode: 0555, want: true},
		{name: "writable root library parent", path: "usr/lib", mode: 0755, want: true},
		{name: "group writable library parent", path: "usr/lib", mode: 0775},
		{name: "restricted library parent", path: "usr/lib", mode: 0550},
		{name: "unapproved library parent mode", path: "usr/lib", mode: 0750},
		{name: "other shared parent stays exact", path: "usr/libexec", mode: 0555},
		{name: "product directory stays exact", path: "usr/libexec/syswarden", mode: 0555},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			installTestRHELPackageOwnedProfile(t, root)
			path := filepath.Join(root, test.path)
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Chmod(path, 0755); err != nil { // #nosec G302 -- restore the private fixture directory for cleanup
					t.Error(err)
				}
			}()
			host := testRHELPackageOwnedHost(t, root)
			present, err := host.attest()
			if (err == nil && present) != test.want {
				t.Fatalf("attest() = (%t, %v), want accepted=%t", present, err, test.want)
			}
			info, statErr := os.Lstat(path)
			if statErr != nil || info.Mode().Perm() != test.mode {
				t.Fatalf("attestation changed directory metadata: %v", statErr)
			}
		})
	}
}

func installTestRHELPackageOwnedProductSkeleton(t *testing.T, root string) {
	t.Helper()
	for _, path := range rhelPackageOwnedProductDirectories {
		if err := os.MkdirAll(filepath.Join(root, strings.TrimPrefix(path, "/")), 0755); err != nil { // #nosec G301 -- fixture reproduces the reviewed 0755 RPM product-directory contract
			t.Fatal(err)
		}
	}
	for _, file := range rhelPackageOwnedProductFiles {
		path := filepath.Join(root, strings.TrimPrefix(file.path, "/"))
		if err := os.WriteFile(path, []byte("rpm payload\n"), file.mode); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRHELPackageOwnedProfileAttestationFailsClosed(t *testing.T) {
	t.Parallel()

	t.Run("absent is standard", func(t *testing.T) {
		root := t.TempDir()
		host := testRHELPackageOwnedHost(t, root)
		host.queryInstalled = func() ([]byte, error) {
			return []byte("syswarden\t0\t4.10.0\t1\tx86_64\n"), nil
		}
		present, err := host.attest()
		if err != nil || present {
			t.Fatalf("attest() = (%t, %v), want (false, nil)", present, err)
		}
	})

	t.Run("standard package preun does not query rpm", func(t *testing.T) {
		root := t.TempDir()
		uid, gid := testRHELPackageOwnedOwner(t, root)
		host := rhelPackageOwnedAttestationHost{
			root: root, expectedUID: uid, expectedGID: gid,
			skipAbsentPackageQuery: true,
			queryInstalled: func() ([]byte, error) {
				t.Fatal("standard package preun queried rpm")
				return nil, nil
			},
			queryFileOwner: func(string) ([]byte, error) {
				t.Fatal("standard package preun queried rpm file ownership")
				return nil, nil
			},
			verifyInstalledPayload: func() ([]byte, error) {
				t.Fatal("standard package preun verified an absent RHELPO payload")
				return nil, nil
			},
		}
		present, err := host.attest()
		if err != nil || present {
			t.Fatalf("attest() = (%t, %v), want (false, nil)", present, err)
		}
	})

	t.Run("partial package preun payload refuses before querying rpm", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, strings.TrimPrefix(rhelPackageOwnedCoreUnitPath, "/"))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { // #nosec G301 -- fixture reproduces the standard 0755 systemd unit-directory contract
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(systemdCoreService), 0644); err != nil { // #nosec G306 -- fixture reproduces the reviewed root-owned 0644 RPM unit payload
			t.Fatal(err)
		}
		uid, gid := testRHELPackageOwnedOwner(t, root)
		host := rhelPackageOwnedAttestationHost{
			root: root, expectedUID: uid, expectedGID: gid,
			skipAbsentPackageQuery: true,
			queryInstalled: func() ([]byte, error) {
				t.Fatal("partial package preun payload queried rpm")
				return nil, nil
			},
		}
		if present, err := host.attest(); err == nil || present {
			t.Fatalf("attest() = (%t, %v), want refusal", present, err)
		}
	})

	t.Run("RHEL NEVRA with absent payload refuses", func(t *testing.T) {
		root := t.TempDir()
		host := testRHELPackageOwnedHost(t, root)
		present, err := host.attest()
		if err == nil || !present {
			t.Fatalf("attest() = (%t, %v), want (true, error)", present, err)
		}
	})

	t.Run("exact profile", func(t *testing.T) {
		root := t.TempDir()
		installTestRHELPackageOwnedProfile(t, root)
		host := testRHELPackageOwnedHost(t, root)
		present, err := host.attest()
		if err != nil || !present {
			t.Fatalf("attest() = (%t, %v), want (true, nil)", present, err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, root string, host *rhelPackageOwnedAttestationHost)
	}{
		{
			name: "rpm verification deviation",
			mutate: func(t *testing.T, _ string, host *rhelPackageOwnedAttestationHost) {
				t.Helper()
				host.verifyInstalledPayload = func() ([]byte, error) {
					return []byte("S.5....T.  /opt/syswarden/bin/syswarden-cli\n"), nil
				}
			},
		},
		{
			name: "unexpected static inventory entry",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(root, "usr/libexec/syswarden/unexpected")
				if err := os.WriteFile(path, []byte("unexpected\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "modified required ancestor mode",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, "usr/libexec"), 0750); err != nil { // #nosec G302 -- adversarial fixture intentionally changes a package directory away from its exact 0755 contract
					t.Fatal(err)
				}
			},
		},
		{
			name: "conflicting finalizing marker",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(root, strings.TrimPrefix(RemovalFinalizingPath, "/"))
				if err := os.WriteFile(path, []byte(RemovalFinalizingRecord), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "conflicting migration link",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(
					root,
					"etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration",
				)
				if err := os.Symlink("/usr/lib/systemd/system/syswarden-core.service", path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard linked additional payload",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(root, "usr/share/bash-completion/completions/syswarden")
				if err := os.Link(path, filepath.Join(root, "additional-hardlink")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "partial payload",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "usr/lib/systemd/system/syswarden-core.service")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong NEVRA",
			mutate: func(t *testing.T, _ string, host *rhelPackageOwnedAttestationHost) {
				t.Helper()
				host.queryInstalled = func() ([]byte, error) {
					return []byte("syswarden\t0\t4.10.0\t1\tx86_64\n"), nil
				}
			},
		},
		{
			name: "wrong file owner NEVRA",
			mutate: func(t *testing.T, _ string, host *rhelPackageOwnedAttestationHost) {
				t.Helper()
				host.queryFileOwner = func(string) ([]byte, error) {
					return []byte("syswarden\t0\t4.10.0\t2.rhelpo\tx86_64\n"), nil
				}
			},
		},
		{
			name: "modified content",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(root, "usr/lib/systemd/system/syswarden-core.service")
				if err := os.WriteFile(path, []byte("modified\n"), 0644); err != nil { // #nosec G306 -- fixture preserves the exact 0644 RPM mode so only content deviation is exercised
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong mode",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(root, "usr/lib/systemd/system/syswarden-core.service")
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard linked payload",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(root, "usr/lib/systemd/system/syswarden-core.service")
				if err := os.Link(path, filepath.Join(root, "hardlink")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "priority unit remains",
			mutate: func(t *testing.T, root string, _ *rhelPackageOwnedAttestationHost) {
				t.Helper()
				path := filepath.Join(root, "etc/systemd/system/syswarden-core.service")
				if err := os.WriteFile(path, []byte(systemdCoreService), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ownership changes",
			mutate: func(t *testing.T, _ string, host *rhelPackageOwnedAttestationHost) {
				t.Helper()
				queries := 0
				host.queryFileOwner = func(string) ([]byte, error) {
					queries++
					if queries > len(rhelPackageOwnedFiles) {
						return nil, fmt.Errorf("changed owner")
					}
					return testRHELPackageOwnedIdentity(), nil
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			installTestRHELPackageOwnedProfile(t, root)
			host := testRHELPackageOwnedHost(t, root)
			test.mutate(t, root, &host)
			if present, err := host.attest(); err == nil || present {
				t.Fatalf("attest() = (%t, %v), want refusal", present, err)
			}
		})
	}
}

func TestRHELPackageOwnedProfileAttestsRestrictiveEraseTemporaryReadOnly(t *testing.T) {
	recordPrefix := rhelPackageOwnedEraseReadyRecord[:17]
	for _, mode := range []os.FileMode{0000, 0200, 0400} {
		mode := mode
		t.Run(fmt.Sprintf("mode-%04o", mode), func(t *testing.T) {
			root := t.TempDir()
			installTestRHELPackageOwnedProfile(t, root)
			temporaryPath := filepath.Join(
				root,
				strings.TrimPrefix(rhelPackageOwnedEraseReadyPath+".new", "/"),
			)
			if err := os.WriteFile(temporaryPath, []byte(recordPrefix), 0600); err != nil {
				t.Fatal(err)
			}
			var preopened *os.File
			defer func() {
				if preopened != nil {
					_ = preopened.Close()
				}
			}()
			if mode == 0000 || mode == 0200 {
				var err error
				preopened, err = os.OpenFile(temporaryPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- private test fixture
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(temporaryPath, mode); err != nil { // #nosec G302 -- restrictive crash mode is the test subject
				if preopened != nil {
					_ = preopened.Close()
				}
				t.Fatal(err)
			}
			beforeInfo, err := os.Lstat(temporaryPath)
			if err != nil {
				t.Fatal(err)
			}
			beforeIdentity, err := exactRemovalArtifactIdentity(beforeInfo)
			if err != nil {
				t.Fatal(err)
			}

			host := testRHELPackageOwnedHost(t, root)
			if preopened != nil {
				used := false
				host.attestRecoveryTemporary = func(
					directory *pinnedServiceDirectory,
					name, record string,
					expectedUID, expectedGID uint32,
				) (os.FileInfo, bool, error) {
					return attestRestrictiveRecoverableRemovalRecordUsing(
						directory,
						name,
						record,
						expectedUID,
						expectedGID,
						func() (*os.File, error) {
							if used {
								return nil, fmt.Errorf("preopened RHEL recovery descriptor was requested twice")
							}
							used = true
							return preopened, nil
						},
						func() {},
					)
				}
			}
			verifyCalled := false
			host.verifyInstalledPayload = func() ([]byte, error) {
				verifyCalled = true
				currentInfo, err := os.Lstat(temporaryPath)
				currentIdentity, identityErr := exactRemovalArtifactIdentity(currentInfo)
				if err != nil || identityErr != nil || currentIdentity != beforeIdentity {
					return nil, errors.Join(
						fmt.Errorf("erase-ready temporary mutated before exhaustive RPM verification"),
						err,
						identityErr,
					)
				}
				return nil, nil
			}
			present, err := host.attest()
			preopened = nil // the read-only attestor owns and closes the descriptor
			if err != nil || !present || !verifyCalled {
				t.Fatalf("attest restrictive RHEL recovery temporary: present=%t verify=%t err=%v", present, verifyCalled, err)
			}
			afterInfo, err := os.Lstat(temporaryPath)
			afterIdentity, identityErr := exactRemovalArtifactIdentity(afterInfo)
			if err != nil || identityErr != nil || beforeIdentity != afterIdentity || afterInfo.Mode().Perm() != mode {
				t.Fatalf("read-only RHEL attestation mutated temporary: info=%v err=%v identity_err=%v", afterInfo, err, identityErr)
			}
		})
	}
}

func TestRHELPackageOwnedProfileRejectsUnsafeEraseTemporaryBeforeRPMVerification(t *testing.T) {
	tests := []struct {
		name       string
		mode       os.FileMode
		specialBit os.FileMode
	}{
		{name: "other-execute-0001", mode: 0001},
		{name: "group-execute-0010", mode: 0010},
		{name: "group-read-0040", mode: 0040},
		{name: "setuid", mode: 0600 | os.ModeSetuid, specialBit: os.ModeSetuid},
		{name: "setgid", mode: 0600 | os.ModeSetgid, specialBit: os.ModeSetgid},
		{name: "sticky", mode: 0600 | os.ModeSticky, specialBit: os.ModeSticky},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			installTestRHELPackageOwnedProfile(t, root)
			temporaryPath := filepath.Join(
				root,
				strings.TrimPrefix(rhelPackageOwnedEraseReadyPath+".new", "/"),
			)
			if err := os.WriteFile(temporaryPath, []byte(rhelPackageOwnedEraseReadyRecord[:17]), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(temporaryPath, test.mode); err != nil { // #nosec G302 -- unsafe mode is the test subject
				t.Fatal(err)
			}
			beforeInfo, err := os.Lstat(temporaryPath)
			if err != nil {
				t.Fatal(err)
			}
			if test.specialBit != 0 && beforeInfo.Mode()&test.specialBit == 0 {
				t.Skipf("filesystem did not retain special mode bit %v", test.specialBit)
			}
			beforeIdentity, err := exactRemovalArtifactIdentity(beforeInfo)
			if err != nil {
				t.Fatal(err)
			}
			host := testRHELPackageOwnedHost(t, root)
			verifyCalled := false
			host.verifyInstalledPayload = func() ([]byte, error) {
				verifyCalled = true
				return nil, nil
			}
			if present, err := host.attest(); err == nil || present || verifyCalled {
				t.Fatalf("unsafe RHEL recovery temporary: present=%t verify=%t err=%v", present, verifyCalled, err)
			}
			afterInfo, err := os.Lstat(temporaryPath)
			afterIdentity, identityErr := exactRemovalArtifactIdentity(afterInfo)
			if err != nil || identityErr != nil || beforeIdentity != afterIdentity {
				t.Fatalf("unsafe RHEL temporary changed before refusal: info=%v err=%v identity_err=%v", afterInfo, err, identityErr)
			}
		})
	}
}

func TestRHELPackageOwnedProfileRejectsEraseTemporarySubstitutionBeforeRPMVerification(t *testing.T) {
	root := t.TempDir()
	installTestRHELPackageOwnedProfile(t, root)
	temporaryPath := filepath.Join(root, strings.TrimPrefix(rhelPackageOwnedEraseReadyPath+".new", "/"))
	replacement := temporaryPath + ".replacement"
	for _, path := range []string{temporaryPath, replacement} {
		if err := os.WriteFile(path, []byte(rhelPackageOwnedEraseReadyRecord[:17]), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0400); err != nil { // #nosec G302 -- restrictive crash mode is the test subject
			t.Fatal(err)
		}
	}
	host := testRHELPackageOwnedHost(t, root)
	host.attestRecoveryTemporary = func(
		directory *pinnedServiceDirectory,
		name, record string,
		expectedUID, expectedGID uint32,
	) (os.FileInfo, bool, error) {
		return attestRestrictiveRecoverableRemovalRecordUsing(
			directory,
			name,
			record,
			expectedUID,
			expectedGID,
			func() (*os.File, error) {
				return directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			},
			func() {
				if err := os.Rename(replacement, temporaryPath); err != nil {
					t.Fatalf("substitute RHEL recovery temporary: %v", err)
				}
			},
		)
	}
	verifyCalled := false
	host.verifyInstalledPayload = func() ([]byte, error) {
		verifyCalled = true
		return nil, nil
	}
	if present, err := host.attest(); err == nil || present || verifyCalled {
		t.Fatalf("substituted RHEL recovery temporary: present=%t verify=%t err=%v", present, verifyCalled, err)
	}
	info, err := os.Lstat(temporaryPath)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatalf("substituted RHEL recovery temporary was mutated: info=%v err=%v", info, err)
	}
}

func TestRHELPackageOwnedEraseReadyRecord(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	uid, gid := testRHELPackageOwnedOwner(t, root)
	if err := publishRHELPackageOwnedEraseReadyAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != 0600 || stat.Nlink != 1 {
		t.Fatalf("erase-ready marker metadata is not exact: mode=%v stat=%#v", info.Mode(), stat)
	}
	content, err := os.ReadFile(path) // #nosec G304 -- path is a fixed marker beneath the private test root
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != rhelPackageOwnedEraseReadyRecord {
		t.Fatalf("erase-ready content = %q", content)
	}
	if _, err := os.Lstat(path + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("erase-ready publication left a temporary marker: %v", err)
	}
}

func installTestRHELPackageOwnedRuntimeWithCanary(t *testing.T, root string) string {
	t.Helper()
	for _, path := range rhelPackageOwnedRuntimeDirectories {
		if err := os.MkdirAll(filepath.Join(root, strings.TrimPrefix(path, "/")), 0750); err != nil {
			t.Fatal(err)
		}
	}
	installTestRHELPackageOwnedProductSkeleton(t, root)
	state := filepath.Join(root, "var/lib/syswarden")
	if err := os.WriteFile(filepath.Join(state, removalTombstoneName), []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(root, "etc/syswarden/config/modules/operator.toml")
	if err := os.WriteFile(canary, []byte("must remain\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return canary
}

func TestPrepareRHELPackageOwnedRuntimeForEraseRejectsUnsafeTemporaryBeforeCleanup(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		create func(t *testing.T, path string)
	}{
		{
			name: "malformed",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("malformed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong mode",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(rhelPackageOwnedEraseReadyRecord[:8]), 0644); err != nil { // #nosec G306 -- adversarial fixture intentionally creates an unsafe erase marker mode
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			create: func(t *testing.T, path string) {
				t.Helper()
				source := filepath.Join(filepath.Dir(path), "unsafe-hardlink-source")
				if err := os.WriteFile(source, []byte(rhelPackageOwnedEraseReadyRecord[:8]), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(source, path); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			canary := installTestRHELPackageOwnedRuntimeWithCanary(t, root)
			marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
			test.create(t, marker+".new")
			uid, gid := testRHELPackageOwnedOwner(t, root)
			if err := prepareRHELPackageOwnedRuntimeForEraseAt(
				root, marker, uid, gid,
				testSuccessfulRHELPackagePayloadAttestation,
			); err == nil {
				t.Fatal("unsafe erase-ready temporary was accepted")
			}
			if content, err := os.ReadFile(canary); err != nil || string(content) != "must remain\n" { // #nosec G304 -- canary is a fixed file beneath the private test root
				t.Fatalf("runtime was mutated before temporary refusal: %q, %v", content, err)
			}
			if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("erase-ready marker was published after temporary refusal: %v", err)
			}
		})
	}
}

func TestPrepareRHELPackageOwnedRuntimeForEraseRecoversSafeTemporaryBeforeCleanup(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		rhelPackageOwnedEraseReadyRecord[:8],
		rhelPackageOwnedEraseReadyRecord,
	} {
		content := content
		t.Run(fmt.Sprintf("length-%d", len(content)), func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			canary := installTestRHELPackageOwnedRuntimeWithCanary(t, root)
			marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
			if err := os.WriteFile(marker+".new", []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			uid, gid := testRHELPackageOwnedOwner(t, root)
			if err := prepareRHELPackageOwnedRuntimeForEraseAt(
				root, marker, uid, gid,
				testSuccessfulRHELPackagePayloadAttestation,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(canary); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("runtime canary remains after successful cleanup: %v", err)
			}
			if final, err := os.ReadFile(marker); err != nil || string(final) != rhelPackageOwnedEraseReadyRecord { // #nosec G304 -- marker is a fixed file beneath the private test root
				t.Fatalf("erase-ready marker = %q, %v", final, err)
			}
			if _, err := os.Lstat(marker + ".new"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("safe temporary remains after recovery: %v", err)
			}
		})
	}
}

func TestPrepareRHELPackageOwnedRuntimeForEraseAttestsPayloadBeforeCleanup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	canary := installTestRHELPackageOwnedRuntimeWithCanary(t, root)
	marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
	temporaryContent := rhelPackageOwnedEraseReadyRecord[:8]
	if err := os.WriteFile(marker+".new", []byte(temporaryContent), 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := testRHELPackageOwnedOwner(t, root)
	if err := prepareRHELPackageOwnedRuntimeForEraseAt(
		root, marker, uid, gid,
		func() error { return fmt.Errorf("modified package payload") },
	); err == nil {
		t.Fatal("modified package payload was accepted")
	}
	if content, err := os.ReadFile(canary); err != nil || string(content) != "must remain\n" { // #nosec G304 -- canary is a fixed file beneath the private test root
		t.Fatalf("runtime was mutated before package-payload refusal: %q, %v", content, err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("erase-ready marker was published after package-payload refusal: %v", err)
	}
	if content, err := os.ReadFile(marker + ".new"); err != nil || string(content) != temporaryContent { // #nosec G304 -- marker is a fixed file beneath the private test root
		t.Fatalf("safe temporary was mutated before package-payload refusal: %q, %v", content, err)
	}
}

func TestPrepareRHELPackageOwnedRuntimeForErasePreservesOnlyRPMSkeleton(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	uid, gid := testRHELPackageOwnedOwner(t, root)
	for _, path := range rhelPackageOwnedRuntimeDirectories {
		if err := os.MkdirAll(filepath.Join(root, strings.TrimPrefix(path, "/")), 0750); err != nil {
			t.Fatal(err)
		}
	}
	installTestRHELPackageOwnedProductSkeleton(t, root)
	state := filepath.Join(root, "var/lib/syswarden")
	if err := os.WriteFile(filepath.Join(state, removalTombstoneName), []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"etc/syswarden/config/modules/operator.toml",
		"etc/syswarden/lists/runtime.list",
		"etc/syswarden/tls/runtime.pem",
		"var/lib/syswarden/ui/state.json",
		"var/lib/syswarden/runtime.db",
		"var/log/syswarden/syswarden.log",
		"opt/syswarden/legacy-config.bak",
	} {
		candidate := filepath.Join(root, path)
		if err := os.WriteFile(candidate, []byte("runtime\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("must survive\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "opt/syswarden/untrusted-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "opt/syswarden/untrusted-hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "opt/syswarden/untrusted-fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
	if err := prepareRHELPackageOwnedRuntimeForEraseAt(
		root, marker, uid, gid, testSuccessfulRHELPackagePayloadAttestation,
	); err != nil {
		t.Fatal(err)
	}
	if err := prepareRHELPackageOwnedRuntimeForEraseAt(
		root, marker, uid, gid, testSuccessfulRHELPackagePayloadAttestation,
	); err != nil {
		t.Fatalf("idempotent erase preparation failed: %v", err)
	}
	for _, path := range rhelPackageOwnedRuntimeDirectories {
		info, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(path, "/")))
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0750 {
			t.Fatalf("RPM directory %s was not preserved exactly: %v, %v", path, info, err)
		}
	}
	for _, path := range []string{
		"etc/syswarden/config/modules/operator.toml",
		"etc/syswarden/lists/runtime.list",
		"etc/syswarden/tls/runtime.pem",
		"var/lib/syswarden/ui/state.json",
		"var/lib/syswarden/runtime.db",
		"var/log/syswarden/syswarden.log",
		"opt/syswarden/legacy-config.bak",
		"opt/syswarden/untrusted-link",
		"opt/syswarden/untrusted-hardlink",
		"opt/syswarden/untrusted-fifo",
	} {
		if _, err := os.Lstat(filepath.Join(root, path)); !os.IsNotExist(err) {
			t.Fatalf("runtime path %s remains: %v", path, err)
		}
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "must survive\n" { // #nosec G304 -- outside is a fixed canary beneath a separate private test root
		t.Fatalf("cleanup escaped the product root: %q, %v", content, err)
	}
	if content, err := os.ReadFile(filepath.Join(state, removalTombstoneName)); err != nil || string(content) != RemovalTombstoneRecord { // #nosec G304 -- state is confined to the private test root and the tombstone name is fixed
		t.Fatalf("removal tombstone = %q, %v", content, err)
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != rhelPackageOwnedEraseReadyRecord { // #nosec G304 -- marker is a fixed file beneath the private test root
		t.Fatalf("erase-ready marker = %q, %v", content, err)
	}
}

func TestPrepareRHELPackageOwnedRuntimeForEraseRejectsModifiedSkeleton(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, path := range rhelPackageOwnedRuntimeDirectories {
		if err := os.MkdirAll(filepath.Join(root, strings.TrimPrefix(path, "/")), 0750); err != nil {
			t.Fatal(err)
		}
	}
	installTestRHELPackageOwnedProductSkeleton(t, root)
	state := filepath.Join(root, "var/lib/syswarden")
	if err := os.WriteFile(filepath.Join(state, removalTombstoneName), []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc/syswarden/config"), 0770); err != nil { // #nosec G302 -- adversarial fixture intentionally relaxes a package directory to prove attestation refusal
		t.Fatal(err)
	}
	marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
	uid, gid := testRHELPackageOwnedOwner(t, root)
	if err := prepareRHELPackageOwnedRuntimeForEraseAt(
		root, marker, uid, gid,
		testSuccessfulRHELPackagePayloadAttestation,
	); err == nil {
		t.Fatal("modified RPM directory was accepted")
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker was published after refusal: %v", err)
	}
}

func TestPrepareRHELPackageOwnedRuntimeForEraseRejectsMarkerBeforeCleanup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, path := range rhelPackageOwnedRuntimeDirectories {
		if err := os.MkdirAll(filepath.Join(root, strings.TrimPrefix(path, "/")), 0750); err != nil {
			t.Fatal(err)
		}
	}
	installTestRHELPackageOwnedProductSkeleton(t, root)
	state := filepath.Join(root, "var/lib/syswarden")
	if err := os.WriteFile(filepath.Join(state, removalTombstoneName), []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(root, "etc/syswarden/config/modules/operator.toml")
	if err := os.WriteFile(runtime, []byte("must remain\n"), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
	if err := os.WriteFile(marker, []byte("malformed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := testRHELPackageOwnedOwner(t, root)
	if err := prepareRHELPackageOwnedRuntimeForEraseAt(
		root, marker, uid, gid,
		testSuccessfulRHELPackagePayloadAttestation,
	); err == nil {
		t.Fatal("malformed pre-existing erase marker was accepted")
	}
	if content, err := os.ReadFile(runtime); err != nil || string(content) != "must remain\n" { // #nosec G304 -- runtime is a fixed canary beneath the private test root
		t.Fatalf("runtime was mutated before marker refusal: %q, %v", content, err)
	}
}

func TestPrepareRHELPackageOwnedRuntimeForEraseRejectsPresetRecoveryBeforeCleanup(t *testing.T) {
	t.Parallel()
	for _, pendingPath := range []string{
		rhelPackageOwnedPresetPendingPath,
		rhelPackageOwnedPresetPendingTempPath,
	} {
		t.Run(filepath.Base(pendingPath), func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			for _, path := range rhelPackageOwnedRuntimeDirectories {
				if err := os.MkdirAll(filepath.Join(root, strings.TrimPrefix(path, "/")), 0750); err != nil {
					t.Fatal(err)
				}
			}
			installTestRHELPackageOwnedProductSkeleton(t, root)
			state := filepath.Join(root, "var/lib/syswarden")
			if err := os.WriteFile(filepath.Join(state, removalTombstoneName), []byte(RemovalTombstoneRecord), 0600); err != nil {
				t.Fatal(err)
			}
			runtime := filepath.Join(root, "etc/syswarden/config/modules/operator.toml")
			if err := os.WriteFile(runtime, []byte("must remain\n"), 0600); err != nil {
				t.Fatal(err)
			}
			pending := filepath.Join(root, strings.TrimPrefix(pendingPath, "/"))
			if err := os.WriteFile(pending, []byte("pending\n"), 0600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
			uid, gid := testRHELPackageOwnedOwner(t, root)
			if err := prepareRHELPackageOwnedRuntimeForEraseAt(
				root, marker, uid, gid,
				testSuccessfulRHELPackagePayloadAttestation,
			); err == nil {
				t.Fatalf("preset recovery boundary %s was accepted", pendingPath)
			}
			if content, err := os.ReadFile(runtime); err != nil || string(content) != "must remain\n" { // #nosec G304 -- runtime is a fixed canary beneath the private test root
				t.Fatalf("runtime was mutated before preset recovery refusal: %q, %v", content, err)
			}
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Fatalf("erase marker was published after preset recovery refusal: %v", err)
			}
		})
	}
}

//go:build linux

package system

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNativePackageLifecycleAttestsBothFullPayloadVariants(t *testing.T) {
	current, err := currentSysWardenPackageVersion()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"syswarden", "syswarden-base"} {
		for _, manager := range []string{"dpkg-query", "rpm"} {
			t.Run(name+"/"+manager, func(t *testing.T) {
				root, path, uid, gid := testSysWardenSystemdOrderingFixture(t)
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				original := mustReadTestFile(t, path)
				executor := testSysWardenOrderingPackageExecutorForVariant(t, path, manager == "dpkg-query", manager == "rpm", func(kind string) string {
					if kind == "rpm" {
						return current + "-1"
					}
					return current
				}, name)
				evidence, err := attestExactSystemdFirewallOrderingDropInAt(executor, path, path, root, uid, gid)
				if err != nil || !strings.Contains(evidence, "#"+name+"@"+current) {
					t.Fatalf("full-payload package ownership not established: %q %v", evidence, err)
				}
				assertNativeIdentityFilePreserved(t, path, before, original)
			})
		}
	}
}

func TestNativePackageLifecycleRefusesCoexistenceWrongOwnerAndDrift(t *testing.T) {
	for _, test := range []struct{ name, manager string }{
		{"coexisting", "dpkg-query"}, {"coexisting", "rpm"}, {"wrong file owner", "rpm"},
		{"registration drift", "dpkg-query"}, {"registration drift", "rpm"},
	} {
		t.Run(test.manager+"/"+test.name, func(t *testing.T) {
			root, path, uid, gid := testSysWardenSystemdOrderingFixture(t)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			original := mustReadTestFile(t, path)
			executor := testSysWardenOrderingPackageExecutorForVariant(t, path, test.manager == "dpkg-query", test.manager == "rpm", func(kind string) string {
				if kind == "rpm" {
					return "4.10.4-1"
				}
				return "4.10.4"
			}, "syswarden-base")
			output := executor.output
			baseQueries := 0
			executor.output = func(candidate string, args ...string) ([]byte, error) {
				name, registration := nativeRegistrationTestQuery(filepath.Base(candidate), args)
				if registration && name == "syswarden-base" {
					baseQueries++
					if test.name == "registration drift" && baseQueries == 2 {
						return nativeRegistrationTestOutput(test.manager, name, "")
					}
				}
				if registration && name == "syswarden" && test.name == "coexisting" {
					return nativeRegistrationTestOutput(test.manager, name, "installed")
				}
				result, err := output(candidate, args...)
				if !registration && test.name == "wrong file owner" {
					result = []byte(strings.ReplaceAll(string(result), "syswarden-base", "syswarden"))
				}
				return result, err
			}
			if _, err := attestExactSystemdFirewallOrderingDropInAt(executor, path, path, root, uid, gid); err == nil {
				t.Fatal("ambiguous package authority accepted")
			}
			assertNativeIdentityFilePreserved(t, path, before, original)
		})
	}
}

func TestNativePackageLifecycleHistoricalExceptionIsCompatibilityOnly(t *testing.T) {
	root, path, uid, gid := testSysWardenSystemdOrderingFixture(t)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	original := mustReadTestFile(t, path)
	executor := testSysWardenOrderingPackageExecutorForVariant(t, path, true, false, func(string) string { return "4.10.2" }, "syswarden-base")
	called := false
	_, err = attestExactSystemdPackageDropInWithDPKGOwner(executor, path, path, root, uid, gid, systemdFirewallWireGuardOrderingDropIn, "ordering", func([]byte) (string, error) {
		called = true
		return "syswarden@4.10.2#amd64#dpkg#half-configured-removal", nil
	})
	if err == nil || called {
		t.Fatalf("base package received historical removal exception: %v", err)
	}
	assertNativeIdentityFilePreserved(t, path, before, original)
}

func TestNativePackageLifecycleBaseRPMOverlapKeepsOneIdentity(t *testing.T) {
	current := "syswarden-base\t4.10.4-1\tx86_64\t8\n"
	old := "syswarden-base\t4.04.3-1\tx86_64\t8\n"
	if _, err := parseSysWardenRPMDropInOwners([]byte(old+current), true); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.ReplaceAll(old, "syswarden-base", "syswarden") + current,
		strings.ReplaceAll(current, "4.10.4-1", "4.10.4-1.rhelpo"),
		current + current + current,
	} {
		if _, err := parseSysWardenRPMDropInOwners([]byte(invalid), true); err == nil {
			t.Fatalf("invalid base transaction owner accepted: %q", invalid)
		}
	}
	if _, err := parseSysWardenRPMDropInOwners([]byte(old+current), false); err == nil {
		t.Fatal("base RPM overlap allowed outside package transaction")
	}
}

func TestNativePackageLifecycleMissingBasePayloadCannotBecomeStandalone(t *testing.T) {
	for _, manager := range []string{"dpkg-query", "rpm"} {
		executor := testFirewallRemovalPackageExecutor(t, []string{manager}, func(candidate string, args ...string) ([]byte, error) {
			if name, registration := nativeRegistrationTestQuery(filepath.Base(candidate), args); registration {
				state := ""
				if name == "syswarden-base" {
					state = "installed"
				}
				return nativeRegistrationTestOutput(manager, name, state)
			}
			if manager == "dpkg-query" && reflect.DeepEqual(args, []string{"--show", "--showformat=" + syswardenDropInDPKGInstalledFormat, "syswarden-base"}) {
				return []byte("install ok installed\tamd64\t4.10.4\n"), nil
			}
			if manager == "rpm" && reflect.DeepEqual(args, []string{"--query", "syswarden-base", "--queryformat", syswardenDropInRPMOwnerFormat}) {
				return []byte("syswarden-base\t4.10.4-1\tx86_64\t8\n"), nil
			}
			t.Fatalf("unexpected installed package query: %q", args)
			return nil, nil
		})
		claim, err := detectInstalledSysWardenPackageAuthority(executor)
		if err != nil || !strings.HasPrefix(claim, "syswarden-base@") {
			t.Fatalf("base package discovery: %q %v", claim, err)
		}
		if err := attestAbsentSystemdFirewallOrderingDropIn(executor, filepath.Join(t.TempDir(), "absent.conf"), false); err == nil {
			t.Fatal("missing base payload was treated as standalone installation")
		}
	}
}

//go:build linux

package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testCompatibilityUpdateIdentity(manager string) nativeUpdateIdentity {
	return nativeUpdateIdentity{name: "syswarden", manager: manager, state: "installed"}
}

func nativeRegistrationTestQuery(manager string, arguments []string) (string, bool) {
	for _, name := range []string{"syswarden", "syswarden-base"} {
		var expected []string
		switch manager {
		case "dpkg-query":
			expected = []string{"--show", "--showformat=${Package}\\t${db:Status-Status}\\n", name}
		case "rpm":
			expected = []string{"--query", "--queryformat", "%{NAME}\\n", name}
		case "apk":
			expected = []string{"info", "--quiet", "-e", name}
		}
		if expected != nil && reflect.DeepEqual(arguments, expected) {
			return name, true
		}
	}
	return "", false
}

func nativeRegistrationTestOutput(manager, name, state string) ([]byte, error) {
	if state == "" {
		switch manager {
		case "dpkg-query":
			return []byte("dpkg-query: no packages found matching " + name + "\n"), packageAuthorityTestExit(1)
		case "rpm":
			return []byte("package " + name + " is not installed\n"), packageAuthorityTestExit(1)
		case "apk":
			return nil, packageAuthorityTestExit(1)
		}
	}
	switch manager {
	case "dpkg-query":
		return []byte(name + "\t" + state + "\n"), nil
	case "rpm":
		return []byte(name + "\n"), nil
	case "apk":
		return nil, nil
	default:
		return nil, errors.New("unknown test package manager")
	}
}

func testNativeRegistrationExecutor(t *testing.T, manager string, states map[string]string) firewallManagerExecutor {
	t.Helper()
	return testFirewallRemovalPackageExecutor(t, []string{manager}, func(path string, arguments ...string) ([]byte, error) {
		name, matched := nativeRegistrationTestQuery(filepath.Base(path), arguments)
		if !matched {
			t.Fatalf("unexpected native registration query: %s %q", path, arguments)
		}
		return nativeRegistrationTestOutput(manager, name, states[name])
	})
}

func TestNativePackageIdentityQueriesAreClosedAndReadOnly(t *testing.T) {
	for _, command := range []struct{ path, manager string }{
		{"/usr/bin/dpkg-query", "dpkg-query"}, {"/usr/bin/rpm", "rpm"},
		{"/sbin/apk", "apk"}, {"/usr/sbin/apk", "apk"},
	} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			args, err := nativeProductRegistrationArguments(command.manager, name)
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := nativeRegistrationTestQuery(command.manager, args); !ok || got != name ||
				!allowedNativeProductRegistrationQuery(command.path, args) || !allowedQualificationQuery(command.path, args) {
				t.Fatalf("expected fixed query not allowed: %s %q", command.path, args)
			}
			for _, invalid := range [][]string{
				append(append([]string{}, args...), "syswarden-extra"),
				append(append([]string{}, args[:len(args)-1]...), "syswarden-extra"),
				append([]string{"--root=/tmp/other"}, args...),
			} {
				if allowedNativeProductRegistrationQuery(command.path, invalid) {
					t.Fatalf("unbounded query allowed: %q", invalid)
				}
			}
			if allowedNativeProductRegistrationQuery("/tmp/"+command.manager, args) {
				t.Fatal("untrusted query path allowed")
			}
		}
	}
}

func TestNativePackageIdentityUninstallRefusesBaseProfileAndCoexistence(t *testing.T) {
	for _, manager := range []string{"dpkg-query", "rpm", "apk"} {
		for _, both := range []bool{false, true} {
			states := map[string]string{"syswarden-base": "installed"}
			if both {
				states["syswarden"] = "installed"
			}
			executor := testNativeRegistrationExecutor(t, manager, states)
			profileCalled := false
			err := preflightUninstallWithProfile(executor, func(string) (bool, error) { return false, nil }, func() (bool, error) {
				profileCalled = true
				return true, nil
			})
			if err == nil || profileCalled {
				t.Fatalf("base/coexisting registration reached compatibility profile: %s both=%v err=%v", manager, both, err)
			}
		}
	}
}

func TestNativePackageIdentityUpdateRequiresSingleInstalledCompatibility(t *testing.T) {
	for _, manager := range []string{"dpkg-query", "rpm", "apk"} {
		for _, test := range []struct {
			name      string
			states    map[string]string
			wantError bool
		}{
			{"compatibility", map[string]string{"syswarden": "installed"}, false},
			{"base", map[string]string{"syswarden-base": "installed"}, true},
			{"coexisting", map[string]string{"syswarden": "installed", "syswarden-base": "installed"}, true},
			{"absent", nil, true},
		} {
			t.Run(manager+"/"+test.name, func(t *testing.T) {
				executor := testNativeRegistrationExecutor(t, manager, test.states)
				identity, err := preflightStandardNativeUpdateWith(t.Context(), executor, func(string) (bool, error) { return false, nil })
				if (err != nil) != test.wantError {
					t.Fatalf("identity preflight: %v", err)
				}
				if test.name == "base" && !strings.Contains(err.Error(), "authenticated release inventory") {
					t.Fatalf("missing base update refusal: %v", err)
				}
				if err == nil && identity != testCompatibilityUpdateIdentity(manager) {
					t.Fatalf("registration authority was not retained: %#v", identity)
				}
			})
		}
	}
	for _, state := range []string{"config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending"} {
		executor := testNativeRegistrationExecutor(t, "dpkg-query", map[string]string{"syswarden": state})
		if _, err := preflightStandardNativeUpdateWith(t.Context(), executor, func(string) (bool, error) { return false, nil }); err == nil {
			t.Fatalf("partial native state %q permitted update", state)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := preflightStandardNativeUpdateWith(ctx, firewallManagerExecutor{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation did not precede native queries: %v", err)
	}
}

func TestNativePackageIdentityUpdaterRefusesBeforeNetworkAndMutation(t *testing.T) {
	for _, missingGuard := range []bool{false, true} {
		var network, mutation atomic.Int32
		u := testUpdater(staticHTTPClient(func(*http.Request) (*http.Response, error) {
			network.Add(1)
			return nil, errors.New("unexpected network")
		}), t.TempDir(), "amd64", nil, func(context.Context, string, ...string) error {
			mutation.Add(1)
			return nil
		})
		u.preflightNativeIdentity = nil
		if !missingGuard {
			executor := testNativeRegistrationExecutor(t, "apk", map[string]string{"syswarden-base": "installed"})
			u.preflightNativeIdentity = func(ctx context.Context) (nativeUpdateIdentity, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > u.metadataTimeout {
					t.Fatal("identity preflight lacks bounded deadline")
				}
				return preflightStandardNativeUpdateWith(ctx, executor, func(string) (bool, error) { return false, nil })
			}
		}
		if err := u.run(t.Context()); err == nil || network.Load() != 0 || mutation.Load() != 0 {
			t.Fatalf("early identity refusal failed: %v network=%d mutation=%d", err, network.Load(), mutation.Load())
		}
		assertEmptyDirectory(t, u.tempBase)
	}
}

func TestNativePackageIdentityPreflightRequiresBoundedContext(t *testing.T) {
	called := false
	u := &updater{preflightNativeIdentity: func(context.Context) (nativeUpdateIdentity, error) {
		called = true
		return testCompatibilityUpdateIdentity("dpkg-query"), nil
	}}
	for _, test := range []struct {
		ctx     context.Context
		timeout time.Duration
	}{
		{nil, time.Second}, {t.Context(), 0}, {t.Context(), -time.Second},
	} {
		if _, err := u.preflightStandardNativeIdentity(test.ctx, test.timeout); err == nil || called {
			t.Fatalf("invalid bounded context reached query callback: %v", err)
		}
	}
}

func TestNativePackageIdentityUpdaterRechecksBeforeInstallation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated compatibility package")
	manifest := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, payload))
	var mutation atomic.Int32
	u := testUpdater(newUpdaterTestClient(manifest, testSignManifest(privateKey, manifest), payload), t.TempDir(), "amd64",
		map[string]ed25519.PublicKey{testReleaseKeyID: publicKey}, func(context.Context, string, ...string) error {
			mutation.Add(1)
			return nil
		})
	calls := 0
	sentinel := errors.New("package identity changed")
	u.preflightNativeIdentity = func(context.Context) (nativeUpdateIdentity, error) {
		calls++
		if calls == 2 {
			return nativeUpdateIdentity{}, sentinel
		}
		return testCompatibilityUpdateIdentity("dpkg-query"), nil
	}
	if err := u.run(t.Context()); !errors.Is(err, sentinel) || calls != 2 || mutation.Load() != 0 {
		t.Fatalf("late identity refusal failed: %v calls=%d mutation=%d", err, calls, mutation.Load())
	}
	assertEmptyDirectory(t, u.tempBase)
}

func TestNativePackageIdentityQualificationRefusesBeforeBundleAndInstallation(t *testing.T) {
	for _, late := range []bool{false, true} {
		fixture := newQualificationFixture(t)
		var network, installs atomic.Int32
		u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.09.9", &network, &installs)
		sentinel := errors.New("native package identity refused")
		calls := 0
		u.preflightNativeIdentity = func(ctx context.Context) (nativeUpdateIdentity, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("unbounded identity query")
			}
			calls++
			if !late || calls == 2 {
				return nativeUpdateIdentity{}, sentinel
			}
			return testCompatibilityUpdateIdentity("dpkg-query"), nil
		}
		bundle := fixture.bundle
		if !late {
			bundle = filepath.Join(t.TempDir(), "absent-bundle")
		}
		if err := u.runQualificationBundle(t.Context(), bundle, testQualificationCandidate); !errors.Is(err, sentinel) || network.Load() != 0 || installs.Load() != 0 {
			t.Fatalf("qualification identity refusal failed: %v network=%d installs=%d", err, network.Load(), installs.Load())
		}
		if late && calls != 2 {
			t.Fatal("qualification did not recheck identity")
		}
		assertEmptyDirectory(t, tempBase)
	}
}

func assertNativeIdentityFilePreserved(t *testing.T, path string, before os.FileInfo, content []byte) {
	t.Helper()
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	actual := mustReadTestFile(t, path)
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || string(content) != string(actual) {
		t.Fatal("package identity check changed the preserved payload")
	}
}

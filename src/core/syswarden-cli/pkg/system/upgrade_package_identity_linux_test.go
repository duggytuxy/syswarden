package system

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type nativeUpdateTestDeadlineContext struct {
	context.Context
	expired chan struct{}
}

func (ctx nativeUpdateTestDeadlineContext) Done() <-chan struct{} { return ctx.expired }

func (ctx nativeUpdateTestDeadlineContext) Err() error {
	select {
	case <-ctx.expired:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestNativeUpdateIdentityPreflightRejectsCanceledSuccess(t *testing.T) {
	for _, phase := range []string{"before-callback", "during-callback", "deadline-before-callback", "deadline-during-callback"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wantError := context.Canceled
			timeout := time.Second
			var expire func()
			switch phase {
			case "before-callback":
				cancel()
			case "deadline-before-callback":
				var cancelDeadline context.CancelFunc
				ctx, cancelDeadline = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancelDeadline()
				wantError = context.DeadlineExceeded
			case "deadline-during-callback":
				controlled := nativeUpdateTestDeadlineContext{Context: context.Background(), expired: make(chan struct{})}
				ctx = controlled
				expire = func() { close(controlled.expired) }
				timeout = time.Hour
				wantError = context.DeadlineExceeded
			}
			called := false
			u := &updater{preflightNativeIdentity: func(bounded context.Context) (nativeUpdateIdentity, error) {
				called = true
				if phase == "deadline-during-callback" {
					expire()
					<-bounded.Done()
				} else {
					cancel()
				}
				return testCompatibilityUpdateIdentity("dpkg-query"), nil
			}}
			identity, err := u.preflightStandardNativeIdentity(ctx, timeout)
			wantCalled := phase == "during-callback" || phase == "deadline-during-callback"
			if !errors.Is(err, wantError) || identity != (nativeUpdateIdentity{}) || called != wantCalled {
				t.Fatalf("identity=%#v error=%v called=%v", identity, err, called)
			}
		})
	}
}

func TestNativeUpdateMalformedCallbackIdentityRefusesBeforeMetadata(t *testing.T) {
	for _, identity := range []nativeUpdateIdentity{
		{}, {name: "syswarden-base", manager: "apk", state: "installed"},
		{name: "syswarden", manager: "unknown", state: "installed"},
		{name: "syswarden", manager: "dpkg-query", state: "unpacked"},
	} {
		for _, channel := range []string{"online", "offline"} {
			t.Run(identity.name+"/"+identity.manager+"/"+identity.state+"/"+channel, func(t *testing.T) {
				u := testUpdater(staticHTTPClient(func(*http.Request) (*http.Response, error) {
					t.Fatal("malformed identity reached metadata download")
					return nil, errors.New("unexpected network")
				}), t.TempDir(), "amd64", nil, func(context.Context, string, ...string) error {
					t.Fatal("malformed identity reached native mutation")
					return nil
				})
				var network, installs atomic.Int32
				if channel == "offline" {
					u, _, _ = qualificationTestUpdater(t, newQualificationFixture(t), "v4.09.9", &network, &installs)
				}
				u.preflightNativeIdentity = func(context.Context) (nativeUpdateIdentity, error) { return identity, nil }
				var err error
				if channel == "offline" {
					err = u.runQualificationBundle(t.Context(), filepath.Join(t.TempDir(), "absent-bundle"), testUpdateVersion)
				} else {
					err = u.run(t.Context())
				}
				if err == nil || err.Error() != identity.validate().Error() {
					t.Fatalf("malformed identity was not refused at preflight: %v", err)
				}
				if network.Load() != 0 || installs.Load() != 0 {
					t.Fatalf("malformed identity reached qualification actions: network=%d installs=%d", network.Load(), installs.Load())
				}
				assertEmptyDirectory(t, u.tempBase)
			})
		}
	}
}

func testAllPackageFrontends(name string) (string, error) {
	switch name {
	case "apt-get", "dnf", "yum":
		return "/usr/bin/" + name, nil
	case "apk":
		return "/sbin/apk", nil
	default:
		return "", os.ErrNotExist
	}
}

func TestNativeUpdateIdentityRetainsTheOnlyRegisteredAuthority(t *testing.T) {
	for _, authority := range []string{"dpkg-query", "rpm", "apk", "coexisting-authorities"} {
		t.Run(authority, func(t *testing.T) {
			executor := testFirewallRemovalPackageExecutor(t, []string{"dpkg-query", "rpm", "apk"}, func(path string, args ...string) ([]byte, error) {
				manager := filepath.Base(path)
				name, ok := nativeRegistrationTestQuery(manager, args)
				if !ok {
					t.Fatalf("unexpected query: %s %q", path, args)
				}
				state := ""
				if name == "syswarden" && (manager == authority || authority == "coexisting-authorities") {
					state = "installed"
				}
				return nativeRegistrationTestOutput(manager, name, state)
			})
			identity, err := preflightStandardNativeUpdateWith(t.Context(), executor, func(string) (bool, error) { return false, nil })
			if authority == "coexisting-authorities" {
				if err == nil {
					t.Fatal("multiple native authorities accepted")
				}
				return
			}
			if err != nil || identity != testCompatibilityUpdateIdentity(authority) {
				t.Fatalf("identity=%#v error=%v", identity, err)
			}
		})
	}
}

func TestDetectPackageTargetCannotFallBackToUnrelatedAuthority(t *testing.T) {
	for _, authority := range []string{"dpkg-query", "rpm", "apk"} {
		for _, missing := range []bool{false, true} {
			t.Run(authority+"/missing="+map[bool]string{false: "false", true: "true"}[missing], func(t *testing.T) {
				wantFormat, wantInstaller := packageFormatDEB, "/usr/bin/apt-get"
				switch authority {
				case "rpm":
					wantFormat, wantInstaller = packageFormatRPM, "/usr/bin/yum"
				case "apk":
					wantFormat, wantInstaller = packageFormatAPK, "/sbin/apk"
				}
				target, err := detectPackageTarget("linux", "amd64", testUpdateVersion, testCompatibilityUpdateIdentity(authority), func(name string) (string, error) {
					matches := (authority == "dpkg-query" && name == "apt-get") ||
						(authority == "rpm" && (name == "dnf" || name == "yum")) ||
						(authority == "apk" && name == "apk")
					if !matches {
						t.Fatalf("looked up unrelated frontend %q for %q", name, authority)
					}
					if missing || name == "dnf" {
						return "", os.ErrNotExist
					}
					return testAllPackageFrontends(name)
				})
				if missing {
					if err == nil {
						t.Fatal("missing registered authority selected another frontend")
					}
					return
				}
				if err != nil || target.format != wantFormat || target.installer != wantInstaller {
					t.Fatalf("target=%#v error=%v", target, err)
				}
			})
		}
	}
	for _, identity := range []nativeUpdateIdentity{
		{}, {name: "other", manager: "rpm", state: "installed"},
		{name: "syswarden-base", manager: "apk", state: "installed"},
		{name: "syswarden", manager: "unknown", state: "installed"},
		{name: "syswarden", manager: "dpkg-query", state: "unpacked"},
	} {
		_, err := detectPackageTarget("linux", "amd64", testUpdateVersion, identity, func(string) (string, error) {
			t.Fatal("invalid identity reached frontend lookup")
			return "", nil
		})
		if err == nil {
			t.Fatalf("invalid identity accepted: %#v", identity)
		}
	}
}

func TestNativeUpdateAuthoritySelectsOnlineAndOfflineArtifacts(t *testing.T) {
	for _, tc := range []struct{ authority, format, installer string }{
		{"dpkg-query", packageFormatDEB, "/usr/bin/apt-get"},
		{"rpm", packageFormatRPM, "/usr/bin/dnf"},
		{"apk", packageFormatAPK, "/sbin/apk"},
	} {
		for _, offline := range []bool{false, true} {
			channel := "online"
			if offline {
				channel = "offline"
			}
			t.Run(tc.authority+"/"+channel, func(t *testing.T) {
				fixture := newQualificationFixture(t)
				filename, err := packageFilename(testQualificationCandidate, tc.format, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				var network, installs atomic.Int32
				var u *updater
				if offline {
					debName, _ := packageFilename(testQualificationCandidate, packageFormatDEB, "amd64")
					if filename != debName {
						if err := os.Rename(filepath.Join(fixture.bundle, debName), filepath.Join(fixture.bundle, filename)); err != nil {
							t.Fatal(err)
						}
					}
					u, _, _ = qualificationTestUpdater(t, fixture, "v4.09.9", &network, &installs)
				} else {
					manifest := testMarshalManifest(t, fixture.manifest)
					client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
						switch request.URL.Path {
						case "/latest":
							return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testQualificationCandidate+`"}`)), nil
						case "/download/" + testQualificationCandidate + "/" + updateManifestAssetName:
							return testHTTPResponse(http.StatusOK, manifest), nil
						case "/download/" + testQualificationCandidate + "/" + updateManifestSignatureAssetName:
							return testHTTPResponse(http.StatusOK, testSignManifest(fixture.privateKey, manifest)), nil
						case "/download/" + testQualificationCandidate + "/" + filename:
							return testHTTPResponse(http.StatusOK, fixture.payload), nil
						default:
							t.Fatalf("selected wrong artifact: %s", request.URL.Path)
							return nil, errors.New("wrong artifact")
						}
					})
					u = testUpdater(client, t.TempDir(), "amd64", map[string]ed25519.PublicKey{testReleaseKeyID: fixture.publicKey}, nil)
				}
				u.preflightNativeIdentity = func(context.Context) (nativeUpdateIdentity, error) {
					return testCompatibilityUpdateIdentity(tc.authority), nil
				}
				u.lookPath = testAllPackageFrontends
				u.attestRPM = func(context.Context, string) error { return nil }
				u.installPackage = guardedTestNativeInstaller(offline, func(_ context.Context, name string, args ...string) error {
					wantInstaller := tc.installer
					if offline && tc.format == packageFormatDEB {
						wantInstaller = "/usr/bin/dpkg"
					}
					if name != wantInstaller || len(args) == 0 || filepath.Base(args[len(args)-1]) != filename {
						t.Fatalf("wrong native transaction: %s %q", name, args)
					}
					installs.Add(1)
					return nil
				})
				if offline {
					err = u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
				} else {
					err = u.run(t.Context())
				}
				if err != nil || installs.Load() != 1 || network.Load() != 0 {
					t.Fatalf("error=%v installs=%d unexpected network=%d", err, installs.Load(), network.Load())
				}
				assertEmptyDirectory(t, u.tempBase)
			})
		}
	}
}

func TestNativeUpdateIdentityDriftRefusesOnlineAndOfflineInstallation(t *testing.T) {
	for _, changed := range []nativeUpdateIdentity{
		testCompatibilityUpdateIdentity("rpm"),
		{name: "syswarden-base", manager: "dpkg-query", state: "installed"},
		{name: "syswarden", manager: "dpkg-query", state: "unpacked"},
	} {
		for _, offline := range []bool{false, true} {
			channel := "online"
			if offline {
				channel = "offline"
			}
			t.Run(changed.name+"/"+changed.manager+"/"+changed.state+"/"+channel, func(t *testing.T) {
				fixture := newVersionedQualificationFixture(t, testUpdateVersion)
				var network, installs atomic.Int32
				u, _, _ := qualificationTestUpdater(t, fixture, "v4.02.8", &network, &installs)
				if !offline {
					manifest := testMarshalManifest(t, fixture.manifest)
					u = testUpdater(newUpdaterTestClient(manifest, testSignManifest(fixture.privateKey, manifest), fixture.payload), t.TempDir(), "amd64",
						map[string]ed25519.PublicKey{testReleaseKeyID: fixture.publicKey}, func(context.Context, string, ...string) error {
							installs.Add(1)
							return nil
						})
				}
				observations := 0
				u.preflightNativeIdentity = func(context.Context) (nativeUpdateIdentity, error) {
					observations++
					if observations == 1 {
						return testCompatibilityUpdateIdentity("dpkg-query"), nil
					}
					return changed, nil
				}
				var err error
				if offline {
					err = u.runQualificationBundle(t.Context(), fixture.bundle, testUpdateVersion)
				} else {
					err = u.run(t.Context())
				}
				if err == nil || !strings.Contains(err.Error(), "native package identity changed before") || observations != 2 || installs.Load() != 0 {
					t.Fatalf("error=%v observations=%d installs=%d", err, observations, installs.Load())
				}
				assertEmptyDirectory(t, u.tempBase)
			})
		}
	}
}

func TestNativeUpdateCurrentVersionAttestationUsesRegisteredAuthority(t *testing.T) {
	for _, tc := range []struct{ authority, format string }{
		{"dpkg-query", packageFormatDEB}, {"rpm", packageFormatRPM}, {"apk", packageFormatAPK},
	} {
		t.Run(tc.authority, func(t *testing.T) {
			u := testUpdater(staticHTTPClient(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/latest" {
					t.Fatalf("unexpected download: %s", request.URL.Path)
				}
				return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
			}), t.TempDir(), "amd64", nil, func(context.Context, string, ...string) error {
				t.Fatal("current release invoked native mutation")
				return nil
			})
			u.currentVersion = testUpdateVersion
			u.lookPath = testAllPackageFrontends
			u.preflightNativeIdentity = func(context.Context) (nativeUpdateIdentity, error) {
				return testCompatibilityUpdateIdentity(tc.authority), nil
			}
			attestations := 0
			u.attestInstalled = func(_ context.Context, target packageTarget, _ int) (installedQualificationEvidence, error) {
				attestations++
				if target.format != tc.format {
					t.Fatalf("attested wrong authority: %#v", target)
				}
				return installedQualificationEvidence{version: testUpdateVersion}, nil
			}
			if err := u.run(t.Context()); err != nil || attestations != 1 {
				t.Fatalf("error=%v attestations=%d", err, attestations)
			}
		})
	}
}

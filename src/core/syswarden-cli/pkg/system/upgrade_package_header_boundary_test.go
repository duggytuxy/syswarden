package system

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func packageHeaderBoundaryTarget(t *testing.T, name, format, version string) packageTarget {
	t.Helper()
	filename, err := packageFilenameForName(version, format, "amd64", name)
	if err != nil {
		t.Fatal(err)
	}
	return packageTarget{packageName: name, os: "linux", architecture: "amd64", format: format, filename: filename}
}

func packageHeaderBoundaryFile(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "header-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write([]byte("inert authenticated package fixture")); err != nil {
		t.Fatal(err)
	}
	return file
}

func mutatePackageHeaderBoundaryFile(t *testing.T, file *os.File, size int) {
	t.Helper()
	if file == nil {
		t.Fatal("mutation boundary was reached before authenticated header inspection")
	}
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(bytes.Repeat([]byte{'X'}, size), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		t.Fatal("mutation did not retain the same inode and size", err)
	}
}

func packageHeaderBoundaryIdentity(name, format string) nativePackageHeaderIdentity {
	identity := nativePackageHeaderIdentity{name: name, version: "5.00.0", architecture: "x86_64"}
	if format == packageFormatDEB {
		identity.architecture = "amd64"
	}
	if format == packageFormatAPK {
		identity.version += "-r0"
	}
	return identity
}

func TestNativePackageHeaderBoundaryBindsExactSelectedIdentity(t *testing.T) {
	for _, name := range []string{"syswarden", "syswarden-base"} {
		for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
			for _, change := range []string{"valid", "other-variant", "empty-name", "foreign-name", "wrong-version", "release-prefix", "noncanonical-version", "revision", "empty-architecture", "architecture-alias", "foreign-architecture"} {
				t.Run(name+"/"+format+"/"+change, func(t *testing.T) {
					target := packageHeaderBoundaryTarget(t, name, format, "v5.00.0")
					identity := packageHeaderBoundaryIdentity(name, format)
					switch change {
					case "other-variant":
						identity.name = "syswarden-base"
						if name == identity.name {
							identity.name = "syswarden"
						}
					case "empty-name":
						identity.name = ""
					case "foreign-name":
						identity.name = "unrelated-package"
					case "wrong-version":
						identity.version = strings.Replace(identity.version, "5.00.0", "5.00.1", 1)
					case "release-prefix":
						identity.version = "v" + identity.version
					case "noncanonical-version":
						identity.version = strings.Replace(identity.version, "5.00.0", "5.0.0", 1)
					case "revision":
						identity.version = "5.00.0-1"
						if format == packageFormatAPK {
							identity.version = "5.00.0-r1"
						}
					case "empty-architecture":
						identity.architecture = ""
					case "architecture-alias":
						identity.architecture = "amd64"
						if format == packageFormatDEB {
							identity.architecture = "x86_64"
						}
					case "foreign-architecture":
						identity.architecture = "i386"
					}
					file := packageHeaderBoundaryFile(t)
					calls := 0
					err := attestNativePackageHeaderWith(t.Context(), target, "v5.00.0", file,
						func(ctx context.Context, got *os.File) (nativePackageHeaderIdentity, error) {
							calls++
							if got != file || ctx.Err() != nil {
								t.Fatal("reader did not receive the selected live descriptor and context")
							}
							return identity, nil
						})
					if calls != 1 || (err == nil) != (change == "valid") {
						t.Fatalf("header binding calls=%d error=%v", calls, err)
					}
				})
			}
		}
	}
}

func TestNativePackageHeaderBoundaryRejectsSelectionBeforeReader(t *testing.T) {
	for _, name := range []string{"syswarden", "syswarden-base"} {
		for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
			for _, change := range []string{"empty-name", "foreign-name", "platform", "architecture", "format", "filename", "other-variant-filename", "other-version-filename", "version", "legacy-base"} {
				if change == "legacy-base" && name != "syswarden-base" {
					continue
				}
				t.Run(name+"/"+format+"/"+change, func(t *testing.T) {
					target := packageHeaderBoundaryTarget(t, name, format, "v5.00.0")
					version := "v5.00.0"
					switch change {
					case "empty-name":
						target.packageName = ""
					case "foreign-name":
						target.packageName = "unrelated-package"
					case "platform":
						target.os = "unsupported"
					case "architecture":
						target.architecture = "386"
					case "format":
						target.format = "tar"
					case "filename":
						target.filename = "../" + target.filename
					case "other-variant-filename":
						other := "syswarden-base"
						if name == other {
							other = "syswarden"
						}
						target.filename = packageHeaderBoundaryTarget(t, other, format, version).filename
					case "other-version-filename":
						target.filename = packageHeaderBoundaryTarget(t, name, format, "v5.00.1").filename
					case "version":
						version = "5.00.0"
					case "legacy-base":
						version = "v4.10.0"
					}
					calls := 0
					err := attestNativePackageHeaderWith(t.Context(), target, version, packageHeaderBoundaryFile(t),
						func(context.Context, *os.File) (nativePackageHeaderIdentity, error) {
							calls++
							return packageHeaderBoundaryIdentity(name, format), nil
						})
					if err == nil || calls != 0 {
						t.Fatalf("invalid selection reached reader: calls=%d error=%v", calls, err)
					}
				})
			}
		}
	}
}

// Closing expired inside a callback exercises a deadline after entry without
// relying on a short timer or scheduler timing.
type packageHeaderBoundaryDeadlineContext struct {
	context.Context
	expired chan struct{}
}

func (ctx packageHeaderBoundaryDeadlineContext) Done() <-chan struct{} { return ctx.expired }

func (ctx packageHeaderBoundaryDeadlineContext) Err() error {
	select {
	case <-ctx.expired:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestNativePackageHeaderBoundaryCancellationCannotBecomeEvidence(t *testing.T) {
	for _, layer := range []string{"reader", "wrapper"} {
		for _, phase := range []string{"before", "during", "deadline-during", "reader-error", "success"} {
			t.Run(layer+"/"+phase, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var expire func()
				wantErr := context.Canceled
				if phase == "before" {
					cancel()
				}
				if phase == "deadline-during" {
					controlled := packageHeaderBoundaryDeadlineContext{Context: context.Background(), expired: make(chan struct{})}
					ctx = controlled
					expire = func() { close(controlled.expired) }
					wantErr = context.DeadlineExceeded
				}
				sentinel := errors.New("header inspection refused")
				if phase == "reader-error" {
					wantErr = sentinel
				}
				target := packageHeaderBoundaryTarget(t, "syswarden", packageFormatDEB, "v5.00.0")
				file := packageHeaderBoundaryFile(t)
				calls := 0
				callback := func(bounded context.Context) error {
					calls++
					if layer == "wrapper" {
						if _, ok := bounded.Deadline(); !ok {
							t.Fatal("header callback lacks its independent deadline")
						}
					}
					switch phase {
					case "during":
						cancel()
						<-bounded.Done()
					case "deadline-during":
						expire()
						<-bounded.Done()
					case "reader-error":
						return sentinel
					}
					return nil // Success after cancellation is deliberately untrustworthy.
				}
				var err error
				if layer == "reader" {
					err = attestNativePackageHeaderWith(ctx, target, "v5.00.0", file,
						func(bounded context.Context, got *os.File) (nativePackageHeaderIdentity, error) {
							if got != file {
								t.Fatal("reader descriptor changed")
							}
							return packageHeaderBoundaryIdentity("syswarden", packageFormatDEB), callback(bounded)
						})
				} else {
					u := updater{attestPackageIdentity: func(bounded context.Context, got packageTarget, version string, descriptor *os.File) error {
						if got != target || version != "v5.00.0" || descriptor != file {
							t.Fatal("wrapper changed the selected target, version or descriptor")
						}
						return callback(bounded)
					}}
					err = u.attestAuthenticatedPackageIdentity(ctx, target, "v5.00.0", file, time.Hour)
				}
				wantCalls := 1
				if phase == "before" {
					wantCalls = 0
				}
				if calls != wantCalls || (phase == "success" && err != nil) || (phase != "success" && !errors.Is(err, wantErr)) {
					t.Fatalf("calls=%d want=%d error=%v", calls, wantCalls, err)
				}
			})
		}
	}
}

func TestNativePackageHeaderBoundaryRejectsMissingInputsAndInvalidDescriptors(t *testing.T) {
	for _, invalid := range []string{"nil-context", "nil-reader", "nil-file", "closed-file", "empty-file", "directory", "oversize"} {
		t.Run(invalid, func(t *testing.T) {
			target := packageHeaderBoundaryTarget(t, "syswarden", packageFormatDEB, "v5.00.0")
			ctx := t.Context()
			file := packageHeaderBoundaryFile(t)
			calls := 0
			var reader nativePackageHeaderReader = func(context.Context, *os.File) (nativePackageHeaderIdentity, error) {
				calls++
				return packageHeaderBoundaryIdentity("syswarden", packageFormatDEB), nil
			}
			switch invalid {
			case "nil-context":
				ctx = nil
			case "nil-reader":
				reader = nil
			case "nil-file":
				file = nil
			case "closed-file":
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "empty-file":
				if err := file.Truncate(0); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := file.Truncate(maxPackageBytes + 1); err != nil {
					t.Fatal(err)
				}
			case "directory":
				var err error
				file, err = os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = file.Close() })
			}
			if err := attestNativePackageHeaderWith(ctx, target, "v5.00.0", file, reader); err == nil || calls != 0 {
				t.Fatalf("invalid input reached reader: calls=%d error=%v", calls, err)
			}
		})
	}
	for _, invalid := range []string{"nil-context", "nil-callback", "zero-timeout", "negative-timeout"} {
		t.Run("wrapper/"+invalid, func(t *testing.T) {
			ctx, timeout, calls := t.Context(), time.Second, 0
			u := updater{attestPackageIdentity: func(context.Context, packageTarget, string, *os.File) error { calls++; return nil }}
			switch invalid {
			case "nil-context":
				ctx = nil
			case "nil-callback":
				u.attestPackageIdentity = nil
			case "zero-timeout":
				timeout = 0
			case "negative-timeout":
				timeout = -time.Second
			}
			err := u.attestAuthenticatedPackageIdentity(ctx, packageHeaderBoundaryTarget(t, "syswarden", packageFormatDEB, "v5.00.0"), "v5.00.0", packageHeaderBoundaryFile(t), timeout)
			if err == nil || calls != 0 {
				t.Fatalf("invalid wrapper configuration reached callback: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestNativePackageHeaderBoundaryProductionConstructorsRequireGate(t *testing.T) {
	for _, channel := range []string{"online", "offline"} {
		t.Run(channel, func(t *testing.T) {
			constructor := newProductionUpdater
			if channel == "offline" {
				constructor = newQualificationUpdater
			}
			u, err := constructor()
			if err != nil {
				t.Fatal(err)
			}
			if u.attestPackageIdentity == nil || reflect.ValueOf(u.attestPackageIdentity).Pointer() != reflect.ValueOf(attestNativePackageHeader).Pointer() {
				t.Fatal("production constructor does not use the native package header verifier")
			}
			installer := runAuthenticatedNativeInstall
			if channel == "offline" {
				installer = runAuthenticatedQualificationInstall
			}
			if u.installPackage == nil || reflect.ValueOf(u.installPackage).Pointer() != reflect.ValueOf(installer).Pointer() {
				t.Fatal("production constructor does not use the authenticated native execution boundary")
			}
			u.requireRoot = false // Configuration validation itself is read-only.
			validate := u.validateConfiguration
			if channel == "offline" {
				validate = u.validateQualificationConfiguration
			}
			if err := validate(); err != nil {
				t.Fatal("complete production configuration was refused", err)
			}
			u.attestPackageIdentity = nil
			if err := validate(); err == nil {
				t.Fatal("updater accepted an absent native package header gate")
			}
			u.attestPackageIdentity = attestNativePackageHeader
			u.installPackage = nil
			if err := validate(); err == nil {
				t.Fatal("updater accepted an absent authenticated native installer")
			}
		})
	}
}

func TestNativePackageHeaderBoundaryUpdaterRefusesBeforeInstallation(t *testing.T) {
	for _, channel := range []string{"online", "offline"} {
		for _, outcome := range []string{"success", "error", "invalid-native-header", "cancel", "mutation", "late-mutation", "late-cancel", "nil-gate"} {
			t.Run(channel+"/"+outcome, func(t *testing.T) {
				var network, installs, activations, candidateCalls, retirements atomic.Int32
				var u *updater
				var run func(context.Context) error
				var payload []byte
				var version, base string
				if channel == "offline" {
					fixture := newQualificationFixture(t)
					payload, version = fixture.payload, testQualificationCandidate
					u, _, base = qualificationTestUpdater(t, fixture, "v4.09.9", &network, &installs)
					run = func(ctx context.Context) error { return u.runQualificationBundle(ctx, fixture.bundle, version) }
					originalCandidate := u.attestCandidateCLI
					u.attestCandidateCLI = func(ctx context.Context, target packageTarget, file *os.File) (string, error) {
						candidateCalls.Add(1)
						return originalCandidate(ctx, target, file)
					}
				} else {
					publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					payload, version, base = []byte("authenticated header boundary package"), testUpdateVersion, t.TempDir()
					manifest := testMarshalManifest(t, testUpdateManifest(t, version, payload))
					u = testUpdater(newUpdaterTestClient(manifest, testSignManifest(privateKey, manifest), payload), base, "amd64",
						map[string]ed25519.PublicKey{testReleaseKeyID: publicKey}, func(context.Context, string, ...string) error { installs.Add(1); return nil })
					run = u.run
				}
				u.activateCandidate = func(context.Context, installedQualificationEvidence) error { activations.Add(1); return nil }
				u.retireWebTUI = func() error { retirements.Add(1); return nil }
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				sentinel := errors.New("native header selection refused")
				headerCalls, identityCalls := 0, 0
				var authenticatedFile *os.File
				u.preflightNativeIdentity = func(context.Context) (nativeUpdateIdentity, error) {
					identityCalls++
					if identityCalls == 2 {
						switch outcome {
						case "late-mutation":
							mutatePackageHeaderBoundaryFile(t, authenticatedFile, len(payload))
						case "late-cancel":
							if authenticatedFile == nil {
								t.Fatal("late cancellation preceded authenticated header inspection")
							}
							cancel()
						}
					}
					return testCompatibilityUpdateIdentity("dpkg-query"), nil
				}
				u.attestPackageIdentity = func(bounded context.Context, target packageTarget, gotVersion string, file *os.File) error {
					headerCalls++
					want := packageHeaderBoundaryTarget(t, "syswarden", packageFormatDEB, version)
					if target.packageName != want.packageName || target.os != want.os || target.architecture != want.architecture ||
						target.format != want.format || target.filename != want.filename || gotVersion != version || identityCalls != 1 {
						t.Fatal("header gate did not receive the selected identity before its installation recheck")
					}
					if _, ok := bounded.Deadline(); !ok {
						t.Fatal("header gate has no bounded context")
					}
					actual, err := io.ReadAll(io.NewSectionReader(file, 0, int64(len(payload)+1)))
					if err != nil || !bytes.Equal(actual, payload) {
						t.Fatal("header gate did not receive the authenticated bytes", err)
					}
					authenticatedFile = file
					switch outcome {
					case "error":
						return sentinel
					case "invalid-native-header":
						// The signature and digest authenticate these deliberately
						// opaque bytes, but the actual native parser must refuse them.
						return attestNativePackageHeader(bounded, target, gotVersion, file)
					case "cancel":
						cancel()
						<-bounded.Done()
					case "mutation":
						mutatePackageHeaderBoundaryFile(t, file, len(payload))
					}
					return nil
				}
				if outcome == "nil-gate" {
					u.attestPackageIdentity = nil
				}
				err := run(ctx)
				wantHeaders, wantIdentities := 1, 1
				if outcome == "nil-gate" {
					wantHeaders, wantIdentities = 0, 0
				}
				if outcome == "late-mutation" || outcome == "late-cancel" {
					wantIdentities = 2
				}
				if outcome == "success" {
					wantIdentities = 2
					if err != nil || installs.Load() != 1 {
						t.Fatalf("valid gate did not permit one installation: installs=%d error=%v", installs.Load(), err)
					}
					if channel == "offline" && (activations.Load() != 1 || candidateCalls.Load() != 1) {
						t.Fatal("valid offline gate did not reach candidate proof and activation")
					}
					if channel == "online" && retirements.Load() != 1 {
						t.Fatal("valid online gate did not reach post-install finalization")
					}
				} else {
					if err == nil || installs.Load()+activations.Load()+retirements.Load() != 0 {
						t.Fatalf("refused header reached mutation: installs=%d activations=%d finalizations=%d error=%v", installs.Load(), activations.Load(), retirements.Load(), err)
					}
					if outcome != "mutation" && outcome != "late-mutation" && outcome != "late-cancel" && candidateCalls.Load() != 0 {
						t.Fatal("refused header reached candidate CLI extraction")
					}
					if outcome == "error" && !errors.Is(err, sentinel) {
						t.Fatalf("header error was lost: %v", err)
					}
					if (outcome == "cancel" || outcome == "late-cancel") && !errors.Is(err, context.Canceled) {
						t.Fatalf("successful canceled callback was not refused: %v", err)
					}
				}
				if headerCalls != wantHeaders || identityCalls != wantIdentities || network.Load() != 0 {
					t.Fatalf("header=%d identity=%d offline-network=%d", headerCalls, identityCalls, network.Load())
				}
				assertEmptyDirectory(t, base)
			})
		}
	}
}

func TestNativePackageHeaderBoundaryNeverReceivesUnauthenticatedBytes(t *testing.T) {
	for _, channel := range []string{"online", "offline"} {
		for _, altered := range []string{"signature", "package"} {
			t.Run(channel+"/"+altered, func(t *testing.T) {
				fixture := newQualificationFixture(t)
				var network, installs atomic.Int32
				u, _, base := qualificationTestUpdater(t, fixture, "v4.09.9", &network, &installs)
				var run func() error
				if channel == "offline" {
					name := updateManifestSignatureAssetName
					payload := []byte("invalid signature")
					if altered == "package" {
						name = fixture.manifest.Artifacts[0].Filename
						payload = bytes.Repeat([]byte{'X'}, len(fixture.payload))
					}
					root, err := os.OpenRoot(fixture.bundle)
					if err != nil {
						t.Fatal(err)
					}
					if err := root.WriteFile(name, payload, 0600); err != nil {
						_ = root.Close()
						t.Fatal(err)
					}
					if err := root.Close(); err != nil {
						t.Fatal(err)
					}
					run = func() error { return u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate) }
				} else {
					manifest := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, fixture.payload))
					signature, payload := testSignManifest(fixture.privateKey, manifest), fixture.payload
					if altered == "signature" {
						signature = []byte("invalid signature")
					} else {
						payload = bytes.Repeat([]byte{'X'}, len(payload))
					}
					u = testUpdater(newUpdaterTestClient(manifest, signature, payload), base, "amd64",
						map[string]ed25519.PublicKey{testReleaseKeyID: fixture.publicKey}, func(context.Context, string, ...string) error { installs.Add(1); return nil })
					run = func() error { return u.run(t.Context()) }
				}
				calls := 0
				u.attestPackageIdentity = func(context.Context, packageTarget, string, *os.File) error { calls++; return nil }
				if err := run(); err == nil || calls != 0 || installs.Load() != 0 || network.Load() != 0 {
					t.Fatalf("unauthenticated input reached header or installer: calls=%d installs=%d network=%d error=%v", calls, installs.Load(), network.Load(), err)
				}
				assertEmptyDirectory(t, base)
			})
		}
	}
}

// Keep the hostile online transport assertion independent of metadata fixtures:
// missing configuration must fail before even the release API is contacted.
func TestNativePackageHeaderBoundaryNilGatePrecedesOnlineDiscovery(t *testing.T) {
	calls := 0
	u := testUpdater(staticHTTPClient(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected discovery")
	}), t.TempDir(), "amd64", nil, func(context.Context, string, ...string) error {
		t.Fatal("missing header gate reached the installer")
		return nil
	})
	u.attestPackageIdentity = nil
	if err := u.run(t.Context()); err == nil || calls != 0 {
		t.Fatalf("missing header gate reached discovery: calls=%d error=%v", calls, err)
	}
	assertEmptyDirectory(t, u.tempBase)
}

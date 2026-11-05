package system

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOnlineUpdateAttestationRequiresExactInstalledCandidate(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	packageBytes := []byte("authenticated online package fixture")
	cliBytes := []byte("authenticated candidate CLI fixture")
	cliDigest := fmt.Sprintf("%x", sha256.Sum256(cliBytes))
	manifest := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, packageBytes))
	signature := testSignManifest(privateKey, manifest)
	sentinel := errors.New("injected attestation refusal")
	for _, platform := range []struct{ manager, format, installer string }{
		{"dpkg-query", packageFormatDEB, "/usr/bin/apt-get"},
		{"rpm", packageFormatRPM, "/usr/bin/dnf"},
		{"apk", packageFormatAPK, "/sbin/apk"},
	} {
		for _, outcome := range []struct {
			name, wantError string
			beforeInstall   bool
			cause           error
		}{
			{name: "valid"},
			{name: "changed-package-name", wantError: "native package identity changed"},
			{name: "changed-native-authority", wantError: "native package identity changed"},
			{name: "incomplete-native-state", wantError: "native package identity changed"},
			{name: "identity-error", wantError: "native package identity changed", cause: sentinel},
			{name: "wrong-installed-version", wantError: "want exact candidate"},
			{name: "wrong-installed-bytes", wantError: "does not match authenticated package payload"},
			{name: "missing-installed-digest", wantError: "lacks a valid SHA-256 digest"},
			{name: "installed-error", wantError: "candidate attestation failed", cause: sentinel},
			{name: "candidate-error", wantError: "attest candidate CLI", beforeInstall: true, cause: sentinel},
			{name: "missing-candidate-digest", wantError: "lacks a valid SHA-256 digest", beforeInstall: true},
			{name: "candidate-package-mutation", wantError: "reverify package after candidate CLI attestation", beforeInstall: true},
			{name: "candidate-cancel", wantError: "attest candidate CLI", beforeInstall: true, cause: context.Canceled},
			{name: "candidate-deadline", wantError: "attest candidate CLI", beforeInstall: true, cause: context.DeadlineExceeded},
			{name: "installer-cancel", wantError: "install " + platform.format + " package", cause: context.Canceled},
			{name: "identity-cancel", wantError: "native package identity changed", cause: context.Canceled},
			{name: "installed-cancel", wantError: "candidate attestation failed", cause: context.Canceled},
			{name: "installed-deadline", wantError: "candidate attestation failed", cause: context.DeadlineExceeded},
			{name: "finalization-cancel", wantError: "post-install finalization failed", cause: context.Canceled},
		} {
			t.Run(platform.format+"/"+outcome.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				filename, err := packageFilename(testUpdateVersion, platform.format, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
					switch request.URL.Path {
					case "/latest":
						return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
					case "/download/" + testUpdateVersion + "/" + updateManifestAssetName:
						return testHTTPResponse(http.StatusOK, manifest), nil
					case "/download/" + testUpdateVersion + "/" + updateManifestSignatureAssetName:
						return testHTTPResponse(http.StatusOK, signature), nil
					case "/download/" + testUpdateVersion + "/" + filename:
						return testHTTPResponse(http.StatusOK, packageBytes), nil
					default:
						t.Fatalf("unexpected asset request: %s", request.URL.Path)
						return nil, errors.New("unexpected asset request")
					}
				})
				installs, finalizations, activations, identities, payloads, installed := 0, 0, 0, 0, 0, 0
				u := testUpdater(client, t.TempDir(), "amd64", map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
					func(_ context.Context, name string, _ ...string) error {
						if name != platform.installer || payloads != 1 || installed != 0 {
							t.Fatalf("unexpected native execution %s: payloads=%d installed=%d", name, payloads, installed)
						}
						installs++
						if outcome.name == "installer-cancel" {
							cancel()
						}
						return nil
					})
				var output bytes.Buffer
				u.stdout = &output
				u.lookPath = testAllPackageFrontends
				u.attestRPM = func(context.Context, string, string) error { return nil }
				if strings.HasSuffix(outcome.name, "-deadline") {
					u.attestTimeout = 20 * time.Millisecond
				}
				u.preflightNativeIdentity = func(bounded context.Context) (nativeUpdateIdentity, error) {
					identities++
					if _, ok := bounded.Deadline(); !ok {
						t.Fatal("native identity attestation is unbounded")
					}
					identity := testCompatibilityUpdateIdentity(platform.manager)
					if installs == 1 {
						switch outcome.name {
						case "changed-package-name":
							identity.name = baseNativePackageName
						case "changed-native-authority":
							identity.manager = "rpm"
							if platform.manager == "rpm" {
								identity.manager = "apk"
							}
						case "incomplete-native-state":
							identity.state = "unpacked"
						case "identity-error":
							return identity, sentinel
						case "identity-cancel":
							cancel()
						}
					}
					return identity, nil
				}
				assertTarget := func(bounded context.Context, target packageTarget) {
					t.Helper()
					if _, ok := bounded.Deadline(); !ok {
						t.Fatal("CLI attestation is unbounded")
					}
					if target.packageName != compatibilityNativePackageName || target.format != platform.format ||
						target.installer != platform.installer || target.filename != filename || target.os != "linux" || target.architecture != "amd64" {
						t.Fatalf("attestation changed selected package: %#v", target)
					}
				}
				u.attestCandidateCLI = func(bounded context.Context, target packageTarget, file *os.File) (string, error) {
					assertTarget(bounded, target)
					payloads++
					if installs != 0 {
						t.Fatal("candidate payload attested after native installation")
					}
					actual, err := io.ReadAll(io.NewSectionReader(file, 0, int64(len(packageBytes)+1)))
					if err != nil || !bytes.Equal(actual, packageBytes) {
						t.Fatal("candidate attestor did not receive the authenticated descriptor", err)
					}
					switch outcome.name {
					case "candidate-error":
						return "", sentinel
					case "missing-candidate-digest":
						return "", nil
					case "candidate-package-mutation":
						mutatePackageHeaderBoundaryFile(t, file, len(packageBytes))
					case "candidate-cancel":
						cancel()
					case "candidate-deadline":
						<-bounded.Done()
					}
					return cliDigest, nil
				}
				u.attestInstalled = func(bounded context.Context, target packageTarget, uid int) (installedQualificationEvidence, error) {
					assertTarget(bounded, target)
					installed++
					if installs != 1 || identities != 3 || uid != u.effectiveUID {
						t.Fatalf("installed attestation preceded the native transaction or identity recheck: installs=%d identities=%d uid=%d", installs, identities, uid)
					}
					evidence := installedQualificationEvidence{version: testUpdateVersion, cliSHA256: cliDigest}
					switch outcome.name {
					case "wrong-installed-version":
						evidence.version = "v4.02.8"
					case "wrong-installed-bytes":
						evidence.cliSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("different installed CLI bytes")))
					case "missing-installed-digest":
						evidence.cliSHA256 = ""
					case "installed-error":
						return evidence, sentinel
					case "installed-cancel":
						cancel()
					case "installed-deadline":
						<-bounded.Done()
					}
					return evidence, nil
				}
				u.retireWebTUI = func() error {
					finalizations++
					if installed != 1 {
						t.Fatal("finalization preceded installed candidate attestation")
					}
					if outcome.name == "finalization-cancel" {
						cancel()
					}
					return nil
				}
				u.activateCandidate = func(context.Context, installedQualificationEvidence) error { activations++; return nil }
				err = u.run(ctx)
				wantInstalls, wantFinalizations := 1, 0
				if outcome.beforeInstall {
					wantInstalls = 0
				}
				if outcome.name == "valid" || outcome.name == "finalization-cancel" {
					wantFinalizations = 1
				}
				if outcome.wantError == "" {
					if err != nil || !strings.Contains(output.String(), "completed successfully") {
						t.Fatalf("valid candidate refused: %v; output=%q", err, output.String())
					}
				} else if err == nil || !strings.Contains(err.Error(), outcome.wantError) || strings.Contains(output.String(), "completed successfully") {
					t.Fatalf("invalid or cancelled candidate reported success: %v; output=%q", err, output.String())
				}
				if outcome.cause != nil && !errors.Is(err, outcome.cause) {
					t.Fatalf("attestation lost failure cause: %v, want %v", err, outcome.cause)
				}
				if installs != wantInstalls || finalizations != wantFinalizations || activations != 0 || payloads != 1 {
					t.Fatalf("installs=%d finalizations=%d activations=%d payloads=%d", installs, finalizations, activations, payloads)
				}
				assertEmptyDirectory(t, u.tempBase)
			})
		}
	}
}

func TestOnlineUpdateAttestationProductionDependencies(t *testing.T) {
	u, err := newProductionUpdater()
	if err != nil {
		t.Fatal(err)
	}
	if u.attestInstalled == nil || reflect.ValueOf(u.attestInstalled).Pointer() != reflect.ValueOf(attestInstalledQualificationVersion).Pointer() ||
		u.attestCandidateCLI == nil || reflect.ValueOf(u.attestCandidateCLI).Pointer() != reflect.ValueOf(attestQualificationPackageCLI).Pointer() || u.attestTimeout <= 0 {
		t.Fatal("production updater does not use the bounded native installed and candidate CLI attestors")
	}
	for _, missing := range []string{"installed-attestor", "candidate-attestor", "attestation-timeout"} {
		t.Run(missing, func(t *testing.T) {
			copy := *u
			copy.requireRoot = false
			switch missing {
			case "installed-attestor":
				copy.attestInstalled = nil
			case "candidate-attestor":
				copy.attestCandidateCLI = nil
			case "attestation-timeout":
				copy.attestTimeout = 0
			}
			if err := copy.validateConfiguration(); err == nil {
				t.Fatal("updater accepted incomplete candidate attestation dependencies")
			}
		})
	}
}

func TestOnlineUpdateAttestationCanceledFinalizationHasNoEffects(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	u := &updater{stdout: &output, retireWebTUI: func() error { t.Fatal("canceled finalization changed configuration"); return nil }}
	if err := u.finishUpgrade(ctx, packageTarget{os: "linux"}); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("canceled finalization result=%v output=%q", err, output.String())
	}
}

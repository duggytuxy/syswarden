package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSignedManifestRequiresVersionedRetentionContract(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version string
		schema  string
		accept  bool
	}{
		{"v4.10.4", "syswarden-update-manifest/v1", true},
		{"v4.10.4", "syswarden-update-manifest/v2", false},
		{"v5.00.0", "syswarden-update-manifest/v2", true},
		{"v5.00.0", "syswarden-update-manifest/v1", false},
		{"v5.00.1", "syswarden-update-manifest/v2", true},
		{"v5.01.0", "syswarden-update-manifest/v1", false},
		{"v6.00.0", "syswarden-update-manifest/v2", true},
		{"v5.00.0", "syswarden-update-manifest/v3", false},
		{"v5.00.0", "", false},
	} {
		t.Run(tc.version+"/"+tc.schema, func(t *testing.T) {
			manifest := testUpdateManifest(t, tc.version, []byte("package"))
			manifest.Schema = tc.schema
			data := testMarshalManifest(t, manifest)
			_, err := verifySignedManifest(data, testSignManifest(privateKey, data), tc.version,
				map[string]ed25519.PublicKey{testReleaseKeyID: publicKey})
			if (err == nil) != tc.accept {
				t.Fatalf("accepted=%v, want %v; error=%v", err == nil, tc.accept, err)
			}
		})
	}
}

func TestSignedManifestRejectsIncompatibleRetentionRequirement(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ version, transition string }{
		{"v4.10.4", "syswarden-native-dependency-retention/v1"},
		{"v4.10.4", "unknown"},
		{"v5.00.0", ""},
		{"v5.00.0", "unknown"},
	} {
		t.Run(tc.version+"/"+tc.transition, func(t *testing.T) {
			manifest := testUpdateManifest(t, tc.version, []byte("package"))
			manifest.NativeTransition = tc.transition
			data := testMarshalManifest(t, manifest)
			_, err := verifySignedManifest(data, testSignManifest(privateKey, data), tc.version,
				map[string]ed25519.PublicKey{testReleaseKeyID: publicKey})
			if err == nil || !strings.Contains(err.Error(), "native transition contract") {
				t.Fatalf("expected signed transition refusal, got %v", err)
			}
		})
	}
}

func TestQualificationRefusesIncompatibleTransitionBeforeHostInspection(t *testing.T) {
	for _, tc := range []struct{ name, schema, transition string }{
		{"legacy schema", "syswarden-update-manifest/v1", ""},
		{"missing retention", "syswarden-update-manifest/v2", ""},
		{"unknown retention", "syswarden-update-manifest/v2", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const version = "v5.00.0"
			fixture := newVersionedQualificationFixture(t, version)
			fixture.manifest.Schema = tc.schema
			fixture.manifest.NativeTransition = tc.transition
			data := testMarshalManifest(t, fixture.manifest)
			for name, contents := range map[string][]byte{
				updateManifestAssetName:          data,
				updateManifestSignatureAssetName: testSignManifest(fixture.privateKey, data),
			} {
				if err := os.WriteFile(filepath.Join(fixture.bundle, name), contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var network, installs, inspected, dependencies atomic.Int32
			u, _, base := qualificationTestUpdater(t, fixture, "v4.10.4", &network, &installs)
			u.currentVersion = version
			u.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
				inspected.Add(1)
				return installedQualificationEvidence{}, errors.New("must not inspect host")
			}
			u.attestDependencies = func(context.Context, packageTarget) error {
				dependencies.Add(1)
				return errors.New("must not inspect dependencies")
			}
			err := u.runQualificationBundle(t.Context(), fixture.bundle, version)
			if err == nil || !strings.Contains(err.Error(), "verify qualification update manifest") {
				t.Fatalf("expected manifest refusal, got %v", err)
			}
			if network.Load()+installs.Load()+inspected.Load()+dependencies.Load() != 0 {
				t.Fatalf("network=%d installs=%d inspected=%d dependencies=%d", network.Load(), installs.Load(), inspected.Load(), dependencies.Load())
			}
			assertEmptyDirectory(t, base)
		})
	}
}

func TestV5SignedUpdateStillRequiresDependencyRetention(t *testing.T) {
	const version = "v5.00.0"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated test package")
	data := testMarshalManifest(t, testUpdateManifest(t, version, payload))
	signature := testSignManifest(privateKey, data)
	for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dnf"} {
		t.Run(manager, func(t *testing.T) {
			var downloads, prepared, executed atomic.Int32
			client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/latest":
					return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+version+`"}`)), nil
				case "/download/" + version + "/" + updateManifestAssetName:
					return testHTTPResponse(http.StatusOK, data), nil
				case "/download/" + version + "/" + updateManifestSignatureAssetName:
					return testHTTPResponse(http.StatusOK, signature), nil
				case "/download/" + version + "/syswarden_5.00.0_amd64.deb", "/download/" + version + "/syswarden-5.00.0-1.x86_64.rpm":
					downloads.Add(1)
					return testHTTPResponse(http.StatusOK, payload), nil
				default:
					return nil, fmt.Errorf("unexpected URL %s", request.URL.Path)
				}
			})
			base := t.TempDir()
			refused := errors.New("dependency retention refused")
			u := testUpdater(client, base, "amd64", map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
				func(ctx context.Context, name string, args ...string) error {
					// Map only the isolated fixture parent to the fixed production
					// temporary parent at this inert runner boundary. The payload
					// has already passed the real download and final hash checks.
					args = append([]string(nil), args...)
					last := len(args) - 1
					args[last] = filepath.Join(productionTempBase, filepath.Base(filepath.Dir(args[last])), filepath.Base(args[last]))
					return runWithNativeDependencyRetention(ctx, name, args, false,
						func(context.Context, string) error { prepared.Add(1); return refused },
						func(context.Context, string, ...string) error { executed.Add(1); return nil })
				})
			u.attestRPM = func(context.Context, string) error { return nil }
			u.lookPath = func(name string) (string, error) {
				if name == filepath.Base(manager) {
					return manager, nil
				}
				return "", os.ErrNotExist
			}
			err := u.run(t.Context())
			if !errors.Is(err, refused) || downloads.Load() != 1 || prepared.Load() != 1 || executed.Load() != 0 {
				t.Fatalf("error=%v downloads=%d prepared=%d executed=%d", err, downloads.Load(), prepared.Load(), executed.Load())
			}
			assertEmptyDirectory(t, base)
		})
	}
}

func TestUpdaterRefusesWrongTransitionSchemaBeforePackageAccess(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ version, schema string }{
		{"v5.00.0", "syswarden-update-manifest/v1"},
		{"v4.10.4", "syswarden-update-manifest/v2"},
		{"v5.00.1", "syswarden-update-manifest/v3"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			manifest := testUpdateManifest(t, tc.version, []byte("package must not be requested"))
			manifest.Schema = tc.schema
			data := testMarshalManifest(t, manifest)
			signature := testSignManifest(privateKey, data)
			var metadata, unexpected, commands atomic.Int32
			client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/latest":
					metadata.Add(1)
					return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+tc.version+`"}`)), nil
				case "/download/" + tc.version + "/" + updateManifestAssetName:
					metadata.Add(1)
					return testHTTPResponse(http.StatusOK, data), nil
				case "/download/" + tc.version + "/" + updateManifestSignatureAssetName:
					metadata.Add(1)
					return testHTTPResponse(http.StatusOK, signature), nil
				default:
					unexpected.Add(1)
					return nil, fmt.Errorf("unexpected package access: %s", request.URL.Path)
				}
			})
			base := t.TempDir()
			u := testUpdater(client, base, "amd64", map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
				func(context.Context, string, ...string) error { commands.Add(1); return nil })
			err := u.run(t.Context())
			if err == nil || !strings.Contains(err.Error(), "manifest schema") {
				t.Fatalf("expected schema refusal, got %v", err)
			}
			if metadata.Load() != 3 || unexpected.Load() != 0 || commands.Load() != 0 {
				t.Fatalf("metadata=%d unexpected=%d commands=%d", metadata.Load(), unexpected.Load(), commands.Load())
			}
			assertEmptyDirectory(t, base)
		})
	}
}

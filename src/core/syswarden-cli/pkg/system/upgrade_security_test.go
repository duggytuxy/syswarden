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
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSecureExclusiveFileRejectsTempCollisionsAndSymlinks(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	workspace, err := createSecureWorkspace(base, os.Geteuid())
	if err != nil {
		t.Fatalf("createSecureWorkspace() error = %v", err)
	}
	defer func() {
		if err := removeSecureWorkspace(workspace); err != nil {
			t.Errorf("removeSecureWorkspace() error = %v", err)
		}
	}()

	packageName := "syswarden_4.02.9_amd64.deb"
	packagePath := filepath.Join(workspace, packageName)
	if err := os.WriteFile(packagePath, []byte("collision"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if file, _, err := createSecureExclusiveFile(workspace, packageName, os.Geteuid()); err == nil {
		_ = file.Close()
		t.Fatal("createSecureExclusiveFile() truncated an existing collision")
	}
	content, err := readUpdaterTestFile(workspace, packageName)
	if err != nil || string(content) != "collision" {
		t.Fatalf("collision content = %q, error = %v", content, err)
	}

	if err := os.Remove(packagePath); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	victim := filepath.Join(base, "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0600); err != nil {
		t.Fatalf("WriteFile(victim) error = %v", err)
	}
	if err := os.Symlink(victim, packagePath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if file, _, err := createSecureExclusiveFile(workspace, packageName, os.Geteuid()); err == nil {
		_ = file.Close()
		t.Fatal("createSecureExclusiveFile() followed a destination symlink")
	}
	victimContent, err := readUpdaterTestFile(base, "victim")
	if err != nil || string(victimContent) != "victim" {
		t.Fatalf("victim content = %q, error = %v", victimContent, err)
	}
}

func TestSecureFileValidationRejectsModeOwnerLinksAndReplacement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(t *testing.T, file *os.File, path, base string) int
	}{
		{
			name: "wrong mode",
			mutate: func(t *testing.T, file *os.File, _, _ string) int {
				t.Helper()
				if err := file.Chmod(0644); err != nil {
					t.Fatalf("Chmod() error = %v", err)
				}
				return os.Geteuid()
			},
		},
		{
			name: "wrong owner expectation",
			mutate: func(_ *testing.T, _ *os.File, _, _ string) int {
				return os.Geteuid() + 1
			},
		},
		{
			name: "hard link",
			mutate: func(t *testing.T, _ *os.File, path, base string) int {
				t.Helper()
				if err := os.Link(path, filepath.Join(base, "second-link")); err != nil {
					t.Fatalf("Link() error = %v", err)
				}
				return os.Geteuid()
			},
		},
		{
			name: "path replaced by symlink",
			mutate: func(t *testing.T, _ *os.File, path, base string) int {
				t.Helper()
				victim := filepath.Join(base, "victim")
				if err := os.WriteFile(victim, []byte("victim"), 0600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatalf("Remove() error = %v", err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
				return os.Geteuid()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			workspace, err := createSecureWorkspace(base, os.Geteuid())
			if err != nil {
				t.Fatalf("createSecureWorkspace() error = %v", err)
			}
			defer func() { _ = removeSecureWorkspace(workspace) }()
			file, path, err := createSecureExclusiveFile(workspace, "package.deb", os.Geteuid())
			if err != nil {
				t.Fatalf("createSecureExclusiveFile() error = %v", err)
			}
			defer func() { _ = file.Close() }()

			expectedUID := test.mutate(t, file, path, base)
			if err := validateSecureOpenFile(file, path, expectedUID); err == nil {
				t.Fatal("validateSecureOpenFile() accepted adversarial file state")
			}
		})
	}
}

func TestSecureWorkspaceRejectsSymlinkBase(t *testing.T) {
	t.Parallel()

	realBase := t.TempDir()
	linkBase := filepath.Join(t.TempDir(), "temp-link")
	if err := os.Symlink(realBase, linkBase); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if workspace, err := createSecureWorkspace(linkBase, os.Geteuid()); err == nil {
		_ = removeSecureWorkspace(workspace)
		t.Fatal("createSecureWorkspace() accepted a symbolic-link base")
	}
}

func TestDownloadVerifiedPackageRejectsWrongHashAndSize(t *testing.T) {
	t.Parallel()

	payload := []byte("expected package")
	tests := []struct {
		name    string
		served  []byte
		size    int64
		digest  string
		wantErr bool
	}{
		{
			name:    "valid",
			served:  payload,
			size:    int64(len(payload)),
			digest:  fmt.Sprintf("%x", sha256.Sum256(payload)),
			wantErr: false,
		},
		{
			name:    "wrong hash",
			served:  []byte("tampered package"),
			size:    int64(len([]byte("tampered package"))),
			digest:  fmt.Sprintf("%x", sha256.Sum256(payload)),
			wantErr: true,
		},
		{
			name:    "wrong size",
			served:  payload,
			size:    int64(len(payload) + 1),
			digest:  fmt.Sprintf("%x", sha256.Sum256(payload)),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := staticHTTPClient(func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(http.StatusOK, test.served), nil
			})

			base := t.TempDir()
			workspace, err := createSecureWorkspace(base, os.Geteuid())
			if err != nil {
				t.Fatalf("createSecureWorkspace() error = %v", err)
			}
			defer func() { _ = removeSecureWorkspace(workspace) }()
			file, _, err := createSecureExclusiveFile(workspace, "package.deb", os.Geteuid())
			if err != nil {
				t.Fatalf("createSecureExclusiveFile() error = %v", err)
			}
			defer func() { _ = file.Close() }()

			err = downloadVerifiedPackage(t.Context(), client, "https://updates.test/package", file, updateArtifact{
				Size:   test.size,
				SHA256: test.digest,
			}, os.Geteuid())
			if (err != nil) != test.wantErr {
				t.Fatalf("downloadVerifiedPackage() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

func TestFinalPackageVerificationRejectsSameInodeSameSizeMutation(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	workspace, err := createSecureWorkspace(base, os.Geteuid())
	if err != nil {
		t.Fatalf("createSecureWorkspace() error = %v", err)
	}
	defer func() { _ = removeSecureWorkspace(workspace) }()
	file, path, err := createSecureExclusiveFile(workspace, "package.deb", os.Geteuid())
	if err != nil {
		t.Fatalf("createSecureExclusiveFile() error = %v", err)
	}
	defer func() { _ = file.Close() }()

	original := []byte("authenticated-package")
	artifact := updateArtifact{
		Size:   int64(len(original)),
		SHA256: fmt.Sprintf("%x", sha256.Sum256(original)),
	}
	if _, err := file.Write(original); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if err := verifySecurePackageForInstallation(file, path, artifact, os.Geteuid()); err != nil {
		t.Fatalf("verifySecurePackageForInstallation(valid) error = %v", err)
	}

	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(before) error = %v", err)
	}
	mutated := bytes.Repeat([]byte{'X'}, len(original))
	if _, err := file.WriteAt(mutated, 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("Sync(mutated) error = %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(after) error = %v", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() {
		t.Fatal("test mutation did not preserve inode and size")
	}
	if err := verifySecurePackageForInstallation(file, path, artifact, os.Geteuid()); err == nil {
		t.Fatal("final package verification accepted same-inode, same-size tampering")
	}
}

func TestUpdaterRejectsSameInodeMutationBetweenDownloadAndInstaller(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	packagePayload := []byte("verified deb package")
	manifestBytes := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, packagePayload))
	signature := testSignManifest(privateKey, manifestBytes)
	tempBase := t.TempDir()
	packageName := "syswarden_4.02.9_amd64.deb"
	var mutated atomic.Bool
	client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/latest":
			return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
		case "/download/" + testUpdateVersion + "/" + updateManifestAssetName:
			return testHTTPResponse(http.StatusOK, manifestBytes), nil
		case "/download/" + testUpdateVersion + "/" + updateManifestSignatureAssetName:
			return testHTTPResponse(http.StatusOK, signature), nil
		case "/download/" + testUpdateVersion + "/" + packageName:
			response := testHTTPResponse(http.StatusOK, packagePayload)
			response.Body = &callbackReadCloser{
				Reader: bytes.NewReader(packagePayload),
				close: func() error {
					entries, err := os.ReadDir(tempBase)
					if err != nil {
						return fmt.Errorf("locate update workspace after download: %w", err)
					}
					if len(entries) != 1 {
						return fmt.Errorf("locate update workspace after download: found %d entries", len(entries))
					}
					baseRoot, err := os.OpenRoot(tempBase)
					if err != nil {
						return err
					}
					defer baseRoot.Close()
					workspaceRoot, err := baseRoot.OpenRoot(entries[0].Name())
					if err != nil {
						return err
					}
					defer workspaceRoot.Close()
					file, err := workspaceRoot.OpenFile(packageName, os.O_WRONLY, 0)
					if err != nil {
						return err
					}
					defer func() { _ = file.Close() }()
					replacement := bytes.Repeat([]byte{'X'}, len(packagePayload))
					if _, err := file.WriteAt(replacement, 0); err != nil {
						return err
					}
					mutated.Store(true)
					return file.Sync()
				},
			}
			return response, nil
		default:
			return testHTTPResponse(http.StatusNotFound, []byte("not found")), nil
		}
	})
	var installs atomic.Int32
	u := testUpdater(
		client,
		tempBase,
		"amd64",
		map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		func(_ context.Context, name string, _ ...string) error {
			if name == "/usr/bin/apt-get" {
				installs.Add(1)
			}
			return nil
		},
	)
	err = u.run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "verify package immediately before installation") {
		t.Fatalf("updater.run() error = %v, want final verification failure", err)
	}
	if !mutated.Load() {
		t.Fatal("test did not mutate the downloaded package")
	}
	if installs.Load() != 0 {
		t.Fatalf("installer was called %d times after package mutation", installs.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestDownloadBoundedBytesEnforcesLimitAndContextTimeout(t *testing.T) {
	t.Parallel()

	t.Run("limit", func(t *testing.T) {
		t.Parallel()
		client := staticHTTPClient(func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusOK, []byte("12345")), nil
		})
		if _, err := downloadBoundedBytes(t.Context(), client, "https://updates.test/large", 4); err == nil {
			t.Fatal("downloadBoundedBytes() accepted an oversized response")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		if _, err := downloadBoundedBytes(ctx, client, "https://updates.test/slow", 4); err == nil {
			t.Fatal("downloadBoundedBytes() ignored its context deadline")
		}
	})
}

func TestFetchLatestVersionPreservesRateLimitDiagnostic(t *testing.T) {
	t.Parallel()

	u := &updater{
		client: staticHTTPClient(func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusForbidden, []byte("rate limited")), nil
		}),
		latestURL:       "https://updates.test/latest",
		metadataTimeout: time.Second,
	}
	if _, err := u.fetchLatestVersion(t.Context()); err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("fetchLatestVersion() error = %v", err)
	}
}

func TestExternalCommandContractRejectsUnexpectedArguments(t *testing.T) {
	t.Parallel()

	validPackage := "/var/tmp/syswarden-update-safe/package.deb"
	if err := validateExternalCommand("/usr/bin/apt-get", []string{"install", "-y", validPackage}); err != nil {
		t.Fatalf("validateExternalCommand() rejected exact installer contract: %v", err)
	}
	validTXZ := "/var/tmp/syswarden-update-safe/package.txz"
	if err := validateExternalCommand("/usr/sbin/pkg", []string{"add", "-f", validTXZ}); err != nil {
		t.Fatalf("validateExternalCommand() rejected exact FreeBSD installer contract: %v", err)
	}
	invalid := []struct {
		name string
		args []string
	}{
		{name: "/tmp/apt-get", args: []string{"install", "-y", validPackage}},
		{name: "/usr/bin/apt-get", args: []string{"install", "-y", "/tmp/package.deb"}},
		{name: "/usr/bin/apt-get", args: []string{"remove", "-y", validPackage}},
		{name: "/sbin/apk", args: []string{"add", "/var/tmp/syswarden-update-safe/package.apk"}},
		{name: "/usr/sbin/pkg", args: []string{"add", validTXZ}},
		{name: "/usr/sbin/pkg", args: []string{"add", "-f", "/tmp/package.txz"}},
		{name: "/tmp/pkg", args: []string{"add", "-f", validTXZ}},
		{name: "/usr/sbin/service", args: []string{"syswarden", "stop"}},
		{name: "/usr/sbin/service", args: []string{"operator-service", "restart"}},
	}
	for _, command := range invalid {
		if err := validateExternalCommand(command.name, command.args); err == nil {
			t.Fatalf("validateExternalCommand(%q, %#v) accepted invalid command", command.name, command.args)
		}
	}
}

func TestUpdaterFailsClosedBeforeInstallationAndCleansWorkspace(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	packagePayload := []byte("verified deb package")
	validManifest := testUpdateManifest(t, testUpdateVersion, packagePayload)
	validManifestBytes := testMarshalManifest(t, validManifest)
	validSignature := testSignManifest(privateKey, validManifestBytes)

	tests := []struct {
		name          string
		manifestBytes []byte
		signature     []byte
		packageBytes  []byte
		goarch        string
		keys          map[string]ed25519.PublicKey
	}{
		{
			name:          "manifest tampering",
			manifestBytes: testTamperedManifest(t, validManifest),
			signature:     validSignature,
			packageBytes:  packagePayload,
			goarch:        "amd64",
			keys:          map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name:          "signature tampering",
			manifestBytes: validManifestBytes,
			signature:     testTamperedSignature(t, validSignature),
			packageBytes:  packagePayload,
			goarch:        "amd64",
			keys:          map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name:          "package hash tampering",
			manifestBytes: validManifestBytes,
			signature:     validSignature,
			packageBytes:  []byte("tampered deb package"),
			goarch:        "amd64",
			keys:          map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name:          "wrong host architecture",
			manifestBytes: validManifestBytes,
			signature:     validSignature,
			packageBytes:  packagePayload,
			goarch:        "ppc64le",
			keys:          map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name:          "no embedded trust root",
			manifestBytes: validManifestBytes,
			signature:     validSignature,
			packageBytes:  packagePayload,
			goarch:        "amd64",
			keys:          nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var installs atomic.Int32
			tempBase := t.TempDir()
			client := newUpdaterTestClient(test.manifestBytes, test.signature, test.packageBytes)
			u := testUpdater(client, tempBase, test.goarch, test.keys, func(_ context.Context, name string, _ ...string) error {
				if name == "/usr/bin/apt-get" {
					installs.Add(1)
				}
				return nil
			})

			if err := u.run(t.Context()); err == nil {
				t.Fatal("updater accepted adversarial release data")
			}
			if installs.Load() != 0 {
				t.Fatalf("installer was called %d times", installs.Load())
			}
			assertEmptyDirectory(t, tempBase)
		})
	}
}

func TestUpdaterInstallsOnlyVerifiedPackageAndCleansWorkspace(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	packagePayload := []byte("verified deb package")
	manifestBytes := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, packagePayload))
	signature := testSignManifest(privateKey, manifestBytes)
	client := newUpdaterTestClient(manifestBytes, signature, packagePayload)
	tempBase := t.TempDir()
	var installs atomic.Int32
	u := testUpdater(
		client,
		tempBase,
		"amd64",
		map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		func(_ context.Context, name string, args ...string) error {
			if name != "/usr/bin/apt-get" {
				return nil
			}
			installs.Add(1)
			if len(args) != 3 || args[0] != "install" || args[1] != "-y" {
				t.Fatalf("installer arguments = %#v", args)
			}
			content, err := os.ReadFile(args[2])
			if err != nil {
				t.Fatalf("ReadFile(installer package) error = %v", err)
			}
			if !bytes.Equal(content, packagePayload) {
				t.Fatalf("installer package content = %q", content)
			}
			info, err := os.Lstat(args[2])
			if err != nil {
				t.Fatalf("Lstat(installer package) error = %v", err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatalf("installer package mode = %v", info.Mode())
			}
			return nil
		},
	)

	if err := u.run(t.Context()); err != nil {
		t.Fatalf("updater.run() error = %v", err)
	}
	if installs.Load() != 1 {
		t.Fatalf("installer was called %d times, want 1", installs.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestAPKAllowUntrustedIsReachableOnlyAfterManifestAndPackageVerification(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	packagePayload := []byte("verified apk package")
	manifestBytes := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, packagePayload))
	validSignature := testSignManifest(privateKey, manifestBytes)

	for _, test := range []struct {
		name          string
		signature     []byte
		wantError     bool
		wantInstalls  int32
		wantDownloads bool
	}{
		{name: "valid signed APK", signature: validSignature, wantInstalls: 1, wantDownloads: true},
		{name: "invalid manifest signature", signature: testTamperedSignature(t, validSignature), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var manifestDownloaded atomic.Bool
			var signatureDownloaded atomic.Bool
			var packageDownloaded atomic.Bool
			var installs atomic.Int32
			packageName := "syswarden_4.02.9_x86_64.apk"
			client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/latest":
					return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
				case "/download/" + testUpdateVersion + "/" + updateManifestAssetName:
					manifestDownloaded.Store(true)
					return testHTTPResponse(http.StatusOK, manifestBytes), nil
				case "/download/" + testUpdateVersion + "/" + updateManifestSignatureAssetName:
					signatureDownloaded.Store(true)
					return testHTTPResponse(http.StatusOK, test.signature), nil
				case "/download/" + testUpdateVersion + "/" + packageName:
					packageDownloaded.Store(true)
					return testHTTPResponse(http.StatusOK, packagePayload), nil
				default:
					return testHTTPResponse(http.StatusNotFound, []byte("not found")), nil
				}
			})
			u := testUpdater(
				client,
				t.TempDir(),
				"amd64",
				map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
				func(_ context.Context, name string, args ...string) error {
					if name != "/sbin/apk" {
						return nil
					}
					if !manifestDownloaded.Load() || !signatureDownloaded.Load() || !packageDownloaded.Load() {
						t.Fatal("APK native-signature bypass ran before independent Ed25519/package verification")
					}
					if len(args) != 3 || args[0] != "add" || args[1] != "--allow-untrusted" {
						t.Fatalf("APK installer arguments = %#v", args)
					}
					installs.Add(1)
					return nil
				},
			)
			u.lookPath = func(name string) (string, error) {
				switch name {
				case "apk":
					return "/sbin/apk", nil
				case "rc-service":
					return "/sbin/rc-service", nil
				}
				return "", os.ErrNotExist
			}

			err := u.run(t.Context())
			if test.wantError && err == nil {
				t.Fatal("updater accepted invalid APK signature")
			}
			if !test.wantError && err != nil {
				t.Fatalf("updater.run() error = %v", err)
			}
			if installs.Load() != test.wantInstalls {
				t.Fatalf("APK installer calls = %d, want %d", installs.Load(), test.wantInstalls)
			}
			if packageDownloaded.Load() != test.wantDownloads {
				t.Fatalf("APK package downloaded = %t, want %t", packageDownloaded.Load(), test.wantDownloads)
			}
		})
	}
}

func TestFreeBSDUpdaterInstallsOnlyVerifiedTXZAndActivatesRCD(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	packagePayload := []byte("verified FreeBSD txz package")
	manifestBytes := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, packagePayload))
	validSignature := testSignManifest(privateKey, manifestBytes)

	for _, test := range []struct {
		name         string
		signature    []byte
		wantError    bool
		wantInstalls int32
	}{
		{name: "valid signed TXZ", signature: validSignature, wantInstalls: 1},
		{name: "invalid manifest signature", signature: testTamperedSignature(t, validSignature), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var installs atomic.Int32
			var packageDownloaded atomic.Bool
			var activationCalls atomic.Int32
			packageName := "syswarden-4.02.9.txz"
			client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/latest":
					return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
				case "/download/" + testUpdateVersion + "/" + updateManifestAssetName:
					return testHTTPResponse(http.StatusOK, manifestBytes), nil
				case "/download/" + testUpdateVersion + "/" + updateManifestSignatureAssetName:
					return testHTTPResponse(http.StatusOK, test.signature), nil
				case "/download/" + testUpdateVersion + "/" + packageName:
					packageDownloaded.Store(true)
					return testHTTPResponse(http.StatusOK, packagePayload), nil
				default:
					return testHTTPResponse(http.StatusNotFound, []byte("not found")), nil
				}
			})
			u := testUpdaterForPlatform(
				client,
				t.TempDir(),
				"freebsd",
				"amd64",
				map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
				func(_ context.Context, name string, args ...string) error {
					switch name {
					case "/usr/sbin/pkg":
						if !packageDownloaded.Load() {
							t.Fatal("FreeBSD installer ran before the authenticated package download")
						}
						if len(args) != 3 || args[0] != "add" || args[1] != "-f" {
							t.Fatalf("FreeBSD installer arguments = %#v", args)
						}
						content, err := readUpdaterTestFile(filepath.Dir(args[2]), filepath.Base(args[2]))
						if err != nil {
							t.Fatalf("read authenticated TXZ: %v", err)
						}
						if !bytes.Equal(content, packagePayload) {
							t.Fatalf("FreeBSD installer package content = %q", content)
						}
						installs.Add(1)
					case "/usr/local/syswarden/bin/syswarden-cli", "/usr/sbin/service":
						activationCalls.Add(1)
					default:
						t.Fatalf("unexpected FreeBSD command %q %#v", name, args)
					}
					return nil
				},
			)
			u.lookPath = func(name string) (string, error) {
				switch name {
				case "pkg":
					return "/usr/sbin/pkg", nil
				case "service":
					return "/usr/sbin/service", nil
				default:
					return "", os.ErrNotExist
				}
			}

			err := u.run(t.Context())
			if test.wantError && err == nil {
				t.Fatal("FreeBSD updater accepted an invalid manifest signature")
			}
			if !test.wantError && err != nil {
				t.Fatalf("FreeBSD updater error = %v", err)
			}
			if installs.Load() != test.wantInstalls {
				t.Fatalf("FreeBSD installer calls = %d, want %d", installs.Load(), test.wantInstalls)
			}
			if test.wantError && activationCalls.Load() != 0 {
				t.Fatalf("FreeBSD activation ran %d times after rejected metadata", activationCalls.Load())
			}
			if !test.wantError && activationCalls.Load() != 5 {
				t.Fatalf("FreeBSD activation calls = %d, want 5", activationCalls.Load())
			}
		})
	}
}

func TestFinishUpgradeReturnsPartialAndMultipleActivationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		failures   map[string]error
		wantErrors []string
	}{
		{
			name: "partial service failure",
			failures: map[string]error{
				"/usr/bin/systemctl daemon-reload": errors.New("reload failed"),
			},
			wantErrors: []string{"reload systemd manager configuration", "reload failed"},
		},
		{
			name: "multiple activation failures",
			failures: map[string]error{
				"/opt/syswarden/bin/syswarden-cli web-token":  errors.New("token failed"),
				"/usr/bin/systemctl daemon-reload":            errors.New("reload failed"),
				"/usr/bin/systemctl restart syswarden-core":   errors.New("core failed"),
				"/usr/bin/systemctl restart syswarden-webtui": errors.New("web failed"),
			},
			wantErrors: []string{
				"initialize Web-TUI token", "token failed",
				"reload systemd manager configuration", "reload failed",
				"restart syswarden-core", "core failed",
				"restart syswarden-webtui", "web failed",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			var calls atomic.Int32
			u := &updater{
				stdout: &output,
				lookPath: func(name string) (string, error) {
					if name == "systemctl" {
						return "/usr/bin/systemctl", nil
					}
					return "", os.ErrNotExist
				},
				runCommand: func(_ context.Context, name string, args ...string) error {
					calls.Add(1)
					key := strings.Join(append([]string{name}, args...), " ")
					return test.failures[key]
				},
			}
			err := u.finishUpgrade(t.Context(), packageTarget{format: packageFormatDEB})
			if err == nil {
				t.Fatal("finishUpgrade() accepted failed activation")
			}
			for _, expected := range test.wantErrors {
				if !strings.Contains(err.Error(), expected) {
					t.Errorf("finishUpgrade() error %q does not contain %q", err, expected)
				}
			}
			if calls.Load() != 4 {
				t.Errorf("activation command calls = %d, want 4", calls.Load())
			}
			if strings.Contains(output.String(), "completed successfully") {
				t.Fatalf("failed activation printed a success message: %q", output.String())
			}
		})
	}
}

func TestFinishUpgradeFreeBSDAggregatesActivationFailures(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var calls atomic.Int32
	u := &updater{
		stdout: &output,
		lookPath: func(name string) (string, error) {
			if name == "service" {
				return "/usr/sbin/service", nil
			}
			return "", os.ErrNotExist
		},
		runCommand: func(_ context.Context, name string, args ...string) error {
			calls.Add(1)
			key := strings.Join(append([]string{name}, args...), " ")
			switch key {
			case "/usr/local/syswarden/bin/syswarden-cli web-token":
				return errors.New("token failed")
			case "/usr/sbin/service syswarden restart":
				return errors.New("core failed")
			case "/usr/sbin/service syswarden onestatus":
				return errors.New("core status failed")
			case "/usr/sbin/service syswardenwebtui restart":
				return errors.New("web failed")
			case "/usr/sbin/service syswardenwebtui onestatus":
				return errors.New("web status failed")
			default:
				return nil
			}
		},
	}
	err := u.finishUpgrade(t.Context(), packageTarget{os: "freebsd", format: packageFormatTXZ})
	if err == nil {
		t.Fatal("finishUpgrade() accepted failed FreeBSD activation")
	}
	for _, expected := range []string{
		"initialize Web-TUI token",
		"restart syswarden",
		"verify syswarden status",
		"restart syswardenwebtui",
		"verify syswardenwebtui status",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("finishUpgrade() error %q does not contain %q", err, expected)
		}
	}
	if calls.Load() != 5 {
		t.Errorf("FreeBSD activation command calls = %d, want 5", calls.Load())
	}
	if strings.Contains(output.String(), "completed successfully") {
		t.Fatalf("failed FreeBSD activation printed a success message: %q", output.String())
	}
}

func newUpdaterTestClient(
	manifestBytes, signatureBytes, packageBytes []byte,
) *http.Client {
	packageName := "syswarden_4.02.9_amd64.deb"
	return staticHTTPClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/latest":
			return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
		case "/download/" + testUpdateVersion + "/" + updateManifestAssetName:
			return testHTTPResponse(http.StatusOK, manifestBytes), nil
		case "/download/" + testUpdateVersion + "/" + updateManifestSignatureAssetName:
			return testHTTPResponse(http.StatusOK, signatureBytes), nil
		case "/download/" + testUpdateVersion + "/" + packageName:
			return testHTTPResponse(http.StatusOK, packageBytes), nil
		default:
			return testHTTPResponse(http.StatusNotFound, []byte("not found")), nil
		}
	})
}

func testUpdater(
	client *http.Client,
	tempBase, goarch string,
	keys map[string]ed25519.PublicKey,
	runner commandRunner,
) *updater {
	return testUpdaterForPlatform(client, tempBase, "linux", goarch, keys, runner)
}

func testUpdaterForPlatform(
	client *http.Client,
	tempBase, goos, goarch string,
	keys map[string]ed25519.PublicKey,
	runner commandRunner,
) *updater {
	return &updater{
		client:          client,
		latestURL:       "https://updates.test/latest",
		downloadBaseURL: "https://updates.test/download",
		currentVersion:  "v4.02.8",
		goos:            goos,
		goarch:          goarch,
		tempBase:        tempBase,
		trustedKeys:     keys,
		lookPath: func(name string) (string, error) {
			switch name {
			case "apt-get":
				return "/usr/bin/apt-get", nil
			case "systemctl":
				return "/usr/bin/systemctl", nil
			}
			return "", os.ErrNotExist
		},
		runCommand:      runner,
		effectiveUID:    os.Geteuid(),
		stdout:          io.Discard,
		metadataTimeout: time.Second,
		packageTimeout:  time.Second,
		installTimeout:  time.Second,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func staticHTTPClient(function roundTripFunc) *http.Client {
	return &http.Client{Transport: function}
}

type callbackReadCloser struct {
	io.Reader
	close func() error
}

func (closer *callbackReadCloser) Close() error {
	return closer.close()
}

func testHTTPResponse(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

func assertEmptyDirectory(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", directory, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("temporary residue = %s", strings.Join(names, ", "))
	}
}

func readUpdaterTestFile(directory, name string) ([]byte, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

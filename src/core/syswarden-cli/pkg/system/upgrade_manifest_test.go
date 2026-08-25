package system

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	testUpdateVersion = "v4.02.9"
	testReleaseKeyID  = "test-release-2026"
)

func TestFirstSignedUpdaterVersionContract(t *testing.T) {
	t.Parallel()
	if got := firstSignedUpdaterVersion(); got != testUpdateVersion {
		t.Fatalf("first signed updater version = %q, want %q", got, testUpdateVersion)
	}
}

func TestVerifySignedManifestAdversarialInputs(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	payload := []byte("authenticated package payload")
	validManifest := testUpdateManifest(t, testUpdateVersion, payload)
	validBytes := testMarshalManifest(t, validManifest)
	validSignature := testSignManifest(privateKey, validBytes)

	tests := []struct {
		name            string
		manifest        updateManifest
		manifestBytes   []byte
		signatureBytes  []byte
		expectedVersion string
		keys            map[string]ed25519.PublicKey
	}{
		{
			name:            "tampered manifest",
			manifestBytes:   testTamperedManifest(t, validManifest),
			signatureBytes:  validSignature,
			expectedVersion: testUpdateVersion,
			keys:            map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name:            "wrong signature",
			manifestBytes:   validBytes,
			signatureBytes:  testTamperedSignature(t, validSignature),
			expectedVersion: testUpdateVersion,
			keys:            map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name:            "wrong version",
			manifest:        testUpdateManifest(t, "v4.03.0", payload),
			expectedVersion: testUpdateVersion,
			keys:            map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name: "wrong architecture inventory",
			manifest: func() updateManifest {
				manifest := testUpdateManifest(t, testUpdateVersion, payload)
				manifest.Artifacts[0].Architecture = "arm64"
				return manifest
			}(),
			expectedVersion: testUpdateVersion,
			keys:            map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name: "wrong hash metadata",
			manifest: func() updateManifest {
				manifest := testUpdateManifest(t, testUpdateVersion, payload)
				manifest.Artifacts[0].SHA256 = strings.Repeat("A", sha256.Size*2)
				return manifest
			}(),
			expectedVersion: testUpdateVersion,
			keys:            map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
		{
			name:            "untrusted key id",
			manifestBytes:   validBytes,
			signatureBytes:  validSignature,
			expectedVersion: testUpdateVersion,
			keys:            map[string]ed25519.PublicKey{"different-key": publicKey},
		},
		{
			name:            "noncanonical json",
			manifestBytes:   append([]byte(" "), validBytes...),
			signatureBytes:  validSignature,
			expectedVersion: testUpdateVersion,
			keys:            map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifestBytes := test.manifestBytes
			signatureBytes := test.signatureBytes
			if manifestBytes == nil {
				manifestBytes = testMarshalManifest(t, test.manifest)
				signatureBytes = testSignManifest(privateKey, manifestBytes)
			}
			if _, err := verifySignedManifest(manifestBytes, signatureBytes, test.expectedVersion, test.keys); err == nil {
				t.Fatal("verifySignedManifest() accepted adversarial input")
			}
		})
	}
}

func TestVerifySignedManifestAcceptsExactContract(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	manifestBytes := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, []byte("package")))
	signatureBytes := testSignManifest(privateKey, manifestBytes)

	manifest, err := verifySignedManifest(
		manifestBytes,
		signatureBytes,
		testUpdateVersion,
		map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
	)
	if err != nil {
		t.Fatalf("verifySignedManifest() error = %v", err)
	}
	if manifest.Schema != updateManifestSchema || len(manifest.Artifacts) != 3 {
		t.Fatalf("verified manifest = %#v", manifest)
	}
}

func TestDetectPackageTargetSelectsAMD64PackageFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		goos          string
		manager       string
		managerPath   string
		architecture  string
		wantFormat    string
		wantFilename  string
		wantInstaller string
	}{
		{
			name:          "deb amd64",
			goos:          "linux",
			manager:       "apt-get",
			managerPath:   "/usr/bin/apt-get",
			architecture:  "amd64",
			wantFormat:    packageFormatDEB,
			wantFilename:  "syswarden_4.02.9_amd64.deb",
			wantInstaller: "/usr/bin/apt-get",
		},
		{
			name:          "rpm amd64",
			goos:          "linux",
			manager:       "dnf",
			managerPath:   "/usr/bin/dnf",
			architecture:  "amd64",
			wantFormat:    packageFormatRPM,
			wantFilename:  "syswarden-4.02.9-1.x86_64.rpm",
			wantInstaller: "/usr/bin/dnf",
		},
		{
			name:          "apk amd64",
			goos:          "linux",
			manager:       "apk",
			managerPath:   "/sbin/apk",
			architecture:  "amd64",
			wantFormat:    packageFormatAPK,
			wantFilename:  "syswarden_4.02.9_x86_64.apk",
			wantInstaller: "/sbin/apk",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			target, err := detectPackageTarget(test.goos, test.architecture, testUpdateVersion, func(name string) (string, error) {
				if name == test.manager {
					return test.managerPath, nil
				}
				return "", os.ErrNotExist
			})
			if err != nil {
				t.Fatalf("detectPackageTarget() error = %v", err)
			}
			if target.format != test.wantFormat || target.filename != test.wantFilename || target.installer != test.wantInstaller {
				t.Fatalf("target = %#v, want format=%q filename=%q installer=%q", target, test.wantFormat, test.wantFilename, test.wantInstaller)
			}
		})
	}
}

func TestAPKUnsignedFlagRemainsBehindVerifiedManifestPipeline(t *testing.T) {
	t.Parallel()

	arguments := (packageTarget{format: packageFormatAPK}).installArguments("/var/tmp/syswarden-update-safe/package.apk")
	if len(arguments) != 3 || arguments[0] != "add" || arguments[1] != "--allow-untrusted" ||
		arguments[2] != "/var/tmp/syswarden-update-safe/package.apk" {
		t.Fatalf("APK install arguments = %#v", arguments)
	}
}

func TestDetectPackageTargetRejectsWrongOSArchitectureAndPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		goos     string
		goarch   string
		resolved string
	}{
		{name: "wrong os", goos: "windows", goarch: "amd64", resolved: "/usr/bin/apt-get"},
		{name: "retired arm64 architecture", goos: "linux", goarch: "arm64", resolved: "/usr/bin/apt-get"},
		{name: "unknown architecture", goos: "linux", goarch: "ppc64le", resolved: "/usr/bin/apt-get"},
		{name: "relative manager", goos: "linux", goarch: "amd64", resolved: "apt-get"},
		{name: "untrusted absolute manager", goos: "linux", goarch: "amd64", resolved: "/tmp/apt-get"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := detectPackageTarget(test.goos, test.goarch, testUpdateVersion, func(string) (string, error) {
				return test.resolved, nil
			})
			if err == nil {
				t.Fatal("detectPackageTarget() accepted invalid target")
			}
		})
	}
}

func testUpdateManifest(t *testing.T, version string, payload []byte) updateManifest {
	t.Helper()
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	identities := expectedManifestIdentities()
	artifacts := make([]updateArtifact, 0, len(identities))
	for _, identity := range identities {
		filename, err := packageFilename(version, identity.format, identity.architecture)
		if err != nil {
			t.Fatalf("packageFilename() error = %v", err)
		}
		artifacts = append(artifacts, updateArtifact{
			OS:           identity.os,
			Architecture: identity.architecture,
			Format:       identity.format,
			Filename:     filename,
			Size:         int64(len(payload)),
			SHA256:       digest,
		})
	}
	return updateManifest{
		Schema:    updateManifestSchema,
		KeyID:     testReleaseKeyID,
		Version:   version,
		Artifacts: artifacts,
	}
}

func testMarshalManifest(t *testing.T, manifest updateManifest) []byte {
	t.Helper()
	encoded, err := marshalCanonicalManifest(&manifest)
	if err != nil {
		t.Fatalf("marshalCanonicalManifest() error = %v", err)
	}
	return encoded
}

func testSignManifest(privateKey ed25519.PrivateKey, manifestBytes []byte) []byte {
	signature := ed25519.Sign(privateKey, manifestBytes)
	return []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
}

func testTamperedManifest(t *testing.T, manifest updateManifest) []byte {
	t.Helper()
	manifest.Artifacts[0].SHA256 = strings.Repeat("0", sha256.Size*2)
	return testMarshalManifest(t, manifest)
}

func testTamperedSignature(t *testing.T, signatureAsset []byte) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(signatureAsset), "\n"))
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	decoded[0] ^= 0xff
	tampered := []byte(base64.StdEncoding.EncodeToString(decoded) + "\n")
	if bytes.Equal(tampered, signatureAsset) {
		t.Fatal("signature tampering did not change bytes")
	}
	return tampered
}

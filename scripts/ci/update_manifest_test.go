package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testKeyID  = "syswarden-update-test-01"
	testSeed   = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="
	testPublic = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
)

type manifestFixture struct {
	repository string
	packages   string
	manifest   string
	signature  string
	privateKey ed25519.PrivateKey
}

func makeManifestFixture(t *testing.T) manifestFixture {
	t.Helper()
	root := t.TempDir()
	repository := filepath.Join(root, "repository")
	trustPath := filepath.Join(repository, filepath.FromSlash(trustRootsRepository))
	if err := os.MkdirAll(filepath.Dir(trustPath), 0700); err != nil {
		t.Fatal(err)
	}
	trustData := []byte(`{"schema":"syswarden-release-trust-roots/v1","keys":[{"id":"` + testKeyID + `","public_key":"` + testPublic + `"}]}` + "\n")
	if err := os.WriteFile(trustPath, trustData, 0600); err != nil {
		t.Fatal(err)
	}

	packageDirectory := filepath.Join(root, "packages")
	if err := os.Mkdir(packageDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	names, err := packageNames(firstSignedVersion)
	if err != nil {
		t.Fatal(err)
	}
	checksumLines := make([]string, 0, len(names))
	for _, name := range names {
		content := []byte("qualified package:" + name + "\n")
		if err := os.WriteFile(filepath.Join(packageDirectory, name), content, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		checksumLines = append(checksumLines, hex.EncodeToString(digest[:])+"  "+name)
	}
	if err := os.WriteFile(filepath.Join(packageDirectory, packageChecksumName), []byte(strings.Join(checksumLines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	seed, err := base64.StdEncoding.DecodeString(testSeed)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	records, err := loadPackages(packageDirectory, firstSignedVersion, false)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := buildManifest(firstSignedVersion, testKeyID, records)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := canonicalJSON(candidate)
	if err != nil {
		t.Fatal(err)
	}
	signatureData := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestData)) + "\n")
	manifestPath := filepath.Join(root, manifestName)
	signaturePath := filepath.Join(root, signatureName)
	if err := os.WriteFile(manifestPath, manifestData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, signatureData, 0600); err != nil {
		t.Fatal(err)
	}
	return manifestFixture{
		repository: repository,
		packages:   packageDirectory,
		manifest:   manifestPath,
		signature:  signaturePath,
		privateKey: privateKey,
	}
}

func (fixture manifestFixture) resign(t *testing.T, candidate *manifest) {
	t.Helper()
	data, err := canonicalJSON(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(fixture.privateKey, data)
	if err := os.WriteFile(fixture.signature, []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func (fixture manifestFixture) parsed(t *testing.T) *manifest {
	t.Helper()
	data, err := os.ReadFile(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	var candidate manifest
	if err := decodeStrictJSON(data, &candidate, "test manifest"); err != nil {
		t.Fatal(err)
	}
	return &candidate
}

func TestVerifyAcceptsDeterministicSignedManifest(t *testing.T) {
	fixture := makeManifestFixture(t)
	if err := verify(fixture.repository, firstSignedVersion, fixture.packages, fixture.manifest, fixture.signature); err != nil {
		t.Fatalf("verify valid signed manifest: %v", err)
	}
	candidate := fixture.parsed(t)
	if len(candidate.Artifacts) != 3 {
		t.Fatalf("manifest artifact count = %d, want 3", len(candidate.Artifacts))
	}
	for _, item := range candidate.Artifacts {
		if item.OS != "linux" || (item.Format != "deb" && item.Format != "rpm" && item.Format != "apk") {
			t.Fatalf("non-Linux manifest artifact = %#v", item)
		}
	}
}

func TestVerifyRejectsAdversarialSignedMetadata(t *testing.T) {
	tests := map[string]func(*manifest){
		"wrong version":      func(candidate *manifest) { candidate.Version = "v4.02.10" },
		"wrong OS":           func(candidate *manifest) { candidate.Artifacts[0].OS = "other" },
		"wrong architecture": func(candidate *manifest) { candidate.Artifacts[0].Architecture = "arm64" },
		"wrong format":       func(candidate *manifest) { candidate.Artifacts[0].Format = "rpm" },
		"wrong filename":     func(candidate *manifest) { candidate.Artifacts[0].Filename = candidate.Artifacts[1].Filename },
		"wrong size":         func(candidate *manifest) { candidate.Artifacts[0].Size++ },
		"wrong hash":         func(candidate *manifest) { candidate.Artifacts[0].SHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := makeManifestFixture(t)
			candidate := fixture.parsed(t)
			mutate(candidate)
			fixture.resign(t, candidate)
			if err := verify(fixture.repository, firstSignedVersion, fixture.packages, fixture.manifest, fixture.signature); err == nil {
				t.Fatal("adversarial signed metadata was accepted")
			}
		})
	}
}

func TestVerifyRejectsTamperingAndNonCanonicalAssets(t *testing.T) {
	t.Run("signature", func(t *testing.T) {
		fixture := makeManifestFixture(t)
		data, err := os.ReadFile(fixture.signature)
		if err != nil {
			t.Fatal(err)
		}
		data[0] ^= 1
		if err := os.WriteFile(fixture.signature, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := verify(fixture.repository, firstSignedVersion, fixture.packages, fixture.manifest, fixture.signature); err == nil {
			t.Fatal("tampered signature was accepted")
		}
	})
	t.Run("manifest whitespace", func(t *testing.T) {
		fixture := makeManifestFixture(t)
		data, err := os.ReadFile(fixture.manifest)
		if err != nil {
			t.Fatal(err)
		}
		data = append([]byte(" "), data...)
		if err := os.WriteFile(fixture.manifest, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := verify(fixture.repository, firstSignedVersion, fixture.packages, fixture.manifest, fixture.signature); err == nil {
			t.Fatal("non-canonical manifest was accepted")
		}
	})
	t.Run("package bytes", func(t *testing.T) {
		fixture := makeManifestFixture(t)
		name, err := packageFilename(firstSignedVersion, "deb", "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.packages, name), []byte("tampered\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verify(fixture.repository, firstSignedVersion, fixture.packages, fixture.manifest, fixture.signature); err == nil {
			t.Fatal("tampered package was accepted")
		}
	})
}

func TestGenerateUsesOnlyProtectedPEMEnvironmentAndIsDeterministic(t *testing.T) {
	fixture := makeManifestFixture(t)
	der, err := x509.MarshalPKCS8PrivateKey(fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	firstOutput := filepath.Join(t.TempDir(), "first")
	t.Setenv(privateKeyEnv, string(privatePEM))
	if err := generate(fixture.repository, firstSignedVersion, fixture.packages, firstOutput); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, exists := os.LookupEnv(privateKeyEnv); exists {
		t.Fatal("generate did not unset the private-key environment variable")
	}
	secondOutput := filepath.Join(t.TempDir(), "second")
	t.Setenv(privateKeyEnv, string(privatePEM))
	if err := generate(fixture.repository, firstSignedVersion, fixture.packages, secondOutput); err != nil {
		t.Fatalf("generate second time: %v", err)
	}
	for _, name := range []string{manifestName, signatureName} {
		first, err := os.ReadFile(filepath.Join(firstOutput, name))
		if err != nil {
			t.Fatal(err)
		}
		second, err := os.ReadFile(filepath.Join(secondOutput, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(second) {
			t.Fatalf("generated %s is not deterministic", name)
		}
	}
}

func TestGenerateFailsClosedOnMissingTrustSecretSymlinkAndCollision(t *testing.T) {
	t.Run("missing secret", func(t *testing.T) {
		fixture := makeManifestFixture(t)
		_ = os.Unsetenv(privateKeyEnv)
		if err := generate(fixture.repository, firstSignedVersion, fixture.packages, filepath.Join(t.TempDir(), "output")); err == nil {
			t.Fatal("missing secret was accepted")
		}
	})
	t.Run("untrusted key", func(t *testing.T) {
		fixture := makeManifestFixture(t)
		other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		der, err := x509.MarshalPKCS8PrivateKey(other)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(privateKeyEnv, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
		if err := generate(fixture.repository, firstSignedVersion, fixture.packages, filepath.Join(t.TempDir(), "output")); err == nil {
			t.Fatal("untrusted signing key was accepted")
		}
	})
	t.Run("package symlink", func(t *testing.T) {
		fixture := makeManifestFixture(t)
		name, err := packageFilename(firstSignedVersion, "deb", "amd64")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fixture.packages, name)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("target\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPackages(fixture.packages, firstSignedVersion, false); err == nil {
			t.Fatal("package symlink was accepted")
		}
	})
	t.Run("output collision", func(t *testing.T) {
		fixture := makeManifestFixture(t)
		output := filepath.Join(t.TempDir(), "output")
		if err := os.Mkdir(output, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, manifestName), []byte("collision\n"), 0600); err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(fixture.privateKey)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(privateKeyEnv, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
		if err := generate(fixture.repository, firstSignedVersion, fixture.packages, output); err == nil {
			t.Fatal("non-empty output directory was accepted")
		}
	})
}

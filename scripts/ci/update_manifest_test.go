package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
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
	return makeVersionedManifestFixture(t, firstSignedVersion)
}

func makeVersionedManifestFixture(t *testing.T, version string) manifestFixture {
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
	names, err := packageNames(version)
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
	records, err := loadPackages(packageDirectory, version, false)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := buildManifest(version, testKeyID, records)
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

func TestVersionedManifestPreventsLegacyTransitionAcceptance(t *testing.T) {
	for _, tc := range []struct{ version, schema string }{
		{"v4.10.4", "syswarden-update-manifest/v1"},
		{"v5.00.0", "syswarden-update-manifest/v3"},
		{"v5.00.1", "syswarden-update-manifest/v3"},
		{"v5.01.0", "syswarden-update-manifest/v3"},
		{"v6.00.0", "syswarden-update-manifest/v3"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			fixture := makeVersionedManifestFixture(t, tc.version)
			candidate := fixture.parsed(t)
			if candidate.Schema != tc.schema {
				t.Fatalf("schema = %q, want %q", candidate.Schema, tc.schema)
			}
			if err := verify(fixture.repository, tc.version, fixture.packages, fixture.manifest, fixture.signature); err != nil {
				t.Fatal(err)
			}
			for _, schema := range []string{"", "syswarden-update-manifest/v1", "syswarden-update-manifest/v2", "syswarden-update-manifest/v3", "syswarden-update-manifest/v4"} {
				if schema == tc.schema {
					continue
				}
				candidate.Schema = schema
				fixture.resign(t, candidate)
				if err := verify(fixture.repository, tc.version, fixture.packages, fixture.manifest, fixture.signature); err == nil {
					t.Fatalf("accepted signed %q schema for %s", schema, tc.version)
				}
			}
		})
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

// These identities were captured from the unchanged v4.10.4 producer using
// makeManifestFixture's existing deterministic public test key and payloads.
func TestVersionedManifestPreservesLegacyCanonicalBytes(t *testing.T) {
	fixture := makeManifestFixture(t)
	data, err := os.ReadFile(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "f314ac0eb859c4bc3a23d3d4d09ce059c4f87323834cb75c5d122fd1ef73d352" {
		t.Fatal("legacy canonical manifest bytes changed")
	}
	signature, err := os.ReadFile(fixture.signature)
	if err != nil {
		t.Fatal(err)
	}
	if string(signature) != "m86FX3KauEnRQxCixLTiqT0ClM5TIGnMeCaWTyTz1ctN8alFCg/LcbuMt3gTWQ0XhJUWZLRqvTih6ZAUBrmyAg==\n" {
		t.Fatal("legacy deterministic signature bytes changed")
	}
}

func TestV3ManifestMatchesSharedWireVector(t *testing.T) {
	t.Parallel()

	// PUBLIC TEST vector: the existing deterministic test key signs metadata
	// for six synthetic payloads. These are not release packages or release keys.
	// The consumer verifies these same files without constructing a replacement.
	fixture := makeVersionedManifestFixture(t, "v5.00.0")
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve producer test source path")
	}
	vectorDirectory := filepath.Join(filepath.Dir(sourcePath), "testdata", "native-identity-v3")
	for _, file := range []struct{ name, generatedPath string }{
		{manifestName, fixture.manifest},
		{signatureName, fixture.signature},
	} {
		want, err := os.ReadFile(filepath.Join(vectorDirectory, file.name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(file.generatedPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("generated %s differs from the shared v3 public test vector", file.name)
		}
	}
}

func TestVersionedManifestRejectsMissingOrUnsupportedRetention(t *testing.T) {
	for _, version := range []string{"v4.10.4", "v5.00.0"} {
		for _, transition := range []string{"", "unknown", "syswarden-native-dependency-retention/v1"} {
			if (version == "v4.10.4" && transition == "") || (version == "v5.00.0" && transition == nativeRetentionContract) {
				continue
			}
			t.Run(version+"/"+transition, func(t *testing.T) {
				fixture := makeVersionedManifestFixture(t, version)
				candidate := fixture.parsed(t)
				candidate.NativeTransition = transition
				fixture.resign(t, candidate)
				if err := verify(fixture.repository, version, fixture.packages, fixture.manifest, fixture.signature); err == nil {
					t.Fatal("accepted incompatible signed retention contract")
				}
			})
		}
	}
}

func TestV3ManifestBindsExactlyBothNativePackageIdentities(t *testing.T) {
	const version = "v5.00.0"
	fixture := makeVersionedManifestFixture(t, version)
	if err := verify(fixture.repository, version, fixture.packages, fixture.manifest, fixture.signature); err != nil {
		t.Fatal(err)
	}
	want := []struct{ name, format, filename string }{
		{"syswarden", "deb", "syswarden_5.00.0_amd64.deb"},
		{"syswarden", "rpm", "syswarden-5.00.0-1.x86_64.rpm"},
		{"syswarden", "apk", "syswarden_5.00.0_x86_64.apk"},
		{"syswarden-base", "deb", "syswarden-base_5.00.0_amd64.deb"},
		{"syswarden-base", "rpm", "syswarden-base-5.00.0-1.x86_64.rpm"},
		{"syswarden-base", "apk", "syswarden-base_5.00.0_x86_64.apk"},
	}
	candidate := fixture.parsed(t)
	if candidate.Schema != "syswarden-update-manifest/v3" || candidate.NativeTransition != nativeRetentionContract || len(candidate.Artifacts) != len(want) {
		t.Fatalf("unexpected signed identity contract: %#v", candidate)
	}
	for index, expected := range want {
		actual := candidate.Artifacts[index]
		if actual.PackageName != expected.name || actual.Format != expected.format || actual.Filename != expected.filename || actual.OS != "linux" || actual.Architecture != "amd64" {
			t.Fatalf("artifact %d = %#v, want %#v", index, actual, expected)
		}
	}
}

func TestV3ManifestRejectsSignedIdentitySubstitution(t *testing.T) {
	tests := map[string]func(*manifest){
		"missing artifact": func(candidate *manifest) { candidate.Artifacts = candidate.Artifacts[:5] },
		"extra artifact": func(candidate *manifest) {
			candidate.Artifacts = append(candidate.Artifacts, candidate.Artifacts[0])
		},
		"duplicate identity":     func(candidate *manifest) { candidate.Artifacts[3] = candidate.Artifacts[0] },
		"missing package name":   func(candidate *manifest) { candidate.Artifacts[3].PackageName = "" },
		"unknown package name":   func(candidate *manifest) { candidate.Artifacts[3].PackageName = "syswarden-custom" },
		"cross package name":     func(candidate *manifest) { candidate.Artifacts[3].PackageName = "syswarden" },
		"cross package filename": func(candidate *manifest) { candidate.Artifacts[3].Filename = candidate.Artifacts[0].Filename },
		"noncanonical order": func(candidate *manifest) {
			candidate.Artifacts[0], candidate.Artifacts[3] = candidate.Artifacts[3], candidate.Artifacts[0]
		},
		"downgraded schema": func(candidate *manifest) { candidate.Schema = "syswarden-update-manifest/v2" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := makeVersionedManifestFixture(t, "v5.00.0")
			candidate := fixture.parsed(t)
			mutate(candidate)
			fixture.resign(t, candidate)
			if err := verify(fixture.repository, "v5.00.0", fixture.packages, fixture.manifest, fixture.signature); err == nil {
				t.Fatal("accepted a signed identity contract violation")
			}
		})
	}
}

func TestV3PackageDirectoryRequiresBothCompleteVariants(t *testing.T) {
	for _, extra := range []bool{false, true} {
		fixture := makeVersionedManifestFixture(t, "v5.00.0")
		if extra {
			if err := os.WriteFile(filepath.Join(fixture.packages, "syswarden-custom_5.00.0_amd64.deb"), []byte("extra"), 0600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Remove(filepath.Join(fixture.packages, "syswarden-base_5.00.0_amd64.deb")); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPackages(fixture.packages, "v5.00.0", false); err == nil {
			t.Fatalf("accepted incomplete or extended v3 package inventory, extra=%v", extra)
		}
	}
}

func TestLegacyManifestRejectsPackageIdentityExtension(t *testing.T) {
	fixture := makeManifestFixture(t)
	candidate := fixture.parsed(t)
	candidate.Artifacts[0].PackageName = "syswarden"
	fixture.resign(t, candidate)
	if err := verify(fixture.repository, firstSignedVersion, fixture.packages, fixture.manifest, fixture.signature); err == nil {
		t.Fatal("accepted package_name in the historical manifest schema")
	}
	for _, name := range []string{"", "syswarden-base", "syswarden-custom"} {
		if _, err := packageFilenameForName("v4.10.4", "deb", "amd64", name); err == nil {
			t.Fatalf("accepted historical package identity %q", name)
		}
	}
}

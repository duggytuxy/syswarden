package system

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	_ "embed"
)

const (
	updateManifestSchema             = "syswarden-update-manifest/v1"
	updateManifestAssetName          = "syswarden-update-manifest-v1.json"
	updateManifestSignatureAssetName = updateManifestAssetName + ".sig"
	maxReleaseAPIBytes               = 1 << 20
	maxManifestBytes                 = 64 << 10
	maxSignatureAssetBytes           = 256
	maxPackageBytes                  = 1 << 30
	packageFormatDEB                 = "deb"
	packageFormatRPM                 = "rpm"
	packageFormatAPK                 = "apk"
	releaseTrustRootsSchema          = "syswarden-release-trust-roots/v1"
)

//go:embed release_trust_roots.json
var embeddedReleaseTrustRoots []byte

type releaseTrustRootSet struct {
	Schema string             `json:"schema"`
	Keys   []releaseTrustRoot `json:"keys"`
}

type releaseTrustRoot struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

type updateManifest struct {
	Schema    string           `json:"schema"`
	KeyID     string           `json:"key_id"`
	Version   string           `json:"version"`
	Artifacts []updateArtifact `json:"artifacts"`
}

type updateArtifact struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

type packageTarget struct {
	os           string
	architecture string
	format       string
	filename     string
	installer    string
}

type releaseVersion struct {
	major int64
	minor int64
	patch int64
}

// embeddedTrustedReleaseKeys parses the canonical public trust-root inventory
// compiled into the updater. Any missing or malformed identity fails closed
// before package bytes are downloaded or installed.
func embeddedTrustedReleaseKeys() (map[string]ed25519.PublicKey, error) {
	decoder := json.NewDecoder(bytes.NewReader(embeddedReleaseTrustRoots))
	decoder.DisallowUnknownFields()
	var roots releaseTrustRootSet
	if err := decoder.Decode(&roots); err != nil {
		return nil, fmt.Errorf("decode embedded release trust roots: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode embedded release trust roots: %w", err)
	}
	canonical, err := json.Marshal(&roots)
	if err != nil {
		return nil, fmt.Errorf("encode embedded release trust roots: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, embeddedReleaseTrustRoots) {
		return nil, errors.New("embedded release trust roots are not canonical JSON")
	}
	if roots.Schema != releaseTrustRootsSchema {
		return nil, fmt.Errorf("unsupported embedded release trust-root schema %q", roots.Schema)
	}
	keys := make(map[string]ed25519.PublicKey, len(roots.Keys))
	previousID := ""
	for _, root := range roots.Keys {
		if !validKeyID(root.ID) {
			return nil, fmt.Errorf("embedded release key ID %q is invalid", root.ID)
		}
		if previousID != "" && root.ID <= previousID {
			return nil, errors.New("embedded release keys must have unique, sorted IDs")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(root.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode embedded release key %q: %w", root.ID, err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("embedded release key %q has length %d, want %d", root.ID, len(decoded), ed25519.PublicKeySize)
		}
		if base64.StdEncoding.EncodeToString(decoded) != root.PublicKey {
			return nil, fmt.Errorf("embedded release key %q is not canonical base64", root.ID)
		}
		keys[root.ID] = ed25519.PublicKey(bytes.Clone(decoded))
		previousID = root.ID
	}
	return keys, nil
}

func parseLatestRelease(data []byte) (string, error) {
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return "", fmt.Errorf("decode release JSON: %w", err)
	}
	if _, err := parseReleaseVersion(release.TagName); err != nil {
		return "", fmt.Errorf("invalid tag_name: %w", err)
	}
	return release.TagName, nil
}

func parseReleaseVersion(raw string) (releaseVersion, error) {
	if len(raw) < len("v1.00.0") || raw[0] != 'v' {
		return releaseVersion{}, fmt.Errorf("invalid SYSWARDEN version %q", raw)
	}
	parts := strings.Split(raw[1:], ".")
	if len(parts) != 3 || parts[0] == "" || len(parts[1]) != 2 || parts[2] == "" {
		return releaseVersion{}, fmt.Errorf("invalid SYSWARDEN version %q", raw)
	}
	if (len(parts[0]) > 1 && parts[0][0] == '0') || (len(parts[2]) > 1 && parts[2][0] == '0') {
		return releaseVersion{}, fmt.Errorf("invalid SYSWARDEN version %q", raw)
	}
	values := make([]int64, len(parts))
	for index, part := range parts {
		for _, character := range part {
			if character < '0' || character > '9' {
				return releaseVersion{}, fmt.Errorf("invalid SYSWARDEN version %q", raw)
			}
		}
		value, err := strconv.ParseInt(part, 10, 31)
		if err != nil {
			return releaseVersion{}, fmt.Errorf("invalid SYSWARDEN version %q: %w", raw, err)
		}
		values[index] = value
	}
	return releaseVersion{major: values[0], minor: values[1], patch: values[2]}, nil
}

func compareReleaseVersions(left, right string) (int, error) {
	leftVersion, err := parseReleaseVersion(left)
	if err != nil {
		return 0, fmt.Errorf("left version: %w", err)
	}
	rightVersion, err := parseReleaseVersion(right)
	if err != nil {
		return 0, fmt.Errorf("right version: %w", err)
	}
	leftValues := [...]int64{leftVersion.major, leftVersion.minor, leftVersion.patch}
	rightValues := [...]int64{rightVersion.major, rightVersion.minor, rightVersion.patch}
	for index := range leftValues {
		if leftValues[index] < rightValues[index] {
			return -1, nil
		}
		if leftValues[index] > rightValues[index] {
			return 1, nil
		}
	}
	return 0, nil
}

func verifySignedManifest(
	manifestBytes, signatureBytes []byte,
	expectedVersion string,
	trustedKeys map[string]ed25519.PublicKey,
) (*updateManifest, error) {
	manifest, err := parseCanonicalManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := trustedKeys[manifest.KeyID]
	if !ok {
		return nil, fmt.Errorf("manifest key ID %q is not trusted", manifest.KeyID)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted key %q has invalid length", manifest.KeyID)
	}
	signature, err := parseCanonicalSignature(signatureBytes)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		return nil, errors.New("Ed25519 manifest signature is invalid")
	}
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	if manifest.Version != expectedVersion {
		return nil, fmt.Errorf("manifest version %q does not match release %q", manifest.Version, expectedVersion)
	}
	return manifest, nil
}

func parseCanonicalManifest(data []byte) (*updateManifest, error) {
	if len(data) == 0 || len(data) > maxManifestBytes {
		return nil, fmt.Errorf("manifest size %d is outside the accepted range", len(data))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest updateManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode update manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	canonical, err := marshalCanonicalManifest(&manifest)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("update manifest is not canonical JSON")
	}
	return &manifest, nil
}

func marshalCanonicalManifest(manifest *updateManifest) ([]byte, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode canonical update manifest: %w", err)
	}
	return append(encoded, '\n'), nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("update manifest contains trailing JSON")
		}
		return fmt.Errorf("decode trailing update manifest data: %w", err)
	}
	return nil
}

func parseCanonicalSignature(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > maxSignatureAssetBytes || data[len(data)-1] != '\n' {
		return nil, errors.New("manifest signature asset is not canonical base64")
	}
	encoded := string(data[:len(data)-1])
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode manifest signature: %w", err)
	}
	if len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("manifest signature length is %d, want %d", len(decoded), ed25519.SignatureSize)
	}
	if base64.StdEncoding.EncodeToString(decoded)+"\n" != string(data) {
		return nil, errors.New("manifest signature asset is not canonical base64")
	}
	return decoded, nil
}

func (manifest *updateManifest) validate() error {
	if manifest.Schema != updateManifestSchema {
		return fmt.Errorf("unsupported update manifest schema %q", manifest.Schema)
	}
	if !validKeyID(manifest.KeyID) {
		return fmt.Errorf("invalid manifest key ID %q", manifest.KeyID)
	}
	if _, err := parseReleaseVersion(manifest.Version); err != nil {
		return fmt.Errorf("invalid manifest version: %w", err)
	}
	expected := expectedManifestIdentities()
	if len(manifest.Artifacts) != len(expected) {
		return fmt.Errorf("manifest contains %d artifacts, want %d", len(manifest.Artifacts), len(expected))
	}
	for index, identity := range expected {
		artifact := manifest.Artifacts[index]
		if artifact.OS != identity.os || artifact.Architecture != identity.architecture || artifact.Format != identity.format {
			return fmt.Errorf(
				"manifest artifact %d identity is %s/%s/%s, want %s/%s/%s",
				index, artifact.OS, artifact.Architecture, artifact.Format,
				identity.os, identity.architecture, identity.format,
			)
		}
		expectedFilename, err := packageFilename(manifest.Version, artifact.Format, artifact.Architecture)
		if err != nil {
			return fmt.Errorf("manifest artifact %d: %w", index, err)
		}
		if artifact.Filename != expectedFilename || !safeAssetName(artifact.Filename) {
			return fmt.Errorf("manifest artifact %d filename %q does not match %q", index, artifact.Filename, expectedFilename)
		}
		if artifact.Size <= 0 || artifact.Size > maxPackageBytes {
			return fmt.Errorf("manifest artifact %d size %d is outside the accepted range", index, artifact.Size)
		}
		if !validSHA256(artifact.SHA256) {
			return fmt.Errorf("manifest artifact %d has an invalid SHA-256 digest", index)
		}
	}
	return nil
}

func expectedManifestIdentities() []packageTarget {
	return []packageTarget{
		{os: "linux", architecture: "amd64", format: packageFormatDEB},
		{os: "linux", architecture: "amd64", format: packageFormatRPM},
		{os: "linux", architecture: "amd64", format: packageFormatAPK},
	}
}

func validKeyID(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '.' {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func detectPackageTarget(
	goos, goarch, version string,
	lookPath func(string) (string, error),
) (packageTarget, error) {
	if goos != "linux" {
		return packageTarget{}, fmt.Errorf("in-place updater does not support operating system %q", goos)
	}
	if goarch != "amd64" {
		return packageTarget{}, fmt.Errorf("in-place updater does not support architecture %q", goarch)
	}
	if lookPath == nil {
		return packageTarget{}, errors.New("package-manager lookup is unavailable")
	}
	managerCandidates := []struct {
		name   string
		format string
	}{
		{name: "apt-get", format: packageFormatDEB},
		{name: "dnf", format: packageFormatRPM},
		{name: "yum", format: packageFormatRPM},
		{name: "apk", format: packageFormatAPK},
	}
	for _, candidate := range managerCandidates {
		resolved, err := lookPath(candidate.name)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(resolved, "/") {
			return packageTarget{}, fmt.Errorf("package manager %q did not resolve to an absolute path", candidate.name)
		}
		if !trustedPackageManagerPath(candidate.name, resolved) {
			return packageTarget{}, fmt.Errorf("package manager %q resolved to untrusted path %q", candidate.name, resolved)
		}
		filename, err := packageFilename(version, candidate.format, goarch)
		if err != nil {
			return packageTarget{}, err
		}
		return packageTarget{
			os:           goos,
			architecture: goarch,
			format:       candidate.format,
			filename:     filename,
			installer:    resolved,
		}, nil
	}
	return packageTarget{}, errors.New("no supported package manager found (apt-get/dnf/yum/apk)")
}

func trustedPackageManagerPath(name, resolved string) bool {
	switch name {
	case "apt-get":
		return resolved == "/usr/bin/apt-get"
	case "dnf":
		return resolved == "/usr/bin/dnf"
	case "yum":
		return resolved == "/usr/bin/yum"
	case "apk":
		return resolved == "/sbin/apk" || resolved == "/usr/sbin/apk"
	default:
		return false
	}
}

func packageFilename(version, format, goarch string) (string, error) {
	if _, err := parseReleaseVersion(version); err != nil {
		return "", err
	}
	cleanVersion := strings.TrimPrefix(version, "v")
	switch format {
	case packageFormatDEB:
		if goarch == "amd64" {
			return fmt.Sprintf("syswarden_%s_amd64.deb", cleanVersion), nil
		}
	case packageFormatRPM:
		if goarch == "amd64" {
			return fmt.Sprintf("syswarden-%s-1.x86_64.rpm", cleanVersion), nil
		}
	case packageFormatAPK:
		if goarch == "amd64" {
			return fmt.Sprintf("syswarden_%s_x86_64.apk", cleanVersion), nil
		}
	}
	return "", fmt.Errorf("unsupported package target format=%q architecture=%q", format, goarch)
}

func (target packageTarget) installArguments(packagePath string) []string {
	switch target.format {
	case packageFormatDEB, packageFormatRPM:
		return []string{"install", "-y", packagePath}
	case packageFormatAPK:
		// APK repository signing is not provisioned yet. The independent
		// Ed25519 manifest is mandatory before this narrowly scoped native
		// package-signature bypass can be reached.
		return []string{"add", "--allow-untrusted", packagePath}
	default:
		return nil
	}
}

func (manifest *updateManifest) artifactFor(target packageTarget) (updateArtifact, error) {
	for _, artifact := range manifest.Artifacts {
		if artifact.OS == target.os && artifact.Architecture == target.architecture && artifact.Format == target.format {
			if artifact.Filename != target.filename {
				return updateArtifact{}, fmt.Errorf("manifest selected filename %q, want %q", artifact.Filename, target.filename)
			}
			return artifact, nil
		}
	}
	return updateArtifact{}, fmt.Errorf("manifest has no artifact for %s/%s/%s", target.os, target.architecture, target.format)
}

// Command update_manifest generates and verifies the deterministic, detached-
// signed manifest consumed by the SysWarden in-place updater.
//
// The PKCS#8 Ed25519 private-key PEM is accepted only through the protected
// SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY environment variable. It is never an
// argument, file, log field, or release artifact.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	manifestSchema       = "syswarden-update-manifest/v1"
	trustRootsSchema     = "syswarden-release-trust-roots/v1"
	manifestName         = "syswarden-update-manifest-v1.json"
	signatureName        = manifestName + ".sig"
	packageChecksumName  = "SHA256SUMS.txt"
	privateKeyEnv        = "SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY"
	firstSignedVersion   = "v4.02.9"
	maxManifestBytes     = 64 << 10
	maxSignatureBytes    = 256
	maxTrustRootsBytes   = 64 << 10
	maxChecksumBytes     = 64 << 10
	maxPackageBytes      = 1 << 30
	trustRootsRepository = "src/core/syswarden-cli/pkg/system/release_trust_roots.json"
)

type trustRootSet struct {
	Schema string      `json:"schema"`
	Keys   []trustRoot `json:"keys"`
}

type trustRoot struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

type manifest struct {
	Schema    string     `json:"schema"`
	KeyID     string     `json:"key_id"`
	Version   string     `json:"version"`
	Artifacts []artifact `json:"artifacts"`
}

type artifact struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

type artifactIdentity struct {
	os           string
	architecture string
	format       string
}

type packageRecord struct {
	name   string
	size   int64
	sha256 string
}

type semanticVersion struct {
	major int64
	minor int64
	patch int64
}

var manifestIdentities = []artifactIdentity{
	{os: "linux", architecture: "amd64", format: "deb"},
	{os: "linux", architecture: "amd64", format: "rpm"},
	{os: "linux", architecture: "amd64", format: "apk"},
}

func parseVersion(raw string) (semanticVersion, error) {
	if len(raw) < len("v1.00.0") || raw[0] != 'v' {
		return semanticVersion{}, fmt.Errorf("invalid SysWarden version %q", raw)
	}
	parts := strings.Split(raw[1:], ".")
	if len(parts) != 3 || parts[0] == "" || len(parts[1]) != 2 || parts[2] == "" {
		return semanticVersion{}, fmt.Errorf("invalid SysWarden version %q", raw)
	}
	if (len(parts[0]) > 1 && parts[0][0] == '0') || (len(parts[2]) > 1 && parts[2][0] == '0') {
		return semanticVersion{}, fmt.Errorf("invalid SysWarden version %q", raw)
	}
	values := make([]int64, 3)
	for index, part := range parts {
		for _, character := range part {
			if character < '0' || character > '9' {
				return semanticVersion{}, fmt.Errorf("invalid SysWarden version %q", raw)
			}
		}
		value, err := strconv.ParseInt(part, 10, 31)
		if err != nil {
			return semanticVersion{}, fmt.Errorf("invalid SysWarden version %q", raw)
		}
		values[index] = value
	}
	return semanticVersion{major: values[0], minor: values[1], patch: values[2]}, nil
}

func compareVersions(left, right string) (int, error) {
	leftVersion, err := parseVersion(left)
	if err != nil {
		return 0, err
	}
	rightVersion, err := parseVersion(right)
	if err != nil {
		return 0, err
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

func requireSignedVersion(tag string) error {
	comparison, err := compareVersions(tag, firstSignedVersion)
	if err != nil {
		return err
	}
	if comparison < 0 {
		return fmt.Errorf("release %s predates signed update manifests (%s)", tag, firstSignedVersion)
	}
	return nil
}

func packageFilename(tag, format, architecture string) (string, error) {
	if _, err := parseVersion(tag); err != nil {
		return "", err
	}
	version := strings.TrimPrefix(tag, "v")
	switch format {
	case "deb":
		if architecture == "amd64" {
			return fmt.Sprintf("syswarden_%s_amd64.deb", version), nil
		}
	case "rpm":
		if architecture == "amd64" {
			return fmt.Sprintf("syswarden-%s-1.x86_64.rpm", version), nil
		}
	case "apk":
		if architecture == "amd64" {
			return fmt.Sprintf("syswarden_%s_x86_64.apk", version), nil
		}
	}
	return "", fmt.Errorf("unsupported package target %s/%s", format, architecture)
}

func packageNames(tag string) ([]string, error) {
	if _, err := parseVersion(tag); err != nil {
		return nil, err
	}
	version := strings.TrimPrefix(tag, "v")
	return []string{
		fmt.Sprintf("syswarden_%s_amd64.deb", version),
		fmt.Sprintf("syswarden-%s-1.x86_64.rpm", version),
		fmt.Sprintf("syswarden_%s_x86_64.apk", version),
	}, nil
}

func canonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical JSON: %w", err)
	}
	return append(data, '\n'), nil
}

func decodeStrictJSON(data []byte, destination any, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%s contains trailing JSON", label)
		}
		return fmt.Errorf("decode trailing %s data: %w", label, err)
	}
	return nil
}

func validKeyID(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '.' {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._-", character) {
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

func rejectSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path %s: %w", path, err)
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect path component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are forbidden in path %s", path)
		}
	}
	return nil
}

func readRegular(path string, limit int64, label string) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid file-size limit")
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", label)
	}
	if before.Size() <= 0 || before.Size() > limit {
		return nil, fmt.Errorf("%s size %d is outside the accepted range", label, before.Size())
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open %s: %w", label, err)
	}
	if !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("%s changed while it was opened", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the accepted size", label)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return nil, fmt.Errorf("%s changed while it was read", label)
	}
	return data, nil
}

func readTrustRoots(repository string) (map[string]ed25519.PublicKey, error) {
	path := filepath.Join(repository, filepath.FromSlash(trustRootsRepository))
	data, err := readRegular(path, maxTrustRootsBytes, "embedded release trust roots")
	if err != nil {
		return nil, err
	}
	var roots trustRootSet
	if err := decodeStrictJSON(data, &roots, "embedded release trust roots"); err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(&roots)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("embedded release trust roots are not canonical JSON")
	}
	if roots.Schema != trustRootsSchema {
		return nil, fmt.Errorf("unsupported release trust-root schema %q", roots.Schema)
	}
	keys := make(map[string]ed25519.PublicKey, len(roots.Keys))
	previousID := ""
	for _, root := range roots.Keys {
		if !validKeyID(root.ID) {
			return nil, fmt.Errorf("invalid embedded release key ID %q", root.ID)
		}
		if previousID != "" && root.ID <= previousID {
			return nil, errors.New("embedded release key IDs must be unique and sorted")
		}
		publicKey, err := base64.StdEncoding.Strict().DecodeString(root.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(publicKey) != root.PublicKey {
			return nil, fmt.Errorf("embedded release public key %q is invalid", root.ID)
		}
		keys[root.ID] = ed25519.PublicKey(bytes.Clone(publicKey))
		previousID = root.ID
	}
	return keys, nil
}

func parseChecksumManifest(data []byte, expectedNames []string) (map[string]string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("package checksum manifest must end with one newline")
	}
	records := make(map[string]string, len(expectedNames))
	for lineNumber, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || !validSHA256(parts[0]) || !safeFilename(parts[1]) {
			return nil, fmt.Errorf("invalid package checksum record at line %d", lineNumber+1)
		}
		if _, exists := records[parts[1]]; exists {
			return nil, fmt.Errorf("duplicate package checksum for %s", parts[1])
		}
		records[parts[1]] = parts[0]
	}
	expected := append([]string(nil), expectedNames...)
	sort.Strings(expected)
	actual := make([]string, 0, len(records))
	for name := range records {
		actual = append(actual, name)
	}
	sort.Strings(actual)
	if !equalStrings(actual, expected) {
		return nil, fmt.Errorf("package checksum inventory mismatch; expected=%v actual=%v", expected, actual)
	}
	return records, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func safeFilename(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && !strings.ContainsAny(name, `/\\`)
}

func hashPackage(path string) (int64, string, error) {
	if err := rejectSymlinkComponents(path); err != nil {
		return 0, "", err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return 0, "", fmt.Errorf("inspect package: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxPackageBytes {
		return 0, "", fmt.Errorf("package %s is not a non-empty bounded regular file", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("open package: %w", err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return 0, "", fmt.Errorf("package %s changed while it was opened", filepath.Base(path))
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maxPackageBytes+1))
	if err != nil {
		return 0, "", fmt.Errorf("hash package %s: %w", filepath.Base(path), err)
	}
	if written != before.Size() || written > maxPackageBytes {
		return 0, "", fmt.Errorf("package %s changed while it was hashed", filepath.Base(path))
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
		return 0, "", fmt.Errorf("package %s changed while it was hashed", filepath.Base(path))
	}
	return written, hex.EncodeToString(digest.Sum(nil)), nil
}

func loadPackages(directory, tag string, allowAdditionalFiles bool) (map[string]packageRecord, error) {
	if err := rejectSymlinkComponents(directory); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("package directory is missing or not a real directory")
	}
	names, err := packageNames(tag)
	if err != nil {
		return nil, err
	}
	expected := append(append([]string(nil), names...), packageChecksumName)
	sort.Strings(expected)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read package directory: %w", err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("package directory contains unsupported entry %s", entry.Name())
		}
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	if !allowAdditionalFiles && !equalStrings(actual, expected) {
		return nil, fmt.Errorf("package directory inventory mismatch; expected=%v actual=%v", expected, actual)
	}
	if allowAdditionalFiles {
		actualSet := make(map[string]struct{}, len(actual))
		for _, name := range actual {
			actualSet[name] = struct{}{}
		}
		for _, name := range expected {
			if _, exists := actualSet[name]; !exists {
				return nil, fmt.Errorf("release asset directory is missing package input %s", name)
			}
		}
	}
	checksumData, err := readRegular(filepath.Join(directory, packageChecksumName), maxChecksumBytes, "package checksum manifest")
	if err != nil {
		return nil, err
	}
	checksums, err := parseChecksumManifest(checksumData, names)
	if err != nil {
		return nil, err
	}
	records := make(map[string]packageRecord, len(names))
	for _, name := range names {
		size, digest, err := hashPackage(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		if digest != checksums[name] {
			return nil, fmt.Errorf("package checksum mismatch for %s", name)
		}
		records[name] = packageRecord{name: name, size: size, sha256: digest}
	}
	return records, nil
}

func buildManifest(tag, keyID string, packages map[string]packageRecord) (*manifest, error) {
	result := &manifest{Schema: manifestSchema, KeyID: keyID, Version: tag}
	for _, identity := range manifestIdentities {
		name, err := packageFilename(tag, identity.format, identity.architecture)
		if err != nil {
			return nil, err
		}
		record, exists := packages[name]
		if !exists {
			return nil, fmt.Errorf("package record %s is missing", name)
		}
		result.Artifacts = append(result.Artifacts, artifact{
			OS:           identity.os,
			Architecture: identity.architecture,
			Format:       identity.format,
			Filename:     record.name,
			Size:         record.size,
			SHA256:       record.sha256,
		})
	}
	return result, nil
}

func validateManifestStructure(candidate *manifest, tag string) error {
	if candidate.Schema != manifestSchema {
		return fmt.Errorf("unsupported update manifest schema %q", candidate.Schema)
	}
	if !validKeyID(candidate.KeyID) {
		return fmt.Errorf("invalid update manifest key ID %q", candidate.KeyID)
	}
	if candidate.Version != tag {
		return fmt.Errorf("manifest version %q does not match release %q", candidate.Version, tag)
	}
	if err := requireSignedVersion(candidate.Version); err != nil {
		return err
	}
	if len(candidate.Artifacts) != len(manifestIdentities) {
		return fmt.Errorf("manifest contains %d artifacts, expected %d", len(candidate.Artifacts), len(manifestIdentities))
	}
	for index, identity := range manifestIdentities {
		item := candidate.Artifacts[index]
		if item.OS != identity.os || item.Architecture != identity.architecture || item.Format != identity.format {
			return fmt.Errorf("manifest artifact %d has the wrong OS/architecture/format identity", index)
		}
		name, err := packageFilename(tag, item.Format, item.Architecture)
		if err != nil {
			return err
		}
		if item.Filename != name || !safeFilename(item.Filename) {
			return fmt.Errorf("manifest artifact %d has invalid filename %q", index, item.Filename)
		}
		if item.Size <= 0 || item.Size > maxPackageBytes || !validSHA256(item.SHA256) {
			return fmt.Errorf("manifest artifact %d has invalid size or SHA-256", index)
		}
	}
	return nil
}

func parseCanonicalManifest(data []byte, tag string) (*manifest, error) {
	if len(data) == 0 || len(data) > maxManifestBytes {
		return nil, errors.New("update manifest size is outside the accepted range")
	}
	var candidate manifest
	if err := decodeStrictJSON(data, &candidate, "update manifest"); err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(&candidate)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("update manifest is not canonical JSON")
	}
	if err := validateManifestStructure(&candidate, tag); err != nil {
		return nil, err
	}
	return &candidate, nil
}

func parseCanonicalSignature(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > maxSignatureBytes || data[len(data)-1] != '\n' {
		return nil, errors.New("manifest signature is not canonical base64")
	}
	encoded := string(data[:len(data)-1])
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature)+"\n" != string(data) {
		return nil, errors.New("manifest signature is not canonical base64")
	}
	return signature, nil
}

func verify(repository, tag, packageDirectory, manifestPath, signaturePath string) error {
	if err := requireSignedVersion(tag); err != nil {
		return err
	}
	trustedKeys, err := readTrustRoots(repository)
	if err != nil {
		return err
	}
	if len(trustedKeys) == 0 {
		return errors.New("no trusted Ed25519 release keys are embedded")
	}
	manifestData, err := readRegular(manifestPath, maxManifestBytes, "update manifest")
	if err != nil {
		return err
	}
	candidate, err := parseCanonicalManifest(manifestData, tag)
	if err != nil {
		return err
	}
	publicKey, exists := trustedKeys[candidate.KeyID]
	if !exists {
		return fmt.Errorf("manifest key ID %q is not trusted", candidate.KeyID)
	}
	signatureData, err := readRegular(signaturePath, maxSignatureBytes, "manifest signature")
	if err != nil {
		return err
	}
	signature, err := parseCanonicalSignature(signatureData)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, manifestData, signature) {
		return errors.New("Ed25519 update manifest signature is invalid")
	}
	packages, err := loadPackages(packageDirectory, tag, true)
	if err != nil {
		return err
	}
	for _, item := range candidate.Artifacts {
		record := packages[item.Filename]
		if record.size != item.Size || record.sha256 != item.SHA256 {
			return fmt.Errorf("manifest metadata does not match package %s", item.Filename)
		}
	}
	return nil
}

func decodePrivateKey() (ed25519.PrivateKey, error) {
	encoded, exists := os.LookupEnv(privateKeyEnv)
	_ = os.Unsetenv(privateKeyEnv)
	if !exists || encoded == "" {
		return nil, fmt.Errorf("protected environment variable %s is required", privateKeyEnv)
	}
	encodedBytes := []byte(encoded)
	defer wipe(encodedBytes)
	block, remainder := pem.Decode(encodedBytes)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, fmt.Errorf("protected environment variable %s is not one PKCS#8 Ed25519 PRIVATE KEY PEM block", privateKeyEnv)
	}
	defer wipe(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("protected environment variable %s is not a valid PKCS#8 Ed25519 private key", privateKeyEnv)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("protected environment variable %s does not contain an Ed25519 private key", privateKeyEnv)
	}
	return ed25519.PrivateKey(bytes.Clone(privateKey)), nil
}

func selectSigningIdentity(keys map[string]ed25519.PublicKey, publicKey ed25519.PublicKey) (string, error) {
	matching := ""
	for keyID, trustedKey := range keys {
		if bytes.Equal(trustedKey, publicKey) {
			if matching != "" {
				return "", errors.New("the signing public key has multiple embedded identities")
			}
			matching = keyID
		}
	}
	if matching == "" {
		return "", errors.New("the signing public key is not present in the embedded trust roots")
	}
	return matching, nil
}

func ensureEmptyOutput(directory string) (bool, error) {
	parent := filepath.Dir(directory)
	if err := rejectSymlinkComponents(parent); err != nil {
		return false, err
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(directory, 0700); err != nil {
			return false, fmt.Errorf("create manifest output directory: %w", err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect manifest output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("manifest output must be a real directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, fmt.Errorf("read manifest output directory: %w", err)
	}
	if len(entries) != 0 {
		return false, errors.New("manifest output directory must be empty")
	}
	return false, nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create %s with O_EXCL: %w", filepath.Base(path), err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	written, err := file.Write(data)
	if err != nil || written != len(data) {
		return fmt.Errorf("write %s", filepath.Base(path))
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	success = true
	return nil
}

func wipe(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func generate(repository, tag, packageDirectory, output string) (returnErr error) {
	if err := requireSignedVersion(tag); err != nil {
		return err
	}
	trustedKeys, err := readTrustRoots(repository)
	if err != nil {
		return err
	}
	if len(trustedKeys) == 0 {
		return errors.New("no trusted Ed25519 release keys are embedded")
	}
	privateKey, err := decodePrivateKey()
	if err != nil {
		return err
	}
	defer wipe(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := selectSigningIdentity(trustedKeys, publicKey)
	if err != nil {
		return err
	}
	packages, err := loadPackages(packageDirectory, tag, false)
	if err != nil {
		return err
	}
	candidate, err := buildManifest(tag, keyID, packages)
	if err != nil {
		return err
	}
	manifestData, err := canonicalJSON(candidate)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(privateKey, manifestData)
	signatureData := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
	wipe(signature)

	createdDirectory, err := ensureEmptyOutput(output)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(output, manifestName)
	signaturePath := filepath.Join(output, signatureName)
	defer func() {
		if returnErr != nil {
			_ = os.Remove(manifestPath)
			_ = os.Remove(signaturePath)
			if createdDirectory {
				_ = os.Remove(output)
			}
		}
	}()
	if err := writeExclusive(manifestPath, manifestData); err != nil {
		return err
	}
	if err := writeExclusive(signaturePath, signatureData); err != nil {
		return err
	}
	if err := verify(repository, tag, packageDirectory, manifestPath, signaturePath); err != nil {
		return fmt.Errorf("self-verify generated update manifest: %w", err)
	}
	return nil
}

func generateCommand(arguments []string) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repository := flags.String("repository", "", "repository root")
	tag := flags.String("tag", "", "release tag")
	packages := flags.String("packages", "", "qualified package directory")
	output := flags.String("output", "", "empty output directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *repository == "" || *tag == "" || *packages == "" || *output == "" {
		return errors.New("usage: update_manifest generate --repository DIR --tag TAG --packages DIR --output DIR")
	}
	return generate(*repository, *tag, *packages, *output)
}

func verifyCommand(arguments []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repository := flags.String("repository", "", "repository root")
	tag := flags.String("tag", "", "release tag")
	packages := flags.String("packages", "", "qualified package directory")
	manifestPath := flags.String("manifest", "", "manifest path")
	signaturePath := flags.String("signature", "", "signature path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *repository == "" || *tag == "" || *packages == "" || *manifestPath == "" || *signaturePath == "" {
		return errors.New("usage: update_manifest verify --repository DIR --tag TAG --packages DIR --manifest FILE --signature FILE")
	}
	return verify(*repository, *tag, *packages, *manifestPath, *signaturePath)
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: update_manifest <generate|verify> [options]")
	}
	switch arguments[0] {
	case "generate":
		return generateCommand(arguments[1:])
	case "verify":
		return verifyCommand(arguments[1:])
	default:
		return fmt.Errorf("unknown update manifest command %q", arguments[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

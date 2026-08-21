package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syswarden-cli/config"
	"time"
	"unicode/utf8"
)

const (
	haFenceManifestVersion          = 1
	haFenceInventoryVersion         = 1
	haFenceMembershipDigestHeader   = "syswarden-ha-membership-v1\n"
	haFenceLegacyWriterDigestHeader = "syswarden-ha-legacy-writers-v1\n"
	haFenceCapabilityName           = "native_sync_fence_v1"
	haFenceChallengeRequestHeader   = "X-SysWarden-HA-Challenge"
	haFenceConditionResponseHeader  = "X-SysWarden-HA-Fence-Condition"
	maxHAFenceManifestBytes         = 1024 * 1024
)

var (
	haFenceWriterIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	haFenceUUIDv4RE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	haFenceProofRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

type HAFenceMember struct {
	Address                  string `json:"address"`
	Port                     int    `json:"port"`
	TLSLeafCertificateSHA256 string `json:"tls_leaf_certificate_sha256"`
}

type HAFenceManifest struct {
	SchemaVersion               int             `json:"schema_version"`
	Epoch                       string          `json:"epoch"`
	MembershipScope             string          `json:"membership_scope"`
	OperatorAssertedComplete    bool            `json:"operator_asserted_complete"`
	MembershipSHA256            string          `json:"membership_sha256"`
	LegacyWriterInventorySHA256 string          `json:"legacy_writer_inventory_sha256"`
	LegacyWriterIDs             []string        `json:"legacy_writer_ids"`
	Members                     []HAFenceMember `json:"members"`
}

type HAFenceInventoryMember struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type HAFenceInventory struct {
	SchemaVersion   int                      `json:"schema_version"`
	MembershipScope string                   `json:"membership_scope"`
	LegacyWriterIDs []string                 `json:"legacy_writer_ids"`
	Members         []HAFenceInventoryMember `json:"members"`
}

type haFenceStatusWire struct {
	APIVersion      string   `json:"api_version"`
	Capabilities    []string `json:"capabilities"`
	NativeSyncFence struct {
		Version                     int     `json:"version"`
		Scope                       string  `json:"scope"`
		State                       string  `json:"state"`
		Epoch                       string  `json:"epoch"`
		MembershipSHA256            string  `json:"membership_sha256"`
		LegacyWriterInventorySHA256 string  `json:"legacy_writer_inventory_sha256"`
		Generation                  uint64  `json:"generation"`
		ServerInstanceID            string  `json:"server_instance_id"`
		Condition                   string  `json:"condition"`
		DrainedAt                   *string `json:"drained_at"`
		Challenge                   *string `json:"challenge"`
	} `json:"native_sync_fence"`
}

func canonicalHAFenceAddress(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "[]/") {
		return "", fmt.Errorf("manifest address must be a canonical IP literal")
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != value {
		return "", fmt.Errorf("manifest address %q is not canonical", value)
	}
	return value, nil
}

func canonicalHAFenceMemberLine(member HAFenceMember) (string, error) {
	address, err := canonicalHAFenceAddress(member.Address)
	if err != nil {
		return "", err
	}
	if member.Port < 1 || member.Port > 65535 {
		return "", fmt.Errorf("manifest port is outside 1..65535")
	}
	if !validLowerSHA256(member.TLSLeafCertificateSHA256) {
		return "", fmt.Errorf("manifest leaf certificate fingerprint must be lowercase SHA-256")
	}
	return address + "\t" + strconv.Itoa(member.Port) + "\t" + member.TLSLeafCertificateSHA256 + "\n", nil
}

func HAFenceMembershipPreimage(members []HAFenceMember) ([]byte, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("manifest must contain at least one member")
	}
	lines := make([]string, 0, len(members))
	endpoints := make(map[string]struct{}, len(members))
	fingerprints := make(map[string]struct{}, len(members))
	for _, member := range members {
		line, err := canonicalHAFenceMemberLine(member)
		if err != nil {
			return nil, err
		}
		endpoint := member.Address + "\x00" + strconv.Itoa(member.Port)
		if _, duplicate := endpoints[endpoint]; duplicate {
			return nil, fmt.Errorf("manifest contains a duplicate endpoint")
		}
		if _, duplicate := fingerprints[member.TLSLeafCertificateSHA256]; duplicate {
			return nil, fmt.Errorf("manifest contains a duplicate leaf certificate identity")
		}
		endpoints[endpoint] = struct{}{}
		fingerprints[member.TLSLeafCertificateSHA256] = struct{}{}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	var builder strings.Builder
	builder.WriteString(haFenceMembershipDigestHeader)
	for _, line := range lines {
		builder.WriteString(line)
	}
	return []byte(builder.String()), nil
}

func HAFenceMembershipDigest(members []HAFenceMember) (string, error) {
	preimage, err := HAFenceMembershipPreimage(members)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

func HAFenceLegacyWriterPreimage(writerIDs []string) ([]byte, error) {
	previous := ""
	var builder strings.Builder
	builder.WriteString(haFenceLegacyWriterDigestHeader)
	for index, writerID := range writerIDs {
		if !haFenceWriterIDRE.MatchString(writerID) {
			return nil, fmt.Errorf("legacy writer identifier %q is not canonical", writerID)
		}
		if index > 0 && writerID <= previous {
			return nil, fmt.Errorf("legacy writer identifiers must be sorted and unique")
		}
		previous = writerID
		builder.WriteString(writerID)
		builder.WriteByte('\n')
	}
	return []byte(builder.String()), nil
}

func HAFenceLegacyWriterDigest(writerIDs []string) (string, error) {
	preimage, err := HAFenceLegacyWriterPreimage(writerIDs)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalizeHAFenceMembers(members []HAFenceMember) ([]HAFenceMember, error) {
	canonical := append([]HAFenceMember(nil), members...)
	sort.Slice(canonical, func(i, j int) bool {
		left, _ := canonicalHAFenceMemberLine(canonical[i])
		right, _ := canonicalHAFenceMemberLine(canonical[j])
		return left < right
	})
	if _, err := HAFenceMembershipPreimage(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

func canonicalHAFenceManifestBytes(manifest HAFenceManifest) ([]byte, error) {
	wire, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(wire, '\n'), nil
}

func validateHAFenceManifest(manifest *HAFenceManifest) error {
	if manifest == nil || manifest.SchemaVersion != haFenceManifestVersion ||
		manifest.MembershipScope != cliHAFenceMembershipScope || !manifest.OperatorAssertedComplete ||
		!haFenceUUIDv4RE.MatchString(manifest.Epoch) || manifest.LegacyWriterIDs == nil {
		return fmt.Errorf("invalid HA fence manifest envelope")
	}
	canonicalMembers, err := canonicalizeHAFenceMembers(manifest.Members)
	if err != nil {
		return err
	}
	for index := range canonicalMembers {
		if canonicalMembers[index] != manifest.Members[index] {
			return fmt.Errorf("manifest members are not in canonical order")
		}
	}
	membershipDigest, err := HAFenceMembershipDigest(manifest.Members)
	if err != nil || membershipDigest != manifest.MembershipSHA256 {
		return fmt.Errorf("manifest membership digest mismatch")
	}
	writerDigest, err := HAFenceLegacyWriterDigest(manifest.LegacyWriterIDs)
	if err != nil || writerDigest != manifest.LegacyWriterInventorySHA256 {
		return fmt.Errorf("manifest legacy-writer digest mismatch")
	}
	return nil
}

func readProtectedHAFile(path string, expectedOwnerUID int, maximum int64) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || cleanPath != path || cleanPath == string(filepath.Separator) {
		return nil, fmt.Errorf("protected HA path must be absolute")
	}
	root, name, err := openSafeHAStatusDirectory(cleanPath, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFileOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return nil, fmt.Errorf("protected HA file must be a regular 0600 file owned by UID %d", expectedOwnerUID)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("protected HA file changed while opening")
	}
	wire, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(wire)) > maximum {
		return nil, fmt.Errorf("protected HA file exceeds %d bytes", maximum)
	}
	return wire, nil
}

func decodeStrictHAJSON(wire []byte, value any) error {
	if len(wire) == 0 || !utf8.Valid(wire) || bytes.HasPrefix(wire, []byte{0xef, 0xbb, 0xbf}) {
		return fmt.Errorf("HA JSON is empty, invalid UTF-8, or has a byte-order mark")
	}
	if err := rejectCLIHALedgerDuplicateKeys(wire); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("HA JSON contains trailing data")
	}
	return nil
}

func readHAFenceManifest(path string, expectedOwnerUID int) (*HAFenceManifest, []byte, error) {
	wire, err := readProtectedHAFile(path, expectedOwnerUID, maxHAFenceManifestBytes)
	if err != nil {
		return nil, nil, err
	}
	var manifest HAFenceManifest
	if err := decodeStrictHAJSON(wire, &manifest); err != nil {
		return nil, nil, fmt.Errorf("decode HA fence manifest: %w", err)
	}
	if err := validateHAFenceManifest(&manifest); err != nil {
		return nil, nil, err
	}
	canonical, err := canonicalHAFenceManifestBytes(manifest)
	if err != nil || !bytes.Equal(wire, canonical) {
		return nil, nil, fmt.Errorf("HA fence manifest bytes are not canonical")
	}
	return &manifest, wire, nil
}

func VerifyHAFenceManifest(path string) (*HAFenceManifest, error) {
	manifest, _, err := readHAFenceManifest(path, 0)
	return manifest, err
}

func generateHAFenceUUIDv4(source io.Reader) (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(source, raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func writeProtectedHAFile(path string, expectedOwnerUID int, wire []byte) error {
	root, name, err := openSafeHAStatusDirectory(filepath.Clean(path), expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockHAStatusDirectory(root)
	if err != nil {
		return err
	}
	defer unlockHAStatusDirectory(lock)
	if _, exists, err := inspectHAStatusDestination(root, name, expectedOwnerUID); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("refuse to replace an existing protected HA file")
	}
	return publishHAStatusAtomically(root, name, expectedOwnerUID, wire)
}

type haFenceCreateOptions struct {
	client           *http.Client
	token            string
	random           io.Reader
	expectedOwnerUID int
	requestTimeout   time.Duration
}

func defaultHAFenceCreateOptions() (haFenceCreateOptions, error) {
	client, err := newVerifiedHAHTTPClient(defaultHACAFile, defaultHARequestTimeout)
	if err != nil {
		return haFenceCreateOptions{}, err
	}
	return haFenceCreateOptions{
		client: client, token: config.GlobalConfig.HAToken, random: rand.Reader,
		expectedOwnerUID: 0, requestTimeout: defaultHARequestTimeout,
	}, nil
}

func validateHAFenceInventory(inventory *HAFenceInventory) error {
	if inventory == nil || inventory.SchemaVersion != haFenceInventoryVersion || inventory.MembershipScope != cliHAFenceMembershipScope ||
		inventory.LegacyWriterIDs == nil || len(inventory.Members) == 0 {
		return fmt.Errorf("invalid HA fence inventory envelope")
	}
	writers := append([]string(nil), inventory.LegacyWriterIDs...)
	sort.Strings(writers)
	if _, err := HAFenceLegacyWriterPreimage(writers); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(inventory.Members))
	for _, member := range inventory.Members {
		if _, err := canonicalHAFenceAddress(member.Address); err != nil || member.Port < 1 || member.Port > 65535 {
			return fmt.Errorf("invalid HA fence inventory member")
		}
		key := member.Address + "\x00" + strconv.Itoa(member.Port)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("HA fence inventory contains a duplicate endpoint")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func haFenceStatusURL(member HAFenceInventoryMember) string {
	return "https://" + net.JoinHostPort(member.Address, strconv.Itoa(member.Port)) + "/ha/status"
}

func newHAFenceChallenge(source io.Reader) (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(source, raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func validHAFenceProofToken(value string) bool {
	if !haFenceProofRE.MatchString(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func hasHANoStoreDirective(value string) bool {
	for _, directive := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
			return true
		}
	}
	return false
}

func probeHAFenceMember(ctx context.Context, member HAFenceInventoryMember, options haFenceCreateOptions) (HAFenceMember, error) {
	challenge, err := newHAFenceChallenge(options.random)
	if err != nil {
		return HAFenceMember{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, options.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, haFenceStatusURL(member), nil)
	if err != nil {
		return HAFenceMember{}, err
	}
	request.Header.Set("Authorization", "Bearer "+options.token)
	request.Header.Set(haFenceChallengeRequestHeader, challenge)
	response, err := options.client.Do(request)
	if err != nil {
		return HAFenceMember{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return HAFenceMember{}, fmt.Errorf("HA fence member status or verified TLS identity is unavailable")
	}
	if !hasHANoStoreDirective(response.Header.Get("Cache-Control")) {
		return HAFenceMember{}, fmt.Errorf("HA fence member status is cacheable")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxHAResponseBytes+1))
	if err != nil || len(wire) > maxHAResponseBytes {
		return HAFenceMember{}, fmt.Errorf("HA fence member status exceeds its response bound")
	}
	if err := rejectCLIHALedgerDuplicateKeys(wire); err != nil {
		return HAFenceMember{}, fmt.Errorf("decode HA fence member status: %w", err)
	}
	var status haFenceStatusWire
	if err := json.Unmarshal(wire, &status); err != nil {
		return HAFenceMember{}, fmt.Errorf("decode HA fence member status: %w", err)
	}
	supportCount := 0
	for _, capability := range status.Capabilities {
		if capability == haFenceCapabilityName {
			supportCount++
		}
	}
	if status.APIVersion != "2" || supportCount != 1 || status.NativeSyncFence.Version != cliHAFenceVersion ||
		status.NativeSyncFence.Scope != "legacy_ips_mutations" || status.NativeSyncFence.Generation == 0 ||
		!validHAFenceProofToken(status.NativeSyncFence.ServerInstanceID) ||
		status.NativeSyncFence.State != cliHAFenceStateInactive || status.NativeSyncFence.Epoch != "" ||
		status.NativeSyncFence.MembershipSHA256 != "" || status.NativeSyncFence.LegacyWriterInventorySHA256 != "" ||
		status.NativeSyncFence.Condition != "" || status.NativeSyncFence.DrainedAt != nil ||
		len(response.Header.Values(haFenceConditionResponseHeader)) != 0 ||
		status.NativeSyncFence.Challenge == nil || *status.NativeSyncFence.Challenge != challenge {
		return HAFenceMember{}, fmt.Errorf("HA fence member did not return a fresh capability proof")
	}
	digest := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	return HAFenceMember{
		Address: member.Address, Port: member.Port,
		TLSLeafCertificateSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

func createHAFenceManifest(ctx context.Context, inventoryPath, outputPath string, assertComplete bool, options haFenceCreateOptions) (*HAFenceManifest, error) {
	if !assertComplete {
		return nil, fmt.Errorf("HA fence manifest creation requires --assert-complete")
	}
	if options.client == nil || options.random == nil || options.requestTimeout <= 0 || options.token == "" || strings.TrimSpace(options.token) != options.token {
		return nil, fmt.Errorf("HA fence manifest creation is not safely configured")
	}
	wire, err := readProtectedHAFile(inventoryPath, options.expectedOwnerUID, maxHAFenceManifestBytes)
	if err != nil {
		return nil, err
	}
	var inventory HAFenceInventory
	if err := decodeStrictHAJSON(wire, &inventory); err != nil {
		return nil, fmt.Errorf("decode HA fence inventory: %w", err)
	}
	if err := validateHAFenceInventory(&inventory); err != nil {
		return nil, err
	}
	members := make([]HAFenceMember, 0, len(inventory.Members))
	for _, member := range inventory.Members {
		verified, err := probeHAFenceMember(ctx, member, options)
		if err != nil {
			return nil, fmt.Errorf("verify HA fence member %s:%d: %w", member.Address, member.Port, err)
		}
		members = append(members, verified)
	}
	members, err = canonicalizeHAFenceMembers(members)
	if err != nil {
		return nil, err
	}
	writers := append([]string(nil), inventory.LegacyWriterIDs...)
	sort.Strings(writers)
	membershipDigest, err := HAFenceMembershipDigest(members)
	if err != nil {
		return nil, err
	}
	writerDigest, err := HAFenceLegacyWriterDigest(writers)
	if err != nil {
		return nil, err
	}
	epoch, err := generateHAFenceUUIDv4(options.random)
	if err != nil {
		return nil, err
	}
	manifest := &HAFenceManifest{
		SchemaVersion: haFenceManifestVersion, Epoch: epoch,
		MembershipScope: cliHAFenceMembershipScope, OperatorAssertedComplete: true,
		MembershipSHA256: membershipDigest, LegacyWriterInventorySHA256: writerDigest,
		LegacyWriterIDs: writers, Members: members,
	}
	if err := validateHAFenceManifest(manifest); err != nil {
		return nil, err
	}
	manifestWire, err := canonicalHAFenceManifestBytes(*manifest)
	if err != nil {
		return nil, err
	}
	if err := writeProtectedHAFile(outputPath, options.expectedOwnerUID, manifestWire); err != nil {
		return nil, err
	}
	return manifest, nil
}

func CreateHAFenceManifest(ctx context.Context, inventoryPath, outputPath string, assertComplete bool) (*HAFenceManifest, error) {
	options, err := defaultHAFenceCreateOptions()
	if err != nil {
		return nil, err
	}
	return createHAFenceManifest(ctx, inventoryPath, outputPath, assertComplete, options)
}

func tlsLeafFingerprintFromPEM(path string, expectedOwnerUID int) (string, error) {
	wire, err := readProtectedHAFile(path, expectedOwnerUID, maxHAFenceManifestBytes)
	if err != nil {
		return "", err
	}
	if !bytes.HasPrefix(wire, []byte("-----BEGIN CERTIFICATE-----\n")) {
		return "", fmt.Errorf("HA TLS leaf file must begin with one CERTIFICATE block")
	}
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", fmt.Errorf("HA TLS leaf file must contain exactly one CERTIFICATE block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse HA TLS leaf certificate: %w", err)
	}
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:]), nil
}

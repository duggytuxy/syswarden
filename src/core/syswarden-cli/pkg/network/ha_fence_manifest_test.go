package network

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type haFenceRoundTripFunc func(*http.Request) (*http.Response, error)

func (function haFenceRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHAFenceDigestNormativeVectors(t *testing.T) {
	members := []HAFenceMember{{
		Address: "192.0.2.10", Port: 62026,
		TLSLeafCertificateSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}}
	preimage, err := HAFenceMembershipPreimage(members)
	if err != nil {
		t.Fatal(err)
	}
	if len(preimage) != 109 {
		t.Fatalf("membership preimage length = %d, want 109", len(preimage))
	}
	digest, err := HAFenceMembershipDigest(members)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "2908f61be12360d6a32de1dafd834be4fc4617a265726b670549b9c41dae2add" {
		t.Fatalf("membership digest = %s", digest)
	}
	writerDigest, err := HAFenceLegacyWriterDigest([]string{"bunkerweb-primary"})
	if err != nil {
		t.Fatal(err)
	}
	if writerDigest != "fb6c30d7a84dda99a990c709017395dab0ae825b88c19bce6dc3b877beac44fe" {
		t.Fatalf("writer digest = %s", writerDigest)
	}
	emptyDigest, err := HAFenceLegacyWriterDigest([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if emptyDigest != "f9bfe56aeb4a03ff07607c64e982dd075c84d1414be7d2e952bef41817e80119" {
		t.Fatalf("empty writer digest = %s", emptyDigest)
	}
}

func TestProbeHAFenceMemberRequiresFreshInactiveFenceProof(t *testing.T) {
	directory := haFenceTestDirectory(t)
	certificatePath := filepath.Join(directory, "server.crt")
	wantFingerprint := createHAFenceTestCertificate(t, certificatePath)
	certificateWire, err := os.ReadFile(certificatePath) // #nosec G304 -- certificatePath is created by this test under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificateWire)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverInstance := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	client := &http.Client{Transport: haFenceRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://192.0.2.10:62026/ha/status" || request.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("unexpected HA fence probe request: %s, headers=%v", request.URL, request.Header)
		}
		challenge := request.Header.Get(haFenceChallengeRequestHeader)
		wire, marshalErr := json.Marshal(map[string]any{
			"api_version": "2", "capabilities": []string{haFenceCapabilityName},
			"native_sync_fence": map[string]any{
				"version": cliHAFenceVersion, "scope": "legacy_ips_mutations", "state": cliHAFenceStateInactive,
				"epoch": "", "membership_sha256": "", "legacy_writer_inventory_sha256": "",
				"generation": 1, "server_instance_id": serverInstance, "condition": "", "drained_at": nil,
				"challenge": challenge,
			},
		})
		if marshalErr != nil {
			return nil, marshalErr
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Cache-Control": []string{"private, no-store"}},
			Body: io.NopCloser(bytes.NewReader(wire)),
			TLS:  &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}, Request: request,
		}, nil
	})}
	member, err := probeHAFenceMember(context.Background(), HAFenceInventoryMember{Address: "192.0.2.10", Port: 62026}, haFenceCreateOptions{
		client: client, token: "test-token", random: bytes.NewReader(bytes.Repeat([]byte{0x45}, 32)),
		expectedOwnerUID: os.Geteuid(), requestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if member.TLSLeafCertificateSHA256 != wantFingerprint {
		t.Fatalf("leaf fingerprint = %s, want %s", member.TLSLeafCertificateSHA256, wantFingerprint)
	}
	if hasHANoStoreDirective("private, no-store-bogus") {
		t.Fatal("invalid no-store directive was accepted")
	}
}

func writeHAFenceTestFile(t *testing.T, path string, wire []byte) {
	t.Helper()
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}

func haFenceTestDirectory(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(workingDirectory, ".ha-fence-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func skipHAFenceOwnerRemap(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "neither root nor expected UID") {
		t.Skipf("sandbox remaps an HA path ancestor owner: %v", err)
	}
}

func createHAFenceTestCertificate(t *testing.T, path string) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HA fence test"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeHAFenceTestFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func canonicalHAFenceTestManifest(t *testing.T, fingerprint string) HAFenceManifest {
	t.Helper()
	members := []HAFenceMember{{Address: "192.0.2.10", Port: 62026, TLSLeafCertificateSHA256: fingerprint}}
	membershipDigest, err := HAFenceMembershipDigest(members)
	if err != nil {
		t.Fatal(err)
	}
	writers := []string{"bunkerweb-primary"}
	writerDigest, err := HAFenceLegacyWriterDigest(writers)
	if err != nil {
		t.Fatal(err)
	}
	return HAFenceManifest{
		SchemaVersion:   haFenceManifestVersion,
		Epoch:           "7f67f63c-3f70-47b5-8b37-42f5827614a3",
		MembershipScope: cliHAFenceMembershipScope, OperatorAssertedComplete: true,
		MembershipSHA256: membershipDigest, LegacyWriterInventorySHA256: writerDigest,
		LegacyWriterIDs: writers, Members: members,
	}
}

func TestHAFenceManifestStrictCanonicalVerification(t *testing.T) {
	directory := haFenceTestDirectory(t)
	certificatePath := filepath.Join(directory, "server.crt")
	fingerprint := createHAFenceTestCertificate(t, certificatePath)
	manifest := canonicalHAFenceTestManifest(t, fingerprint)
	wire, err := canonicalHAFenceManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	writeHAFenceTestFile(t, manifestPath, wire)
	if _, _, err := readHAFenceManifest(manifestPath, os.Geteuid()); err != nil {
		skipHAFenceOwnerRemap(t, err)
		t.Fatalf("canonical manifest rejected: %v", err)
	}

	noncanonicalPath := filepath.Join(directory, "noncanonical.json")
	writeHAFenceTestFile(t, noncanonicalPath, bytes.TrimSpace(wire))
	if _, _, err := readHAFenceManifest(noncanonicalPath, os.Geteuid()); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("noncanonical manifest error = %v", err)
	}

	duplicatePath := filepath.Join(directory, "duplicate.json")
	duplicate := bytes.Replace(wire, []byte(`"schema_version": 1,`), []byte(`"schema_version": 1, "schema_version": 1,`), 1)
	writeHAFenceTestFile(t, duplicatePath, duplicate)
	if _, _, err := readHAFenceManifest(duplicatePath, os.Geteuid()); err == nil {
		t.Fatal("duplicate manifest key was accepted")
	}
}

func TestHAFenceEngageRecoverReleaseAndEpochReuse(t *testing.T) {
	directory := haFenceTestDirectory(t)
	certificatePath := filepath.Join(directory, "server.crt")
	fingerprint := createHAFenceTestCertificate(t, certificatePath)
	manifest := canonicalHAFenceTestManifest(t, fingerprint)
	manifestWire, err := canonicalHAFenceManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	writeHAFenceTestFile(t, manifestPath, manifestWire)

	fenceDirectory := filepath.Join(directory, "fence")
	if err := os.Mkdir(fenceDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	initialState, err := jsonMarshalLine(cliHAFenceDiskState{Version: cliHAFenceVersion, State: cliHAFenceStateInactive, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	writeHAFenceTestFile(t, filepath.Join(fenceDirectory, cliHAFenceStateName), initialState)
	now := time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC)
	options := haFenceAdminOptions{
		fence: newHALegacyWriterFence(fenceDirectory, os.Geteuid()), tlsLeafPath: certificatePath,
		expectedOwnerUID: os.Geteuid(), now: func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 256)),
	}
	if err := engageHAFence(manifestPath, options); err != nil {
		skipHAFenceOwnerRemap(t, err)
		t.Fatal(err)
	}
	status, err := readLocalHAFenceStatus(options)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != cliHAFenceStateActiveDrained || status.Generation != 3 || !validCLIHAFenceCondition(status.Condition) {
		t.Fatalf("engaged status = %+v", status)
	}
	if release, err := acquireHALegacyWriterLease(options.fence); err == nil {
		release()
		t.Fatal("legacy writer lease was accepted while the fence was active")
	}
	if err := engageHAFence(manifestPath, options); err == nil {
		t.Fatal("engaging a used epoch was accepted")
	}
	if err := recoverHAFence(manifestPath, options); err != nil {
		t.Fatal(err)
	}
	status, err = readLocalHAFenceStatus(options)
	if err != nil || status.State != cliHAFenceStateActiveDrained || status.Generation != 5 {
		t.Fatalf("recovered status = %+v, err = %v", status, err)
	}

	closure := HAFenceWriterClosure{
		SchemaVersion: haFenceWriterClosureVersion, Epoch: manifest.Epoch,
		MembershipSHA256:            manifest.MembershipSHA256,
		LegacyWriterInventorySHA256: manifest.LegacyWriterInventorySHA256,
		LegacyRetryQueueDrained:     true,
		Writers: []HAFenceWriterClosureEntry{{
			ID: "bunkerweb-primary", Disposition: "migrated_enriched_only",
			ClosureGeneration: "bunkerweb-config-42", ClosedAt: now.Format(time.RFC3339),
			EvidenceSHA256: strings.Repeat("a", 64),
		}},
	}
	closureWire, err := canonicalHAFenceWriterClosureBytes(closure)
	if err != nil {
		t.Fatal(err)
	}
	closurePath := filepath.Join(directory, "closure.json")
	writeHAFenceTestFile(t, closurePath, closureWire)
	if err := releaseHAFence(manifestPath, closurePath, options); err != nil {
		t.Fatal(err)
	}
	status, err = readLocalHAFenceStatus(options)
	if err != nil || status.State != cliHAFenceStateInactive || status.Generation != 6 {
		t.Fatalf("released status = %+v, err = %v", status, err)
	}
	if err := releaseHAFence(manifestPath, closurePath, options); err != nil {
		t.Fatalf("idempotent release failed: %v", err)
	}
	if err := engageHAFence(manifestPath, options); err == nil {
		t.Fatal("retired epoch was re-engaged")
	}
}

func jsonMarshalLine(value any) ([]byte, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(wire, '\n'), nil
}

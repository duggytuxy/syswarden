package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCreateHAFenceManifestWriterInventory(t *testing.T) {
	for _, test := range []struct {
		name           string
		writers        string
		assertComplete bool
		proof          string
		wantWriters    []string
		wantError      bool
		wantProbes     int
	}{
		{name: "explicit empty", writers: `[]`, assertComplete: true, wantWriters: []string{}, wantProbes: 1},
		{name: "sorted writers", writers: `["writer-z","writer-a"]`, assertComplete: true, wantWriters: []string{"writer-a", "writer-z"}, wantProbes: 1},
		{name: "null", writers: `null`, assertComplete: true, wantError: true},
		{name: "missing", assertComplete: true, wantError: true},
		{name: "duplicate", writers: `["writer-a","writer-a"]`, assertComplete: true, wantError: true},
		{name: "invalid identifier", writers: `["Writer A"]`, assertComplete: true, wantError: true},
		{name: "no completeness assertion", writers: `[]`, wantError: true},
		{name: "empty still requires fresh proof", writers: `[]`, assertComplete: true, proof: "stale", wantError: true, wantProbes: 1},
		{name: "empty still requires TLS identity", writers: `[]`, assertComplete: true, proof: "no-tls", wantError: true, wantProbes: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := haFenceTestDirectory(t)
			certificatePath := filepath.Join(directory, "server.crt")
			fingerprint := createHAFenceTestCertificate(t, certificatePath)
			certificateWire, err := readProtectedHAFile(certificatePath, os.Geteuid(), maxHAFenceManifestBytes)
			if err != nil {
				skipHAFenceOwnerRemap(t, err)
				t.Fatal(err)
			}
			block, _ := pem.Decode(certificateWire)
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			inventory := `{"schema_version":1,"membership_scope":"one_receiving_api_endpoint_per_syswarden_node","members":[{"address":"192.0.2.10","port":62026}]`
			if test.writers != "" {
				inventory += `,"legacy_writer_ids":` + test.writers
			}
			inventory += "}"
			inventoryPath := filepath.Join(directory, "inventory.json")
			manifestPath := filepath.Join(directory, "manifest.json")
			writeHAFenceTestFile(t, inventoryPath, []byte(inventory))
			probes := 0
			client := &http.Client{Transport: haFenceRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				probes++
				challenge := request.Header.Get(haFenceChallengeRequestHeader)
				if request.URL.String() != "https://192.0.2.10:62026/ha/status" || request.Header.Get("Authorization") != "Bearer test-token" || !validHAFenceProofToken(challenge) {
					t.Fatal("manifest creation did not send the authenticated member challenge")
				}
				if test.proof == "stale" {
					challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
				}
				wire, marshalErr := json.Marshal(map[string]any{
					"api_version": "2", "capabilities": []string{haFenceCapabilityName},
					"native_sync_fence": map[string]any{
						"version": cliHAFenceVersion, "scope": "legacy_ips_mutations", "state": cliHAFenceStateInactive,
						"epoch": "", "membership_sha256": "", "legacy_writer_inventory_sha256": "", "generation": 1,
						"server_instance_id": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
						"condition":          "", "drained_at": nil, "challenge": challenge,
					},
				})
				if marshalErr != nil {
					return nil, marshalErr
				}
				response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Cache-Control": []string{"no-store"}},
					Body: io.NopCloser(bytes.NewReader(wire)), Request: request,
					TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}}
				if test.proof == "no-tls" {
					response.TLS = nil
				}
				return response, nil
			})}
			manifest, err := createHAFenceManifest(context.Background(), inventoryPath, manifestPath, test.assertComplete, haFenceCreateOptions{
				client: client, token: "test-token", random: bytes.NewReader(bytes.Repeat([]byte{0x45}, 64)),
				expectedOwnerUID: os.Geteuid(), requestTimeout: time.Second,
			})
			if probes != test.wantProbes {
				t.Fatalf("probes = %d, want %d", probes, test.wantProbes)
			}
			if test.wantError {
				if err == nil {
					t.Fatal("invalid inventory or member proof was accepted")
				}
				if _, statErr := os.Lstat(manifestPath); !os.IsNotExist(statErr) {
					t.Fatalf("rejected creation left a manifest: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(manifest.LegacyWriterIDs, test.wantWriters) || manifest.Members[0].TLSLeafCertificateSHA256 != fingerprint {
				t.Fatalf("manifest lost writer inventory or member identity: %+v", manifest)
			}
			verified, wire, err := readHAFenceManifest(manifestPath, os.Geteuid())
			if err != nil || !reflect.DeepEqual(verified, manifest) {
				t.Fatalf("created manifest did not round-trip: %v", err)
			}
			if len(test.wantWriters) == 0 {
				if !bytes.Contains(wire, []byte(`"legacy_writer_ids": []`)) || manifest.LegacyWriterInventorySHA256 != "f9bfe56aeb4a03ff07607c64e982dd075c84d1414be7d2e952bef41817e80119" {
					t.Fatalf("empty inventory lost its canonical array or normative digest: %s", wire)
				}
				for _, malformed := range [][]byte{
					bytes.Replace(wire, []byte(`"legacy_writer_ids": []`), []byte(`"legacy_writer_ids": null`), 1),
					[]byte(strings.Replace(string(wire), "  \"legacy_writer_ids\": [],\n", "", 1)),
				} {
					writeHAFenceTestFile(t, manifestPath, malformed)
					if _, _, err := readHAFenceManifest(manifestPath, os.Geteuid()); err == nil {
						t.Fatal("null or missing writer inventory was accepted as explicit empty")
					}
				}
			}
		})
	}
}

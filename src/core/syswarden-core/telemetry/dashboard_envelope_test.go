package telemetry

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestDashboardPublicationHonorsExactOneMiBBoundary_SW_RES_006(t *testing.T) {
	data := DashboardData{WAF: WAF{
		BannedIPs:     []BannedIP{},
		AllowedEvents: make([]AllowedEvent, 400),
	}}
	for index := range data.WAF.AllowedEvents {
		data.WAF.AllowedEvents[index].IP = "192.0.2.1"
		data.WAF.AllowedEvents[index].Service = "sshd"
	}
	withProjection := data
	withProjection.Projection = &DashboardProjection{Quality: dashboardProjectionQualityComplete}
	base, err := json.Marshal(withProjection)
	if err != nil {
		t.Fatal(err)
	}
	remaining := maxDashboardJSONBytes - len(base)
	if remaining <= 0 || remaining > len(data.WAF.AllowedEvents)*maxDashboardDisplayStringBytes {
		t.Fatalf("test fixture cannot span exact boundary: base=%d remaining=%d", len(base), remaining)
	}
	for index := range data.WAF.AllowedEvents {
		if remaining == 0 {
			break
		}
		width := min(remaining, maxDashboardDisplayStringBytes)
		data.WAF.AllowedEvents[index].Payload = strings.Repeat("x", width)
		remaining -= width
	}

	wire, err := marshalDashboardDataForPublication(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != maxDashboardJSONBytes {
		t.Fatalf("exact boundary telemetry size = %d, want %d", len(wire), maxDashboardJSONBytes)
	}
	var decoded DashboardData
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Projection == nil || decoded.Projection.Quality != dashboardProjectionQualityComplete || decoded.Projection.PayloadsProjected != 0 {
		t.Fatalf("exact boundary projection = %#v", decoded.Projection)
	}

	for index := range data.WAF.AllowedEvents {
		if len(data.WAF.AllowedEvents[index].Payload) < maxDashboardDisplayStringBytes {
			data.WAF.AllowedEvents[index].Payload += "x"
			break
		}
	}
	projectedA, err := marshalDashboardDataForPublication(data)
	if err != nil {
		t.Fatal(err)
	}
	projectedB, err := marshalDashboardDataForPublication(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(projectedA) > maxDashboardJSONBytes || !bytes.Equal(projectedA, projectedB) {
		t.Fatalf("projected envelope is not bounded and deterministic: size=%d equal=%t", len(projectedA), bytes.Equal(projectedA, projectedB))
	}
	if err := json.Unmarshal(projectedA, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Projection == nil || decoded.Projection.Quality != dashboardProjectionQualityDegraded ||
		decoded.Projection.Reason != dashboardProjectionReasonEnvelope || decoded.Projection.PayloadsProjected == 0 {
		t.Fatalf("oversized payload projection = %#v", decoded.Projection)
	}
	for _, event := range decoded.WAF.AllowedEvents {
		if event.Payload != dashboardProjectionPayloadOmission {
			t.Fatal("envelope projection retained a display payload")
		}
	}
}

func TestDashboardPublicationProjectsUnsafePayloadsAndRejectsUnsafeIdentity_SW_RES_006(t *testing.T) {
	originalPayload := "line-one\n[red]line-two[-]" + string([]byte{0xff}) + strings.Repeat("x", maxDashboardDisplayStringBytes)
	data := DashboardData{WAF: WAF{BannedIPs: []BannedIP{{Payload: originalPayload}}}}
	wire, err := marshalDashboardDataForPublication(data)
	if err != nil {
		t.Fatal(err)
	}
	if data.WAF.BannedIPs[0].Payload != originalPayload {
		t.Fatal("dashboard publication mutated its input")
	}
	var decoded DashboardData
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Projection == nil || decoded.Projection.Quality != dashboardProjectionQualityDegraded ||
		decoded.Projection.Reason != dashboardProjectionReasonPayload || decoded.Projection.PayloadsProjected != 1 {
		t.Fatalf("unsafe payload projection = %#v", decoded.Projection)
	}
	payload := decoded.WAF.BannedIPs[0].Payload
	if len(payload) > maxDashboardDisplayStringBytes || !utf8.ValidString(payload) {
		t.Fatalf("projected payload remains outside display bounds: bytes=%d valid=%t", len(payload), utf8.ValidString(payload))
	}
	for _, r := range payload {
		if unicode.IsControl(r) {
			t.Fatalf("projected payload retained control character %U", r)
		}
	}

	data = DashboardData{ProfileName: strings.Repeat("x", maxDashboardDisplayStringBytes+1)}
	if _, err := marshalDashboardDataForPublication(data); err == nil {
		t.Fatal("oversized non-payload identity was published")
	}
}

func TestDashboardPublicationPreservesEmptyBanInventoryAsJSONArray_SW_RES_006(t *testing.T) {
	data := DashboardData{}
	wire, err := marshalDashboardDataForPublication(data)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		WAF struct {
			BannedIPs json.RawMessage `json:"banned_ips"`
		} `json:"waf"`
	}
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.WAF.BannedIPs, []byte("[]")) {
		t.Fatalf("empty ban inventory = %s, want []", decoded.WAF.BannedIPs)
	}
}

func TestDashboardPublicationRejectsProjectionCountBeyondPayloadInventory_SW_RES_006(t *testing.T) {
	data := DashboardData{
		Projection: &DashboardProjection{
			Quality:           dashboardProjectionQualityDegraded,
			Reason:            dashboardProjectionReasonPayload,
			PayloadsProjected: 2,
		},
		WAF: WAF{BannedIPs: []BannedIP{{}}},
	}
	if err := validateDashboardPublicationData(data); err == nil {
		t.Fatal("projection count beyond the payload inventory was accepted")
	}
}

func TestDashboardPublicationPreservesLastSnapshotWhenEnvelopeCannotFit_SW_RES_006(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	previous := []byte(`{"previous":true}`)
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	data := DashboardData{Whitelist: Whitelist{IPs: make([]string, 300)}}
	for index := range data.Whitelist.IPs {
		data.Whitelist.IPs[index] = strings.Repeat("x", maxDashboardDisplayStringBytes)
	}
	if err := publishDashboardData(path, data); err == nil {
		t.Fatal("non-projectable oversized dashboard was published")
	}
	retained, err := os.ReadFile(path) // #nosec G304 -- path is a fixed dashboard filename beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, previous) {
		t.Fatalf("failed publication replaced last valid snapshot: %q", retained)
	}
}

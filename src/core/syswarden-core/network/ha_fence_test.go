package network

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newHAFenceTestAPI(t *testing.T) *haAPI {
	t.Helper()
	directory := t.TempDir()
	api, err := newHAAPI(HAConfig{
		Token: "fence-test-token", PeerIPs: []string{"9.9.9.10"}, BunkerWebEnabled: true,
	}, noOpFirewallManager{}, "v4.03.0", filepath.Join(directory, "blacklist.ipv4"), filepath.Join(directory, "blacklist.ipv6"),
		filepath.Join(directory, "telemetry.json"), filepath.Join(directory, "bans.json"))
	if err != nil {
		t.Fatal(err)
	}
	api.localInterfaceAddresses = func() ([]netip.Addr, error) { return nil, nil }
	api.isWhitelisted = func(string) (bool, error) { return false, nil }
	return api
}

func authenticatedHAFenceRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://syswarden.test"+path, strings.NewReader(body))
	request.RemoteAddr = "9.9.9.10:43210"
	request.Header.Set("Authorization", "Bearer fence-test-token")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func activateHAFenceForTest(t *testing.T, api *haAPI) string {
	t.Helper()
	condition := "sw-fence-v1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	err := api.fence.withLock(true, false, func(root *os.Root) error {
		state, err := readHAFenceState(root, api.fence.expectedOwnerUID)
		if err != nil {
			return err
		}
		drainedAt := time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC).Format(time.RFC3339)
		state.State = haFenceStateActiveDrained
		state.Epoch = "7f67f63c-3f70-47b5-8b37-42f5827614a3"
		state.MembershipSHA256 = strings.Repeat("a", 64)
		state.LegacyWriterInventorySHA256 = strings.Repeat("b", 64)
		state.Generation++
		state.Condition = condition
		state.DrainedAt = &drainedAt
		return publishHAFenceState(root, state)
	})
	if err != nil {
		t.Fatal(err)
	}
	return condition
}

func TestHAFenceStatusCapabilityChallengeAndNoStore(t *testing.T) {
	api := newHAFenceTestAPI(t)
	condition := activateHAFenceForTest(t, api)
	challenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	request := authenticatedHAFenceRequest(t, http.MethodGet, "/ha/status", "")
	request.Header.Set(haFenceChallengeHeader, challenge)
	recorder := httptest.NewRecorder()
	api.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
	if recorder.Header().Get(haFenceConditionHeader) != condition || recorder.Header().Get("ETag") != "" {
		t.Fatalf("condition headers = %#v", recorder.Header())
	}
	var response struct {
		Capabilities    []string                `json:"capabilities"`
		NativeSyncFence haNativeSyncFenceStatus `json:"native_sync_fence"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, capability := range response.Capabilities {
		if capability == haFenceCapability {
			found = true
		}
	}
	if !found || response.NativeSyncFence.State != haFenceStateActiveDrained ||
		response.NativeSyncFence.Challenge == nil || *response.NativeSyncFence.Challenge != challenge ||
		response.NativeSyncFence.Condition != condition || response.NativeSyncFence.ServerInstanceID == "" {
		t.Fatalf("fence status = %+v, capabilities = %v", response.NativeSyncFence, response.Capabilities)
	}

	malformed := authenticatedHAFenceRequest(t, http.MethodGet, "/ha/status", "")
	malformed.Header.Set(haFenceChallengeHeader, "not-a-valid-challenge")
	malformedRecorder := httptest.NewRecorder()
	api.handler().ServeHTTP(malformedRecorder, malformed)
	if malformedRecorder.Code != http.StatusBadRequest || malformedRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("malformed challenge result = %d, headers = %#v", malformedRecorder.Code, malformedRecorder.Header())
	}
}

func TestHAFenceLegacyMutationPreconditionsAreZeroMutation(t *testing.T) {
	api := newHAFenceTestAPI(t)
	condition := activateHAFenceForTest(t, api)
	handler := api.handler()
	tests := []struct {
		name       string
		method     string
		headers    []string
		wantStatus int
	}{
		{name: "post blocked", method: http.MethodPost, wantStatus: http.StatusLocked},
		{name: "missing", method: http.MethodDelete, wantStatus: http.StatusPreconditionRequired},
		{name: "If-Match is not the contract", method: http.MethodDelete, headers: []string{"If-Match", condition}, wantStatus: http.StatusPreconditionRequired},
		{name: "malformed", method: http.MethodDelete, headers: []string{haFenceConditionHeader, "bad"}, wantStatus: http.StatusBadRequest},
		{name: "stale", method: http.MethodDelete, headers: []string{haFenceConditionHeader, "sw-fence-v1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))}, wantStatus: http.StatusPreconditionFailed},
		{name: "duplicate", method: http.MethodDelete, headers: []string{haFenceConditionHeader, condition, haFenceConditionHeader, condition}, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := authenticatedHAFenceRequest(t, test.method, "/ha/sync", `{"ips":["1.1.1.9"]}`)
			for index := 0; index < len(test.headers); index += 2 {
				request.Header.Add(test.headers[index], test.headers[index+1])
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
	for _, path := range []string{api.blacklistIPv4, api.blacklistIPv6} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("precondition failure mutated %s: %v", path, err)
		}
	}

	approved := authenticatedHAFenceRequest(t, http.MethodDelete, "/ha/sync", `{"ips":[]}`)
	approved.Header.Set(haFenceConditionHeader, condition)
	approvedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(approvedRecorder, approved)
	if approvedRecorder.Code != http.StatusOK {
		t.Fatalf("conditioned cleanup status = %d, body = %s", approvedRecorder.Code, approvedRecorder.Body.String())
	}

	enriched := authenticatedHAFenceRequest(t, http.MethodDelete, "/ha/sync", `{"bans":[{"ip":"1.1.1.7","source":"partner"}]}`)
	enrichedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(enrichedRecorder, enriched)
	if enrichedRecorder.Code != http.StatusOK {
		t.Fatalf("enriched ledger cleanup status = %d, body = %s", enrichedRecorder.Code, enrichedRecorder.Body.String())
	}
}

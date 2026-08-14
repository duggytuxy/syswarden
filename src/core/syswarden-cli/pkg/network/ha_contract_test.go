package network

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"syswarden-cli/config"
)

type recordedHARequest struct {
	Method        string
	Authorization string
}

func TestSyncHAPeerAuthorizationHeaderContract_SW_HA_001(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantHeader string
	}{
		{name: "legacy tokenless node"},
		{name: "token-aware node", token: "shared-secret", wantHeader: "Bearer shared-secret"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan recordedHARequest, 1)
			server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests <- recordedHARequest{Method: request.Method, Authorization: request.Header.Get("Authorization")}
				http.Error(w, "fixture rejection", http.StatusUnauthorized)
			}))
			defer server.Close()
			host, port := splitTestServerAddress(t, server.Listener.Addr().String())

			withGlobalConfig(t, &config.Config{
				HAEnabled:  true,
				HAPeerIP:   host,
				HAPeerPort: port,
				HAToken:    test.token,
			})
			if err := SyncHAPeer(); err != nil {
				t.Fatalf("SyncHAPeer() error = %v", err)
			}
			got := <-requests
			if got.Method != http.MethodGet || got.Authorization != test.wantHeader {
				t.Fatalf("request = %#v, want GET authorization %q", got, test.wantHeader)
			}
		})
	}
}

func TestSyncHAUnbanLegacyAuthorizationContract_SW_HA_001(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "legacy tokenless node"},
		{name: "configured token is not sent on DELETE", token: "shared-secret"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var mu sync.Mutex
			var got recordedHARequest
			server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				mu.Lock()
				got = recordedHARequest{Method: request.Method, Authorization: request.Header.Get("Authorization")}
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			host, port := splitTestServerAddress(t, server.Listener.Addr().String())

			withGlobalConfig(t, &config.Config{
				HAEnabled:  true,
				HAPeerIP:   host,
				HAPeerPort: port,
				HAToken:    test.token,
			})
			if err := SyncHAUnban([]string{"192.0.2.44", "2001:db8::44"}); err != nil {
				t.Fatalf("SyncHAUnban() error = %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if got.Method != http.MethodDelete {
				t.Fatalf("method = %q, want DELETE", got.Method)
			}
			// This assertion freezes the v4.02.8 mixed-version behavior. SW-HA-001
			// must invert it when DELETE token authentication is implemented.
			if got.Authorization != "" {
				t.Fatalf("legacy DELETE authorization = %q, want empty", got.Authorization)
			}
		})
	}
}

func TestHASyncPayloadMixedVersionJSONContract(t *testing.T) {
	t.Parallel()
	fixture := []byte(`{"ips":["192.0.2.10","2001:db8::10"],"sender_version":"v4.03.0","future_field":{"enabled":true}}`)
	var payload HASyncPayload
	if err := json.Unmarshal(fixture, &payload); err != nil {
		t.Fatalf("newer payload with unknown fields was rejected: %v", err)
	}
	if strings.Join(payload.IPs, " ") != "192.0.2.10 2001:db8::10" {
		t.Fatalf("decoded IPs = %v", payload.IPs)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"ips":["192.0.2.10","2001:db8::10"]}` {
		t.Fatalf("wire payload = %s", encoded)
	}
}

func TestGetLocalBlocklistGrammar(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blocklist")
	if err := os.WriteFile(path, []byte("\n192.0.2.1\n# retained as a payload entry\n 2001:db8::1 \n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := getLocalBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "# retained as a payload entry", "2001:db8::1"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("blocklist entries = %q, want %q", got, want)
	}
	missing, err := getLocalBlocklist(filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing blocklist = %v, %v", missing, err)
	}
}

func splitTestServerAddress(t *testing.T, address string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func newLoopbackTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			requireOrSkipLoopbackHA(t, err)
		}
		t.Fatalf("create loopback listener: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.StartTLS()
	return server
}

func requireOrSkipLoopbackHA(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("CI") != "" || os.Getenv("ACT") == "true" || os.Getenv("SYSWARDEN_REQUIRE_LOOPBACK_TESTS") == "1" {
		t.Fatalf("loopback HA contract is mandatory in CI/Act but sockets are unavailable: %v", err)
	}
	t.Skipf("loopback HA contract requires sockets unavailable in this sandbox: %v", err)
}

func withGlobalConfig(t *testing.T, value *config.Config) {
	t.Helper()
	previous := config.GlobalConfig
	config.GlobalConfig = value
	t.Cleanup(func() { config.GlobalConfig = previous })
}

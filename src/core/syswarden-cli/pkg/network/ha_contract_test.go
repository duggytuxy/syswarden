package network

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"syswarden-cli/config"
)

func TestSetupHAClusterFailsClosedWhenAutoWhitelistFails_SW2_M6(t *testing.T) {
	previousConfig := config.GlobalConfig
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
	})
	config.GlobalConfig.HAEnabled = true
	config.GlobalConfig.HAPeerIP = "8.8.8.8"
	config.GlobalConfig.HAPeerPort = "62026"

	var cronCalls []bool
	err := setupHACluster(
		func(peer string) (*exec.Cmd, error) {
			if peer != "8.8.8.8" {
				t.Fatalf("auto-whitelist peer = %q", peer)
			}
			return exec.Command("false"), nil
		},
		func(enable bool) error {
			cronCalls = append(cronCalls, enable)
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "failed to auto-whitelist HA peer 8.8.8.8") {
		t.Fatalf("auto-whitelist failure = %v", err)
	}
	if len(cronCalls) != 1 || cronCalls[0] {
		t.Fatalf("HA cron recovery calls = %v, want one disable", cronCalls)
	}
}

func TestSetupHAClusterJoinsAutoWhitelistAndCronDisableFailures_SW2_M6(t *testing.T) {
	previousConfig := config.GlobalConfig
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
	})
	config.GlobalConfig.HAEnabled = true
	config.GlobalConfig.HAPeerIP = "8.8.8.8"
	config.GlobalConfig.HAPeerPort = "62026"

	whitelistErr := errors.New("whitelist failed")
	cronErr := errors.New("cron disable failed")
	err := setupHACluster(
		func(string) (*exec.Cmd, error) {
			return nil, whitelistErr
		},
		func(enable bool) error {
			if enable {
				t.Fatal("HA cron was enabled after setup failure")
			}
			return cronErr
		},
	)
	if !errors.Is(err, whitelistErr) || !errors.Is(err, cronErr) {
		t.Fatalf("setupHACluster() error = %v, want joined whitelist and cron failures", err)
	}
}

func newStrictHATestCertificatePEM(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newHALoopbackServerCertificate(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestStrictHACABundleParserConsumesAllBytes_SW_HA_001(t *testing.T) {
	certificateA := newStrictHATestCertificatePEM(t, 1)
	certificateB := newStrictHATestCertificatePEM(t, 2)
	decoded, _ := pem.Decode(certificateA)
	if decoded == nil {
		t.Fatal("test certificate did not decode")
	}
	validMulti := append(append([]byte("\n\t"), certificateA...), certificateB...)
	if err := addStrictHACertificates(x509.NewCertPool(), validMulti); err != nil {
		t.Fatalf("valid multi-certificate bundle: %v", err)
	}
	invalid := map[string][]byte{
		"empty":              nil,
		"junk prefix":        append([]byte("junk\n"), certificateA...),
		"junk suffix":        append(append([]byte(nil), certificateA...), []byte("junk")...),
		"junk between":       bytes.Join([][]byte{certificateA, []byte("junk\n"), certificateB}, nil),
		"non certificate":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: decoded.Bytes}),
		"certificate header": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: decoded.Bytes}),
		"invalid DER":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}),
		"malformed PEM":      []byte("-----BEGIN CERTIFICATE-----\nAAAA\n"),
	}
	for name, wire := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := addStrictHACertificates(x509.NewCertPool(), wire); err == nil {
				t.Fatal("strict CA parser accepted invalid bundle")
			}
		})
	}
}

type recordedHARequest struct {
	Method        string
	Authorization string
}

func TestSyncHAPeerAuthorizationHeaderContract_SW_HA_001(t *testing.T) {
	requests := make(chan recordedHARequest, 1)
	server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- recordedHARequest{Method: request.Method, Authorization: request.Header.Get("Authorization")}
		http.Error(w, "fixture rejection", http.StatusUnauthorized)
	}))
	defer server.Close()
	host, port := splitTestServerAddress(t, server.Listener.Addr().String())
	cfg := &config.Config{HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret"}
	if err := syncHAPeers(context.Background(), cfg, testHASyncOptions(t, server.Client())); err == nil {
		t.Fatal("syncHAPeers() accepted the fixture rejection")
	}
	got := <-requests
	if got.Method != http.MethodGet || got.Authorization != "Bearer shared-secret" {
		t.Fatalf("request = %#v, want authenticated GET", got)
	}
}

func TestSyncHAUnbanAuthorizationContract_SW_HA_002(t *testing.T) {
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
	cfg := &config.Config{HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret"}
	if err := syncHAUnban(context.Background(), cfg, []string{"192.0.2.44", "2001:db8::44"}, testHASyncOptions(t, server.Client())); err != nil {
		t.Fatalf("syncHAUnban() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Method != http.MethodDelete || got.Authorization != "Bearer shared-secret" {
		t.Fatalf("DELETE request = %#v", got)
	}
}

type haRoundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip haRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestHAClientsRejectInvalidTokenBeforeTransport_SW_HA_001(t *testing.T) {
	for _, token := range []string{"", " shared-secret", "shared-secret ", "\t"} {
		t.Run(strings.ReplaceAll(token, " ", "_"), func(t *testing.T) {
			requests := 0
			client := &http.Client{Transport: haRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				requests++
				return nil, errors.New("unexpected transport")
			})}
			options := testHASyncOptions(t, client)
			cfg := &config.Config{HAEnabled: true, HAPeerIP: "192.0.2.10", HAPeerPort: "62026", HAToken: token}
			if err := syncHAPeers(context.Background(), cfg, options); err == nil ||
				!strings.Contains(err.Error(), "integrations.ha.token") || !strings.Contains(err.Error(), "upgrade") {
				t.Fatalf("sync invalid-token operator error = %v", err)
			}
			if err := syncHAUnban(context.Background(), cfg, []string{"192.0.2.44"}, options); err == nil ||
				!strings.Contains(err.Error(), "integrations.ha.token") || !strings.Contains(err.Error(), "upgrade") {
				t.Fatalf("unban invalid-token operator error = %v", err)
			}
			if requests != 0 {
				t.Fatalf("invalid token emitted %d transport requests", requests)
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
	if err := os.WriteFile(path, []byte("\n192.0.2.1\n 2001:0db8::1 \n192.0.2.1\n192.0.2.99/24\n2001:db8::44/64\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := getLocalBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "192.0.2.1", "2001:db8::/64", "2001:db8::1"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("blocklist entries = %q, want %q", got, want)
	}
	missing, err := getLocalBlocklist(filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing blocklist = %v, %v", missing, err)
	}
	invalid := filepath.Join(t.TempDir(), "invalid")
	if err := os.WriteFile(invalid, []byte("192.0.2.1\n# not an address\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := getLocalBlocklist(invalid); err == nil || !strings.Contains(err.Error(), "invalid HA IP or CIDR address") {
		t.Fatalf("invalid blocklist error = %v", err)
	}
}

func TestSyncHAPeerDurableWireIndependentOfBunkerGateAndDoesNotRelayTemporaryLedger_SW_HA_004(t *testing.T) {
	for _, bunkerWebEnabled := range []bool{false, true} {
		label := "disabled"
		if bunkerWebEnabled {
			label = "enabled"
		}
		t.Run(label, func(t *testing.T) {
			type observedHARequest struct {
				Method        string
				Authorization string
				Body          []byte
			}
			var observationsMu sync.Mutex
			observations := make([]observedHARequest, 0, 2)
			remoteTemporaryIP := "192.0.2.251"
			certificate := newHALoopbackServerCertificate(t, 201)
			if bunkerWebEnabled {
				certificate = newHALoopbackServerCertificate(t, 202)
			}
			server := newLoopbackTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				wire, _ := io.ReadAll(request.Body)
				observationsMu.Lock()
				observations = append(observations, observedHARequest{
					Method: request.Method, Authorization: request.Header.Get("Authorization"), Body: wire,
				})
				observationsMu.Unlock()
				switch request.Method {
				case http.MethodGet:
					_ = json.NewEncoder(w).Encode(HASyncPayload{IPs: []string{remoteTemporaryIP}})
				case http.MethodPost:
					w.WriteHeader(http.StatusOK)
				default:
					http.Error(w, "method", http.StatusMethodNotAllowed)
				}
			}), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
			defer server.Close()

			bundle := filepath.Join(t.TempDir(), "ha-ca.pem")
			if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
				t.Fatal(err)
			}
			client, err := newVerifiedHAHTTPClient(bundle, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			options := testHASyncOptions(t, client)
			durable := []string{
				"198.51.100.10", "198.51.100.0/25", "203.0.113.77",
				"2001:db8::10", "2001:db8:1::/64",
			}
			if err := os.WriteFile(options.blacklistIPv4, []byte("198.51.100.10\n198.51.100.0/25\n203.0.113.77\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(options.blacklistIPv6, []byte("2001:db8::10\n2001:db8:1::/64\n"), 0600); err != nil {
				t.Fatal(err)
			}

			// A real active temporary ledger exists beside the sync status file.
			// It remains partner-owned and must not be converted into a durable
			// legacy POST by the node scheduler.
			now := options.now().UTC()
			localTemporaryIP := "192.0.2.250"
			ledgerPath := filepath.Join(filepath.Dir(options.statusFile), "bans.json")
			ledgerWire, err := json.Marshal(cliHABanLedger{Version: cliHALedgerVersion, Bans: []cliHABanLedgerRecord{{
				IP: localTemporaryIP, Source: "bunkerweb-a", Reason: "partner-owned temporary ban",
				PeerScope: "127.0.0.1/32", OriginPeerIP: "127.0.0.1",
				CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339),
				ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339), State: "active",
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ledgerPath, ledgerWire, 0600); err != nil {
				t.Fatal(err)
			}
			active, err := ReadActiveHABans(ledgerPath, now)
			if err != nil || len(active) != 1 || active[0].IP != localTemporaryIP {
				t.Fatalf("active local temporary ledger = %#v, err=%v", active, err)
			}

			host, port := splitTestServerAddress(t, server.Listener.Addr().String())
			cfg := &config.Config{
				HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret",
				BunkerWebEnabled: bunkerWebEnabled,
			}
			if err := syncHAPeers(context.Background(), cfg, options); err != nil {
				t.Fatal(err)
			}

			observationsMu.Lock()
			got := append([]observedHARequest(nil), observations...)
			observationsMu.Unlock()
			if len(got) != 2 || got[0].Method != http.MethodGet || got[1].Method != http.MethodPost {
				t.Fatalf("bunkerweb=%t request sequence = %#v", bunkerWebEnabled, got)
			}
			for _, request := range got {
				if request.Authorization != "Bearer shared-secret" {
					t.Fatalf("bunkerweb=%t %s bearer = %q", bunkerWebEnabled, request.Method, request.Authorization)
				}
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(got[1].Body, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != 1 || fields["ips"] == nil || fields["bans"] != nil {
				t.Fatalf("bunkerweb=%t outbound legacy fields = %s", bunkerWebEnabled, got[1].Body)
			}
			var posted HASyncPayload
			if err := json.Unmarshal(got[1].Body, &posted); err != nil {
				t.Fatal(err)
			}
			wantPosted, err := canonicalHAIPList(durable)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(posted.IPs, "|") != strings.Join(wantPosted, "|") ||
				strings.Contains(strings.Join(posted.IPs, "|"), localTemporaryIP) ||
				strings.Contains(strings.Join(posted.IPs, "|"), remoteTemporaryIP) {
				t.Fatalf("bunkerweb=%t durable POST = %v, want %v without temporary relay", bunkerWebEnabled, posted.IPs, wantPosted)
			}

			statusWire, err := os.ReadFile(options.statusFile)
			if err != nil {
				t.Fatal(err)
			}
			var status HASyncStatusSnapshot
			if err := json.Unmarshal(statusWire, &status); err != nil || len(status.Peers) != 1 ||
				status.Peers[0].MissingLocally != 1 || status.Peers[0].Pushed != len(wantPosted) {
				t.Fatalf("bunkerweb=%t non-relay status = %#v, err=%v", bunkerWebEnabled, status, err)
			}
		})
	}
}

func TestSyncHAPeerRetriesAndPublishesPerPeerDesyncTelemetry_SW_HA_002(t *testing.T) {
	var mu sync.Mutex
	getRequests := 0
	postRequests := 0
	server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Header.Get("Authorization") != "Bearer shared-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch request.Method {
		case http.MethodGet:
			getRequests++
			_, _ = w.Write([]byte(`{"ips":["198.51.100.9"],"future_field":true}`))
		case http.MethodPost:
			postRequests++
			if postRequests == 1 {
				http.Error(w, "retry", http.StatusServiceUnavailable)
				return
			}
			var payload HASyncPayload
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Errorf("decode POST: %v", err)
			}
			if strings.Join(payload.IPs, ",") != "192.0.2.8" {
				t.Errorf("POST payload = %v", payload.IPs)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	host, port := splitTestServerAddress(t, server.Listener.Addr().String())
	options := testHASyncOptions(t, server.Client())
	options.retryAttempts = 2
	options.retryBackoff = 0
	if err := os.WriteFile(options.blacklistIPv4, []byte("192.0.2.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret"}
	if err := syncHAPeers(context.Background(), cfg, options); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if getRequests != 1 || postRequests != 2 {
		t.Fatalf("requests GET=%d POST=%d, want 1/2", getRequests, postRequests)
	}
	mu.Unlock()
	wire, err := os.ReadFile(options.statusFile)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot HASyncStatusSnapshot
	if err := json.Unmarshal(wire, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Peers) != 1 {
		t.Fatalf("peer telemetry = %#v", snapshot.Peers)
	}
	status := snapshot.Peers[0]
	if status.State != "desynced" || status.InSync || !status.Desynced || status.MissingOnPeer != 0 || status.MissingLocally != 1 || status.Pushed != 1 || status.Attempts != 2 {
		t.Fatalf("peer telemetry = %#v", status)
	}
}

func TestSyncHAContextCancellationStopsRetries_SW_HA_002(t *testing.T) {
	requests := 0
	server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		http.Error(w, "retry", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	host, port := splitTestServerAddress(t, server.Listener.Addr().String())
	options := testHASyncOptions(t, server.Client())
	options.retryAttempts = 3
	options.retryBackoff = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := syncHAPeers(ctx, &config.Config{HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret"}, options)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("sync cancellation error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("canceled sync emitted %d requests", requests)
	}
}

func TestSyncHARequestTimeoutIsBounded_SW_HA_002(t *testing.T) {
	server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	host, port := splitTestServerAddress(t, server.Listener.Addr().String())
	options := testHASyncOptions(t, server.Client())
	options.requestTimeout = 25 * time.Millisecond
	started := time.Now()
	err := syncHAPeers(context.Background(), &config.Config{HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret"}, options)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("bounded timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded HA request took %s", elapsed)
	}
}

func TestSyncHAUnbanRetriesTransientFailure_SW_HA_002(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if request.Header.Get("Authorization") != "Bearer shared-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if requests == 1 {
			http.Error(w, "retry", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	host, port := splitTestServerAddress(t, server.Listener.Addr().String())
	options := testHASyncOptions(t, server.Client())
	options.retryAttempts = 2
	options.retryBackoff = 0
	if err := syncHAUnban(context.Background(), &config.Config{
		HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret",
	}, []string{"192.0.2.77/24"}, options); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 2 {
		t.Fatalf("DELETE attempts = %d, want 2", requests)
	}
}

func TestSyncHARejectsInvalidAddressesBeforeNetworkMutation_SW_HA_003(t *testing.T) {
	requests := 0
	server := newLoopbackTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	host, port := splitTestServerAddress(t, server.Listener.Addr().String())
	options := testHASyncOptions(t, server.Client())
	if err := syncHAUnban(context.Background(), &config.Config{HAEnabled: true, HAPeerIP: host, HAPeerPort: port, HAToken: "shared-secret"}, []string{"../../not-an-ip"}, options); err == nil {
		t.Fatal("invalid unban IP was accepted")
	}
	if requests != 0 {
		t.Fatalf("invalid unban emitted %d requests", requests)
	}
	if _, err := haPeerSyncURL("2001:db8::10", "62026"); err != nil {
		t.Fatalf("IPv6 peer URL rejected: %v", err)
	}
	if got, _ := haPeerSyncURL("2001:db8::10", "62026"); got != "https://[2001:db8::10]:62026/ha/sync" {
		t.Fatalf("IPv6 peer URL = %q", got)
	}
	if _, err := haPeerSyncURL("peer.example/path", "62026"); err == nil {
		t.Fatal("peer URL path injection was accepted")
	}
}

func TestHACIDRPeersAreInboundOnlyAndNeverDialed_SW_HA_001(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: haRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("CIDR destination was dialed")
	})}
	options := testHASyncOptions(t, client)
	cfg := &config.Config{HAEnabled: true, HAPeerIP: "10.20.30.0/24", HAPeerPort: "62026", HAToken: "shared-secret"}
	if err := syncHAPeers(context.Background(), cfg, options); !errors.Is(err, errNoDialableHAPeer) {
		t.Fatalf("manual inbound-only sync error = %v", err)
	}
	if err := syncHAUnban(context.Background(), cfg, []string{"192.0.2.44"}, options); err != nil {
		t.Fatalf("local unban in inbound-only mode = %v", err)
	}
	if requests != 0 {
		t.Fatalf("CIDR-only HA configuration emitted %d requests", requests)
	}

	plan, err := planHAClusterPeers("10.20.30.0/24, fd00:20:30::/64 10.20.30.7 fd00:20:30::7")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Allowlist, ",") != "10.20.30.0/24,fd00:20:30::/64,10.20.30.7,fd00:20:30::7" {
		t.Fatalf("HA allowlist plan = %v", plan.Allowlist)
	}
	if strings.Join(plan.Dialable, ",") != "10.20.30.7,fd00:20:30::7" {
		t.Fatalf("HA outbound plan = %v", plan.Dialable)
	}
	for _, invalid := range []string{
		"0.0.0.0/0",
		"10.20.30.0/23",
		"10.20.30.1/24",
		"::/0",
		"fd00:20:30::/63",
		"fd00:20:30::1/64",
		"::ffff:192.0.2.1",
		"::ffff:192.0.2.0/120",
		"fe80::1%eth0",
		"[fd00:20:30::7]",
	} {
		if _, err := planHAClusterPeers(invalid); err == nil {
			t.Fatalf("HA peer planner accepted %q", invalid)
		}
	}
}

func TestPersistHASyncStatusRejectsUnsafePathsAndPublishes0600_SW_HA_003(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ha")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	ownerUID := testHAOwnerUID(t, directory)
	path := filepath.Join(directory, "sync-status.json")
	snapshot := HASyncStatusSnapshot{UpdatedAt: "2026-08-14T12:00:00Z"}
	if err := persistHASyncStatus(path, ownerUID, snapshot); err != nil {
		temporaryInfo, statErr := os.Lstat(os.TempDir())
		if statErr == nil {
			temporaryOwner, ownerErr := haFileOwnerUID(temporaryInfo)
			if ownerErr == nil && temporaryOwner != 0 && strings.Contains(err.Error(), "neither root nor expected UID") {
				t.Skipf("sandbox remaps the sticky temporary directory owner: %v", err)
			}
		}
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("HA status mode = %s", info.Mode())
	}
	if err := persistHASyncStatus(path, ownerUID, HASyncStatusSnapshot{UpdatedAt: "2026-08-14T12:01:00Z"}); err != nil {
		t.Fatalf("atomic HA status replacement: %v", err)
	}

	symlinkPath := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := persistHASyncStatus(symlinkPath, ownerUID, snapshot); err == nil {
		t.Fatal("HA status publisher accepted a symbolic-link destination")
	}
	unsafeParent := t.TempDir()
	unsafeRoot, err := os.OpenRoot(unsafeParent)
	if err != nil {
		t.Fatal(err)
	}
	defer unsafeRoot.Close()
	if err := unsafeRoot.Mkdir("unsafe", 0700); err != nil {
		t.Fatal(err)
	}
	unsafeHandle, err := unsafeRoot.Open("unsafe")
	if err != nil {
		t.Fatal(err)
	}
	if err := unsafeHandle.Chmod(0777); err != nil {
		_ = unsafeHandle.Close()
		t.Fatal(err)
	}
	if err := unsafeHandle.Close(); err != nil {
		t.Fatal(err)
	}
	unsafeDirectory := filepath.Join(unsafeParent, "unsafe")
	if err := persistHASyncStatus(filepath.Join(unsafeDirectory, "status.json"), testHAOwnerUID(t, unsafeDirectory), snapshot); err == nil {
		t.Fatal("HA status publisher accepted a world-writable parent")
	}
}

func TestReadAndRenderActiveHABansStrictReadOnlyContract_SW_HA_004(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bans.json")
	ledger := cliHABanLedger{Version: cliHALedgerVersion, Bans: []cliHABanLedgerRecord{
		{IP: "198.51.100.2", Source: "producer-b", Reason: "active second", PeerScope: "10.20.30.0/29", OriginPeerIP: "10.20.30.3", CreatedAt: "2026-08-14T12:00:00Z", UpdatedAt: "2026-08-14T12:00:00Z", ExpiresAt: "2026-08-14T13:00:00Z", State: "active"},
		{IP: "198.51.100.1", Source: "producer-a", Reason: "active first", PeerScope: "10.20.30.0/29", OriginPeerIP: "10.20.30.2", CreatedAt: "2026-08-14T12:00:00Z", UpdatedAt: "2026-08-14T12:00:00Z", ExpiresAt: "2026-08-14T12:30:00Z", State: "active"},
		{IP: "198.51.100.3", Source: "expired", Reason: "expired record", PeerScope: "10.20.30.0/29", OriginPeerIP: "10.20.30.4", CreatedAt: "2026-08-14T10:00:00Z", UpdatedAt: "2026-08-14T10:00:00Z", ExpiresAt: "2026-08-14T11:00:00Z", State: "active"},
		{IP: "198.51.100.4", Source: "pending", Reason: "pending record", PeerScope: "10.20.30.0/29", OriginPeerIP: "10.20.30.5", CreatedAt: "2026-08-14T12:00:00Z", UpdatedAt: "2026-08-14T12:00:00Z", ExpiresAt: "2026-08-14T13:00:00Z", State: "pending_apply"},
	}}
	wire, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	bans, err := ReadActiveHABans(path, time.Date(2026, 8, 14, 12, 10, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 2 || bans[0].IP != "198.51.100.1" || bans[1].IP != "198.51.100.2" {
		t.Fatalf("active HA bans = %#v", bans)
	}
	var rendered strings.Builder
	if err := RenderActiveHABans(&rendered, bans); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"198.51.100.1", "claimed_source=producer-a", "observed_origin=10.20.30.2", "peer_scope=10.20.30.0/29", "reason=active first", "expires_at=2026-08-14T12:30:00Z"} {
		if !strings.Contains(rendered.String(), field) {
			t.Fatalf("rendered HA bans missing %q: %s", field, rendered.String())
		}
	}
	if strings.Contains(rendered.String(), "expired record") || strings.Contains(rendered.String(), "pending record") {
		t.Fatalf("rendered inactive HA records: %s", rendered.String())
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadActiveHABans(path, time.Date(2026, 8, 14, 12, 10, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		t.Fatalf("read-only HA ledger reader changed the file: before=%v after=%v err=%v", before, after, err)
	}

	ledgerRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerRoot.Close()
	ledgerHandle, err := ledgerRoot.Open(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledgerHandle.Chmod(0644); err != nil {
		_ = ledgerHandle.Close()
		t.Fatal(err)
	}
	if err := ledgerHandle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadActiveHABans(path, time.Now()); err == nil {
		t.Fatal("HA ledger reader accepted mode 0644")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadActiveHABans(path, time.Now()); err == nil {
		t.Fatal("HA ledger reader accepted a symbolic link")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"bans":[],"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadActiveHABans(path, time.Now()); err == nil {
		t.Fatal("HA ledger reader accepted an unknown schema field")
	}
	recordWithDuplicateSource := `{"ip":"198.51.100.9","source":"producer-a","source":"producer-b","reason":"duplicate schema","peer_scope":"10.20.30.0/29","origin_peer_ip":"10.20.30.2","expires_at":"2026-08-14T13:00:00Z","created_at":"2026-08-14T12:00:00Z","updated_at":"2026-08-14T12:00:00Z","state":"active"}`
	for name, duplicateWire := range map[string]string{
		"root":   `{"version":1,"version":1,"bans":[]}`,
		"record": `{"version":1,"bans":[` + recordWithDuplicateSource + `]}`,
	} {
		if err := os.WriteFile(path, []byte(duplicateWire), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadActiveHABans(path, time.Now()); err == nil {
			t.Fatalf("HA ledger reader accepted duplicate %s JSON key", name)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	oversized, err := ledgerRoot.OpenFile(filepath.Base(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.Truncate(maxCLIHALedgerBytes + 1); err != nil {
		_ = oversized.Close()
		t.Fatal(err)
	}
	if err := oversized.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadActiveHABans(path, time.Now()); err == nil {
		t.Fatal("HA ledger reader accepted an oversized file")
	}
	if bans, err := ReadActiveHABans(filepath.Join(directory, "missing.json"), time.Now()); err != nil || len(bans) != 0 {
		t.Fatalf("missing HA ledger = %#v, %v", bans, err)
	}
}

func TestVerifiedHAClientUsesExclusiveBundleAndTLS13_SW_HA_001(t *testing.T) {
	trustedCertificate := newHALoopbackServerCertificate(t, 101)
	trusted := newLoopbackTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{trustedCertificate}})
	defer trusted.Close()
	bundle := filepath.Join(t.TempDir(), "ha-ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := newVerifiedHAHTTPClient(bundle, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("verified HA client TLS contract changed")
	}
	response, err := client.Get(trusted.URL)
	if err != nil {
		t.Fatalf("trusted HA server rejected: %v", err)
	}
	_ = response.Body.Close()

	untrustedCertificate := newHALoopbackServerCertificate(t, 102)
	untrusted := newLoopbackTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{untrustedCertificate}})
	defer untrusted.Close()
	if _, err := client.Get(untrusted.URL); err == nil {
		t.Fatal("explicit HA CA bundle was not used as an exclusive pool")
	}

	_, trustedPort := splitTestServerAddress(t, trusted.Listener.Addr().String())
	if _, err := client.Get("https://localhost:" + trustedPort); err == nil {
		t.Fatal("HA client accepted a certificate with the wrong SAN")
	}

	symlink := filepath.Join(t.TempDir(), "ha-ca-link.pem")
	if err := os.Symlink(bundle, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := newVerifiedHAHTTPClient(symlink, time.Second); err == nil {
		t.Fatal("HA client accepted a symbolic-link CA bundle")
	}
	invalid := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newVerifiedHAHTTPClient(invalid, time.Second); err == nil {
		t.Fatal("HA client accepted an invalid CA bundle")
	}

	legacyProbeCertificate := newHALoopbackServerCertificate(t, 103)
	offeredVersions := make(chan []uint16, 1)
	legacyProbe := newLoopbackTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{legacyProbeCertificate},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			offeredVersions <- append([]uint16(nil), hello.SupportedVersions...)
			return nil, errors.New("TLS version probe complete")
		},
	})
	defer legacyProbe.Close()
	legacyProbeBundle := filepath.Join(t.TempDir(), "legacy-probe-ca.pem")
	if err := os.WriteFile(legacyProbeBundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: legacyProbe.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	tls13Client, err := newVerifiedHAHTTPClient(legacyProbeBundle, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls13Client.Get(legacyProbe.URL); err == nil {
		t.Fatal("HA TLS version probe unexpectedly completed a request")
	}
	select {
	case versions := <-offeredVersions:
		hasTLS13 := false
		for _, version := range versions {
			if version == tls.VersionTLS13 {
				hasTLS13 = true
			}
			if version <= tls.VersionTLS12 {
				t.Fatalf("HA client offered legacy TLS version %#x: %v", version, versions)
			}
		}
		if !hasTLS13 {
			t.Fatalf("HA client did not offer TLS 1.3: %v", versions)
		}
	case <-time.After(time.Second):
		t.Fatal("HA TLS version probe did not observe a ClientHello")
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
	return newLoopbackTLSServerWithConfig(t, handler, nil)
}

func newLoopbackTLSServerWithConfig(t *testing.T, handler http.Handler, tlsConfig *tls.Config) *httptest.Server {
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
	if tlsConfig != nil {
		server.TLS = tlsConfig
	}
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

func testHASyncOptions(t *testing.T, client *http.Client) haSyncOptions {
	t.Helper()
	root := t.TempDir()
	lists := filepath.Join(root, "lists")
	if err := os.Mkdir(lists, 0700); err != nil {
		t.Fatal(err)
	}
	statusDirectory := filepath.Join(root, "ha")
	if err := os.Mkdir(statusDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	return haSyncOptions{
		client:         client,
		requestTimeout: time.Second,
		retryAttempts:  1,
		retryBackoff:   0,
		statusFile:     filepath.Join(statusDirectory, "sync-status.json"),
		statusOwnerUID: testHAOwnerUID(t, statusDirectory),
		blacklistIPv4:  filepath.Join(lists, "blacklist.ipv4"),
		blacklistIPv6:  filepath.Join(lists, "blacklist.ipv6"),
		now:            func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) },
	}
}

func testHAOwnerUID(t *testing.T, path string) int {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	ownerUID, err := haFileOwnerUID(info)
	if err != nil {
		t.Fatal(err)
	}
	return ownerUID
}

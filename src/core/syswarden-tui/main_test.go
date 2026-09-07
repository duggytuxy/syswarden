package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rivo/tview"
	"golang.org/x/sys/unix"
)

func checkedTUITestIdentity(t *testing.T, name string, value int) uint32 {
	t.Helper()
	wide := int64(value)
	if wide < 0 || wide > math.MaxUint32 {
		t.Fatalf("effective %s is outside uint32: %d", name, value)
		return 0
	}
	return uint32(wide)
}

func tuiTestIdentity(t *testing.T) (uint32, uint32) {
	t.Helper()
	return checkedTUITestIdentity(t, "UID", os.Geteuid()), checkedTUITestIdentity(t, "GID", os.Getegid())
}

func newStrictTUIHATestCertificatePEM(t *testing.T, serial int64) []byte {
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

func TestTUIRemovalTombstoneStartupGuard_SW2_FWBACKEND_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "removal-in-progress-v1")
	uid, gid := tuiTestIdentity(t)
	present, err := inspectTUIRemovalTombstone(path, uid, gid)
	if err != nil || present {
		t.Fatalf("missing tombstone result = present %t, error %v", present, err)
	}
	if err := os.WriteFile(path, []byte(tuiRemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	present, err = inspectTUIRemovalTombstone(path, uid, gid)
	if err != nil || !present {
		t.Fatalf("valid tombstone result = present %t, error %v", present, err)
	}
	if err := os.WriteFile(path, []byte("SYSWARDEN_REMOVAL_V1\nstate=modified\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if present, err = inspectTUIRemovalTombstone(path, uid, gid); err == nil || !present {
		t.Fatalf("modified tombstone result = present %t, error %v", present, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(tuiRemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if present, err = inspectTUIRemovalTombstone(path, uid, gid); err == nil || !present {
		t.Fatalf("symlink tombstone result = present %t, error %v", present, err)
	}
}

func TestTUIRemovalTombstoneRejectsUnsafeParentBeforeMissingFile_SW2_FWBACKEND_001(t *testing.T) {
	uid, gid := tuiTestIdentity(t)

	unsafeParent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(unsafeParent, 0700); err != nil {
		t.Fatal(err)
	}
	unsafeParentFD, err := unix.Open(
		unsafeParent,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Fchmod(unsafeParentFD, 0700); err != nil {
			t.Errorf("restore unsafe parent mode: %v", err)
		}
		if err := unix.Close(unsafeParentFD); err != nil {
			t.Errorf("close unsafe parent: %v", err)
		}
	})
	if err := unix.Fchmod(unsafeParentFD, 0720); err != nil {
		t.Fatal(err)
	}
	unsafePath := filepath.Join(unsafeParent, "removal-in-progress-v1")
	if present, err := inspectTUIRemovalTombstone(unsafePath, uid, gid); err == nil || !present {
		t.Fatalf("unsafe parent result = present %t, error %v", present, err)
	}

	root := t.TempDir()
	realParent := filepath.Join(root, "real-state")
	linkedParent := filepath.Join(root, "linked-state")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	linkedPath := filepath.Join(linkedParent, "removal-in-progress-v1")
	if present, err := inspectTUIRemovalTombstone(linkedPath, uid, gid); err == nil || !present {
		t.Fatalf("symlink parent result = present %t, error %v", present, err)
	}
}

func TestTUIRemovalGuardRunsBeforeTerminalAndStateAccess_SW2_FWBACKEND_001(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	guard := strings.Index(content, "inspectTUIRemovalTombstone(tuiRemovalTombstonePath")
	terminal := strings.Index(content, "term.IsTerminal")
	if guard < 0 || terminal < 0 || guard > terminal {
		t.Fatalf("TUI removal guard is not the first startup boundary: guard=%d terminal=%d", guard, terminal)
	}
}

func newTUIHALoopbackServerCertificate(t *testing.T, serial int64) tls.Certificate {
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

func TestStrictTUIHACABundleParserConsumesAllBytes_SW_HA_001(t *testing.T) {
	certificateA := newStrictTUIHATestCertificatePEM(t, 1)
	certificateB := newStrictTUIHATestCertificatePEM(t, 2)
	decoded, _ := pem.Decode(certificateA)
	if decoded == nil {
		t.Fatal("test certificate did not decode")
	}
	validMulti := append(append([]byte("\n\t"), certificateA...), certificateB...)
	if err := addStrictHATrustCertificates(x509.NewCertPool(), validMulti); err != nil {
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
			if err := addStrictHATrustCertificates(x509.NewCertPool(), wire); err == nil {
				t.Fatal("strict TUI CA parser accepted invalid bundle")
			}
		})
	}
}

func TestHAHTTPClientFailsClosedAndVerifiesTrustedTLS13Peer(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TLS loopback unavailable: %v", err)
	}
	_ = listener.Close()

	trustedCertificate := newTUIHALoopbackServerCertificate(t, 201)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{trustedCertificate}}
	server.StartTLS()
	t.Cleanup(server.Close)

	untrustedClient, err := newHAHTTPClient(filepath.Join(t.TempDir(), "missing-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrustedClient.Get(server.URL); err == nil {
		t.Fatal("HA client accepted an untrusted self-signed peer certificate")
	}

	invalidBundle := filepath.Join(t.TempDir(), "invalid-ha-ca.pem")
	if err := os.WriteFile(invalidBundle, []byte("not a certificate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	invalidClient, invalidErr := newHAHTTPClient(invalidBundle)
	if invalidErr == nil || invalidClient != nil {
		t.Fatal("HA client accepted an invalid configured CA bundle")
	}

	caBundle := filepath.Join(t.TempDir(), "ha-ca.pem")
	if err := os.WriteFile(caBundle, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	}), 0600); err != nil {
		t.Fatal(err)
	}
	trustedClient, err := newHAHTTPClient(caBundle)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := trustedClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("HA client has no explicit TLS configuration")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("HA client minimum TLS version = %x", transport.TLSClientConfig.MinVersion)
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HA client disabled peer certificate verification")
	}
	response, err := trustedClient.Get(server.URL)
	if err != nil {
		t.Fatalf("HA client rejected an explicitly trusted TLS peer: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("trusted HA response status = %d", response.StatusCode)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("trusted HA response TLS state = %#v, want TLS 1.3", response.TLS)
	}

	untrustedCertificate := newTUIHALoopbackServerCertificate(t, 202)
	otherServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	otherServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{untrustedCertificate}}
	otherServer.StartTLS()
	t.Cleanup(otherServer.Close)
	if _, err := trustedClient.Get(otherServer.URL); err == nil {
		t.Fatal("explicit HA CA bundle was not used as an exclusive trust pool")
	}
	_, trustedPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedClient.Get("https://localhost:" + trustedPort); err == nil {
		t.Fatal("HA client accepted a certificate with the wrong SAN")
	}

	legacyProbeCertificate := newTUIHALoopbackServerCertificate(t, 203)
	offeredVersions := make(chan []uint16, 1)
	legacyProbeServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	legacyProbeServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{legacyProbeCertificate},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			offeredVersions <- append([]uint16(nil), hello.SupportedVersions...)
			return nil, errors.New("TLS version probe complete")
		},
	}
	legacyProbeServer.StartTLS()
	t.Cleanup(legacyProbeServer.Close)
	legacyProbeBundle := filepath.Join(t.TempDir(), "legacy-probe-ca.pem")
	if err := os.WriteFile(legacyProbeBundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: legacyProbeServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	tls13Client, err := newHAHTTPClient(legacyProbeBundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls13Client.Get(legacyProbeServer.URL); err == nil {
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

	symlinkBundle := filepath.Join(t.TempDir(), "ha-ca-link.pem")
	if err := os.Symlink(caBundle, symlinkBundle); err != nil {
		t.Fatal(err)
	}
	if _, err := newHAHTTPClient(symlinkBundle); err == nil {
		t.Fatal("HA client accepted a symbolic-link CA bundle")
	}
}

type tuiRoundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip tuiRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestHAPeerURLSupportsOnlyExactIPv4AndIPv6(t *testing.T) {
	for _, test := range []struct {
		peer string
		want string
	}{
		{peer: "192.0.2.10", want: "https://192.0.2.10:62026/ha/status"},
		{peer: "2001:db8::10", want: "https://[2001:db8::10]:62026/ha/status"},
		{peer: "[2001:db8::10]", want: "https://[2001:db8::10]:62026/ha/status"},
	} {
		got, err := haPeerURL(test.peer, "/ha/status")
		if err != nil {
			t.Fatalf("haPeerURL(%q): %v", test.peer, err)
		}
		if got != test.want {
			t.Fatalf("haPeerURL(%q) = %q, want %q", test.peer, got, test.want)
		}
	}
	for _, peer := range []string{"node.example", "10.0.0.0/29", "::ffff:192.0.2.10", "fe80::1%eth0"} {
		if _, err := haPeerURL(peer, "/ha/status"); err == nil {
			t.Fatalf("haPeerURL accepted non-dialable peer %q", peer)
		}
	}
}

func TestDashboardDataSchemaCompatibility(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("..", "..", "..", "testdata", "contracts", "dashboard-data-v4.02.8.json")
	fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatalf("read shared dashboard fixture: %v", err)
	}

	var decoded DashboardData
	if err := json.Unmarshal(fixture, &decoded); err != nil {
		t.Fatalf("DashboardData fixture no longer decodes: %v", err)
	}
	if decoded.ProfileName != "production" || decoded.System.Hostname != "node-a" {
		t.Fatalf("decoded identity changed: profile=%q host=%q", decoded.ProfileName, decoded.System.Hostname)
	}
	if decoded.WAF.ActiveSignatures != 78 || len(decoded.WAF.BannedIPs) != 1 {
		t.Fatalf("decoded WAF schema changed: signatures=%d bans=%d", decoded.WAF.ActiveSignatures, len(decoded.WAF.BannedIPs))
	}
	if decoded.WAF.Sparkline24h[23] != 4 {
		t.Fatalf("sparkline final bucket = %d, want 4", decoded.WAF.Sparkline24h[23])
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumer JSON contract diverged:\ngot=%s\nwant=%s", encoded, fixture)
	}
}

func TestDashboardDataDecodesAdditiveKPIEvidence_SW_KPI_001(t *testing.T) {
	t.Parallel()
	fixture := []byte(`{
  "waf": {
    "kpi_evidence_quality": "degraded",
    "journal_scan_complete": false,
    "journal_bytes_total": 4096,
    "journal_bytes_scanned": 2048,
    "journal_decode_errors": 2,
    "metric_rejected_events": 3,
    "metric_excluded_events": 4,
    "metric_admitted_events": 5,
    "top_attackers": [{"ip":"192.0.2.40","recorded_hits":6}]
  }
}`)
	var decoded DashboardData
	if err := json.Unmarshal(fixture, &decoded); err != nil {
		t.Fatal(err)
	}
	waf := decoded.WAF
	if waf.KPIEvidenceQuality != "degraded" || waf.JournalScanComplete == nil || *waf.JournalScanComplete ||
		waf.JournalBytesTotal == nil || *waf.JournalBytesTotal != 4096 ||
		waf.JournalBytesScanned == nil || *waf.JournalBytesScanned != 2048 ||
		waf.JournalDecodeErrors == nil || *waf.JournalDecodeErrors != 2 ||
		waf.MetricRejectedEvents == nil || *waf.MetricRejectedEvents != 3 ||
		waf.MetricExcludedEvents == nil || *waf.MetricExcludedEvents != 4 ||
		waf.MetricAdmittedEvents == nil || *waf.MetricAdmittedEvents != 5 ||
		len(waf.TopAttackers) != 1 || waf.TopAttackers[0].RecordedHits != 6 {
		t.Fatalf("additive KPI evidence decode = %#v", waf)
	}
}

func TestDashboardDataDecodesAndRendersThreatFeedEvidence_SW_FEED_015(t *testing.T) {
	t.Parallel()
	fixture := []byte(`{
  "layer3": {
    "threat_feeds": [
      {
        "feed_name": "syswarden_threatintel.ipv4",
        "address_family": "ipv4",
        "state": "current",
        "freshness": "current",
        "attestation": "verified",
        "source_origins": ["https://feed.example.test"],
        "retrieved_at": "2026-09-03T10:00:00Z",
        "age_seconds": 3600,
        "license_identifier": "CC-BY-4.0",
        "evidence_quality": "source-validated",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "accepted_count": 2,
        "skipped_count": 1,
        "rejected_count": 0
      },
      {
        "feed_name": "syswarden_threatintel.ipv6",
        "address_family": "ipv6",
        "state": "unavailable",
        "freshness": "unavailable",
        "attestation": "missing",
        "source_origins": [],
        "accepted_count": 0,
        "skipped_count": 0,
        "rejected_count": 0
      }
    ]
  }
}`)
	var decoded DashboardData
	if err := json.Unmarshal(fixture, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Layer3.ThreatFeeds) != 2 || decoded.Layer3.ThreatFeeds[0].AcceptedCount != 2 ||
		decoded.Layer3.ThreatFeeds[0].AgeSeconds == nil || *decoded.Layer3.ThreatFeeds[0].AgeSeconds != 3600 {
		t.Fatalf("threat-feed projection = %#v", decoded.Layer3.ThreatFeeds)
	}
	ipv4, ipv6 := threatFeedStatusSummaries(decoded.Layer3.ThreatFeeds, false)
	if ipv4 != "IPv4 current/source-validated" || ipv6 != "IPv6 unavailable/missing" {
		t.Fatalf("threat-feed summaries = %q / %q", ipv4, ipv6)
	}
	legacyIPv4, legacyIPv6 := threatFeedStatusSummaries(nil, false)
	if legacyIPv4 != "IPv4 not-reported/not-reported" || legacyIPv6 != "IPv6 not-reported/not-reported" {
		t.Fatalf("legacy summaries = %q / %q", legacyIPv4, legacyIPv6)
	}
}

func TestWAAPKPIEvidenceVisibility_SW_KPI_001(t *testing.T) {
	t.Parallel()
	completeGRCKPI := `{"schema_version":1,"status":"complete","window":{"scope":"retained-telemetry-journal","first_observed":"2026-09-03T10:00:00Z","last_observed":"2026-09-03T10:01:00Z","complete":true},"catalog":{"version":"catalog-v1","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","risk_model_version":"sw-risk-v1"},"evidence":{"journal_bytes_total":4096,"journal_bytes_scanned":4096,"journal_decode_errors":0,"admitted_events":4,"rejected_events":0,"excluded_events":0,"records_truncated":0},"lifecycle":{"scope":"ha-v2-runtime-snapshot","deletion_records":0,"expiry_records":0,"tombstone_records":0,"runtime_state_linked":true,"runtime_snapshot_complete":true,"runtime_cluster_id":"cluster-a","runtime_epoch":7,"runtime_node_id":"node-a","runtime_role":"writer","runtime_coordination":"healthy","runtime_model_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","runtime_checkpoint_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","runtime_peer_checkpoint_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","runtime_checkpoint_at":"2026-09-03T10:01:00Z","runtime_captured_at":"2026-09-03T10:01:01Z","active_claims":1},"records":[{"ip":"198.51.100.8","physical_hits":4,"first_observed":"2026-09-03T10:00:00Z","last_observed":"2026-09-03T10:01:00Z","selected_jail":"BF-SSH","jail_hits":4,"policy_hits":4,"enforcement":{"jail":"BF-SSH","action":"track"},"enforcement_state":"active","risk_category":"brute_force","policy_action":"track","severity_score":80,"severity_label":"Critical","peak_window_hits":4,"effective_threshold":4,"effective_window_seconds":60,"threshold_reached":true,"threshold_evidence":"observed-window","metric_quality":"attested","policy_quality":"attested","hit_evidence":"kernel-log-observation-v1","hit_quality":"measured","degraded_hits":0,"catalog":{"version":"catalog-v1","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","risk_model_version":"sw-risk-v1"}}]}`
	degradedUnlinkedGRCKPI := `{"schema_version":1,"status":"degraded","window":{"scope":"retained-telemetry-journal-tail","complete":false},"catalog":{"version":"catalog-v1","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","risk_model_version":"sw-risk-v1"},"evidence":{"journal_bytes_total":4096,"journal_bytes_scanned":2048,"journal_decode_errors":0,"admitted_events":0,"rejected_events":1,"excluded_events":0,"records_truncated":0},"lifecycle":{"scope":"observed-telemetry-records-only","deletion_records":0,"expiry_records":0,"tombstone_records":0,"runtime_state_linked":false},"records":[]}`
	complete := true
	zero := 0
	bytes := int64(4096)
	admitted := 4
	completeWAF := WAF{
		KPIEvidenceQuality:   "complete",
		JournalScanComplete:  &complete,
		JournalBytesTotal:    &bytes,
		JournalBytesScanned:  &bytes,
		JournalDecodeErrors:  &zero,
		MetricRejectedEvents: &zero,
		MetricExcludedEvents: &zero,
		MetricAdmittedEvents: &admitted,
		GRCKPI:               json.RawMessage(completeGRCKPI),
	}
	if kpiEvidenceDegradedOrUnavailable(completeWAF) {
		t.Fatal("complete KPI evidence was marked degraded")
	}
	if got := topAttackersKPIEvidenceTitle(completeWAF); got != topAttackersTitleNormal {
		t.Fatalf("complete title = %q", got)
	}
	if got, want := waapKPIEvidenceSummary(completeWAF), "quality=complete journal_complete=true scan_bytes=4096/4096 decode_errors=0 rejected_events=0 grc=complete/ha-v2-healthy"; got != want {
		t.Fatalf("complete summary = %q, want %q", got, want)
	}

	if !kpiEvidenceDegradedOrUnavailable(WAF{}) {
		t.Fatal("missing additive KPI evidence was not marked unavailable")
	}
	if got := topAttackersKPIEvidenceTitle(WAF{}); got != topAttackersTitleDegraded {
		t.Fatalf("unavailable title = %q", got)
	}
	if got, want := waapKPIEvidenceSummary(WAF{}), "quality=unavailable journal_complete=unavailable scan_bytes=unavailable/unavailable decode_errors=unavailable rejected_events=unavailable grc=unavailable"; got != want {
		t.Fatalf("unavailable summary = %q, want %q", got, want)
	}

	one := 1
	degraded := completeWAF
	degraded.KPIEvidenceQuality = "degraded"
	degraded.MetricRejectedEvents = &one
	if !kpiEvidenceDegradedOrUnavailable(degraded) || !strings.Contains(topAttackersKPIEvidenceTitle(degraded), "KPI EVIDENCE DEGRADED") {
		t.Fatal("rejected metric event was not made visible as degraded KPI evidence")
	}

	unlinked := completeWAF
	unlinked.GRCKPI = json.RawMessage(degradedUnlinkedGRCKPI)
	if !kpiEvidenceDegradedOrUnavailable(unlinked) || grcKPIEvidenceSummary(unlinked.GRCKPI) != "degraded/runtime-unlinked" {
		t.Fatal("unlinked GRC runtime evidence was not made visible as degraded")
	}

	invalidDigest := completeWAF
	invalidDigest.GRCKPI = json.RawMessage(strings.Replace(completeGRCKPI, strings.Repeat("b", 64), strings.Repeat("B", 64), 1))
	if !kpiEvidenceDegradedOrUnavailable(invalidDigest) {
		t.Fatal("noncanonical GRC runtime identity was presented as complete")
	}

	missingEpoch := completeWAF
	missingEpoch.GRCKPI = json.RawMessage(strings.Replace(completeGRCKPI, `"runtime_epoch":7,`, "", 1))
	if !kpiEvidenceDegradedOrUnavailable(missingEpoch) || grcKPIEvidenceSummary(missingEpoch.GRCKPI) != "invalid" {
		t.Fatal("GRC runtime evidence without an epoch was presented as complete")
	}

	invalidNode := completeWAF
	invalidNode.GRCKPI = json.RawMessage(strings.Replace(completeGRCKPI, `"runtime_node_id":"node-a"`, `"runtime_node_id":"Node A"`, 1))
	if !kpiEvidenceDegradedOrUnavailable(invalidNode) || grcKPIEvidenceSummary(invalidNode.GRCKPI) != "invalid" {
		t.Fatal("GRC runtime evidence with a noncanonical node identity was presented as valid")
	}

	adversarial := map[string]json.RawMessage{
		"incomplete":               json.RawMessage(`{"schema_version":1,"status":"complete","lifecycle":{"runtime_state_linked":true}}`),
		"missing cluster identity": json.RawMessage(strings.Replace(completeGRCKPI, `"runtime_cluster_id":"cluster-a",`, "", 1)),
		"unknown":                  json.RawMessage(strings.TrimSuffix(completeGRCKPI, "}") + `,"unknown":true}`),
		"duplicate":                json.RawMessage(strings.Replace(completeGRCKPI, `"status":"complete"`, `"status":"complete","status":"complete"`, 1)),
		"trailing":                 json.RawMessage(completeGRCKPI + ` {}`),
		"risk category":            json.RawMessage(strings.Replace(completeGRCKPI, `"risk_category":"brute_force"`, `"risk_category":"invalid"`, 1)),
		"policy action":            json.RawMessage(strings.Replace(completeGRCKPI, `"policy_action":"track"`, `"policy_action":"detect"`, 1)),
		"hit evidence":             json.RawMessage(strings.Replace(completeGRCKPI, `"hit_evidence":"kernel-log-observation-v1"`, `"hit_evidence":"claimed"`, 1)),
		"threshold evidence":       json.RawMessage(strings.Replace(completeGRCKPI, `"threshold_evidence":"observed-window"`, `"threshold_evidence":"none"`, 1)),
		"severity score":           json.RawMessage(strings.Replace(completeGRCKPI, `"severity_score":80`, `"severity_score":70`, 1)),
		"missing checkpoint":       json.RawMessage(strings.Replace(completeGRCKPI, `"runtime_checkpoint_sha256":"`+strings.Repeat("c", 64)+`",`, "", 1)),
		"peer checkpoint mismatch": json.RawMessage(strings.Replace(completeGRCKPI, `"runtime_peer_checkpoint_sha256":"`+strings.Repeat("c", 64)+`"`, `"runtime_peer_checkpoint_sha256":"`+strings.Repeat("d", 64)+`"`, 1)),
		"invalid calendar date":    json.RawMessage(strings.Replace(completeGRCKPI, `"runtime_checkpoint_at":"2026-09-03T10:01:00Z"`, `"runtime_checkpoint_at":"2026-02-30T10:01:00Z"`, 1)),
		"stale healthy checkpoint": json.RawMessage(strings.Replace(completeGRCKPI, `"runtime_checkpoint_at":"2026-09-03T10:01:00Z"`, `"runtime_checkpoint_at":"2026-09-03T09:55:59Z"`, 1)),
		"future degraded checkpoint": json.RawMessage(strings.Replace(
			strings.Replace(
				strings.Replace(completeGRCKPI, `"status":"complete"`, `"status":"degraded"`, 1),
				`"runtime_coordination":"healthy","runtime_model_sha256"`, `"runtime_coordination":"degraded","runtime_model_sha256"`, 1,
			),
			`"runtime_checkpoint_at":"2026-09-03T10:01:00Z"`, `"runtime_checkpoint_at":"2026-09-03T10:06:01.000000001Z"`, 1,
		)),
		"degraded healthy peer mismatch": json.RawMessage(strings.Replace(
			strings.Replace(completeGRCKPI, `"status":"complete"`, `"status":"degraded"`, 1),
			`"runtime_peer_checkpoint_sha256":"`+strings.Repeat("c", 64)+`"`, `"runtime_peer_checkpoint_sha256":"`+strings.Repeat("d", 64)+`"`, 1,
		)),
	}
	for name, raw := range adversarial {
		t.Run(name, func(t *testing.T) {
			candidate := completeWAF
			candidate.GRCKPI = raw
			if !kpiEvidenceDegradedOrUnavailable(candidate) || grcKPIEvidenceSummary(raw) != "invalid" {
				t.Fatal("malformed GRC KPI evidence was presented as complete")
			}
		})
	}
}

func TestBannedRegistryStateRequiresActiveRuntimeEvidence_SW_GRC_017(t *testing.T) {
	t.Parallel()
	if got := bannedRegistryState(BannedIP{EnforcementState: "active"}); got != "BAN" {
		t.Fatalf("active state = %q", got)
	}
	for _, state := range []string{"", "unknown", "absent", "expired", "deleted", "tombstoned", "invalid"} {
		if got := bannedRegistryState(BannedIP{EnforcementState: state}); got != "UNKNOWN" {
			t.Fatalf("state %q was rendered as %q", state, got)
		}
	}
}

func TestDashboardDataBackwardAndForwardDecodeContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		release string
		host    string
	}{
		{fixture: "dashboard-data-v4.02.7.json", release: "v4.02.7", host: "node-n-minus-one"},
		{fixture: "dashboard-data-v4.02.8.json", release: "v4.02.8", host: "node-a"},
		{fixture: "dashboard-data-forward-extension.json", release: "v4.03.0", host: "node-forward"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.fixture, func(t *testing.T) {
			t.Parallel()
			fixturePath := filepath.Join("..", "..", "..", "testdata", "contracts", test.fixture)
			fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
			if err != nil {
				t.Fatal(err)
			}
			var decoded DashboardData
			if err := json.Unmarshal(fixture, &decoded); err != nil {
				t.Fatalf("compatible dashboard fixture was rejected: %v", err)
			}
			if decoded.GithubRelease != test.release || decoded.System.Hostname != test.host {
				t.Fatalf("decoded identity = %q/%q", decoded.GithubRelease, decoded.System.Hostname)
			}
		})
	}
}

func TestTUIHAStatusAndTelemetryRequireBearer_SW_HA_001(t *testing.T) {
	if haPeerPort != "62026" {
		t.Fatalf("default HA peer port = %q, want 62026", haPeerPort)
	}
	requests := 0
	testClient := &http.Client{Transport: tuiRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer shared-secret" {
			t.Errorf("missing TUI bearer on %s", request.URL.Path)
		}
		if request.URL.Path != "/ha/status" && request.URL.Path != "/ha/telemetry" {
			t.Errorf("unexpected TUI HA path %q", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})}

	haRuntimeConfigMu.Lock()
	previousClient, previousCAErr := httpClient, haCAErr
	previousToken, previousConfigErr := haBearerToken, haRuntimeConfigErr
	httpClient, haCAErr = testClient, nil
	haBearerToken, haRuntimeConfigErr = "shared-secret", nil
	haRuntimeConfigMu.Unlock()
	t.Cleanup(func() {
		haRuntimeConfigMu.Lock()
		httpClient, haCAErr = previousClient, previousCAErr
		haBearerToken, haRuntimeConfigErr = previousToken, previousConfigErr
		haRuntimeConfigMu.Unlock()
	})
	for _, endpoint := range []string{"/ha/status", "/ha/telemetry"} {
		response, err := haGet("https://192.0.2.10:62026" + endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	if requests != 2 {
		t.Fatalf("authenticated TUI requests = %d, want 2", requests)
	}

	haRuntimeConfigMu.Lock()
	haBearerToken = " bad-token "
	haRuntimeConfigMu.Unlock()
	if _, err := haGet("https://192.0.2.10:62026/ha/status"); err == nil || strings.Contains(err.Error(), "bad-token") ||
		!strings.Contains(err.Error(), "integrations.ha.token") || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("invalid token did not fail closed without disclosure: %v", err)
	}
	if requests != 2 {
		t.Fatal("TUI issued an HTTP request before validating the bearer token")
	}
	haRuntimeConfigMu.Lock()
	haBearerToken = "shared-secret"
	httpClient = &http.Client{Transport: tuiRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxTUIHAResponseBytes+1))), Header: make(http.Header)}, nil
	})}
	haRuntimeConfigMu.Unlock()
	if _, err := haGet("https://192.0.2.10:62026/ha/status"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized TUI HA response error = %v", err)
	}
}

func TestTUIHAModularConfigAndInboundOnlyCIDR_SW_HA_001(t *testing.T) {
	root := t.TempDir()
	modular := filepath.Join(root, "config")
	modules := filepath.Join(modular, "modules")
	if err := os.MkdirAll(modules, 0700); err != nil {
		t.Fatal(err)
	}
	master := "[integrations.ha]\nenabled = true\npeer_ips = [\"10.20.30.0/29\", \"2001:db8::10\"]\npeer_port = \"62026\"\ntoken = \"old-token\"\n"
	if err := os.WriteFile(filepath.Join(modular, "config.toml"), []byte(master), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "10-port.toml"), []byte("[integrations.ha]\npeer_port = \"62443\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "20-token.toml"), []byte("[integrations.ha]\ntoken = \"shared-secret\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadTUIHAConfig(modular, filepath.Join(root, "legacy.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.PeerPort != "62443" || cfg.Token != "shared-secret" {
		t.Fatalf("merged modular HA config = %#v", cfg)
	}
	if got := dialableTUIHAPeers(cfg.PeerIPs); !reflect.DeepEqual(got, []string{"2001:db8::10"}) {
		t.Fatalf("dialable modular peers = %v", got)
	}
}

func TestTUIHALegacyFallbackIsFailClosed_SW_HA_001(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy.conf")
	wire := "SYSWARDEN_HA_ENABLED=y\nSYSWARDEN_HA_PEER_IP=192.0.2.10,10.20.30.0/29\nSYSWARDEN_HA_PEER_PORT=62026\nSYSWARDEN_HA_TOKEN=shared-secret\n"
	if err := os.WriteFile(legacy, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadTUIHAConfig(filepath.Join(root, "missing-modular"), legacy)
	if err != nil {
		t.Fatal(err)
	}
	if got := dialableTUIHAPeers(cfg.PeerIPs); !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
		t.Fatalf("legacy dialable peers = %v", got)
	}

	modular := filepath.Join(root, "config")
	if err := os.Mkdir(modular, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modular, "config.toml"), []byte("[integrations.ha]\nenabled=true\npeer_ips=[\"192.0.2.10\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTUIHAConfig(modular, legacy); err == nil || !strings.Contains(err.Error(), "integrations.ha.token") ||
		!strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("modular HA config without token did not provide a safe upgrade action: %v", err)
	}
	modularRoot, err := os.OpenRoot(modular)
	if err != nil {
		t.Fatal(err)
	}
	defer modularRoot.Close()
	configHandle, err := modularRoot.Open("config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if err := configHandle.Chmod(0666); err != nil {
		_ = configHandle.Close()
		t.Fatal(err)
	}
	if err := configHandle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTUIHAConfig(modular, legacy); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("TUI accepted a group/world-writable modular config containing HA credentials: %v", err)
	}
}

func TestBuildProgressBarCompatibility(t *testing.T) {
	t.Parallel()

	if got := buildProgressBar(0, 0, "RAM", "green"); got != "[gray][RAM 0%][-]" {
		t.Fatalf("zero progress bar = %q", got)
	}
	if got := buildProgressBar(50, 100, "RAM", "green"); !strings.Contains(got, "RAM 50.0%") {
		t.Fatalf("half progress bar = %q", got)
	}
	if got := buildProgressBar(90, 100, "RAM", "green"); !strings.HasPrefix(got, "[red]") {
		t.Fatalf("high utilization did not use red: %q", got)
	}
	if got := buildProgressBar(200, 100, "RAM", "green"); !strings.Contains(got, "100.0%") {
		t.Fatalf("over-capacity progress bar was not capped: %q", got)
	}
}

func TestDashboardSnapshotTitleIsOperationalAndNeutral_SW_DOC_001(t *testing.T) {
	lower := strings.ToLower(dashboardSnapshotTitle)
	if !strings.Contains(lower, "local dashboard") {
		t.Fatalf("dashboard snapshot title = %q", dashboardSnapshotTitle)
	}
	for _, forbidden := range []string{"enterprise", "compliant", "certified"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("dashboard snapshot title contains unsupported claim %q", forbidden)
		}
	}
}

func TestEmptyRegistryMessageDoesNotClaimSecurity_SW_DOC_001(t *testing.T) {
	if emptyRegistryMessage != "Registry is empty. No active entries." {
		t.Fatalf("empty registry message = %q", emptyRegistryMessage)
	}
	for _, forbidden := range []string{"secure", "safe", "compliant", "certified"} {
		if strings.Contains(strings.ToLower(emptyRegistryMessage), forbidden) {
			t.Fatalf("empty registry message contains unsupported claim %q", forbidden)
		}
	}
}

func TestBuildProgressBarRejectsNegativeInputWithoutPanic_SW_RES_001(t *testing.T) {
	if got := buildProgressBar(-1, 10, "RAM", "green"); got != "[gray][RAM 0%][-]" {
		t.Fatalf("negative progress bar = %q", got)
	}
	if got := buildProgressBar(1, -10, "RAM", "green"); got != "[gray][RAM 0%][-]" {
		t.Fatalf("negative-total progress bar = %q", got)
	}
}

func TestTUIRunFailureIsReportedWithoutPanic_SW_RES_005(t *testing.T) {
	var output bytes.Buffer
	err := errors.New("terminal unavailable")
	if code := reportTUIRunResult(err, &output); code != 1 {
		t.Fatalf("TUI run failure exit code = %d, want 1", code)
	}
	if !strings.Contains(output.String(), "Terminal application failed: terminal unavailable") {
		t.Fatalf("TUI run failure output = %q", output.String())
	}
	output.Reset()
	if code := reportTUIRunResult(nil, &output); code != 0 || output.Len() != 0 {
		t.Fatalf("successful TUI run returned code=%d output=%q", code, output.String())
	}
	if code := reportTUIRunResult(err, nil); code != 1 {
		t.Fatalf("TUI run failure with nil output exit code = %d, want 1", code)
	}
}

func TestDashboardSelectionRejectsStaleResultsAndAttributesCurrentErrors_SW_RES_002(t *testing.T) {
	selection := &tuiNodeSelection{ip: "192.0.2.10"}
	staleNode, staleGeneration := selection.snapshot()
	selection.selectNode("192.0.2.11")

	mu.Lock()
	previousError := fetchError
	fetchError = errors.New("sentinel")
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		fetchError = previousError
		mu.Unlock()
	})
	if applyDashboardFetchResult(selection, staleNode, staleGeneration, DashboardData{}, errors.New("stale failure")) {
		t.Fatal("stale node result was published")
	}
	mu.Lock()
	if fetchError == nil || fetchError.Error() != "sentinel" {
		t.Fatalf("stale result changed current error state: %v", fetchError)
	}
	mu.Unlock()

	currentNode, currentGeneration := selection.snapshot()
	if !applyDashboardFetchResult(selection, currentNode, currentGeneration, DashboardData{}, errors.New("current failure")) {
		t.Fatal("current node result was not published")
	}
	mu.Lock()
	currentError := fetchError
	mu.Unlock()
	if currentError == nil || !strings.Contains(currentError.Error(), currentNode) || strings.Contains(currentError.Error(), staleNode) {
		t.Fatalf("current error attribution = %v", currentError)
	}
}

func TestDashboardSelectionIsRaceSafe_SW_RES_003(t *testing.T) {
	selection := &tuiNodeSelection{ip: "local"}
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for iteration := 0; iteration < 1000; iteration++ {
				if worker%2 == 0 {
					if iteration%2 == 0 {
						selection.selectNode("192.0.2.10")
					} else {
						selection.selectNode("192.0.2.11")
					}
				} else {
					node, generation := selection.snapshot()
					selection.ifCurrent(node, generation, func() {})
				}
			}
		}(worker)
	}
	group.Wait()
}

func TestDecodeTUIDashboardDataRejectsUnsafeCounters_SW_RES_004(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DashboardData)
	}{
		{name: "negative memory", mutate: func(snapshot *DashboardData) { snapshot.System.RamUsedMb = -1 }},
		{name: "negative sparkline", mutate: func(snapshot *DashboardData) { snapshot.WAF.Sparkline24h[0] = -1 }},
		{name: "invalid severity", mutate: func(snapshot *DashboardData) {
			snapshot.WAF.TopAttackers = []Attacker{{SeverityScore: 101}}
		}},
		{name: "negative GRC evidence", mutate: func(snapshot *DashboardData) {
			value := -1
			snapshot.WAF.MetricAdmittedEvents = &value
		}},
		{name: "oversized profile", mutate: func(snapshot *DashboardData) {
			snapshot.ProfileName = strings.Repeat("x", maxTUIDashboardStringBytes+1)
		}},
		{name: "system terminal control", mutate: func(snapshot *DashboardData) {
			snapshot.System.Hostname = "node\x1b[2J"
		}},
		{name: "oversized service", mutate: func(snapshot *DashboardData) {
			snapshot.System.Services = []Service{{Name: strings.Repeat("x", maxTUIDashboardStringBytes+1)}}
		}},
		{name: "oversized threat feed origin", mutate: func(snapshot *DashboardData) {
			snapshot.Layer3.ThreatFeeds = []ThreatFeedStatus{{SourceOrigins: []string{strings.Repeat("x", maxTUIDashboardStringBytes+1)}}}
		}},
		{name: "oversized attacker text", mutate: func(snapshot *DashboardData) {
			snapshot.WAF.TopAttackers = []Attacker{{Threat: strings.Repeat("x", maxTUIDashboardStringBytes+1)}}
		}},
		{name: "payload terminal control", mutate: func(snapshot *DashboardData) {
			snapshot.WAF.AllowedEvents = []AllowedEvent{{Payload: "line-one\nline-two"}}
		}},
		{name: "oversized whitelist", mutate: func(snapshot *DashboardData) {
			snapshot.Whitelist.IPs = []string{strings.Repeat("x", maxTUIDashboardStringBytes+1)}
		}},
		{name: "invalid complete projection", mutate: func(snapshot *DashboardData) {
			snapshot.Projection = &DashboardProjection{Quality: "complete", Reason: "dashboard-envelope-bound", PayloadsProjected: 1}
		}},
		{name: "invalid degraded projection", mutate: func(snapshot *DashboardData) {
			snapshot.Projection = &DashboardProjection{Quality: "degraded"}
		}},
		{name: "projection count beyond payload inventory", mutate: func(snapshot *DashboardData) {
			snapshot.Projection = &DashboardProjection{Quality: "degraded", Reason: "display-payload-bound", PayloadsProjected: 2}
			snapshot.WAF.BannedIPs = []BannedIP{{}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := DashboardData{}
			test.mutate(&snapshot)
			wire, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeTUIDashboardData(wire); err == nil {
				t.Fatal("unsafe telemetry snapshot was accepted")
			}
		})
	}
}

func TestTUIDashboardAcceptsExactOneMiBBoundary_SW_RES_006(t *testing.T) {
	snapshot := DashboardData{
		Projection: &DashboardProjection{Quality: "complete"},
		WAF:        WAF{AllowedEvents: make([]AllowedEvent, 400)},
	}
	for index := range snapshot.WAF.AllowedEvents {
		snapshot.WAF.AllowedEvents[index].IP = "192.0.2.1"
		snapshot.WAF.AllowedEvents[index].Service = "sshd"
	}
	base, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	remaining := maxTUIDashboardJSONBytes - len(base)
	if remaining <= 0 || remaining > len(snapshot.WAF.AllowedEvents)*maxTUIDashboardStringBytes {
		t.Fatalf("test fixture cannot span exact boundary: base=%d remaining=%d", len(base), remaining)
	}
	for index := range snapshot.WAF.AllowedEvents {
		if remaining == 0 {
			break
		}
		width := min(remaining, maxTUIDashboardStringBytes)
		snapshot.WAF.AllowedEvents[index].Payload = strings.Repeat("x", width)
		remaining -= width
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != maxTUIDashboardJSONBytes {
		t.Fatalf("exact boundary fixture size = %d, want %d", len(wire), maxTUIDashboardJSONBytes)
	}
	if _, err := decodeTUIDashboardData(wire); err != nil {
		t.Fatalf("exact boundary dashboard was rejected: %v", err)
	}
	if _, err := decodeTUIDashboardData(append(append([]byte(nil), wire...), ' ')); err == nil {
		t.Fatal("dashboard one byte above the shared envelope was accepted")
	}
}

func TestTUIDashboardEscapesUntrustedDynamicColorMarkup_SW_RES_007(t *testing.T) {
	oldHeader, oldL3, oldVectors, oldTrusted := headerText, l3Text, vectorsText, trustedText
	oldPorts, oldSparkline, oldAttackers, oldBanned := portsTable, sparklineText, attackersTable, bannedTable
	mu.Lock()
	oldData, oldFetchError := data, fetchError
	mu.Unlock()
	t.Cleanup(func() {
		headerText, l3Text, vectorsText, trustedText = oldHeader, oldL3, oldVectors, oldTrusted
		portsTable, sparklineText, attackersTable, bannedTable = oldPorts, oldSparkline, oldAttackers, oldBanned
		mu.Lock()
		data, fetchError = oldData, oldFetchError
		mu.Unlock()
	})

	headerText = tview.NewTextView().SetDynamicColors(true)
	l3Text = tview.NewTextView().SetDynamicColors(true)
	vectorsText = tview.NewTextView().SetDynamicColors(true)
	trustedText = tview.NewTextView().SetDynamicColors(true)
	portsTable = tview.NewTable()
	sparklineText = tview.NewTextView().SetDynamicColors(true)
	attackersTable = tview.NewTable()
	bannedTable = tview.NewTable()

	malicious := map[string]string{
		"profile":   "[purple]profile[-]",
		"hostname":  "[navy]host[-]",
		"service":   "[MAROON]SERVICE[-]",
		"status":    "ACTIVE[OLIVE]OWNED[-]",
		"whitelist": "[teal]192.0.2.10[-]",
		"freshness": "[lime]current[-]",
		"quality":   "[aqua]verified[-]",
	}
	snapshot := DashboardData{
		ProfileName: malicious["profile"],
		System: SystemData{
			Hostname: malicious["hostname"],
			Services: []Service{{Name: malicious["service"], Status: malicious["status"]}},
		},
		Layer3: Layer3{ThreatFeeds: []ThreatFeedStatus{{
			AddressFamily:   "ipv4",
			Freshness:       malicious["freshness"],
			Attestation:     "verified",
			EvidenceQuality: malicious["quality"],
		}}},
		Whitelist: Whitelist{ActiveIPs: 1, IPs: []string{malicious["whitelist"]}},
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeTUIDashboardData(wire)
	if err != nil {
		t.Fatalf("printable markup fixture was rejected instead of escaped: %v", err)
	}
	mu.Lock()
	data, fetchError = decoded, nil
	mu.Unlock()
	refreshUI()

	headerWire := headerText.GetText(false)
	trustedWire := trustedText.GetText(false)
	l3Wire := l3Text.GetText(false)
	for name, raw := range malicious {
		view := headerWire
		switch name {
		case "whitelist":
			view = trustedWire
		case "freshness", "quality":
			view = l3Wire
		}
		if strings.Contains(view, raw) {
			t.Fatalf("%s markup remained active in dynamic-color view: %q", name, view)
		}
		if !strings.Contains(view, escapeTUIDynamicValue(raw)) {
			t.Fatalf("%s markup was not retained as escaped text: %q", name, view)
		}
	}
}

func TestPayloadTranslationsCompatibility(t *testing.T) {
	t.Parallel()

	const timestamp = "2026-08-13 08:00:00"
	allowed := TranslateAllowedPayload(
		"sshd",
		"Accepted publickey for alice from 192.0.2.10 port 22 ssh2: ED25519 SHA256:test",
		"192.0.2.10",
		timestamp,
	)
	if !strings.Contains(allowed, "user 'alice' via public key") || !strings.Contains(allowed, "ED25519 SHA256:test") {
		t.Fatalf("allowed SSH translation = %q", allowed)
	}

	attack := TranslatePayload(
		"ssh-auth",
		"Failed password from 198.51.100.9 port 2222",
		"198.51.100.9",
		timestamp,
	)
	if !strings.Contains(attack, "SSH brute-force on port 2222") {
		t.Fatalf("SSH attack translation = %q", attack)
	}

	web := TranslatePayload(
		"sqli",
		"GET /search?q=attack HTTP/1.1",
		"198.51.100.9",
		timestamp,
	)
	if !strings.Contains(web, "Web exploit (SQLI) on URI '/search?q=attack'") {
		t.Fatalf("web attack translation = %q", web)
	}
}

package network

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestResolveSaaSAllowancePrecedence_SW_SAAS_001(t *testing.T) {
	tests := []struct {
		name     string
		official any
		legacy   any
		want     bool
	}{
		{name: "new modular configuration is disabled", want: false},
		{name: "legacy true remains compatible", legacy: true, want: true},
		{name: "legacy false remains disabled", legacy: false, want: false},
		{name: "official true wins", official: true, legacy: false, want: true},
		{name: "official false wins", official: false, legacy: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := viper.New()
			if test.official != nil {
				configuration.Set("network.saas.allow_monitors", test.official)
			}
			if test.legacy != nil {
				configuration.Set("integrations.saas.enabled", test.legacy)
			}
			if got := resolveSaaSAllowance(configuration); got != test.want {
				t.Fatalf("resolveSaaSAllowance() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSaaSFeedParsingAndPairRetention_SW_SAAS_001(t *testing.T) {
	responseBody := "# Better Stack\n2606:4700:4700::2\n8.8.8.2\n8.8.8.2\n8.8.8.129/24\n"
	status := http.StatusOK
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return textResponse(request, status, responseBody), nil
	})}

	directory := t.TempDir()
	ipv4Path := filepath.Join(directory, "monitors.ipv4")
	ipv6Path := filepath.Join(directory, "monitors.ipv6")
	if err := os.WriteFile(ipv4Path, []byte("8.8.4.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipv6Path, []byte("2606:4700:4700:ffff::1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	downloader := &SaasMonitorDownloader{
		client:                  client,
		feeds:                   []saasFeed{{url: "https://feeds.example.test/ips.txt", required: true}},
		targetIPv4:              ipv4Path,
		targetIPv6:              ipv6Path,
		localInterfaceAddresses: func() ([]netip.Addr, error) { return nil, nil },
		protectedHAPeers:        func() ([]netip.Prefix, error) { return nil, nil },
	}

	status = http.StatusServiceUnavailable
	if err := downloader.fetchMonitors(); err == nil {
		t.Fatal("required feed failure did not fail closed")
	}
	assertFileContent(t, ipv4Path, "8.8.4.1\n")
	assertFileContent(t, ipv6Path, "2606:4700:4700:ffff::1\n")

	status = http.StatusOK
	if err := downloader.fetchMonitors(); err != nil {
		t.Fatalf("fetchMonitors() rejected a valid feed: %v", err)
	}
	assertFileContent(t, ipv4Path, "8.8.8.0/24\n8.8.8.2\n")
	assertFileContent(t, ipv6Path, "2606:4700:4700::2\n")
	assertFileContent(
		t,
		filepath.Join(directory, saasPairManifestName),
		string(renderSaaSPairManifest([]byte("8.8.8.0/24\n8.8.8.2\n"), []byte("2606:4700:4700::2\n"))),
	)
	for _, path := range []string{ipv4Path, ipv6Path} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("published mode for %s = %#o, want 0600", path, info.Mode().Perm())
		}
	}
}

func TestSaaSNetworkFailurePreservesLegacyIPv4OnlyState_SW_SAAS_001(t *testing.T) {
	directory := t.TempDir()
	ipv4Path := filepath.Join(directory, "syswarden_saas_monitors.ipv4")
	ipv6Path := filepath.Join(directory, "syswarden_saas_monitors.ipv6")
	legacyIPv4 := "8.8.8.10\n8.8.4.0/24"
	if err := os.WriteFile(ipv4Path, []byte(legacyIPv4), 0600); err != nil {
		t.Fatal(err)
	}
	downloader := &SaasMonitorDownloader{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network unavailable")
		})},
		feeds:                   []saasFeed{{url: "https://feeds.example.test/ips.txt", required: true}},
		targetIPv4:              ipv4Path,
		targetIPv6:              ipv6Path,
		localInterfaceAddresses: func() ([]netip.Addr, error) { return nil, nil },
		protectedHAPeers:        func() ([]netip.Prefix, error) { return nil, nil },
	}
	if err := downloader.fetchMonitors(); err == nil || !strings.Contains(err.Error(), "network unavailable") {
		t.Fatalf("network failure error = %v", err)
	}
	assertFileContent(t, ipv4Path, legacyIPv4)
	for _, path := range []string{ipv6Path, filepath.Join(directory, saasPairManifestName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("network failure created %s: %v", path, err)
		}
	}
}

func TestSaaSProtectedEntriesPreserveLastKnownGoodPair_SW_SEC_H4(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		localErr error
	}{
		{name: "IPv4 default route", body: "0.0.0.0/0\n"},
		{name: "IPv6 default route", body: "::/0\n"},
		{name: "too broad public prefix", body: "8.0.0.0/8\n"},
		{name: "private bogon", body: "10.0.0.0/24\n"},
		{name: "documentation bogon", body: "192.0.2.1\n"},
		{name: "local interface network", body: "9.9.9.0/24\n"},
		{name: "HA peer", body: "8.8.4.44\n"},
		{name: "interface inventory unavailable", body: "8.8.8.44\n", localErr: errors.New("injected interface failure")},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			ipv4Path := filepath.Join(directory, "monitors.ipv4")
			ipv6Path := filepath.Join(directory, "monitors.ipv6")
			if err := os.WriteFile(ipv4Path, []byte("8.8.8.8\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ipv6Path, []byte("2606:4700:4700::1111\n"), 0600); err != nil {
				t.Fatal(err)
			}
			downloader := &SaasMonitorDownloader{
				client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					return textResponse(request, http.StatusOK, test.body), nil
				})},
				feeds:      []saasFeed{{url: "https://feeds.example.test/ips.txt", required: true}},
				targetIPv4: ipv4Path,
				targetIPv6: ipv6Path,
				localInterfaceAddresses: func() ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, test.localErr
				},
				protectedHAPeers: func() ([]netip.Prefix, error) {
					return []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24")}, nil
				},
			}
			if err := downloader.fetchMonitors(); err == nil {
				t.Fatal("protected SaaS entry was published")
			}
			assertFileContent(t, ipv4Path, "8.8.8.8\n")
			assertFileContent(t, ipv6Path, "2606:4700:4700::1111\n")
			if _, err := os.Lstat(filepath.Join(directory, saasPairManifestName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected SaaS generation created a manifest: %v", err)
			}
		})
	}
}

func TestSaaSFeedRejectsRedirectInvalidEntryAndBounds_SW_SAAS_001(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{name: "invalid entry", status: http.StatusOK, body: "8.8.8.1\nexample.com\n", wantErr: "line 2"},
		{name: "oversized line", status: http.StatusOK, body: strings.Repeat("1", maximumSaaSLineSize+1), wantErr: "scan SaaS feed"},
		{name: "oversized body", status: http.StatusOK, body: strings.Repeat(" ", maximumSaaSBodySize+1), wantErr: "exceeds"},
		{name: "too many lines", status: http.StatusOK, body: strings.Repeat("#\n", maximumSaaSLines+1), wantErr: "exceeds 20000 lines"},
		{name: "too many entries", status: http.StatusOK, body: strings.Repeat("8.8.8.1\n", maximumSaaSEntries+1), wantErr: "exceeds 10000 entries"},
		{name: "non success", status: http.StatusNotFound, wantErr: "HTTP 404"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return textResponse(request, test.status, test.body), nil
			})}
			downloader := &SaasMonitorDownloader{client: client}
			_, err := downloader.downloadList("https://feeds.example.test/ips.txt")
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("downloadList() error = %v, want fragment %q", err, test.wantErr)
			}
		})
	}

	if err := newBoundedSaaSHTTPClient().CheckRedirect(&http.Request{}, []*http.Request{{}}); err == nil {
		t.Fatal("bounded SaaS client permits redirects")
	}
	client := newBoundedSaaSHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("bounded SaaS client does not enforce TLS 1.3")
	}
	if client.Timeout <= 0 || transport.DialContext == nil || transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("bounded SaaS client omits a required network timeout")
	}
}

func TestSaaSFeedRejectsUnsafeURLBeforeNetwork_SW_SAAS_001(t *testing.T) {
	requests := 0
	downloader := &SaasMonitorDownloader{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected network request")
	})}}
	for _, rawURL := range []string{
		"http://feeds.example.test/ips.txt",
		"https://user:secret@feeds.example.test/ips.txt",
		"https://feeds.example.test/ips.txt#fragment",
		"/relative/ips.txt",
		"https:///missing-host",
	} {
		if _, err := downloader.downloadList(rawURL); err == nil {
			t.Fatalf("unsafe SaaS URL %q was accepted", rawURL)
		}
	}
	if requests != 0 {
		t.Fatalf("unsafe SaaS URLs triggered %d network requests", requests)
	}
}

func TestPublishSaaSListPairRejectsSymlinkWithoutMutation_SW_SAAS_001(t *testing.T) {
	directory := t.TempDir()
	ipv4Path := filepath.Join(directory, "monitors.ipv4")
	ipv6Path := filepath.Join(directory, "monitors.ipv6")
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(ipv4Path, []byte("8.8.8.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("do not change\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, ipv6Path); err != nil {
		t.Fatal(err)
	}
	if err := publishSaaSListPair(ipv4Path, ipv6Path, []byte("8.8.4.1\n"), nil); err == nil {
		t.Fatal("pair publication accepted a symlink target")
	}
	assertFileContent(t, ipv4Path, "8.8.8.1\n")
	assertFileContent(t, victim, "do not change\n")
}

func TestPublishSaaSListPairRejectsSymlinkParent_SW_SAAS_001(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	aliasDirectory := filepath.Join(root, "alias")
	if err := os.Mkdir(realDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, aliasDirectory); err != nil {
		t.Fatal(err)
	}
	realIPv4 := filepath.Join(realDirectory, "monitors.ipv4")
	realIPv6 := filepath.Join(realDirectory, "monitors.ipv6")
	if err := os.WriteFile(realIPv4, []byte("8.8.8.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realIPv6, []byte("2606:4700:4700::1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := publishSaaSListPair(
		filepath.Join(aliasDirectory, "monitors.ipv4"),
		filepath.Join(aliasDirectory, "monitors.ipv6"),
		[]byte("8.8.4.1\n"),
		[]byte("2606:4700:4700:ffff::1\n"),
	)
	if err == nil {
		t.Fatal("pair publication followed a symlinked parent")
	}
	assertFileContent(t, realIPv4, "8.8.8.1\n")
	assertFileContent(t, realIPv6, "2606:4700:4700::1\n")
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	content, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("%s content = %q, want %q", path, content, want)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func textResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
		Request:       request,
	}
}

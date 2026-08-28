package telemetry

import (
	"container/list"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type osintRoundTripFunc func(*http.Request) (*http.Response, error)

func (function osintRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestFetchOSINTBoundsAndSanitizesRemoteFields_SW_KPI_001(t *testing.T) {
	previousClient := osintHTTPClient
	defer func() { osintHTTPClient = previousClient }()
	osintHTTPClient = &http.Client{Transport: osintRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://ip.wiredalter.com/json?ip=198.51.100.40" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("OSINT request = %s, headers=%v", request.URL, request.Header)
		}
		body := `{"country_code":"[red]BE\n\u202e","asn":"AS64500\u200b","org":"` + strings.Repeat("x", 300) + `","threat":"[::b]\u2066scanner"}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	attacker, err := fetchOSINT(context.Background(), "198.51.100.40")
	if err != nil {
		t.Fatal(err)
	}
	if attacker.IP != "198.51.100.40" || attacker.Country != "redBE" || attacker.ASN != "AS64500" ||
		len([]rune(attacker.Org)) != 256 || attacker.Threat != "::bscanner" {
		t.Fatalf("sanitized OSINT attacker = %#v", attacker)
	}
}

func TestLoadOSINTCacheIsSizeBoundedAndSanitizesLegacy_SW_KPI_001(t *testing.T) {
	directory := t.TempDir()
	legacyPath := filepath.Join(directory, "legacy.json")
	legacy := `{
  "198.51.100.41":{"ip":"198.51.100.41","country":"[green]BE","asn":"AS64501","org":"Example\nOrg","threat":"scanner"},
  "10.0.0.1":{"ip":"10.0.0.1","country":"PRIVATE"}
}`
	if err := os.WriteFile(legacyPath, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := loadOSINTCacheDocument(legacyPath)
	if len(loaded) != 1 || loaded["198.51.100.41"].Attacker.Country != "greenBE" ||
		loaded["198.51.100.41"].Attacker.Org != "ExampleOrg" {
		t.Fatalf("legacy OSINT cache = %#v", loaded)
	}

	oversizedPath := filepath.Join(directory, "oversized.json")
	file, err := os.OpenFile(oversizedPath, os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- test path is confined to t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(osintCacheMaxBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if loaded := loadOSINTCacheDocument(oversizedPath); len(loaded) != 0 {
		t.Fatalf("oversized OSINT cache was accepted: %d records", len(loaded))
	}
}

func TestOSINTCacheLRUAndLookupPathAreBounded_SW_KPI_001(t *testing.T) {
	osintMu.Lock()
	originalCache := osintCache
	originalLRU := osintLRU
	originalIndex := osintLRUIndex
	originalPending := osintPending
	osintCache = make(map[string]osintCacheRecord)
	osintLRU = list.New()
	osintLRUIndex = make(map[string]*list.Element)
	osintPending = make(map[string]struct{})
	osintMu.Unlock()
	defer func() {
		osintMu.Lock()
		osintCache = originalCache
		osintLRU = originalLRU
		osintLRUIndex = originalIndex
		osintPending = originalPending
		osintMu.Unlock()
	}()

	osintMu.Lock()
	for index := 0; index < osintCacheMaxEntries+5; index++ {
		ip := fmt.Sprintf("cache-key-%d", index)
		cacheOSINTRecordLocked(ip, osintCacheRecord{Attacker: Attacker{IP: ip}, FetchedAt: time.Now()})
	}
	cacheSize := len(osintCache)
	lruSize := osintLRU.Len()
	osintMu.Unlock()
	if cacheSize != osintCacheMaxEntries || lruSize != osintCacheMaxEntries {
		t.Fatalf("bounded OSINT cache sizes = map:%d lru:%d", cacheSize, lruSize)
	}

	var networkCalls atomic.Int32
	previousClient := osintHTTPClient
	osintHTTPClient = &http.Client{Transport: osintRoundTripFunc(func(*http.Request) (*http.Response, error) {
		networkCalls.Add(1)
		return nil, context.Canceled
	})}
	defer func() { osintHTTPClient = previousClient }()

	attacker := enrichOSINT("203.0.113.45", "PROTO=TCP DPT=443", "sqli")
	if networkCalls.Load() != 0 || attacker.IP != "203.0.113.45" || attacker.Port != "443" {
		t.Fatalf("cache-only enrichment = %#v, network_calls=%d", attacker, networkCalls.Load())
	}
	osintMu.Lock()
	delete(osintPending, "203.0.113.45")
	osintMu.Unlock()
	select {
	case <-osintJobs:
	default:
	}
}

func TestActiveSSHPortIsDirectlyParsedAndCached_SW_KPI_001(t *testing.T) {
	activeSSHPortMu.Lock()
	originalActivePort := activeSSHPort
	originalFetched := activeSSHPortFetched
	originalOutput := activeSSHConfigOutput
	activeSSHPort = ""
	activeSSHPortFetched = time.Time{}
	var calls int
	activeSSHConfigOutput = func(context.Context) ([]byte, error) {
		calls++
		return []byte("addressfamily any\nport 62022\n"), nil
	}
	activeSSHPortMu.Unlock()
	defer func() {
		activeSSHPortMu.Lock()
		activeSSHPort = originalActivePort
		activeSSHPortFetched = originalFetched
		activeSSHConfigOutput = originalOutput
		activeSSHPortMu.Unlock()
	}()

	for range 10 {
		if got := getActiveSSHPort(); got != "62022" {
			t.Fatalf("active SSH port = %q", got)
		}
	}
	if calls != 1 {
		t.Fatalf("sshd effective-config calls = %d, want 1", calls)
	}
}

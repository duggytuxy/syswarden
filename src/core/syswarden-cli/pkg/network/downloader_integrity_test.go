package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTLSCIDRServer(t *testing.T, content string) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(content))
	}))
	t.Cleanup(server.Close)
	return server
}

type mirrorRouteTransport struct {
	targets    map[string]*url.URL
	transports map[string]http.RoundTripper
}

type feedRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip feedRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func (transport *mirrorRouteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	hostname := strings.ToLower(request.URL.Hostname())
	target := transport.targets[hostname]
	roundTripper := transport.transports[hostname]
	if target == nil || roundTripper == nil {
		return nil, fmt.Errorf("unexpected mirror test host %q", hostname)
	}
	clone := request.Clone(request.Context())
	requestURL := *request.URL
	requestURL.Scheme = target.Scheme
	requestURL.Host = target.Host
	clone.URL = &requestURL
	return roundTripper.RoundTrip(clone)
}

func newMirrorTestClient(t *testing.T, routes map[string]*httptest.Server) *http.Client {
	t.Helper()
	transport := &mirrorRouteTransport{
		targets:    make(map[string]*url.URL, len(routes)),
		transports: make(map[string]http.RoundTripper, len(routes)),
	}
	for hostname, server := range routes {
		target, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		transport.targets[strings.ToLower(hostname)] = target
		transport.transports[strings.ToLower(hostname)] = server.Client().Transport
	}
	return &http.Client{Transport: transport}
}

func testIPv4FeedPolicy(minimumEntries int) cidrFeedPolicy {
	return cidrFeedPolicy{
		expectedFamily:         4,
		minimumEntries:         minimumEntries,
		minimumIPv4PrefixBits:  24,
		minimumIPv6PrefixBits:  64,
		requirePublicAddresses: true,
	}
}

func TestFetchHTTPSBodyRejectsRedirectWithoutFollowingIt(t *testing.T) {
	t.Parallel()
	var destinationHits atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationHits.Add(1)
		_, _ = w.Write([]byte("8.8.8.8\n"))
	}))
	t.Cleanup(destination.Close)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	_, err := fetchHTTPSBody(t.Context(), redirector.Client(), redirector.URL, 1024, acceptableCIDRContentType)
	if err == nil || !errors.Is(err, errFeedRedirect) {
		t.Fatalf("redirect error = %v, want errFeedRedirect", err)
	}
	if hits := destinationHits.Load(); hits != 0 {
		t.Fatalf("redirect destination received %d requests, want 0", hits)
	}
}

func TestFetchHTTPSBodyRejectsOversizedAndHTMLResponses(t *testing.T) {
	t.Parallel()
	oversized := newTLSCIDRServer(t, strings.Repeat("8", 65))
	if _, err := fetchHTTPSBody(t.Context(), oversized.Client(), oversized.URL, 64, acceptableCIDRContentType); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error = %v", err)
	}

	html := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not a feed</html>"))
	}))
	t.Cleanup(html.Close)
	if _, err := fetchHTTPSBody(t.Context(), html.Client(), html.URL, 1024, acceptableCIDRContentType); err == nil || !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("HTML response error = %v", err)
	}
}

func TestCanonicalizeCIDRFeedRejectsInvalidEmptyAndUnsafeContent(t *testing.T) {
	t.Parallel()
	policy := testIPv4FeedPolicy(1)
	for name, content := range map[string]string{
		"empty":          "\n# comment only\n",
		"invalid":        "8.8.8.8\nnot-an-address\n",
		"default":        "0.0.0.0/0\n",
		"public-slash8":  "8.0.0.0/8\n",
		"public-slash16": "8.8.0.0/16\n",
		"private":        "10.0.0.1\n",
		"wrong-family":   "2606:4700:4700::1111\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := canonicalizeCIDRFeed([]byte(content), policy); err == nil {
				t.Fatal("unsafe feed unexpectedly validated")
			}
		})
	}
}

func TestCanonicalizeCIDRFeedEnforcesIPv6PrefixFloor(t *testing.T) {
	t.Parallel()
	policy := cidrFeedPolicy{
		expectedFamily:         6,
		minimumEntries:         1,
		minimumIPv4PrefixBits:  24,
		minimumIPv6PrefixBits:  64,
		requirePublicAddresses: true,
	}
	for _, content := range []string{"::/0\n", "2606:4700::/32\n", "2606:4700:1000::/48\n"} {
		if _, err := canonicalizeCIDRFeed([]byte(content), policy); err == nil {
			t.Fatalf("broad IPv6 feed %q unexpectedly validated", content)
		}
	}
	if _, err := canonicalizeCIDRFeed([]byte("2606:4700:1000:1::/64\n"), policy); err != nil {
		t.Fatalf("safe IPv6 prefix was rejected: %v", err)
	}
}

func TestCanonicalizeCIDRFeedEnforcesEntryCap(t *testing.T) {
	t.Parallel()
	var content strings.Builder
	for index := 0; index <= maximumCanonicalFeedEntries; index++ {
		_, _ = fmt.Fprintf(&content, "11.%d.%d.%d/32\n", index>>16, index>>8&255, index&255)
	}
	_, err := canonicalizeCIDRFeed([]byte(content.String()), testIPv4FeedPolicy(1))
	if err == nil || !strings.Contains(err.Error(), "entry") {
		t.Fatalf("entry-cap error = %v", err)
	}
}

func TestCanonicalizeCIDRFeedPublishesExactSortedMaskedContent(t *testing.T) {
	t.Parallel()
	feed, err := canonicalizeCIDRFeed([]byte("8.8.8.9/24\n1.1.1.1\n8.8.8.0/24\n"), testIPv4FeedPolicy(2))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(feed.content), "1.1.1.1/32\n8.8.8.0/24\n"; got != want {
		t.Fatalf("canonical content = %q, want %q", got, want)
	}
}

func TestCanonicalizeCIDRFeedSkipsOnlyNonPublicEntriesWhenExplicitlyAllowed(t *testing.T) {
	t.Parallel()
	content := []byte("1.1.1.1\n2002:982a:b983::982a:b983\n8.8.8.8\n")
	policy := cidrFeedPolicy{
		minimumEntries:         2,
		minimumIPv4PrefixBits:  32,
		minimumIPv6PrefixBits:  128,
		requireHostPrefixes:    true,
		requirePublicAddresses: true,
		skipNonPublicEntries:   true,
	}
	feed, err := canonicalizeCIDRFeed(content, policy)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(feed.content), "1.1.1.1/32\n8.8.8.8/32\n"; got != want {
		t.Fatalf("canonical content = %q, want %q", got, want)
	}
	if feed.ignoredNonPublicEntries != 1 {
		t.Fatalf("ignored non-public entries = %d, want 1", feed.ignoredNonPublicEntries)
	}

	policy.skipNonPublicEntries = false
	if _, err := canonicalizeCIDRFeed(content, policy); !errors.Is(err, errNonPublicFeedPrefix) {
		t.Fatalf("strict policy error = %v, want errNonPublicFeedPrefix", err)
	}

	policy.skipNonPublicEntries = true
	if _, err := canonicalizeCIDRFeed([]byte("1.1.1.1\nnot-an-address\n8.8.8.8\n"), policy); err == nil {
		t.Fatal("explicit skip policy accepted a malformed feed entry")
	}

	policy.minimumEntries = 3
	if _, err := canonicalizeCIDRFeed(content, policy); err == nil || !strings.Contains(err.Error(), "after ignoring 1") {
		t.Fatalf("post-filter minimum error = %v", err)
	}
}

func TestReportIgnoredOSINTEntriesUsesBoundedDiagnostic(t *testing.T) {
	t.Parallel()
	var warning strings.Builder
	reportIgnoredOSINTEntries(&warning, "https://blocklist.example", 1)
	if got, want := warning.String(), "[WARNING] OSINT source https://blocklist.example ignored 1 non-public or special-use CIDR entry.\n"; got != want {
		t.Fatalf("warning = %q, want %q", got, want)
	}
}

func TestCollapsedPublicationPreservesLastKnownGoodFeed(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	var old strings.Builder
	for index := 1; index <= 10; index++ {
		_, _ = fmt.Fprintf(&old, "8.8.0.%d/32\n", index)
	}
	if err := writeFeedFileAt(target, ".ipv4", []byte(old.String())); err != nil {
		t.Fatal(err)
	}
	candidate, err := canonicalizeCIDRFeed([]byte("8.8.0.1\n"), testIPv4FeedPolicy(1))
	if err != nil {
		t.Fatal(err)
	}
	err = publishCanonicalFeedAt(target, ".ipv4", candidate, testIPv4FeedPolicy(1), feedPublicationPolicy{
		verified:                    true,
		minimumRetentionPercent:     50,
		plausibilityBaselineEntries: 2,
	})
	if err == nil || !strings.Contains(err.Error(), "collapsed") {
		t.Fatalf("collapsed publication error = %v", err)
	}
	content, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != old.String() {
		t.Fatalf("last-known-good content changed: %q", content)
	}
}

func TestMirrorQuorumRejectsDisagreementAndPreservesLastKnownGood(t *testing.T) {
	t.Parallel()
	servers := []*httptest.Server{
		newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n"),
		newTLSCIDRServer(t, "9.9.9.9\n8.8.4.4\n"),
		newTLSCIDRServer(t, "4.2.2.1\n4.2.2.2\n"),
	}
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	if err := writeFeedFileAt(target, ".ipv4", []byte("208.67.222.222/32\n")); err != nil {
		t.Fatal(err)
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"mirror-one.example":   servers[0],
		"mirror-two.example":   servers[1],
		"mirror-three.example": servers[2],
	})
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
		"https://mirror-three.example/feed",
	}
	err := downloadMirrorQuorumWithClient(t.Context(), client, urls, target, ".ipv4", 2, testIPv4FeedPolicy(2), feedPublicationPolicy{})
	if !errors.Is(err, errFeedMirrorQuorum) {
		t.Fatalf("mirror disagreement error = %v, want errFeedMirrorQuorum", err)
	}
	content, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "208.67.222.222/32\n"; got != want {
		t.Fatalf("last-known-good content = %q, want %q", got, want)
	}
}

func TestDataShieldLifecyclePreservesValidatedLastKnownGoodOnQuorumDisagreement(t *testing.T) {
	t.Parallel()
	servers := []*httptest.Server{
		newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n"),
		newTLSCIDRServer(t, "9.9.9.9\n8.8.4.4\n"),
		newTLSCIDRServer(t, "4.2.2.1\n4.2.2.2\n"),
	}
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	old := []byte("208.67.222.222/32\n")
	if err := writeFeedFileAt(target, ".ipv4", old); err != nil {
		t.Fatal(err)
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"mirror-one.example":   servers[0],
		"mirror-two.example":   servers[1],
		"mirror-three.example": servers[2],
	})
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
		"https://mirror-three.example/feed",
	}
	outcome, err := downloadDataShieldForLifecycleWithClient(
		t.Context(), client, urls, target, ".ipv4", 2,
		testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != dataShieldFeedPreserved {
		t.Fatalf("outcome = %d, want preserved", outcome)
	}
	content, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(old) {
		t.Fatalf("last-known-good content changed: %q", content)
	}

	outcome, err = downloadDataShieldForLifecycleWithClient(
		t.Context(), client, urls, target, ".ipv4", 2,
		testIPv4FeedPolicy(2), feedPublicationPolicy{}, false,
	)
	if !errors.Is(err, errFeedMirrorQuorum) {
		t.Fatalf("explicit update error = %v, want errFeedMirrorQuorum", err)
	}
	if outcome != dataShieldFeedPreserved {
		t.Fatalf("explicit update outcome = %d, want preserved", outcome)
	}
	content, err = readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(old) {
		t.Fatalf("explicit update changed last-known-good content: %q", content)
	}
}

func TestDataShieldLifecycleOmitsFreshFeedWithoutPublishingSingleMirror(t *testing.T) {
	t.Parallel()
	servers := []*httptest.Server{
		newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n"),
		newTLSCIDRServer(t, "9.9.9.9\n8.8.4.4\n"),
		newTLSCIDRServer(t, "4.2.2.1\n4.2.2.2\n"),
	}
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"mirror-one.example":   servers[0],
		"mirror-two.example":   servers[1],
		"mirror-three.example": servers[2],
	})
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
		"https://mirror-three.example/feed",
	}
	outcome, err := downloadDataShieldForLifecycleWithClient(
		t.Context(), client, urls, target, ".ipv4", 2,
		testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != dataShieldFeedOmitted {
		t.Fatalf("outcome = %d, want omitted", outcome)
	}
	if _, err := readFeedFileAt(target, ".ipv4"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("quorum disagreement published a fresh feed: %v", err)
	}
}

func TestDataShieldLifecycleKeepsInvalidMirrorConfigurationFatal(t *testing.T) {
	t.Parallel()
	target := feedFileTarget{directory: t.TempDir(), name: "feed.ipv4"}
	for name, mirrors := range map[string][]string{
		"invalid URL": {
			"http://mirror-one.example/feed",
			"https://mirror-two.example/feed",
		},
		"insufficient distinct origins": {
			"https://mirror-one.example/feed-a",
			"https://mirror-one.example./feed-b",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			outcome, err := downloadDataShieldForLifecycleWithClient(
				t.Context(), &http.Client{}, mirrors, target, ".ipv4", 2,
				testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
			)
			if err == nil {
				t.Fatal("invalid mirror configuration was tolerated")
			}
			if errors.Is(err, errFeedMirrorQuorum) {
				t.Fatalf("configuration error was classified as external quorum unavailability: %v", err)
			}
			if outcome != dataShieldFeedOmitted {
				t.Fatalf("outcome = %d, want omitted", outcome)
			}
		})
	}
}

func TestDataShieldLifecycleKeepsCallerContextTerminationFatal(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
	}
	for name, newContext := range map[string]func() (context.Context, context.CancelFunc){
		"canceled": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx, func() {}
		},
		"deadline": func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(t.Context(), time.Unix(1, 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := newContext()
			defer cancel()
			outcome, err := downloadDataShieldForLifecycleWithClient(
				ctx, &http.Client{}, urls,
				feedFileTarget{directory: t.TempDir(), name: "feed.ipv4"},
				".ipv4", 2, testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
			)
			if err == nil || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatalf("caller context error = %v", err)
			}
			if errors.Is(err, errFeedMirrorQuorum) {
				t.Fatalf("caller context error was classified as external quorum unavailability: %v", err)
			}
			if outcome != dataShieldFeedOmitted {
				t.Fatalf("outcome = %d, want omitted", outcome)
			}
		})
	}
	t.Run("during download", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		client := &http.Client{Transport: feedRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			cancel()
			<-request.Context().Done()
			return nil, request.Context().Err()
		})}
		outcome, err := downloadDataShieldForLifecycleWithClient(
			ctx, client, urls,
			feedFileTarget{directory: t.TempDir(), name: "feed.ipv4"},
			".ipv4", 2, testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
		)
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("caller cancellation during download error = %v", err)
		}
		if errors.Is(err, errFeedMirrorQuorum) {
			t.Fatalf("caller cancellation during download was classified as external quorum unavailability: %v", err)
		}
		if outcome != dataShieldFeedOmitted {
			t.Fatalf("outcome = %d, want omitted", outcome)
		}
	})
}

func TestDataShieldInstallFallbackAcceptsOnlyExternalFetchOrCanonicalizationFailure(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
	}
	t.Run("fetch", func(t *testing.T) {
		t.Parallel()
		client := &http.Client{Transport: feedRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errFeedRedirect
		})}
		target := feedFileTarget{directory: t.TempDir(), name: "feed.ipv4"}
		outcome, err := downloadDataShieldForLifecycleWithClient(
			t.Context(), client, urls, target, ".ipv4", 2,
			testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
		)
		if err != nil {
			t.Fatal(err)
		}
		if outcome != dataShieldFeedOmitted {
			t.Fatalf("outcome = %d, want omitted", outcome)
		}
	})
	t.Run("canonicalization", func(t *testing.T) {
		t.Parallel()
		first := newTLSCIDRServer(t, "not-a-cidr\n")
		second := newTLSCIDRServer(t, "also-not-a-cidr\n")
		client := newMirrorTestClient(t, map[string]*httptest.Server{
			"mirror-one.example": first,
			"mirror-two.example": second,
		})
		target := feedFileTarget{directory: t.TempDir(), name: "feed.ipv4"}
		outcome, err := downloadDataShieldForLifecycleWithClient(
			t.Context(), client, urls, target, ".ipv4", 2,
			testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
		)
		if err != nil {
			t.Fatal(err)
		}
		if outcome != dataShieldFeedOmitted {
			t.Fatalf("outcome = %d, want omitted", outcome)
		}
	})
}

func TestDataShieldLifecycleFailsClosedOnInvalidLastKnownGood(t *testing.T) {
	t.Parallel()
	servers := []*httptest.Server{
		newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n"),
		newTLSCIDRServer(t, "9.9.9.9\n8.8.4.4\n"),
	}
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	invalid := []byte("1.1.1.1/32\nnot-a-cidr\n")
	if err := writeFeedFileAt(target, ".ipv4", invalid); err != nil {
		t.Fatal(err)
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"mirror-one.example": servers[0],
		"mirror-two.example": servers[1],
	})
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
	}
	outcome, err := downloadDataShieldForLifecycleWithClient(
		t.Context(), client, urls, target, ".ipv4", 2,
		testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
	)
	if err == nil || !strings.Contains(err.Error(), "last-known-good attestation failed") {
		t.Fatalf("invalid last-known-good error = %v", err)
	}
	if outcome != dataShieldFeedOmitted {
		t.Fatalf("outcome = %d, want omitted", outcome)
	}
	content, readErr := readFeedFileAt(target, ".ipv4")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != string(invalid) {
		t.Fatalf("invalid last-known-good content changed: %q", content)
	}
}

func TestDataShieldLifecycleRequiresExactLastKnownGoodMode(t *testing.T) {
	t.Parallel()
	servers := []*httptest.Server{
		newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n"),
		newTLSCIDRServer(t, "9.9.9.9\n8.8.4.4\n"),
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"mirror-one.example": servers[0],
		"mirror-two.example": servers[1],
	})
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
	}
	for name, mode := range map[string]fs.FileMode{
		"group readable": 0640,
		"setuid":         0600 | os.ModeSetuid,
		"setgid":         0600 | os.ModeSetgid,
		"sticky":         0600 | os.ModeSticky,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			target := feedFileTarget{directory: directory, name: "feed.ipv4"}
			if err := writeFeedFileAt(target, ".ipv4", []byte("208.67.222.222/32\n")); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(directory, target.name), mode); err != nil {
				t.Fatal(err)
			}
			outcome, err := downloadDataShieldForLifecycleWithClient(
				t.Context(), client, urls, target, ".ipv4", 2,
				testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
			)
			if err == nil || !strings.Contains(err.Error(), "last-known-good attestation failed") {
				t.Fatalf("unsafe last-known-good mode error = %v", err)
			}
			if outcome != dataShieldFeedOmitted {
				t.Fatalf("outcome = %d, want omitted", outcome)
			}
		})
	}
}

func TestDataShieldLifecycleDoesNotDowngradePublicationFailure(t *testing.T) {
	t.Parallel()
	content := "1.1.1.1\n8.8.8.8\n"
	first := newTLSCIDRServer(t, content)
	second := newTLSCIDRServer(t, content)
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	outside := filepath.Join(t.TempDir(), "outside.ipv4")
	if err := os.WriteFile(outside, []byte("9.9.9.9/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, target.name)); err != nil {
		t.Fatal(err)
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"mirror-one.example": first,
		"mirror-two.example": second,
	})
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
	}
	outcome, err := downloadDataShieldForLifecycleWithClient(
		t.Context(), client, urls, target, ".ipv4", 2,
		testIPv4FeedPolicy(2), feedPublicationPolicy{}, true,
	)
	if err == nil {
		t.Fatal("publication failure was downgraded")
	}
	if errors.Is(err, errFeedMirrorQuorum) {
		t.Fatalf("publication failure was misclassified as quorum unavailability: %v", err)
	}
	if outcome != dataShieldFeedOmitted {
		t.Fatalf("outcome = %d, want omitted", outcome)
	}
}

func TestMirrorQuorumPublishesIdenticalCanonicalContent(t *testing.T) {
	t.Parallel()
	servers := []*httptest.Server{
		newTLSCIDRServer(t, "8.8.8.8\n1.1.1.1/32\n"),
		newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8/32\n"),
		newTLSCIDRServer(t, "9.9.9.9\n8.8.4.4\n"),
	}
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"mirror-one.example":   servers[0],
		"mirror-two.example":   servers[1],
		"mirror-three.example": servers[2],
	})
	urls := []string{
		"https://mirror-one.example/feed",
		"https://mirror-two.example/feed",
		"https://mirror-three.example/feed",
	}
	if err := downloadMirrorQuorumWithClient(t.Context(), client, urls, target, ".ipv4", 2, testIPv4FeedPolicy(2), feedPublicationPolicy{}); err != nil {
		t.Fatal(err)
	}
	content, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "1.1.1.1/32\n8.8.8.8/32\n"; got != want {
		t.Fatalf("published content = %q, want %q", got, want)
	}
}

func TestCustomDigestBindingAndUnsignedDenyPreserveLastKnownGood(t *testing.T) {
	t.Parallel()
	server := newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n")
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "custom.ipv4"}
	old := []byte("9.9.9.9/32\n")
	if err := writeFeedFileAt(target, ".ipv4", old); err != nil {
		t.Fatal(err)
	}
	if err := secureDownloadWithClient(t.Context(), server.Client(), server.URL, target, ".ipv4", ""); err == nil || !strings.Contains(err.Error(), "non-authoritative") {
		t.Fatalf("unsigned deny error = %v", err)
	}
	if err := secureDownloadWithClient(t.Context(), server.Client(), server.URL, target, ".ipv4", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("digest mismatch error = %v", err)
	}
	content, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(old) {
		t.Fatalf("failed verification changed last-known-good content: %q", content)
	}
	digest := sha256.Sum256([]byte("1.1.1.1\n8.8.8.8\n"))
	if err := secureDownloadWithClient(t.Context(), server.Client(), server.URL, target, ".ipv4", "sha256:"+hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	content, err = readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "1.1.1.1/32\n8.8.8.8/32\n"; got != want {
		t.Fatalf("verified custom publication = %q, want %q", got, want)
	}
}

func TestVerifiedInvalidOrEmptyFeedPreservesLastKnownGood(t *testing.T) {
	t.Parallel()
	for name, response := range map[string]string{
		"empty":   "\n# no entries\n",
		"invalid": "1.1.1.1\nnot-a-cidr\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newTLSCIDRServer(t, response)
			directory := t.TempDir()
			target := feedFileTarget{directory: directory, name: "custom.ipv4"}
			old := []byte("9.9.9.9/32\n")
			if err := writeFeedFileAt(target, ".ipv4", old); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(response))
			err := secureDownloadWithClient(t.Context(), server.Client(), server.URL, target, ".ipv4", hex.EncodeToString(digest[:]))
			if err == nil {
				t.Fatal("unsafe verified payload unexpectedly published")
			}
			content, readErr := readFeedFileAt(target, ".ipv4")
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(content) != string(old) {
				t.Fatalf("unsafe response changed last-known-good content: %q", content)
			}
		})
	}
}

func TestUnsignedAllowListCanOnlyNarrowExistingAccess(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "allowed_test.ipv4"}
	narrow := newTLSCIDRServer(t, "8.8.8.8\n")
	if err := secureDownloadWithClient(t.Context(), narrow.Client(), narrow.URL, target, ".ipv4", ""); err == nil || !strings.Contains(err.Error(), "cannot create") {
		t.Fatalf("initial unsigned allow-list error = %v", err)
	}
	if err := writeFeedFileAt(target, ".ipv4", []byte("8.8.8.0/24\n")); err != nil {
		t.Fatal(err)
	}
	if err := secureDownloadWithClient(t.Context(), narrow.Client(), narrow.URL, target, ".ipv4", ""); err != nil {
		t.Fatal(err)
	}
	widen := newTLSCIDRServer(t, "1.1.1.1\n")
	if err := secureDownloadWithClient(t.Context(), widen.Client(), widen.URL, target, ".ipv4", ""); err == nil || !strings.Contains(err.Error(), "widen") {
		t.Fatalf("widening unsigned allow-list error = %v", err)
	}
	content, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "8.8.8.8/32\n"; got != want {
		t.Fatalf("allow-list content = %q, want %q", got, want)
	}
}

func TestOSINTPublishesOnlyCanonicalIntersection(t *testing.T) {
	t.Parallel()
	first := newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n9.9.9.9\n")
	second := newTLSCIDRServer(t, "8.8.8.8\n4.2.2.2\n1.1.1.1\n")
	directory := t.TempDir()
	v4Target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	v6Target := feedFileTarget{directory: directory, name: "feed.ipv6"}
	if err := writeFeedFileAt(v4Target, ".ipv4", []byte("208.67.222.222/32\n")); err != nil {
		t.Fatal(err)
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"cins.example":      first,
		"blocklist.example": second,
	})
	urls := []string{"https://cins.example/feed", "https://blocklist.example/feed"}
	if err := downloadOSINTWithClient(t.Context(), client, urls, v4Target, v6Target, 2); err != nil {
		t.Fatal(err)
	}
	content, err := readFeedFileAt(v4Target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "1.1.1.1/32\n8.8.8.8/32\n208.67.222.222/32\n"; got != want {
		t.Fatalf("OSINT publication = %q, want %q", got, want)
	}
}

func TestOSINTIgnoresSpecialUseSourceEntriesWithoutPublishingThem(t *testing.T) {
	t.Parallel()
	first := newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n9.9.9.9\n")
	second := newTLSCIDRServer(t, "8.8.8.8\n2002:982a:b983::982a:b983\n1.1.1.1\n")
	directory := t.TempDir()
	v4Target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	v6Target := feedFileTarget{directory: directory, name: "feed.ipv6"}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"cins.example":      first,
		"blocklist.example": second,
	})
	urls := []string{"https://cins.example/feed", "https://blocklist.example/feed"}
	if err := downloadOSINTWithClient(t.Context(), client, urls, v4Target, v6Target, 2); err != nil {
		t.Fatal(err)
	}
	content, err := readFeedFileAt(v4Target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "1.1.1.1/32\n8.8.8.8/32\n"; got != want {
		t.Fatalf("OSINT publication = %q, want %q", got, want)
	}
	if _, err := readFeedFileAt(v6Target, ".ipv6"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("special-use IPv6 entry created an IPv6 feed: %v", err)
	}
}

func TestOSINTSpecialUseFilteringBelowMinimumPreservesLastKnownGood(t *testing.T) {
	t.Parallel()
	first := newTLSCIDRServer(t, "1.1.1.1\n2002:982a:b983::982a:b983\n")
	second := newTLSCIDRServer(t, "1.1.1.1\n2002:982a:b983::982a:b983\n")
	directory := t.TempDir()
	v4Target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	v6Target := feedFileTarget{directory: directory, name: "feed.ipv6"}
	old := []byte("208.67.222.222/32\n")
	if err := writeFeedFileAt(v4Target, ".ipv4", old); err != nil {
		t.Fatal(err)
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"cins.example":      first,
		"blocklist.example": second,
	})
	urls := []string{"https://cins.example/feed", "https://blocklist.example/feed"}
	err := downloadOSINTWithClient(t.Context(), client, urls, v4Target, v6Target, 2)
	if err == nil || !strings.Contains(err.Error(), "after ignoring 1") {
		t.Fatalf("post-filter minimum error = %v", err)
	}
	content, readErr := readFeedFileAt(v4Target, ".ipv4")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != string(old) {
		t.Fatalf("post-filter minimum failure changed last-known-good content: %q", content)
	}
	if _, statErr := os.Lstat(filepath.Join(directory, v6Target.name)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("post-filter minimum failure created an IPv6 feed: %v", statErr)
	}
}

func TestOSINTDisagreementPreservesLastKnownGood(t *testing.T) {
	t.Parallel()
	first := newTLSCIDRServer(t, "1.1.1.1\n8.8.8.8\n")
	second := newTLSCIDRServer(t, "9.9.9.9\n4.2.2.2\n")
	directory := t.TempDir()
	v4Target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	v6Target := feedFileTarget{directory: directory, name: "feed.ipv6"}
	old := []byte("208.67.222.222/32\n")
	if err := writeFeedFileAt(v4Target, ".ipv4", old); err != nil {
		t.Fatal(err)
	}
	client := newMirrorTestClient(t, map[string]*httptest.Server{
		"cins.example":      first,
		"blocklist.example": second,
	})
	urls := []string{"https://cins.example/feed", "https://blocklist.example/feed"}
	if err := downloadOSINTWithClient(t.Context(), client, urls, v4Target, v6Target, 1); err == nil || !strings.Contains(err.Error(), "intersection") {
		t.Fatalf("OSINT disagreement error = %v", err)
	}
	content, err := readFeedFileAt(v4Target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(old) {
		t.Fatalf("OSINT disagreement changed last-known-good content: %q", content)
	}
}

func TestReadAllBoundedRejectsUnknownLengthOverflow(t *testing.T) {
	t.Parallel()
	if _, err := readAllBounded(strings.NewReader(strings.Repeat("x", 33)), -1, 32); err == nil {
		t.Fatal("unknown-length overflow unexpectedly succeeded")
	}
}

func TestUnauthenticatedRADBNeverPublishesDenyOrAllowLists(t *testing.T) {
	t.Parallel()
	response := []byte("route: 1.1.1.0/24\nroute6: 2606:4700:4700::/64\n")
	for _, allowList := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			name := fmt.Sprintf("allow=%t/existing=%t", allowList, existing)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				directory := t.TempDir()
				base := "AS64500"
				if allowList {
					base = "allowed_AS64500"
				}
				v4Target := feedFileTarget{directory: directory, name: base + ".ipv4"}
				v6Target := feedFileTarget{directory: directory, name: base + ".ipv6"}
				oldV4 := []byte("9.9.9.9/32\n")
				oldV6 := []byte("2606:4700:4700::9999/128\n")
				if existing {
					if err := writeFeedFileAt(v4Target, ".ipv4", oldV4); err != nil {
						t.Fatal(err)
					}
					if err := writeFeedFileAt(v6Target, ".ipv6", oldV6); err != nil {
						t.Fatal(err)
					}
				}

				err := rejectUnauthenticatedASNFeed(response, v4Target, v6Target)
				if !errors.Is(err, errUnauthenticatedASNFeed) {
					t.Fatalf("RADB rejection error = %v", err)
				}
				if !existing {
					for _, target := range []feedFileTarget{v4Target, v6Target} {
						if _, statErr := os.Lstat(filepath.Join(directory, target.name)); !errors.Is(statErr, fs.ErrNotExist) {
							t.Fatalf("unauthenticated RADB created %s: %v", target.name, statErr)
						}
					}
					return
				}
				gotV4, readErr := readFeedFileAt(v4Target, ".ipv4")
				if readErr != nil {
					t.Fatal(readErr)
				}
				gotV6, readErr := readFeedFileAt(v6Target, ".ipv6")
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(gotV4) != string(oldV4) || string(gotV6) != string(oldV6) {
					t.Fatalf("RADB changed LKG files: IPv4=%q IPv6=%q", gotV4, gotV6)
				}
			})
		}
	}
}

func TestGitHubRawAndJSDelivrShareOneMirrorTrustDomain(t *testing.T) {
	t.Parallel()
	raw, err := feedOrigin("https://raw.githubusercontent.com/example/repository/main/feed.txt")
	if err != nil {
		t.Fatal(err)
	}
	cdn, err := feedOrigin("https://cdn.jsdelivr.net./gh/example/repository@main/feed.txt")
	if err != nil {
		t.Fatal(err)
	}
	if raw != cdn {
		t.Fatalf("trust domains differ: raw=%q cdn=%q", raw, cdn)
	}
}

func TestTrailingDNSDotDoesNotCreateAnotherMirrorTrustDomain(t *testing.T) {
	t.Parallel()
	plain, err := feedOrigin("https://mirror.example/feed.txt")
	if err != nil {
		t.Fatal(err)
	}
	dotted, err := feedOrigin("https://mirror.example./feed.txt")
	if err != nil {
		t.Fatal(err)
	}
	if plain != dotted {
		t.Fatalf("trailing DNS dot created another trust domain: plain=%q dotted=%q", plain, dotted)
	}
	if _, err := feedOrigin("https://mirror.example../feed.txt"); err == nil {
		t.Fatal("multiple trailing DNS root markers were accepted")
	}
}

func TestDefaultHTTPSPortDoesNotCreateAnotherMirrorTrustDomain(t *testing.T) {
	t.Parallel()
	implicit, err := feedOrigin("https://mirror.example/feed.txt")
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := feedOrigin("https://mirror.example:443/feed.txt")
	if err != nil {
		t.Fatal(err)
	}
	if implicit != explicit {
		t.Fatalf("default port created another trust domain: implicit=%q explicit=%q", implicit, explicit)
	}
}

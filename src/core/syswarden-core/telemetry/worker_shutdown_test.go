package telemetry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type shutdownRoundTripFunc func(*http.Request) (*http.Response, error)

func (f shutdownRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGithubMetadataRequestsObserveWorkerCancellation(t *testing.T) {
	oldTransport := http.DefaultTransport
	oldStars, oldStarFetch := cachedStars, lastStarFetch
	oldRelease, oldReleaseFetch := cachedRelease, lastReleaseFetch
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
		cachedStars, lastStarFetch = oldStars, oldStarFetch
		cachedRelease, lastReleaseFetch = oldRelease, oldReleaseFetch
	})
	cases := []struct {
		name     string
		fetch    func(context.Context) string
		path     string
		fallback string
	}{
		{"stars", getGithubStars, "/repos/duggytuxy/syswarden", "260"},
		{"release", getGithubRelease, "/repos/duggytuxy/syswarden/releases/latest", "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cachedStars, lastStarFetch = "260", time.Time{}
			cachedRelease, lastReleaseFetch = "Unknown", time.Time{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan *http.Request, 1)
			release := make(chan struct{})
			finished := make(chan string, 1)
			http.DefaultTransport = shutdownRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				started <- req
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-release:
					return nil, errors.New("test transport released")
				}
			})
			go func() { finished <- tc.fetch(ctx) }()
			select {
			case req := <-started:
				if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || req.URL.Path != tc.path || req.Header.Get("Accept") != "application/vnd.github.v3+json" {
					t.Errorf("unexpected metadata request: %s %s", req.Method, req.URL)
				}
			case <-time.After(time.Second):
				close(release)
				<-finished
				t.Fatal("metadata request did not start")
			}
			cancel()
			select {
			case result := <-finished:
				if result != tc.fallback {
					t.Errorf("cancelled request returned %q, want %q", result, tc.fallback)
				}
				close(release)
			case <-time.After(time.Second):
				close(release)
				<-finished
				t.Error("metadata request outlived worker cancellation")
			}
		})
	}
}

func TestGithubMetadataCancelledContextMakesNoRequest(t *testing.T) {
	oldTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	calls := 0
	http.DefaultTransport = shutdownRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected request after cancellation")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := getGithubStars(ctx); got != cachedStars {
		t.Fatalf("lost cached stars: %q", got)
	}
	if got := getGithubRelease(ctx); got != cachedRelease {
		t.Fatalf("lost cached release: %q", got)
	}
	generateTelemetry(ctx, nil)
	if calls != 0 {
		t.Fatalf("cancelled telemetry made %d HTTP requests", calls)
	}
}

func TestGithubMetadataSuccessfulRequestsStillCache(t *testing.T) {
	oldTransport := http.DefaultTransport
	oldStars, oldStarFetch := cachedStars, lastStarFetch
	oldRelease, oldReleaseFetch := cachedRelease, lastReleaseFetch
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
		cachedStars, lastStarFetch = oldStars, oldStarFetch
		cachedRelease, lastReleaseFetch = oldRelease, oldReleaseFetch
	})
	cachedStars, lastStarFetch = "260", time.Time{}
	cachedRelease, lastReleaseFetch = "Unknown", time.Time{}
	calls := 0
	http.DefaultTransport = shutdownRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		body := `{"stargazers_count":321}`
		if req.URL.Path == "/repos/duggytuxy/syswarden/releases/latest" {
			body = `{"tag_name":"v4.04.3"}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	for range 2 {
		if got := getGithubStars(context.Background()); got != "321" {
			t.Errorf("stars = %q", got)
		}
		if got := getGithubRelease(context.Background()); got != "v4.04.3" {
			t.Errorf("release = %q", got)
		}
	}
	if calls != 2 {
		t.Errorf("metadata cache made %d requests, want 2", calls)
	}
	if lastStarFetch.IsZero() || lastReleaseFetch.IsZero() {
		t.Error("successful metadata fetch did not update cache time")
	}
}

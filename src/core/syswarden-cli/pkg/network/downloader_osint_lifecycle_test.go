package network

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

const osintLifecycleFirstSource = "1.1.1.1\n8.8.8.8\n8.8.4.4\n208.67.222.222\n"

func osintLifecycleTargets(t *testing.T, existing bool) (feedFileTarget, feedFileTarget) {
	t.Helper()
	directory := t.TempDir()
	v4 := feedFileTarget{directory: directory, name: "feed.ipv4"}
	v6 := feedFileTarget{directory: directory, name: "feed.ipv6"}
	if existing {
		for _, item := range []struct {
			target feedFileTarget
			prefix string
			family int
		}{
			{v4, "9.9.9.9/32", 4},
			{v6, "2606:4700:4700::1111/128", 6},
		} {
			if err := publishCanonicalFeedWithProvenanceAt(
				item.target, fmt.Sprintf(".ipv%d", item.family),
				canonicalFeedFromPrefixes([]netip.Prefix{netip.MustParsePrefix(item.prefix)}),
				cidrFeedPolicy{expectedFamily: item.family, minimumEntries: 1, minimumIPv4PrefixBits: 32, minimumIPv6PrefixBits: 128, requirePublicAddresses: true},
				feedPublicationPolicy{verified: true},
				[]string{"https://mirror-one.example/feed", "https://mirror-two.example/feed"}, "",
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	return v4, v6
}

func osintLifecycleSnapshot(t *testing.T, directory string) map[string]string {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	snapshot := make(map[string]string)
	if err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := fmt.Sprintf("%s:%d", info.Mode(), info.ModTime().UnixNano())
		if !entry.IsDir() {
			content, err := root.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(":%x", sha256.Sum256(content))
		}
		snapshot[path] = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestOSINTLifecycleDisagreementOnlySkipsInstallWithoutAnyPublication(t *testing.T) {
	t.Parallel()
	for _, existing := range []bool{false, true} {
		for _, common := range []int{0, 1, 3} {
			for _, purpose := range []feedDownloadPurpose{feedDownloadPackageInstall, feedDownloadExplicitUpdate, feedDownloadPurpose(99)} {
				t.Run(fmt.Sprintf("existing=%t/common=%d/purpose=%d", existing, common, purpose), func(t *testing.T) {
					t.Parallel()
					lines := strings.Split(strings.TrimSpace(osintLifecycleFirstSource), "\n")
					secondLines := append([]string{}, lines[:common]...)
					for index := common; index < 4; index++ {
						secondLines = append(secondLines, fmt.Sprintf("9.9.9.%d", index+1))
					}
					first := newTLSCIDRServer(t, osintLifecycleFirstSource)
					second := newTLSCIDRServer(t, strings.Join(secondLines, "\n")+"\n")
					client := newMirrorTestClient(t, map[string]*httptest.Server{"cins.example": first, "blocklist.example": second})
					v4, v6 := osintLifecycleTargets(t, existing)
					before := osintLifecycleSnapshot(t, v4.directory)
					published, err := downloadOSINTForLifecycleWithClient(t.Context(), client,
						[]string{"https://cins.example/feed", "https://blocklist.example/feed"}, v4, v6, 4, purpose)
					if published {
						t.Fatal("uncorroborated addresses were published")
					}
					if purpose == feedDownloadPackageInstall {
						if err != nil {
							t.Fatalf("optional install supplement blocked installation: %v", err)
						}
					} else {
						var disagreement osintIntersectionError
						if !errors.Is(err, errOSINTIntersection) || !errors.As(err, &disagreement) || disagreement.entries != common || disagreement.minimum != 4 {
							t.Fatalf("explicit refresh lost exact disagreement evidence: %v", err)
						}
					}
					if after := osintLifecycleSnapshot(t, v4.directory); !reflect.DeepEqual(before, after) {
						t.Fatalf("disagreement changed a snapshot, provenance file or directory: before=%v after=%v", before, after)
					}
				})
			}
		}
	}
}

func TestOSINTLifecycleInstallStillRejectsInvalidSources(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		body        string
		contentType string
		status      int
	}{
		{"malformed", osintLifecycleFirstSource + "not-an-address\n", "text/plain", http.StatusOK},
		{"too few entries", "1.1.1.1\n8.8.8.8\n8.8.4.4\n", "text/plain", http.StatusOK},
		{"special use below minimum", "1.1.1.1\n8.8.8.8\n8.8.4.4\n2002:982a:b983::982a:b983\n", "text/plain", http.StatusOK},
		{"HTML", "<html>unavailable</html>", "text/html", http.StatusOK},
		{"HTTP failure", "unavailable", "text/plain", http.StatusForbidden},
		{"empty source", "", "text/plain", http.StatusOK},
		{"broad prefix", osintLifecycleFirstSource + "11.0.0.0/8\n", "text/plain", http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first := newTLSCIDRServer(t, osintLifecycleFirstSource)
			second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(second.Close)
			client := newMirrorTestClient(t, map[string]*httptest.Server{"cins.example": first, "blocklist.example": second})
			v4, v6 := osintLifecycleTargets(t, true)
			before := osintLifecycleSnapshot(t, v4.directory)
			published, err := downloadOSINTForLifecycleWithClient(t.Context(), client,
				[]string{"https://cins.example/feed", "https://blocklist.example/feed"}, v4, v6, 4, feedDownloadPackageInstall)
			if published || err == nil || errors.Is(err, errOSINTIntersection) {
				t.Fatalf("invalid source was treated as an optional supplement: published=%t error=%v", published, err)
			}
			if after := osintLifecycleSnapshot(t, v4.directory); !reflect.DeepEqual(before, after) {
				t.Fatal("source rejection changed retained feed evidence")
			}
		})
	}
}

func TestOSINTLifecyclePublishesOnlyFourCorroboratedEntries(t *testing.T) {
	t.Parallel()
	first := newTLSCIDRServer(t, osintLifecycleFirstSource+"9.9.9.1\n")
	second := newTLSCIDRServer(t, osintLifecycleFirstSource+"9.9.9.2\n")
	client := newMirrorTestClient(t, map[string]*httptest.Server{"cins.example": first, "blocklist.example": second})
	v4, v6 := osintLifecycleTargets(t, false)
	published, err := downloadOSINTForLifecycleWithClient(t.Context(), client,
		[]string{"https://cins.example/feed", "https://blocklist.example/feed"}, v4, v6, 4, feedDownloadPackageInstall)
	if err != nil || !published {
		t.Fatalf("valid supplement was not published: published=%t error=%v", published, err)
	}
	content, err := readFeedFileAt(v4, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "1.1.1.1/32\n8.8.4.4/32\n8.8.8.8/32\n208.67.222.222/32\n"; got != want {
		t.Fatalf("unexpected OSINT publication: %q", got)
	}
	if _, err := readFeedFileAt(v6, ".ipv6"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unexpected IPv6 publication: %v", err)
	}
}

func TestOSINTLifecycleDoesNotSkipCancellationOrDuplicateOrigins(t *testing.T) {
	t.Parallel()
	first := newTLSCIDRServer(t, osintLifecycleFirstSource)
	client := newMirrorTestClient(t, map[string]*httptest.Server{"cins.example": first})
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancelled=%t", cancelled), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cancelled {
				cancel()
			}
			v4, v6 := osintLifecycleTargets(t, false)
			published, err := downloadOSINTForLifecycleWithClient(ctx, client,
				[]string{"https://cins.example/first", "https://cins.example/second"}, v4, v6, 4, feedDownloadPackageInstall)
			if published || err == nil || errors.Is(err, errOSINTIntersection) {
				t.Fatalf("invalid authority or context was skipped: published=%t error=%v", published, err)
			}
		})
	}
}

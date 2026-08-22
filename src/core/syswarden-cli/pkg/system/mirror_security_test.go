package system

import (
	"strings"
	"testing"
)

func TestThreatIntelMirrorsAreHTTPSAndReturnedByCopy(t *testing.T) {
	t.Parallel()
	for _, choice := range []string{"1", "2"} {
		mirrors := ThreatIntelMirrors(choice)
		if len(mirrors) < 3 {
			t.Fatalf("choice %s has only %d mirrors", choice, len(mirrors))
		}
		for _, mirror := range mirrors {
			if !strings.HasPrefix(mirror, "https://") || !approvedHTTPSMirror(mirror) {
				t.Fatalf("choice %s contains an unsafe mirror: %q", choice, mirror)
			}
		}
		original := mirrors[0]
		mirrors[0] = "https://invalid.example/changed"
		if got := ThreatIntelMirrors(choice)[0]; got != original {
			t.Fatalf("caller mutation changed built-in mirror: got %q want %q", got, original)
		}
	}
}

func TestApprovedHTTPSMirrorRejectsRedirectProneOrAmbiguousURLs(t *testing.T) {
	t.Parallel()
	for _, rawURL := range []string{
		"http://example.com/feed",
		"https://user@example.com/feed",
		"https://example.com/feed#fragment",
		"//example.com/feed",
	} {
		if approvedHTTPSMirror(rawURL) {
			t.Fatalf("unsafe mirror URL %q was approved", rawURL)
		}
	}
}

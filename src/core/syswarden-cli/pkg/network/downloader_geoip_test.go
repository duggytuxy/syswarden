package network

import (
	"strings"
	"testing"

	"syswarden-cli/pkg/geoip"
)

func TestEmbeddedGeoIPSelectionsValidateWithoutHTTPOrFeedFilesIssue128(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		policy string
		raw    string
	}{
		{policy: "deny", raw: "RU, cn kp"},
		{policy: "allow", raw: "ru"},
	} {
		t.Run(test.policy, func(t *testing.T) {
			t.Parallel()
			var report strings.Builder
			selection, err := selectEmbeddedGeoIPPolicy(&report, test.policy, test.raw)
			if err != nil {
				t.Fatalf("selectEmbeddedGeoIPPolicy() error = %v", err)
			}
			if selection.SnapshotID != geoip.SnapshotID() || len(selection.Countries) == 0 || len(selection.IPv4) == 0 {
				t.Fatalf("embedded selection is incomplete: %#v", selection)
			}
			message := report.String()
			if !strings.Contains(message, "embedded release-bound snapshot") || strings.Contains(message, "last-known-good") {
				t.Fatalf("GeoIP validation report = %q", message)
			}
		})
	}
}

func TestEmbeddedGeoIPSelectionRejectsUnsupportedCountryIssue128(t *testing.T) {
	t.Parallel()
	_, err := selectEmbeddedGeoIPPolicy(&strings.Builder{}, "deny", "ru zz")
	if err == nil || !strings.Contains(err.Error(), "zz") || !strings.Contains(err.Error(), geoip.SnapshotID()) {
		t.Fatalf("unsupported-country error = %v", err)
	}
}

func TestEmbeddedGeoIPSelectionPreservesLegacyNoneSentinelIssue128(t *testing.T) {
	t.Parallel()
	selection, err := selectEmbeddedGeoIPPolicy(&strings.Builder{}, "deny", "none, RU none")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(selection.Countries, " "), "ru"; got != want {
		t.Fatalf("countries = %q, want %q", got, want)
	}
}

func TestFeedLifecycleValidatesEmbeddedGeoIPBeforeLANShortCircuitIssue128(t *testing.T) {
	for name, update := range map[string]func(string, string, string, string, string, string, string, string, string, bool, bool) error{
		"explicit": DownloadFeeds,
		"install":  DownloadFeedsForInstall,
	} {
		t.Run(name, func(t *testing.T) {
			if err := update("https://codeberg.org/", "", "", "", "1", "ru cn", "", "kp", "", true, false); err != nil {
				t.Fatalf("fresh embedded GeoIP selection failed: %v", err)
			}
			if err := update("https://codeberg.org/", "", "", "", "1", "zz", "", "", "", true, false); err == nil || !strings.Contains(err.Error(), "zz") {
				t.Fatalf("unsupported embedded GeoIP selection error = %v", err)
			}
		})
	}
}

func TestCustomFeedContractKeepsChoiceOneHashlessAndChoiceThreePinnedIssue128(t *testing.T) {
	t.Parallel()
	if err := validateCustomFeedContract("1", "https://codeberg.org/", "", "", ""); err != nil {
		t.Fatalf("Data-Shield choice 1 unexpectedly requires a custom digest: %v", err)
	}
	customURL := "https://feeds.example.invalid/deny-v4.txt"
	if err := validateCustomFeedContract("3", customURL, "", "", ""); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("custom choice 3 without digest error = %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	if err := validateCustomFeedContract("3", customURL, "", digest, ""); err != nil {
		t.Fatalf("pinned custom choice 3 was rejected: %v", err)
	}
}

func TestNonAuthoritativeFeedReportDoesNotInventLastKnownGoodIssue128(t *testing.T) {
	t.Parallel()
	var report strings.Builder
	reportNonAuthoritativeFeedTo(&report, "RADB ASN deny source AS64500")
	message := report.String()
	if !strings.Contains(message, "no update was published") || !strings.Contains(message, "existing operator-provisioned files remain unchanged") {
		t.Fatalf("non-authoritative report is not truthful about publication: %q", message)
	}
	if strings.Contains(message, "last-known-good") || strings.Contains(message, "preserved") {
		t.Fatalf("non-authoritative report invented retained state: %q", message)
	}
}

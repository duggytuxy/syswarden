//go:build linux

package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"syswarden-cli/pkg/geoip"
)

func TestAuthenticatedGeoIPIssue128CountriesPopulateFromEmbeddedSnapshot_SW_GEO_001(t *testing.T) {
	const issueCountries = "ru cn kp ir vn pk ph id ng br"
	ipv4, ipv6, err := configuredAuthenticatedGeoIPPopulations(
		issueCountries,
		"syswarden_geoip",
		"syswarden_geoip6",
	)
	if err != nil {
		t.Fatalf("issue #128 country selection failed: %v", err)
	}
	if len(ipv4.entries) == 0 {
		t.Fatal("issue #128 country selection produced no authenticated IPv4 policy")
	}
	if len(ipv6.entries) == 0 {
		t.Fatal("issue #128 country selection produced no authenticated IPv6 policy")
	}
	if ipv4.name != "syswarden_geoip" || ipv6.name != "syswarden_geoip6" {
		t.Fatalf("unexpected GeoIP set names: %q and %q", ipv4.name, ipv6.name)
	}
	assertAuthenticatedPopulationIdentity(
		t,
		ipv4,
		19875,
		"b6adb7d99f57f348f7fb1743f4713c31fe4c98099adcb366a49db1515f81abaf",
		netip.MustParseAddr("255.255.255.255"),
	)
	assertAuthenticatedPopulationIdentity(
		t,
		ipv6,
		18173,
		"bfe53825fbda5c2cdc53090fa803e5e2b37d5189831064aee38cd7fce0c9df6d",
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	)
}

func assertAuthenticatedPopulationIdentity(
	t *testing.T,
	population nftSetPopulation,
	wantCount int,
	wantDigest string,
	familyMaximum netip.Addr,
) {
	t.Helper()
	if len(population.entries) != wantCount {
		t.Fatalf("%s logical entry count = %d, want %d", population.name, len(population.entries), wantCount)
	}
	digest := sha256.Sum256([]byte(strings.Join(population.entries, "\n") + "\n"))
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("%s logical entry SHA-256 = %s, want %s", population.name, got, wantDigest)
	}
	for _, value := range population.entries {
		interval, err := nftPopulationInterval(value)
		if err != nil {
			t.Fatalf("parse %s entry %q: %v", population.name, value, err)
		}
		if interval.end == familyMaximum {
			t.Fatalf("%s entry %q reaches the address-family maximum", population.name, value)
		}
	}
}

func TestAuthenticatedGeoIPAllSupportedCountriesStayWithinFirewallBound_SW_GEO_001(t *testing.T) {
	supported := make([]string, 0, 249)
	for first := 'a'; first <= 'z'; first++ {
		for second := 'a'; second <= 'z'; second++ {
			code := string([]rune{first, second})
			if _, err := geoip.Select(code); err == nil {
				supported = append(supported, code)
			}
		}
	}
	if len(supported) != 249 {
		t.Fatalf("embedded snapshot supports %d country codes, want 249", len(supported))
	}
	selection, err := geoip.Select(strings.Join(supported, " "))
	if err != nil {
		t.Fatalf("select every supported country: %v", err)
	}
	if len(selection.IPv4) != 177951 || len(selection.IPv6) != 69197 {
		t.Fatalf("full selection has IPv4=%d IPv6=%d prefixes, want IPv4=177951 IPv6=69197", len(selection.IPv4), len(selection.IPv6))
	}
	ipv4, ipv6, err := populateAuthenticatedGeoIPSelection(selection, "syswarden_geoip", "syswarden_geoip6")
	if err != nil {
		t.Fatalf("populate every supported country: %v", err)
	}
	if len(ipv4.entries) == 0 || len(ipv6.entries) == 0 {
		t.Fatalf("full country selection produced empty policy: IPv4=%d IPv6=%d", len(ipv4.entries), len(ipv6.entries))
	}
}

func TestAuthenticatedGeoIPCountryWithoutIPv6ProducesValidEmptySet_SW_GEO_001(t *testing.T) {
	ipv4, ipv6, err := configuredAuthenticatedGeoIPPopulations(
		"kp",
		"syswarden_geoip",
		"syswarden_geoip6",
	)
	if err != nil {
		t.Fatalf("KP selection failed: %v", err)
	}
	if len(ipv4.entries) == 0 {
		t.Fatal("KP selection produced no authenticated IPv4 policy")
	}
	if ipv6.entries == nil || len(ipv6.entries) != 0 {
		t.Fatalf("KP IPv6 population = %#v, want a valid empty set", ipv6.entries)
	}
}

func TestAuthenticatedGeoIPPreservesLegacyNoneSentinel_SW_GEO_001(t *testing.T) {
	ipv4, ipv6, err := configuredAuthenticatedGeoIPPopulations(
		"none",
		"syswarden_geoip",
		"syswarden_geoip6",
	)
	if err != nil || ipv4.entries == nil || ipv6.entries == nil || len(ipv4.entries) != 0 || len(ipv6.entries) != 0 {
		t.Fatalf("legacy none selection = %#v/%#v, error=%v; want two valid empty populations", ipv4, ipv6, err)
	}
	withCountry4, _, err := configuredAuthenticatedGeoIPPopulations(
		"none, kp",
		"syswarden_geoip",
		"syswarden_geoip6",
	)
	if err != nil || len(withCountry4.entries) == 0 {
		t.Fatalf("legacy none token hid a valid country selection: entries=%#v error=%v", withCountry4.entries, err)
	}
}

func TestAuthenticatedGeoIPPopulationIsCanonicalBoundedAndDeterministic_SW_GEO_001(t *testing.T) {
	selection, err := geoip.Select("fr, BE")
	if err != nil {
		t.Fatalf("select authenticated countries: %v", err)
	}
	first4, first6, err := populateAuthenticatedGeoIPSelection(selection, "syswarden_geoip", "syswarden_geoip6")
	if err != nil {
		t.Fatalf("valid authenticated selection failed: %v", err)
	}
	if len(first4.entries) == 0 || len(first6.entries) == 0 {
		t.Fatalf("authenticated selection produced an empty family: IPv4=%d IPv6=%d", len(first4.entries), len(first6.entries))
	}

	secondSelection, err := geoip.Select("be BE fr")
	if err != nil {
		t.Fatalf("reselect normalized countries: %v", err)
	}
	second4, second6, err := populateAuthenticatedGeoIPSelection(secondSelection, "syswarden_geoip", "syswarden_geoip6")
	if err != nil {
		t.Fatalf("normalized authenticated selection failed: %v", err)
	}
	if !reflect.DeepEqual(first4, second4) || !reflect.DeepEqual(first6, second6) {
		t.Fatalf("population depends on country input form: first=%#v/%#v second=%#v/%#v", first4, first6, second4, second6)
	}
}

func TestAuthenticatedGeoIPBroadPrefixesDoNotWeakenOperatorListFloors_SW_GEO_001(t *testing.T) {
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "8.8.0.0/23", want: "broader than /24"},
		{value: "2606:4700:4700::/63", want: "broader than /64"},
	} {
		if _, _, err := canonicalFirewallListNetwork(test.value); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("generic firewall list %s error = %v, want %q", test.value, err, test.want)
		}
	}
	selection, err := geoip.Select("us")
	if err != nil {
		t.Fatalf("select authenticated US allocation data: %v", err)
	}
	hasBroadIPv4 := false
	for _, value := range selection.IPv4 {
		prefix := netip.MustParsePrefix(value)
		hasBroadIPv4 = hasBroadIPv4 || prefix.Bits() < 24
	}
	hasBroadIPv6 := false
	for _, value := range selection.IPv6 {
		prefix := netip.MustParsePrefix(value)
		hasBroadIPv6 = hasBroadIPv6 || prefix.Bits() < 64
	}
	if !hasBroadIPv4 || !hasBroadIPv6 {
		t.Fatalf("US selection did not exercise broad authenticated prefixes: IPv4=%t IPv6=%t", hasBroadIPv4, hasBroadIPv6)
	}
	if _, _, err := populateAuthenticatedGeoIPSelection(selection, "syswarden_geoip", "syswarden_geoip6"); err != nil {
		t.Fatalf("authenticated broad public GeoIP prefixes were rejected: %v", err)
	}
}

func TestAuthenticatedGeoIPPopulationRejectsInvalidInput_SW_GEO_001(t *testing.T) {
	tests := []struct {
		name      string
		selection geoip.Selection
		want      string
	}{
		{
			name:      "missing snapshot identity",
			selection: geoip.Selection{IPv4: []string{"8.8.8.0/24"}},
			want:      "no snapshot identity",
		},
		{
			name:      "foreign snapshot identity",
			selection: geoip.Selection{SnapshotID: "foreign-snapshot", IPv4: []string{"8.8.8.0/24"}},
			want:      "does not match embedded snapshot",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := populateAuthenticatedGeoIPSelection(test.selection, "syswarden_geoip", "syswarden_geoip6")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestAuthenticatedGeoIPCanonicalPrefixesRejectInvalidInput_SW_GEO_001(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		ipv6     bool
		want     string
	}{
		{name: "IPv4 slash zero", prefixes: []string{"0.0.0.0/0"}, want: "unbounded /0"},
		{name: "IPv6 slash zero", prefixes: []string{"::/0"}, ipv6: true, want: "unbounded /0"},
		{name: "special use", prefixes: []string{"192.0.2.0/24"}, want: "special-use"},
		{name: "private space", prefixes: []string{"10.0.0.0/8"}, want: "special-use"},
		{name: "wrong family", prefixes: []string{"2a00::/12"}, want: "wrong address family"},
		{name: "host bits", prefixes: []string{"8.8.8.1/24"}, want: "non-canonical"},
		{name: "duplicate", prefixes: []string{"8.8.8.0/24", "8.8.8.0/24"}, want: "duplicates"},
		{name: "overlap", prefixes: []string{"8.0.0.0/8", "8.8.8.0/24"}, want: "overlap"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicalAuthenticatedGeoIPPrefixes(test.prefixes, test.ipv6, "syswarden_geoip")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestAuthenticatedGeoIPSelectionRejectsTampering_SW_GEO_001(t *testing.T) {
	baseline, err := geoip.Select("ru cn")
	if err != nil {
		t.Fatalf("select tamper-test baseline: %v", err)
	}
	if len(baseline.IPv4) < 2 || len(baseline.IPv6) < 2 {
		t.Fatalf("tamper-test baseline is unexpectedly small: IPv4=%d IPv6=%d", len(baseline.IPv4), len(baseline.IPv6))
	}
	if _, _, err := populateAuthenticatedGeoIPSelection(baseline, "syswarden_geoip", "syswarden_geoip6"); err != nil {
		t.Fatalf("untampered selection failed: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*geoip.Selection)
		want   string
	}{
		{
			name: "snapshot identity",
			mutate: func(selection *geoip.Selection) {
				selection.SnapshotID = "foreign-snapshot"
			},
			want: "does not match embedded snapshot",
		},
		{
			name: "country normalization",
			mutate: func(selection *geoip.Selection) {
				selection.Countries[0], selection.Countries[1] = selection.Countries[1], selection.Countries[0]
			},
			want: "country list is not the normalized embedded selection",
		},
		{
			name: "country identity",
			mutate: func(selection *geoip.Selection) {
				selection.Countries = []string{"br"}
			},
			want: "IPv4 prefix list does not match",
		},
		{
			name: "IPv4 prefixes",
			mutate: func(selection *geoip.Selection) {
				selection.IPv4 = selection.IPv4[:len(selection.IPv4)-1]
			},
			want: "IPv4 prefix list does not match",
		},
		{
			name: "IPv4 prefix order",
			mutate: func(selection *geoip.Selection) {
				selection.IPv4[0], selection.IPv4[1] = selection.IPv4[1], selection.IPv4[0]
			},
			want: "IPv4 prefix list does not match",
		},
		{
			name: "IPv6 prefixes",
			mutate: func(selection *geoip.Selection) {
				selection.IPv6 = selection.IPv6[:len(selection.IPv6)-1]
			},
			want: "IPv6 prefix list does not match",
		},
		{
			name: "IPv6 prefix order",
			mutate: func(selection *geoip.Selection) {
				selection.IPv6[0], selection.IPv6[1] = selection.IPv6[1], selection.IPv6[0]
			},
			want: "IPv6 prefix list does not match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection := cloneAuthenticatedGeoIPSelection(baseline)
			test.mutate(&selection)
			_, _, err := populateAuthenticatedGeoIPSelection(selection, "syswarden_geoip", "syswarden_geoip6")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("tampered selection error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func cloneAuthenticatedGeoIPSelection(selection geoip.Selection) geoip.Selection {
	return geoip.Selection{
		SnapshotID: selection.SnapshotID,
		Countries:  append([]string{}, selection.Countries...),
		IPv4:       append([]string{}, selection.IPv4...),
		IPv6:       append([]string{}, selection.IPv6...),
	}
}

func TestAuthenticatedGeoIPSelectionRejectsUnboundedCardinality_SW_GEO_001(t *testing.T) {
	tooMany := make([]string, maximumAuthenticatedGeoIPPrefixesPerFamily+1)
	_, err := canonicalAuthenticatedGeoIPPrefixes(tooMany, false, "syswarden_geoip")
	if err == nil || !strings.Contains(err.Error(), "exceeds 300000 prefixes") {
		t.Fatalf("unbounded selection error = %v", err)
	}
}

func TestAuthenticatedGeoIPIgnoresLegacyCountryFiles_SW_GEO_001(t *testing.T) {
	legacyDirectory := t.TempDir()
	legacyPath := filepath.Join(legacyDirectory, "ru.ipv4")
	if err := os.WriteFile(legacyPath, []byte("9.9.9.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	selection, err := geoip.Select("ru")
	if err != nil {
		t.Fatalf("select authenticated RU allocation data: %v", err)
	}
	ipv4, _, err := populateAuthenticatedGeoIPSelection(selection, "syswarden_geoip", "syswarden_geoip6")
	if err != nil {
		t.Fatalf("authenticated population failed: %v", err)
	}
	if len(ipv4.entries) == 0 || contains(ipv4.entries, "9.9.9.0/24") {
		t.Fatalf("legacy file overrode authenticated data: got %#v", ipv4.entries)
	}
	legacyRoot, err := os.OpenRoot(legacyDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = legacyRoot.Close() }()
	content, err := legacyRoot.ReadFile("ru.ipv4")
	if err != nil || string(content) != "9.9.9.0/24\n" {
		t.Fatalf("legacy evidence was unexpectedly mutated: content=%q error=%v", content, err)
	}
}

func TestAuthenticatedGeoIPStrictAllowMergesWithASNPopulation_SW_GEO_001(t *testing.T) {
	geo4, geo6, err := configuredAuthenticatedGeoIPPopulations(
		"kp",
		"syswarden_zt_allowed",
		"syswarden_zt_allowed6",
	)
	if err != nil {
		t.Fatalf("strict GeoIP allow selection failed: %v", err)
	}
	asn4 := nftSetPopulation{name: "syswarden_zt_allowed", entries: []string{"9.9.9.0/24"}}
	asn6 := nftSetPopulation{name: "syswarden_zt_allowed6", entries: []string{"2606:4700:4700::/48"}}
	merged4, err := mergeNFTAddressPopulations("syswarden_zt_allowed", asn4, geo4)
	if err != nil {
		t.Fatalf("merge strict IPv4 authorities: %v", err)
	}
	merged6, err := mergeNFTAddressPopulations("syswarden_zt_allowed6", asn6, geo6)
	if err != nil {
		t.Fatalf("merge strict IPv6 authorities: %v", err)
	}
	if len(merged4.entries) <= len(geo4.entries) || !contains(merged4.entries, "9.9.9.0/24") {
		t.Fatalf("ASN IPv4 population was not merged with authenticated GeoIP: %#v", merged4.entries)
	}
	if want := []string{"2606:4700:4700::/48"}; !reflect.DeepEqual(merged6.entries, want) {
		t.Fatalf("empty authenticated IPv6 contribution changed ASN policy: got %#v, want %#v", merged6.entries, want)
	}
}

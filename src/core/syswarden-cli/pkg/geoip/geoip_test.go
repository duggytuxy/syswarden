package geoip

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	wantSnapshotID        = "ipverse-20260828T015522Z-07f1cb9cae15413e"
	wantSnapshotSHA256    = "d467540cef649539488dbeab76dbf808349d000a6fedfef7cdc66735e2339400"
	wantLicenseSHA256     = "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499"
	wantSourceCommit      = "7443b1e07cae182ac864a2a4247ea4b641970dfe"
	wantSourceArchiveHash = "ab2de300d06fcf63cdaac7f3cb093d17a1d509b2a32455c731e18331506b28a8"
)

func TestEmbeddedSnapshotIdentityLicenseAndProvenance(t *testing.T) {
	snapshotDigest := sha256.Sum256(embeddedSnapshot)
	if got := hex.EncodeToString(snapshotDigest[:]); got != wantSnapshotSHA256 {
		t.Fatalf("embedded snapshot SHA-256 = %s, want %s", got, wantSnapshotSHA256)
	}
	if got := SnapshotID(); got != wantSnapshotID {
		t.Fatalf("SnapshotID() = %q, want %q", got, wantSnapshotID)
	}
	license := DataLicense()
	if license == "" || !bytes.Equal([]byte(license), embeddedLicense) {
		t.Fatal("DataLicense() did not preserve the exact CC0-1.0 license")
	}
	licenseDigest := sha256.Sum256([]byte(license))
	if got := hex.EncodeToString(licenseDigest[:]); got != wantLicenseSHA256 {
		t.Fatalf("license SHA-256 = %s, want %s", got, wantLicenseSHA256)
	}

	candidate, err := decodeSnapshot(embeddedSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.source.Provider != sourceProvider || candidate.source.License != sourceLicense {
		t.Fatalf("source identity = %+v", candidate.source)
	}
	if candidate.source.Commit != wantSourceCommit || candidate.source.SHA256 != wantSourceArchiveHash || candidate.source.Size != 1760020 {
		t.Fatalf("source provenance = %+v", candidate.source)
	}
	wantMissing := []string{"bv", "cc", "cx", "eh", "gs", "hm", "pn", "sh", "sj", "tf", "um"}
	wantMissingIPv6 := []string{"bv", "cc", "cf", "cx", "eh", "er", "fk", "gs", "hm", "kp", "ms", "pn", "sh", "sj", "tf", "um", "yt"}
	if candidate.accounting.SourceCountries != 238 || !slices.Equal(candidate.accounting.MissingCountries, wantMissing) || !slices.Equal(candidate.accounting.MissingIPv4, wantMissing) || !slices.Equal(candidate.accounting.MissingIPv6, wantMissingIPv6) {
		t.Fatalf("source accounting = %+v", candidate.accounting)
	}
	if candidate.accounting.FilteredIPv4 != 2 || candidate.accounting.FilteredIPv6 != 2 || candidate.accounting.PublishedIPv4 != 177952 || candidate.accounting.PublishedIPv6 != 69197 {
		t.Fatalf("prefix accounting = %+v", candidate.accounting)
	}
}

func TestSelectIssue128Countries(t *testing.T) {
	selection, err := Select(" RU,cn kp  ir,vn PK ph id ng br,ru ")
	if err != nil {
		t.Fatal(err)
	}
	wantCountries := []string{"br", "cn", "id", "ir", "kp", "ng", "ph", "pk", "ru", "vn"}
	if !slices.Equal(selection.Countries, wantCountries) {
		t.Fatalf("Countries = %v, want %v", selection.Countries, wantCountries)
	}
	if selection.SnapshotID != wantSnapshotID {
		t.Fatalf("selection SnapshotID = %q, want %q", selection.SnapshotID, wantSnapshotID)
	}
	assertSelectionFamily(t, selection.IPv4, true)
	assertSelectionFamily(t, selection.IPv6, false)
	assertSelectionDigest(t, "IPv4", selection.IPv4, 28780, "c5bf26e7d5313e7c1471962b8f10d06c6905e5280e8463785f7535095e7bf018")
	assertSelectionDigest(t, "IPv6", selection.IPv6, 18217, "23361c48c5b4cdbe5b2fce61e2638d580444b109182a60776da78c49514b5d4a")
}

func TestSelectSupportsMissingFamilyAndMissingCountryData(t *testing.T) {
	kp, err := Select("kp")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(kp.IPv4, []string{"175.45.176.0/22"}) || len(kp.IPv6) != 0 {
		t.Fatalf("KP selection = %+v", kp)
	}

	bv, err := Select("bv")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bv.Countries, []string{"bv"}) || len(bv.IPv4) != 0 || len(bv.IPv6) != 0 {
		t.Fatalf("BV selection = %+v, want a valid empty contribution", bv)
	}
}

func TestSelectPreservesPublicRemainderOfPartiallyReservedAllocation(t *testing.T) {
	selection, err := Select("us")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"192.175.49.0/24",
		"192.175.50.0/23",
		"192.175.52.0/22",
		"192.175.56.0/21",
	} {
		if !slices.Contains(selection.IPv4, want) {
			t.Fatalf("US selection omitted public remainder %s", want)
		}
	}
	for _, forbidden := range []string{"192.175.48.0/20", "192.175.48.0/24"} {
		if slices.Contains(selection.IPv4, forbidden) {
			t.Fatalf("US selection contains reserved or unsplit prefix %s", forbidden)
		}
	}
}

func TestSelectAllISO3166Countries(t *testing.T) {
	selection, err := Select(iso3166Alpha2)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Countries) != 249 {
		t.Fatalf("country count = %d, want 249", len(selection.Countries))
	}
	assertSelectionFamily(t, selection.IPv4, true)
	assertSelectionFamily(t, selection.IPv6, false)
	assertSelectionDigest(t, "all-country IPv4", selection.IPv4, 177951, "6ab94035c92581a88e88b70acb961c7956c38997b93630f52f7383638e9dac14")
	assertSelectionDigest(t, "all-country IPv6", selection.IPv6, 69197, "87f0dbafb0eaa0202e4c9fa2efb41efd77e2b237b6bf5da76b19468dc4284605")
}

func TestValidateCountryCodesMatchesSelectionContract(t *testing.T) {
	got, err := ValidateCountryCodes(" RU, kp,ru ")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"kp", "ru"}) {
		t.Fatalf("ValidateCountryCodes = %v", got)
	}
	empty, err := ValidateCountryCodes(" , \t\n")
	if err != nil {
		t.Fatal(err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty validation result = %#v", empty)
	}
	for _, raw := range []string{"eu", "zz", "none", "russia", "r;u", "r"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ValidateCountryCodes(raw); err == nil {
				t.Fatalf("ValidateCountryCodes(%q) succeeded", raw)
			}
			if _, err := Select(raw); err == nil {
				t.Fatalf("Select(%q) succeeded", raw)
			}
		})
	}
}

func TestSelectMutationIsolationAndConcurrency(t *testing.T) {
	first, err := Select("kp")
	if err != nil {
		t.Fatal(err)
	}
	first.Countries[0] = "us"
	first.IPv4[0] = "1.0.0.0/8"
	second, err := Select("kp")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(second.Countries, []string{"kp"}) || !slices.Equal(second.IPv4, []string{"175.45.176.0/22"}) {
		t.Fatalf("caller mutation escaped into cached snapshot: %+v", second)
	}

	const workers = 32
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			selection, selectErr := Select("kp,ru")
			if selectErr != nil {
				errorsFound <- selectErr
				return
			}
			if selection.SnapshotID != wantSnapshotID || !slices.Equal(selection.Countries, []string{"kp", "ru"}) {
				errorsFound <- fmt.Errorf("unexpected concurrent selection metadata: %+v", selection)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for found := range errorsFound {
		t.Error(found)
	}
}

func TestValidateSnapshotAcceptsLegitimateBroadPrefixes(t *testing.T) {
	fixture := validSnapshotFixture()
	fixture.Countries[countryIndex("us")].IPv4 = []string{"1.0.0.0/8"}
	fixture.Countries[countryIndex("us")].IPv6 = []string{"2400::/12"}
	finalizeSnapshot(&fixture)
	if _, err := validateSnapshot(fixture); err != nil {
		t.Fatalf("validate broad public prefixes: %v", err)
	}
}

func TestValidateSnapshotRejectsUnsafePrefixData(t *testing.T) {
	tests := []struct {
		name string
		ipv4 []string
		ipv6 []string
	}{
		{name: "IPv4 zero route", ipv4: []string{"0.0.0.0/0"}},
		{name: "IPv6 zero route", ipv6: []string{"::/0"}},
		{name: "private", ipv4: []string{"10.0.0.0/8"}},
		{name: "special use", ipv6: []string{"2002::/16"}},
		{name: "retired 6bone", ipv6: []string{"3ffe::/16"}},
		{name: "wrong family", ipv4: []string{"2400::/12"}},
		{name: "host bits", ipv4: []string{"8.8.8.1/24"}},
		{name: "duplicate", ipv4: []string{"1.0.0.0/8", "1.0.0.0/8"}},
		{name: "overlap", ipv4: []string{"1.0.0.0/8", "1.2.0.0/16"}},
		{name: "unsorted", ipv4: []string{"2.0.0.0/8", "1.0.0.0/8"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validSnapshotFixture()
			index := countryIndex("us")
			if test.ipv4 != nil {
				fixture.Countries[index].IPv4 = test.ipv4
			}
			if test.ipv6 != nil {
				fixture.Countries[index].IPv6 = test.ipv6
			}
			finalizeSnapshot(&fixture)
			if _, err := validateSnapshot(fixture); err == nil {
				t.Fatal("unsafe snapshot passed validation")
			}
		})
	}
}

func TestValidateSnapshotRejectsStructuralTampering(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*snapshot)
		keepBadID bool
	}{
		{name: "bad schema", mutate: func(value *snapshot) { value.Schema = "other/v1" }},
		{name: "pseudo country", mutate: func(value *snapshot) { value.Countries[0].Code = "eu" }},
		{name: "null family", mutate: func(value *snapshot) { value.Countries[0].IPv6 = nil }},
		{name: "missing country", mutate: func(value *snapshot) { value.Countries = value.Countries[:248] }},
		{name: "license changed", mutate: func(value *snapshot) { value.License += "changed" }},
		{name: "provider changed", mutate: func(value *snapshot) { value.Source.Provider = "other" }},
		{name: "license identity changed", mutate: func(value *snapshot) { value.Source.License = "other" }},
		{name: "source URL changed", mutate: func(value *snapshot) { value.Source.URL = "https://example.com/source.tar.gz" }},
		{name: "source digest changed", mutate: func(value *snapshot) { value.Source.SHA256 = strings.Repeat("g", 64) }},
		{name: "source timestamp changed", mutate: func(value *snapshot) { value.Source.Timestamp = "2026-08-28T01:55:23Z" }},
		{name: "as-of changed", mutate: func(value *snapshot) { value.AsOf = "2026-08-28T01:55:23Z" }},
		{name: "published accounting changed", mutate: func(value *snapshot) { value.Accounting.PublishedIPv4++ }},
		{name: "missing list unsorted", mutate: func(value *snapshot) {
			value.Accounting.MissingCountries = []string{"cc", "bv"}
			value.Accounting.SourceCountries = 247
		}},
		{name: "identity changed", mutate: func(value *snapshot) { value.ID = "ipverse-forged" }, keepBadID: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validSnapshotFixture()
			test.mutate(&fixture)
			if !test.keepBadID {
				setSnapshotID(&fixture)
			}
			if _, err := validateSnapshot(fixture); err == nil {
				t.Fatal("tampered snapshot passed validation")
			}
		})
	}
}

func TestDecodeSnapshotRejectsUnknownJSONAndTrailingCompressedData(t *testing.T) {
	fixture := validSnapshotFixture()
	finalizeSnapshot(&fixture)
	plain, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	plain[len(plain)-1] = ','
	plain = append(plain, []byte(`"unexpected":true}`)...)
	if _, err := decodeSnapshot(gzipData(t, plain)); err == nil {
		t.Fatal("snapshot with an unknown JSON field passed validation")
	}
	withTrailingData := append(append([]byte{}, embeddedSnapshot...), 0)
	if _, err := decodeSnapshot(withTrailingData); err == nil {
		t.Fatal("snapshot with trailing compressed data passed validation")
	}
}

func TestCanonicalSelectionCollapsesDuplicatesAndOverlaps(t *testing.T) {
	got, err := canonicalSelection([]string{"2.0.0.0/8", "1.2.0.0/16", "1.0.0.0/8", "1.0.0.0/8"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.0.0.0/8", "2.0.0.0/8"}
	if !slices.Equal(got, want) {
		t.Fatalf("canonicalSelection = %v, want %v", got, want)
	}
}

func FuzzSelect(f *testing.F) {
	for _, seed := range []string{"", "ru,cn", "KP", "bv", "eu", "ru\x00cn", "ru, none"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		first, firstErr := Select(raw)
		second, secondErr := Select(raw)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("non-deterministic error result: %v then %v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if !slices.Equal(first.Countries, second.Countries) || !slices.Equal(first.IPv4, second.IPv4) || !slices.Equal(first.IPv6, second.IPv6) {
			t.Fatal("non-deterministic selection")
		}
		assertSelectionFamily(t, first.IPv4, true)
		assertSelectionFamily(t, first.IPv6, false)
	})
}

func assertSelectionFamily(t *testing.T, values []string, ipv4 bool) {
	t.Helper()
	if err := validateCanonicalPrefixes(values, ipv4); err != nil {
		t.Fatalf("invalid canonical selection: %v", err)
	}
	for _, value := range values {
		prefix := netip.MustParsePrefix(value)
		if prefix.Bits() == 0 || overlapsSpecialUse(prefix) {
			t.Fatalf("selection contains unsafe prefix %s", prefix)
		}
	}
}

func assertSelectionDigest(t *testing.T, label string, values []string, wantCount int, wantDigest string) {
	t.Helper()
	if len(values) != wantCount {
		t.Fatalf("%s prefix count = %d, want %d", label, len(values), wantCount)
	}
	digest := sha256.Sum256([]byte(strings.Join(values, "\n") + "\n"))
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("%s selection SHA-256 = %s, want %s", label, got, wantDigest)
	}
}

func validSnapshotFixture() snapshot {
	codes := strings.Fields(iso3166Alpha2)
	countries := make([]country, 0, len(codes))
	for _, code := range codes {
		countries = append(countries, country{Code: code, IPv4: []string{}, IPv6: []string{}})
	}
	licenseDigest := sha256.Sum256(embeddedLicense)
	commit := "0123456789abcdef0123456789abcdef01234567"
	return snapshot{
		Schema: snapshotSchema,
		AsOf:   "2024-01-02T03:04:05Z",
		Source: source{
			Provider:      sourceProvider,
			License:       sourceLicense,
			URL:           "https://github.com/ipverse/country-ip-blocks/archive/" + commit + ".tar.gz",
			Commit:        commit,
			SHA256:        strings.Repeat("a", 64),
			Size:          1,
			Timestamp:     "2024-01-02T03:04:05Z",
			LicenseSHA256: hex.EncodeToString(licenseDigest[:]),
		},
		Accounting: accounting{
			SourceCountries:  249,
			MissingCountries: []string{},
			MissingIPv4:      []string{},
			MissingIPv6:      []string{},
		},
		License:   string(embeddedLicense),
		Countries: countries,
	}
}

func finalizeSnapshot(value *snapshot) {
	value.Accounting.PublishedIPv4 = 0
	value.Accounting.PublishedIPv6 = 0
	for _, candidate := range value.Countries {
		value.Accounting.PublishedIPv4 += len(candidate.IPv4)
		value.Accounting.PublishedIPv6 += len(candidate.IPv6)
	}
	setSnapshotID(value)
}

func setSnapshotID(value *snapshot) {
	value.ID = ""
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	asOf, err := time.Parse(time.RFC3339, value.AsOf)
	if err != nil {
		panic(err)
	}
	value.ID = "ipverse-" + asOf.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(digest[:8])
}

func countryIndex(code string) int {
	return slices.Index(strings.Fields(iso3166Alpha2), code)
}

func gzipData(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

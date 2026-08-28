// Package geoip exposes the release-bound country allocation snapshot embedded
// in the SysWarden CLI. The snapshot is generated from an exact, digest-pinned
// ipverse/country-ip-blocks commit archive published under CC0-1.0 and is
// validated again at runtime. An official signed SysWarden release authenticates
// the binary and therefore the exact embedded snapshot bytes.
package geoip

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	snapshotSchema                    = "syswarden-geoip-snapshot/v1"
	sourceProvider                    = "ipverse/country-ip-blocks"
	sourceLicense                     = "CC0-1.0"
	maximumEmbeddedSnapshotBytes      = 8 << 20
	maximumExpandedSnapshotBytes      = 32 << 20
	maximumSourceArchiveBytes         = 32 << 20
	maximumSnapshotPrefixesPerFamily  = 500000
	maximumSelectionPrefixesPerFamily = 300000
	minimumSourceCountries            = 230
)

const iso3166Alpha2 = "ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"

var (
	//go:embed snapshot.json.gz
	embeddedSnapshot []byte
	//go:embed LICENSE-CC0-1.0.txt
	embeddedLicense []byte

	loadOnce     sync.Once
	loaded       *validatedSnapshot
	loadError    error
	sha256Format = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitFormat = regexp.MustCompile(`^[0-9a-f]{40}$`)
	specialUse   = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.31.196.0/24"),
		netip.MustParsePrefix("192.52.193.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("192.175.48.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("::ffff:0:0/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("100:0:0:1::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2620:4f:8000::/48"),
		netip.MustParsePrefix("3ffe::/16"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fec0::/10"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// Selection contains a deterministic union of the requested countries.
type Selection struct {
	SnapshotID string
	Countries  []string
	IPv4       []string
	IPv6       []string
}

type snapshot struct {
	Schema     string     `json:"schema"`
	ID         string     `json:"id"`
	AsOf       string     `json:"as_of"`
	Source     source     `json:"source"`
	Accounting accounting `json:"accounting"`
	License    string     `json:"license"`
	Countries  []country  `json:"countries"`
}

type source struct {
	Provider      string `json:"provider"`
	License       string `json:"license"`
	URL           string `json:"url"`
	Commit        string `json:"commit"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	Timestamp     string `json:"timestamp"`
	LicenseSHA256 string `json:"license_sha256"`
}

type accounting struct {
	SourceCountries  int      `json:"source_countries"`
	MissingCountries []string `json:"missing_countries"`
	MissingIPv4      []string `json:"missing_ipv4"`
	MissingIPv6      []string `json:"missing_ipv6"`
	FilteredIPv4     int      `json:"filtered_special_use_ipv4"`
	FilteredIPv6     int      `json:"filtered_special_use_ipv6"`
	PublishedIPv4    int      `json:"published_ipv4"`
	PublishedIPv6    int      `json:"published_ipv6"`
}

type country struct {
	Code string   `json:"code"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

type validatedSnapshot struct {
	id         string
	license    string
	source     source
	accounting accounting
	countries  map[string]country
}

// Select normalizes a comma or whitespace separated country list and returns
// its canonical public allocation prefixes. Unsupported and pseudo-country
// codes fail closed before any policy data is returned.
func Select(raw string) (Selection, error) {
	candidate, err := load()
	if err != nil {
		return Selection{}, fmt.Errorf("load embedded GeoIP snapshot: %w", err)
	}
	codes, err := normalizeCountryCodes(raw, candidate.countries)
	if err != nil {
		return Selection{}, err
	}
	ipv4 := make([]string, 0)
	ipv6 := make([]string, 0)
	for _, code := range codes {
		entry := candidate.countries[code]
		ipv4 = append(ipv4, entry.IPv4...)
		ipv6 = append(ipv6, entry.IPv6...)
	}
	ipv4, err = canonicalSelection(ipv4, true)
	if err != nil {
		return Selection{}, fmt.Errorf("select IPv4 GeoIP prefixes: %w", err)
	}
	ipv6, err = canonicalSelection(ipv6, false)
	if err != nil {
		return Selection{}, fmt.Errorf("select IPv6 GeoIP prefixes: %w", err)
	}
	return Selection{
		SnapshotID: candidate.id,
		Countries:  append([]string{}, codes...),
		IPv4:       ipv4,
		IPv6:       ipv6,
	}, nil
}

// ValidateCountryCodes validates and normalizes a country list without
// materializing its prefixes. An empty input returns a non-nil empty slice.
func ValidateCountryCodes(raw string) ([]string, error) {
	candidate, err := load()
	if err != nil {
		return nil, fmt.Errorf("load embedded GeoIP snapshot: %w", err)
	}
	return normalizeCountryCodes(raw, candidate.countries)
}

// SnapshotID returns the immutable identifier of the validated embedded
// snapshot. An empty string means the embedded data failed closed validation.
func SnapshotID() string {
	candidate, err := load()
	if err != nil {
		return ""
	}
	return candidate.id
}

// DataLicense returns the exact CC0-1.0 license embedded with the snapshot. An
// empty string means the embedded data failed closed validation.
func DataLicense() string {
	candidate, err := load()
	if err != nil {
		return ""
	}
	return candidate.license
}

func load() (*validatedSnapshot, error) {
	loadOnce.Do(func() {
		loaded, loadError = decodeSnapshot(embeddedSnapshot)
	})
	return loaded, loadError
}

func decodeSnapshot(compressed []byte) (*validatedSnapshot, error) {
	if len(compressed) == 0 || len(compressed) > maximumEmbeddedSnapshotBytes {
		return nil, fmt.Errorf("compressed snapshot size %d is outside the accepted range", len(compressed))
	}
	compressedReader := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(compressedReader)
	if err != nil {
		return nil, err
	}
	reader.Multistream(false)
	plain, err := io.ReadAll(io.LimitReader(reader, maximumExpandedSnapshotBytes+1))
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	if err := reader.Close(); err != nil {
		return nil, err
	}
	if compressedReader.Len() != 0 {
		return nil, errors.New("compressed snapshot contains trailing data")
	}
	if len(plain) > maximumExpandedSnapshotBytes {
		return nil, fmt.Errorf("expanded snapshot exceeds %d bytes", maximumExpandedSnapshotBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var raw snapshot
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("snapshot contains trailing JSON data")
		}
		return nil, fmt.Errorf("decode trailing snapshot data: %w", err)
	}
	validated, err := validateSnapshot(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal([]byte(validated.license), embeddedLicense) {
		return nil, errors.New("snapshot license differs from embedded LICENSE-CC0-1.0.txt")
	}
	return validated, nil
}

func validateSnapshot(raw snapshot) (*validatedSnapshot, error) {
	if raw.Schema != snapshotSchema {
		return nil, fmt.Errorf("unsupported snapshot schema %q", raw.Schema)
	}
	asOf, err := parseCanonicalTimestamp("snapshot as_of", raw.AsOf)
	if err != nil {
		return nil, err
	}
	if err := validateSource(raw.Source, asOf); err != nil {
		return nil, err
	}
	licenseDigest := sha256.Sum256([]byte(raw.License))
	if hex.EncodeToString(licenseDigest[:]) != raw.Source.LicenseSHA256 {
		return nil, errors.New("snapshot license SHA-256 mismatch")
	}
	if !bytes.Equal([]byte(raw.License), embeddedLicense) {
		return nil, errors.New("snapshot license does not match embedded license bytes")
	}

	expectedCodes := strings.Fields(iso3166Alpha2)
	if len(raw.Countries) != len(expectedCodes) {
		return nil, fmt.Errorf("snapshot country count = %d, want %d", len(raw.Countries), len(expectedCodes))
	}
	countries := make(map[string]country, len(expectedCodes))
	totalIPv4 := 0
	totalIPv6 := 0
	for index, expectedCode := range expectedCodes {
		entry := raw.Countries[index]
		if entry.Code != expectedCode {
			return nil, fmt.Errorf("snapshot country %d = %q, want %q", index, entry.Code, expectedCode)
		}
		if entry.IPv4 == nil || entry.IPv6 == nil {
			return nil, fmt.Errorf("snapshot country %s has a null prefix family", entry.Code)
		}
		if err := validateCanonicalPrefixes(entry.IPv4, true); err != nil {
			return nil, fmt.Errorf("snapshot country %s IPv4: %w", entry.Code, err)
		}
		if err := validateCanonicalPrefixes(entry.IPv6, false); err != nil {
			return nil, fmt.Errorf("snapshot country %s IPv6: %w", entry.Code, err)
		}
		totalIPv4 += len(entry.IPv4)
		totalIPv6 += len(entry.IPv6)
		if totalIPv4 > maximumSnapshotPrefixesPerFamily || totalIPv6 > maximumSnapshotPrefixesPerFamily {
			return nil, fmt.Errorf("snapshot exceeds %d prefixes per family", maximumSnapshotPrefixesPerFamily)
		}
		countries[entry.Code] = country{
			Code: entry.Code,
			IPv4: append([]string{}, entry.IPv4...),
			IPv6: append([]string{}, entry.IPv6...),
		}
	}
	if err := validateAccounting(raw.Accounting, countries, totalIPv4, totalIPv6); err != nil {
		return nil, err
	}

	identity := raw
	identity.ID = ""
	identityData, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(identityData)
	expectedID := "ipverse-" + asOf.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(digest[:8])
	if raw.ID != expectedID {
		return nil, fmt.Errorf("snapshot ID %q does not match content identity %q", raw.ID, expectedID)
	}
	return &validatedSnapshot{
		id:         raw.ID,
		license:    raw.License,
		source:     raw.Source,
		accounting: raw.Accounting,
		countries:  countries,
	}, nil
}

func validateSource(candidate source, asOf time.Time) error {
	if candidate.Provider != sourceProvider {
		return fmt.Errorf("snapshot source provider = %q, want %q", candidate.Provider, sourceProvider)
	}
	if candidate.License != sourceLicense {
		return fmt.Errorf("snapshot source license = %q, want %q", candidate.License, sourceLicense)
	}
	if !commitFormat.MatchString(candidate.Commit) {
		return errors.New("snapshot source commit is invalid")
	}
	wantURL := "https://github.com/ipverse/country-ip-blocks/archive/" + candidate.Commit + ".tar.gz"
	if candidate.URL != wantURL {
		return fmt.Errorf("snapshot source URL = %q, want %q", candidate.URL, wantURL)
	}
	if !sha256Format.MatchString(candidate.SHA256) || !sha256Format.MatchString(candidate.LicenseSHA256) {
		return errors.New("snapshot source has an invalid SHA-256")
	}
	if candidate.Size < 1 || candidate.Size > maximumSourceArchiveBytes {
		return fmt.Errorf("snapshot source size %d is outside the accepted range", candidate.Size)
	}
	timestamp, err := parseCanonicalTimestamp("snapshot source timestamp", candidate.Timestamp)
	if err != nil {
		return err
	}
	if !timestamp.Equal(asOf) {
		return fmt.Errorf("snapshot as_of %s does not match source timestamp %s", asOf.Format(time.RFC3339), timestamp.Format(time.RFC3339))
	}
	return nil
}

func parseCanonicalTimestamp(label, raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil || parsed.UTC().Format(time.RFC3339) != raw {
		return time.Time{}, fmt.Errorf("%s is not canonical UTC RFC3339: %q", label, raw)
	}
	return parsed.UTC(), nil
}

func validateAccounting(candidate accounting, countries map[string]country, totalIPv4, totalIPv6 int) error {
	validCodes := make(map[string]struct{}, len(countries))
	for code := range countries {
		validCodes[code] = struct{}{}
	}
	missingCountries, err := validateAccountingCodes("missing countries", candidate.MissingCountries, validCodes)
	if err != nil {
		return err
	}
	missingIPv4, err := validateAccountingCodes("missing IPv4", candidate.MissingIPv4, validCodes)
	if err != nil {
		return err
	}
	missingIPv6, err := validateAccountingCodes("missing IPv6", candidate.MissingIPv6, validCodes)
	if err != nil {
		return err
	}
	if candidate.SourceCountries < minimumSourceCountries || candidate.SourceCountries > len(countries) {
		return fmt.Errorf("snapshot source country count %d is outside the accepted range", candidate.SourceCountries)
	}
	if candidate.SourceCountries+len(missingCountries) != len(countries) {
		return errors.New("snapshot source and missing country accounting is inconsistent")
	}
	for code := range missingCountries {
		if _, exists := missingIPv4[code]; !exists {
			return fmt.Errorf("missing country %s is absent from missing IPv4 accounting", code)
		}
		if _, exists := missingIPv6[code]; !exists {
			return fmt.Errorf("missing country %s is absent from missing IPv6 accounting", code)
		}
	}
	for code := range missingIPv4 {
		if len(countries[code].IPv4) != 0 {
			return fmt.Errorf("country %s is marked missing IPv4 but publishes prefixes", code)
		}
	}
	for code := range missingIPv6 {
		if len(countries[code].IPv6) != 0 {
			return fmt.Errorf("country %s is marked missing IPv6 but publishes prefixes", code)
		}
	}
	if candidate.FilteredIPv4 < 0 || candidate.FilteredIPv6 < 0 || candidate.FilteredIPv4 > maximumSnapshotPrefixesPerFamily || candidate.FilteredIPv6 > maximumSnapshotPrefixesPerFamily {
		return errors.New("snapshot filtered special-use accounting is invalid")
	}
	if candidate.PublishedIPv4 != totalIPv4 || candidate.PublishedIPv6 != totalIPv6 {
		return fmt.Errorf("snapshot published prefix accounting = IPv4 %d/%d IPv6 %d/%d", candidate.PublishedIPv4, totalIPv4, candidate.PublishedIPv6, totalIPv6)
	}
	return nil
}

func validateAccountingCodes(label string, values []string, valid map[string]struct{}) (map[string]struct{}, error) {
	if values == nil {
		return nil, fmt.Errorf("snapshot %s list is null", label)
	}
	result := make(map[string]struct{}, len(values))
	previous := ""
	for index, code := range values {
		if _, exists := valid[code]; !exists {
			return nil, fmt.Errorf("snapshot %s contains unsupported country %q", label, code)
		}
		if index != 0 && code <= previous {
			return nil, fmt.Errorf("snapshot %s list is duplicated or unsorted", label)
		}
		previous = code
		result[code] = struct{}{}
	}
	return result, nil
}

func normalizeCountryCodes(raw string, supported map[string]country) ([]string, error) {
	tokens := strings.FieldsFunc(raw, func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
	unique := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		code := strings.ToLower(token)
		if len(code) != 2 || code[0] < 'a' || code[0] > 'z' || code[1] < 'a' || code[1] > 'z' {
			return nil, fmt.Errorf("invalid ISO 3166 alpha-2 country code %q", token)
		}
		if _, exists := supported[code]; !exists {
			return nil, fmt.Errorf("unsupported ISO 3166 alpha-2 country code %q", token)
		}
		unique[code] = struct{}{}
	}
	codes := make([]string, 0, len(unique))
	for code := range unique {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes, nil
}

func canonicalSelection(raw []string, ipv4 bool) ([]string, error) {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefix, err := parsePublicPrefix(value, ipv4)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	sortPrefixes(prefixes)
	canonical := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if len(canonical) != 0 && canonical[len(canonical)-1].Contains(prefix.Addr()) {
			continue
		}
		canonical = append(canonical, prefix)
	}
	if len(canonical) > maximumSelectionPrefixesPerFamily {
		return nil, fmt.Errorf("selection exceeds %d canonical prefixes", maximumSelectionPrefixesPerFamily)
	}
	result := make([]string, len(canonical))
	for index, prefix := range canonical {
		result[index] = prefix.String()
	}
	return result, nil
}

func validateCanonicalPrefixes(values []string, ipv4 bool) error {
	if len(values) > maximumSnapshotPrefixesPerFamily {
		return fmt.Errorf("country exceeds %d prefixes", maximumSnapshotPrefixesPerFamily)
	}
	var previous netip.Prefix
	for index, value := range values {
		prefix, err := parsePublicPrefix(value, ipv4)
		if err != nil {
			return fmt.Errorf("entry %d: %w", index, err)
		}
		if prefix.String() != value {
			return fmt.Errorf("entry %d is not canonical: %q", index, value)
		}
		if index != 0 {
			if comparePrefixes(previous, prefix) >= 0 {
				return fmt.Errorf("entry %d is duplicated or not sorted: %q", index, value)
			}
			if previous.Contains(prefix.Addr()) {
				return fmt.Errorf("entry %d overlaps an earlier prefix: %q", index, value)
			}
		}
		previous = prefix
	}
	return nil
}

func parsePublicPrefix(raw string, ipv4 bool) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("prefix has host bits set")
	}
	address := prefix.Addr()
	if address.Is4In6() || address.Is4() != ipv4 {
		return netip.Prefix{}, errors.New("prefix has the wrong address family")
	}
	if prefix.Bits() == 0 || !address.IsGlobalUnicast() || address.IsPrivate() || overlapsSpecialUse(prefix) {
		return netip.Prefix{}, errors.New("prefix is non-public or special-use")
	}
	return prefix, nil
}

func overlapsSpecialUse(prefix netip.Prefix) bool {
	for _, reserved := range specialUse {
		if prefix.Addr().Is4() == reserved.Addr().Is4() && prefix.Overlaps(reserved) {
			return true
		}
	}
	return false
}

func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(left, right int) bool {
		return comparePrefixes(prefixes[left], prefixes[right]) < 0
	})
}

func comparePrefixes(left, right netip.Prefix) int {
	if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
		return comparison
	}
	if left.Bits() < right.Bits() {
		return -1
	}
	if left.Bits() > right.Bits() {
		return 1
	}
	return 0
}

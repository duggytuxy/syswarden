//go:build ignore

// Command geoip_snapshot creates the deterministic GeoIP allocation snapshot
// embedded in the SysWarden CLI. The source is an immutable commit archive of
// ipverse/country-ip-blocks, published under CC0-1.0. The archive is accepted
// only when its URL, commit, size and independently recorded SHA-256 all match.
//
// Run this file directly with "go run scripts/ci/geoip_snapshot.go".
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	snapshotSchema          = "syswarden-geoip-snapshot/v1"
	sourceProvider          = "ipverse/country-ip-blocks"
	sourceLicense           = "CC0-1.0"
	maximumArchiveBytes     = 32 << 20
	maximumArchiveEntries   = 1000
	maximumArchiveDataBytes = 128 << 20
	maximumMemberBytes      = 16 << 20
	maximumPrefixes         = 500000
	minimumCountryMembers   = 230
)

const iso3166Alpha2 = "ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"

var (
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	specialUse    = []netip.Prefix{
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

type options struct {
	archive       string
	archiveSHA256 string
	archiveSize   int64
	sourceURL     string
	sourceCommit  string
	sourceTime    string
	licenseSHA256 string
	output        string
	licenseOutput string
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

type sourceCountry struct {
	Country          string   `json:"country"`
	CountryCode      string   `json:"countryCode"`
	DelegationStatus []string `json:"delegationStatus"`
	ExportMode       string   `json:"exportMode"`
	Prefixes         struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	} `json:"prefixes"`
}

type countryFiles struct {
	json []byte
	ipv4 []byte
	ipv6 []byte
}

type archiveResult struct {
	license    []byte
	countries  map[string]country
	accounting accounting
}

func main() {
	var candidate options
	flag.StringVar(&candidate.archive, "archive", "", "path to the immutable ipverse commit archive")
	flag.StringVar(&candidate.archiveSHA256, "archive-sha256", "", "independently recorded lowercase SHA-256 of the archive")
	flag.Int64Var(&candidate.archiveSize, "archive-size", 0, "independently recorded exact archive size")
	flag.StringVar(&candidate.sourceURL, "source-url", "", "exact immutable HTTPS archive URL")
	flag.StringVar(&candidate.sourceCommit, "source-commit", "", "exact lowercase 40-character repository commit")
	flag.StringVar(&candidate.sourceTime, "source-timestamp", "", "canonical RFC3339 source commit timestamp")
	flag.StringVar(&candidate.licenseSHA256, "license-sha256", "", "independently recorded lowercase SHA-256 of LICENSE")
	flag.StringVar(&candidate.output, "output", "", "output snapshot.json.gz path")
	flag.StringVar(&candidate.licenseOutput, "license-output", "", "output path for the intact CC0-1.0 LICENSE")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("unexpected positional arguments")
	}
	if err := run(candidate); err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "geoip_snapshot: "+format+"\n", arguments...)
	os.Exit(1)
}

func run(candidate options) error {
	if candidate.archive == "" || candidate.output == "" || candidate.licenseOutput == "" {
		return errors.New("archive, output, and license-output are required")
	}
	if !sha256Pattern.MatchString(candidate.archiveSHA256) || !sha256Pattern.MatchString(candidate.licenseSHA256) {
		return errors.New("archive-sha256 and license-sha256 must be lowercase SHA-256 digests")
	}
	if candidate.archiveSize < 1 || candidate.archiveSize > maximumArchiveBytes {
		return fmt.Errorf("archive-size must be between 1 and %d bytes", maximumArchiveBytes)
	}
	if !commitPattern.MatchString(candidate.sourceCommit) {
		return errors.New("source-commit must be a lowercase 40-character commit")
	}
	if err := validateSourceURL(candidate.sourceURL, candidate.sourceCommit); err != nil {
		return err
	}
	sourceTimestamp, err := parseTimestamp("source-timestamp", candidate.sourceTime)
	if err != nil {
		return err
	}
	archiveData, err := readAuthenticated(candidate.archive, candidate.archiveSHA256, candidate.archiveSize)
	if err != nil {
		return fmt.Errorf("authenticate source archive: %w", err)
	}
	content, err := readArchive(archiveData, candidate.sourceCommit)
	if err != nil {
		return fmt.Errorf("validate source archive: %w", err)
	}
	licenseDigest := sha256.Sum256(content.license)
	if hex.EncodeToString(licenseDigest[:]) != candidate.licenseSHA256 {
		return errors.New("archive LICENSE SHA-256 mismatch")
	}

	codes := strings.Fields(iso3166Alpha2)
	countries := make([]country, 0, len(codes))
	for _, code := range codes {
		entry, found := content.countries[code]
		if !found {
			entry = country{Code: code, IPv4: []string{}, IPv6: []string{}}
		}
		countries = append(countries, entry)
	}
	content.accounting.PublishedIPv4 = countPrefixes(countries, true)
	content.accounting.PublishedIPv6 = countPrefixes(countries, false)
	candidateSnapshot := snapshot{
		Schema: snapshotSchema,
		AsOf:   sourceTimestamp.UTC().Format(time.RFC3339),
		Source: source{
			Provider:      sourceProvider,
			License:       sourceLicense,
			URL:           candidate.sourceURL,
			Commit:        candidate.sourceCommit,
			SHA256:        candidate.archiveSHA256,
			Size:          candidate.archiveSize,
			Timestamp:     sourceTimestamp.UTC().Format(time.RFC3339),
			LicenseSHA256: candidate.licenseSHA256,
		},
		Accounting: content.accounting,
		License:    string(content.license),
		Countries:  countries,
	}
	identityData, err := json.Marshal(candidateSnapshot)
	if err != nil {
		return fmt.Errorf("marshal snapshot identity: %w", err)
	}
	identity := sha256.Sum256(identityData)
	candidateSnapshot.ID = "ipverse-" + sourceTimestamp.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(identity[:8])

	plain, err := json.Marshal(candidateSnapshot)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	compressed, err := deterministicGzip(plain)
	if err != nil {
		return err
	}
	if err := writeAtomic(candidate.licenseOutput, content.license); err != nil {
		return fmt.Errorf("publish license: %w", err)
	}
	if err := writeAtomic(candidate.output, compressed); err != nil {
		return fmt.Errorf("publish snapshot: %w", err)
	}
	fileDigest := sha256.Sum256(compressed)
	_, _ = fmt.Fprintf(os.Stdout,
		"snapshot_id=%s source_countries=%d missing_countries=%d ipv4=%d ipv6=%d filtered_ipv4=%d filtered_ipv6=%d sha256=%s\n",
		candidateSnapshot.ID,
		content.accounting.SourceCountries,
		len(content.accounting.MissingCountries),
		content.accounting.PublishedIPv4,
		content.accounting.PublishedIPv6,
		content.accounting.FilteredIPv4,
		content.accounting.FilteredIPv6,
		hex.EncodeToString(fileDigest[:]),
	)
	return nil
}

func validateSourceURL(raw, commit string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("source-url must be an absolute query-free HTTPS github.com URL")
	}
	wantPath := "/ipverse/country-ip-blocks/archive/" + commit + ".tar.gz"
	if parsed.Path != wantPath {
		return fmt.Errorf("source-url path must be %q", wantPath)
	}
	return nil
}

func parseTimestamp(label, raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil || parsed.UTC().Format(time.RFC3339) != raw {
		return time.Time{}, fmt.Errorf("%s must be a canonical UTC RFC3339 timestamp", label)
	}
	if parsed.After(time.Now().UTC().Add(24 * time.Hour)) {
		return time.Time{}, fmt.Errorf("%s is implausibly far in the future", label)
	}
	return parsed.UTC(), nil
}

func readAuthenticated(name, expected string, exactSize int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != exactSize {
		return nil, fmt.Errorf("source must be a regular file of exactly %d bytes", exactSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, exactSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != exactSize {
		return nil, errors.New("source size changed while reading")
	}
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return nil, fmt.Errorf("SHA-256 mismatch: got %s, want %s", actual, expected)
	}
	return data, nil
}

func readArchive(compressed []byte, commit string) (archiveResult, error) {
	readerSource := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(readerSource)
	if err != nil {
		return archiveResult{}, err
	}
	reader.Multistream(false)
	plain, err := io.ReadAll(io.LimitReader(reader, maximumArchiveDataBytes+maximumArchiveEntries*512+1))
	if err != nil {
		_ = reader.Close()
		return archiveResult{}, err
	}
	if err := reader.Close(); err != nil {
		return archiveResult{}, err
	}
	if readerSource.Len() != 0 {
		return archiveResult{}, errors.New("compressed archive contains trailing data")
	}
	if len(plain) > maximumArchiveDataBytes+maximumArchiveEntries*512 {
		return archiveResult{}, errors.New("archive expands beyond its bounded representation")
	}
	members, err := readTarMembers(plain)
	if err != nil {
		return archiveResult{}, err
	}
	root := "country-ip-blocks-" + commit
	validCodes := isoCodeSet()
	files := make(map[string]*countryFiles)
	seen := make(map[string]struct{})
	var license []byte
	seenGlobalPAX := false
	for index, member := range members {
		if member.typeFlag == 'g' {
			expected := []byte("52 comment=" + commit + "\n")
			if index != 0 || member.name != "pax_global_header" || !bytes.Equal(member.data, expected) {
				return archiveResult{}, errors.New("archive has an unexpected global PAX header")
			}
			seenGlobalPAX = true
			continue
		}
		rawName := member.name
		if member.directory {
			if !strings.HasSuffix(rawName, "/") || strings.HasSuffix(rawName, "//") {
				return archiveResult{}, fmt.Errorf("archive directory has a non-canonical name %q", rawName)
			}
			rawName = strings.TrimSuffix(rawName, "/")
		}
		clean, err := cleanArchiveName(rawName)
		if err != nil {
			return archiveResult{}, err
		}
		if _, duplicate := seen[clean]; duplicate {
			return archiveResult{}, fmt.Errorf("duplicate archive member %q", clean)
		}
		seen[clean] = struct{}{}
		if member.directory {
			if clean == root || clean == root+"/country" {
				continue
			}
			parts := strings.Split(clean, "/")
			if len(parts) == 3 && parts[0] == root && parts[1] == "country" {
				if _, valid := validCodes[parts[2]]; valid {
					continue
				}
			}
			return archiveResult{}, fmt.Errorf("unexpected archive directory %q", clean)
		}
		if len(member.data) > maximumMemberBytes {
			return archiveResult{}, fmt.Errorf("archive member %q exceeds %d bytes", clean, maximumMemberBytes)
		}
		switch clean {
		case root + "/LICENSE":
			license = append([]byte(nil), member.data...)
			continue
		case root + "/.gitignore", root + "/README.md", root + "/STATS.md":
			continue
		}
		parts := strings.Split(clean, "/")
		if len(parts) != 4 || parts[0] != root || parts[1] != "country" {
			return archiveResult{}, fmt.Errorf("unexpected archive member %q", clean)
		}
		code := parts[2]
		if _, valid := validCodes[code]; !valid {
			return archiveResult{}, fmt.Errorf("archive member %q is not an ISO 3166 alpha-2 country", clean)
		}
		entry := files[code]
		if entry == nil {
			entry = &countryFiles{}
			files[code] = entry
		}
		switch parts[3] {
		case "aggregated.json":
			entry.json = append([]byte(nil), member.data...)
		case "ipv4-aggregated.txt":
			entry.ipv4 = append([]byte(nil), member.data...)
		case "ipv6-aggregated.txt":
			entry.ipv6 = append([]byte(nil), member.data...)
		default:
			return archiveResult{}, fmt.Errorf("unexpected country member %q", clean)
		}
	}
	if !seenGlobalPAX {
		return archiveResult{}, errors.New("archive is missing its commit-bound global PAX header")
	}
	if len(license) == 0 || !utf8Text(license) {
		return archiveResult{}, errors.New("archive LICENSE is missing or invalid text")
	}
	if len(files) < minimumCountryMembers {
		return archiveResult{}, fmt.Errorf("archive has only %d country members", len(files))
	}
	result := archiveResult{license: license, countries: make(map[string]country, len(files))}
	result.accounting.SourceCountries = len(files)
	for _, code := range strings.Fields(iso3166Alpha2) {
		entry, found := files[code]
		if !found {
			result.accounting.MissingCountries = append(result.accounting.MissingCountries, code)
			result.accounting.MissingIPv4 = append(result.accounting.MissingIPv4, code)
			result.accounting.MissingIPv6 = append(result.accounting.MissingIPv6, code)
			continue
		}
		parsed, filtered4, filtered6, missing4, missing6, err := parseSourceCountry(code, *entry)
		if err != nil {
			return archiveResult{}, fmt.Errorf("country %s: %w", code, err)
		}
		if missing4 {
			result.accounting.MissingIPv4 = append(result.accounting.MissingIPv4, code)
		}
		if missing6 {
			result.accounting.MissingIPv6 = append(result.accounting.MissingIPv6, code)
		}
		result.accounting.FilteredIPv4 += filtered4
		result.accounting.FilteredIPv6 += filtered6
		result.countries[code] = parsed
	}
	return result, nil
}

func parseSourceCountry(code string, files countryFiles) (country, int, int, bool, bool, error) {
	if len(files.json) == 0 || !utf8Text(files.json) {
		return country{}, 0, 0, false, false, errors.New("aggregated.json is missing or invalid text")
	}
	decoder := json.NewDecoder(bytes.NewReader(files.json))
	decoder.DisallowUnknownFields()
	var raw sourceCountry
	if err := decoder.Decode(&raw); err != nil {
		return country{}, 0, 0, false, false, fmt.Errorf("decode aggregated.json: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return country{}, 0, 0, false, false, errors.New("aggregated.json contains trailing data")
	}
	if raw.Country == "" || !utf8Text([]byte(raw.Country)) || raw.CountryCode != strings.ToUpper(code) {
		return country{}, 0, 0, false, false, errors.New("country identity is invalid")
	}
	if len(raw.DelegationStatus) != 2 || raw.DelegationStatus[0] != "allocated" || raw.DelegationStatus[1] != "assigned" || raw.ExportMode != "aggregated" {
		return country{}, 0, 0, false, false, errors.New("delegation or export contract is invalid")
	}
	if raw.Prefixes.IPv4 == nil || raw.Prefixes.IPv6 == nil {
		return country{}, 0, 0, false, false, errors.New("prefix family must not be null")
	}
	if err := validatePlaintextFamily(files.ipv4, raw.Prefixes.IPv4, "IPv4"); err != nil {
		return country{}, 0, 0, false, false, err
	}
	if err := validatePlaintextFamily(files.ipv6, raw.Prefixes.IPv6, "IPv6"); err != nil {
		return country{}, 0, 0, false, false, err
	}
	ipv4, filtered4, err := canonicalPrefixes(raw.Prefixes.IPv4, true)
	if err != nil {
		return country{}, 0, 0, false, false, fmt.Errorf("IPv4: %w", err)
	}
	ipv6, filtered6, err := canonicalPrefixes(raw.Prefixes.IPv6, false)
	if err != nil {
		return country{}, 0, 0, false, false, fmt.Errorf("IPv6: %w", err)
	}
	return country{Code: code, IPv4: ipv4, IPv6: ipv6}, filtered4, filtered6, len(raw.Prefixes.IPv4) == 0, len(raw.Prefixes.IPv6) == 0, nil
}

func validatePlaintextFamily(data []byte, want []string, family string) error {
	if len(data) == 0 {
		if len(want) == 0 {
			return nil
		}
		return fmt.Errorf("%s plaintext is missing for a non-empty JSON family", family)
	}
	if !utf8Text(data) {
		return fmt.Errorf("%s plaintext is invalid text", family)
	}
	got := make([]string, 0, len(want))
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line != raw || strings.ContainsAny(line, " \t") {
			return fmt.Errorf("%s plaintext line %d is not a bare canonical CIDR", family, index+1)
		}
		got = append(got, line)
	}
	if len(got) != len(want) {
		return fmt.Errorf("%s JSON/plaintext prefix count mismatch", family)
	}
	for index := range got {
		if got[index] != want[index] {
			return fmt.Errorf("%s JSON/plaintext mismatch at prefix %d", family, index+1)
		}
	}
	return nil
}

func canonicalPrefixes(values []string, ipv4 bool) ([]string, int, error) {
	if len(values) > maximumPrefixes {
		return nil, 0, fmt.Errorf("family has more than %d prefixes", maximumPrefixes)
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	filtered := 0
	var previous netip.Prefix
	for index, value := range values {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, " \t\r\n\x00") {
			return nil, 0, fmt.Errorf("entry %d is not a bare CIDR", index+1)
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Is4() != ipv4 {
			return nil, 0, fmt.Errorf("entry %d has an invalid address family", index+1)
		}
		if prefix != prefix.Masked() || prefix.String() != value {
			return nil, 0, fmt.Errorf("entry %d is not canonical", index+1)
		}
		if index != 0 && (comparePrefixes(previous, prefix) >= 0 || previous.Contains(prefix.Addr())) {
			return nil, 0, fmt.Errorf("entry %d is unsorted, duplicated or overlapping", index+1)
		}
		previous = prefix
		if prefix.Bits() == 0 {
			filtered++
			continue
		}
		public, changed, err := excludeSpecialUse(prefix)
		if err != nil {
			return nil, 0, fmt.Errorf("entry %d: %w", index+1, err)
		}
		if changed {
			filtered++
		}
		if len(prefixes)+len(public) > maximumPrefixes {
			return nil, 0, fmt.Errorf("filtered family has more than %d prefixes", maximumPrefixes)
		}
		prefixes = append(prefixes, public...)
	}
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	return result, filtered, nil
}

type tarMember struct {
	name      string
	typeFlag  byte
	directory bool
	data      []byte
}

func readTarMembers(archive []byte) ([]tarMember, error) {
	const blockSize = 512
	if len(archive)%blockSize != 0 {
		return nil, errors.New("tar archive size is not aligned to 512-byte blocks")
	}
	members := make([]tarMember, 0, 800)
	offset := 0
	terminated := false
	for offset+blockSize <= len(archive) {
		header := archive[offset : offset+blockSize]
		offset += blockSize
		if allZero(header) {
			if offset+blockSize > len(archive) || !allZero(archive[offset:offset+blockSize]) {
				return nil, errors.New("tar archive has only one terminating zero block")
			}
			offset += blockSize
			if !allZero(archive[offset:]) {
				return nil, errors.New("tar archive contains data after its terminator")
			}
			terminated = true
			break
		}
		if len(members) >= maximumArchiveEntries {
			return nil, fmt.Errorf("archive has more than %d entries", maximumArchiveEntries)
		}
		if err := verifyTarChecksum(header); err != nil {
			return nil, err
		}
		name, err := tarString(header[0:100])
		if err != nil {
			return nil, fmt.Errorf("invalid tar name: %w", err)
		}
		prefix, err := tarString(header[345:500])
		if err != nil {
			return nil, fmt.Errorf("invalid tar prefix: %w", err)
		}
		if prefix != "" {
			name = prefix + "/" + name
		}
		size, err := tarOctal(header[124:136])
		if err != nil {
			return nil, fmt.Errorf("archive member %q has invalid size: %w", name, err)
		}
		if size > maximumMemberBytes {
			return nil, fmt.Errorf("archive member %q exceeds %d bytes", name, maximumMemberBytes)
		}
		typeFlag := header[156]
		directory := typeFlag == '5'
		globalPAX := typeFlag == 'g'
		if typeFlag != 0 && typeFlag != '0' && !directory && !globalPAX {
			return nil, fmt.Errorf("archive member %q has unsafe type %q", name, typeFlag)
		}
		if directory && size != 0 {
			return nil, fmt.Errorf("archive directory %q has non-zero size", name)
		}
		padded := (size + blockSize - 1) / blockSize * blockSize
		if padded > int64(len(archive)-offset) {
			return nil, fmt.Errorf("archive member %q is truncated", name)
		}
		data := append([]byte(nil), archive[offset:offset+int(size)]...)
		padding := archive[offset+int(size) : offset+int(padded)]
		if !allZero(padding) {
			return nil, fmt.Errorf("archive member %q has non-zero padding", name)
		}
		offset += int(padded)
		members = append(members, tarMember{name: name, typeFlag: typeFlag, directory: directory, data: data})
	}
	if !terminated {
		return nil, errors.New("tar archive is missing its two-block terminator")
	}
	return members, nil
}

func verifyTarChecksum(header []byte) error {
	expected, err := tarOctal(header[148:156])
	if err != nil {
		return fmt.Errorf("invalid tar checksum: %w", err)
	}
	var actual int64
	for index, value := range header {
		if index >= 148 && index < 156 {
			actual += int64(' ')
		} else {
			actual += int64(value)
		}
	}
	if actual != expected {
		return fmt.Errorf("tar checksum mismatch: got %d, want %d", actual, expected)
	}
	return nil
}

func tarOctal(field []byte) (int64, error) {
	if len(field) == 0 || field[0]&0x80 != 0 {
		return 0, errors.New("base-256 or empty numeric field is forbidden")
	}
	value := int64(0)
	terminated := false
	for _, character := range field {
		switch {
		case character == 0 || character == ' ':
			terminated = true
		case character >= '0' && character <= '7' && !terminated:
			value = value*8 + int64(character-'0')
		default:
			return 0, fmt.Errorf("non-canonical octal byte %#x", character)
		}
	}
	return value, nil
}

func tarString(field []byte) (string, error) {
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = len(field)
	} else if !allZero(field[end:]) {
		return "", errors.New("non-zero bytes follow NUL terminator")
	}
	value := field[:end]
	if !utf8.Valid(value) {
		return "", errors.New("field is not UTF-8")
	}
	return string(value), nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func cleanArchiveName(raw string) (string, error) {
	if raw == "" || strings.ContainsRune(raw, '\x00') || strings.Contains(raw, `\`) || path.IsAbs(raw) || !utf8.ValidString(raw) {
		return "", fmt.Errorf("unsafe archive member name %q", raw)
	}
	clean := path.Clean(raw)
	if clean != raw || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "//") {
		return "", fmt.Errorf("unsafe or non-canonical archive member name %q", raw)
	}
	return clean, nil
}

func isoCodeSet() map[string]struct{} {
	result := make(map[string]struct{}, 249)
	for _, code := range strings.Fields(iso3166Alpha2) {
		result[code] = struct{}{}
	}
	return result
}

func overlapsSpecialUse(prefix netip.Prefix) bool {
	for _, reserved := range specialUse {
		if prefix.Addr().Is4() == reserved.Addr().Is4() && prefix.Overlaps(reserved) {
			return true
		}
	}
	return false
}

func excludeSpecialUse(prefix netip.Prefix) ([]netip.Prefix, bool, error) {
	candidates := []netip.Prefix{prefix}
	changed := false
	for _, reserved := range specialUse {
		if prefix.Addr().Is4() != reserved.Addr().Is4() {
			continue
		}
		next := make([]netip.Prefix, 0, len(candidates))
		for _, candidate := range candidates {
			if !candidate.Overlaps(reserved) {
				next = append(next, candidate)
				continue
			}
			changed = true
			next = append(next, subtractReservedPrefix(candidate, reserved)...)
		}
		candidates = next
	}
	for _, candidate := range candidates {
		address := candidate.Addr()
		if candidate.Bits() == 0 || !address.IsGlobalUnicast() || address.IsPrivate() || overlapsSpecialUse(candidate) {
			return nil, false, fmt.Errorf("special-use subtraction left non-public prefix %s", candidate)
		}
	}
	return candidates, changed, nil
}

func subtractReservedPrefix(prefix, reserved netip.Prefix) []netip.Prefix {
	if prefix.Addr().Is4() != reserved.Addr().Is4() || !prefix.Overlaps(reserved) {
		return []netip.Prefix{prefix}
	}
	if reserved.Bits() <= prefix.Bits() {
		return nil
	}
	first, second := splitPrefix(prefix)
	result := subtractReservedPrefix(first, reserved)
	return append(result, subtractReservedPrefix(second, reserved)...)
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	nextBits := prefix.Bits() + 1
	first := netip.PrefixFrom(prefix.Addr(), nextBits)
	bit := prefix.Bits()
	if prefix.Addr().Is4() {
		address := prefix.Addr().As4()
		address[bit/8] |= byte(1 << uint(7-bit%8))
		return first, netip.PrefixFrom(netip.AddrFrom4(address), nextBits)
	}
	address := prefix.Addr().As16()
	address[bit/8] |= byte(1 << uint(7-bit%8))
	return first, netip.PrefixFrom(netip.AddrFrom16(address), nextBits)
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

func utf8Text(data []byte) bool {
	for _, character := range data {
		if character == 0 || (character < 0x20 && character != '\n' && character != '\r' && character != '\t') {
			return false
		}
	}
	return utf8.Valid(data)
}

func countPrefixes(countries []country, ipv4 bool) int {
	total := 0
	for _, candidate := range countries {
		if ipv4 {
			total += len(candidate.IPv4)
		} else {
			total += len(candidate.IPv6)
		}
	}
	return total
}

func deterministicGzip(plain []byte) ([]byte, error) {
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("create compressor: %w", err)
	}
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(plain); err != nil {
		return nil, fmt.Errorf("compress snapshot: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish snapshot compression: %w", err)
	}
	return compressed.Bytes(), nil
}

func writeAtomic(name string, data []byte) error {
	directory := filepath.Dir(name)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".geoip-snapshot-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0644); err != nil {
		return fmt.Errorf("set output permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	committed = true
	return nil
}

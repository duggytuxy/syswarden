//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func TestCleanArchiveName(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "country-ip-blocks-commit/LICENSE", want: "country-ip-blocks-commit/LICENSE", ok: true},
		{raw: "country-ip-blocks-commit/country/us/aggregated.json", want: "country-ip-blocks-commit/country/us/aggregated.json", ok: true},
		{raw: "../LICENSE"},
		{raw: "/LICENSE"},
		{raw: `country\LICENSE`},
		{raw: "./LICENSE"},
		{raw: "country//us"},
		{raw: ""},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%q", test.raw), func(t *testing.T) {
			got, err := cleanArchiveName(test.raw)
			if (err == nil) != test.ok {
				t.Fatalf("cleanArchiveName(%q) error = %v, want success=%v", test.raw, err, test.ok)
			}
			if err == nil && got != test.want {
				t.Fatalf("cleanArchiveName(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestCanonicalPrefixesFiltersSpecialUse(t *testing.T) {
	got, filtered, err := canonicalPrefixes([]string{
		"1.0.0.0/8",
		"10.0.0.0/8",
		"192.0.2.0/24",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1.0.0.0/8"}; !slices.Equal(got, want) {
		t.Fatalf("canonicalPrefixes = %v, want %v", got, want)
	}
	if filtered != 2 {
		t.Fatalf("filtered = %d, want 2", filtered)
	}
}

func TestCanonicalPrefixesSubtractsPartialSpecialUseOverlap(t *testing.T) {
	got, filtered, err := canonicalPrefixes([]string{"192.175.48.0/20"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"192.175.49.0/24",
		"192.175.50.0/23",
		"192.175.52.0/22",
		"192.175.56.0/21",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("canonicalPrefixes = %v, want %v", got, want)
	}
	if filtered != 1 {
		t.Fatalf("filtered = %d, want 1 affected source prefix", filtered)
	}
}

func TestExcludeSpecialUseSplitsIPv6Deterministically(t *testing.T) {
	prefix := netip.MustParsePrefix("2001::/22")
	got, changed, err := excludeSpecialUse(prefix)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("2001:200::/23"),
	}
	if !changed || !slices.Equal(got, want) {
		t.Fatalf("excludeSpecialUse(%s) = %v, changed=%t, want %v", prefix, got, changed, want)
	}
}

func TestCanonicalPrefixesRejectsAmbiguousInput(t *testing.T) {
	for _, values := range [][]string{
		{"8.8.8.1/24"},
		{"2400::/12"},
		{"8.8.8.8"},
		{"8.8.8.0/24 comment"},
		{"2.0.0.0/8", "1.0.0.0/8"},
		{"1.0.0.0/8", "1.0.0.0/8"},
		{"1.0.0.0/8", "1.2.0.0/16"},
	} {
		if _, _, err := canonicalPrefixes(values, true); err == nil {
			t.Fatalf("canonicalPrefixes accepted %v", values)
		}
	}
}

func TestReadTarMembersRejectsUnsafeTypesChecksumAndTermination(t *testing.T) {
	regular := testTarArchive(testArchiveMember{name: "LICENSE", data: []byte("test\n")})
	if _, err := readTarMembers(regular); err != nil {
		t.Fatalf("read valid archive: %v", err)
	}

	symlink := testTarArchive(testArchiveMember{name: "LICENSE", typeFlag: '2'})
	if _, err := readTarMembers(symlink); err == nil || !strings.Contains(err.Error(), "unsafe type") {
		t.Fatalf("unsafe type error = %v", err)
	}

	corrupt := append([]byte(nil), regular...)
	corrupt[0] ^= 1
	if _, err := readTarMembers(corrupt); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt checksum error = %v", err)
	}

	unterminated := regular[:len(regular)-1024]
	if _, err := readTarMembers(unterminated); err == nil || !strings.Contains(err.Error(), "terminator") {
		t.Fatalf("unterminated archive error = %v", err)
	}
}

func TestReadArchiveValidatesCountryFilesAndAccounting(t *testing.T) {
	compressed, license := validSourceArchive(t, testCommit, 230)
	got, err := readArchive(compressed, testCommit)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.license, license) {
		t.Fatal("license bytes changed")
	}
	if got.accounting.SourceCountries != 230 || len(got.accounting.MissingCountries) != 19 {
		t.Fatalf("accounting = %+v", got.accounting)
	}
	if got.accounting.FilteredIPv4 != 0 || got.accounting.FilteredIPv6 != 0 {
		t.Fatalf("unexpected filtering = %+v", got.accounting)
	}
	if candidate := got.countries["ad"]; !slices.Equal(candidate.IPv4, []string{"1.0.0.0/8"}) || !slices.Equal(candidate.IPv6, []string{"2400::/12"}) {
		t.Fatalf("country ad = %+v", candidate)
	}
}

func TestReadArchiveAcceptsMissingEmptyFamily(t *testing.T) {
	members, _ := validSourceMembers(t, testCommit, 230)
	root := "country-ip-blocks-" + testCommit
	for index := range members {
		if members[index].name == root+"/country/ad/aggregated.json" {
			members[index].data = sourceJSON(t, "ad", []string{"1.0.0.0/8"}, []string{})
		}
	}
	members = slices.DeleteFunc(members, func(member testArchiveMember) bool {
		return member.name == root+"/country/ad/ipv6-aggregated.txt"
	})
	got, err := readArchive(gzipBytes(t, testTarArchive(members...)), testCommit)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.accounting.MissingIPv6, "ad") || len(got.countries["ad"].IPv6) != 0 {
		t.Fatalf("missing IPv6 accounting = %+v", got.accounting)
	}
}

func TestReadArchiveRejectsMissingNonEmptyFamilyAndPseudoCountry(t *testing.T) {
	root := "country-ip-blocks-" + testCommit
	members, _ := validSourceMembers(t, testCommit, 230)
	missing := slices.DeleteFunc(slices.Clone(members), func(member testArchiveMember) bool {
		return member.name == root+"/country/ad/ipv4-aggregated.txt"
	})
	if _, err := readArchive(gzipBytes(t, testTarArchive(missing...)), testCommit); err == nil || !strings.Contains(err.Error(), "plaintext is missing") {
		t.Fatalf("missing non-empty family error = %v", err)
	}

	pseudo := append(slices.Clone(members), testArchiveMember{name: root + "/country/eu/", typeFlag: '5'})
	if _, err := readArchive(gzipBytes(t, testTarArchive(pseudo...)), testCommit); err == nil || !strings.Contains(err.Error(), "unexpected archive directory") {
		t.Fatalf("pseudo-country error = %v", err)
	}
}

func TestReadArchiveRequiresCommitBoundGlobalPAXHeader(t *testing.T) {
	members, _ := validSourceMembers(t, testCommit, 230)
	members[0].data = []byte("52 comment=ffffffffffffffffffffffffffffffffffffffff\n")
	if _, err := readArchive(gzipBytes(t, testTarArchive(members...)), testCommit); err == nil || !strings.Contains(err.Error(), "PAX") {
		t.Fatalf("PAX error = %v", err)
	}
}

func TestRunIsDeterministicAndBindsInputs(t *testing.T) {
	compressed, license := validSourceArchive(t, testCommit, 230)
	directory := t.TempDir()
	archiveName := filepath.Join(directory, "source.tar.gz")
	if err := os.WriteFile(archiveName, compressed, 0600); err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(compressed)
	licenseDigest := sha256.Sum256(license)
	base := options{
		archive:       archiveName,
		archiveSHA256: hex.EncodeToString(archiveDigest[:]),
		archiveSize:   int64(len(compressed)),
		sourceURL:     "https://github.com/ipverse/country-ip-blocks/archive/" + testCommit + ".tar.gz",
		sourceCommit:  testCommit,
		sourceTime:    "2024-01-02T03:04:05Z",
		licenseSHA256: hex.EncodeToString(licenseDigest[:]),
	}
	first := base
	first.output = filepath.Join(directory, "first.json.gz")
	first.licenseOutput = filepath.Join(directory, "first-license.txt")
	second := base
	second.output = filepath.Join(directory, "second.json.gz")
	second.licenseOutput = filepath.Join(directory, "second-license.txt")
	if err := run(first); err != nil {
		t.Fatal(err)
	}
	if err := run(second); err != nil {
		t.Fatal(err)
	}
	firstData, err := os.ReadFile(first.output)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second.output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstData, secondData) {
		t.Fatal("snapshot output is not deterministic")
	}
	if got, err := os.ReadFile(first.licenseOutput); err != nil || !bytes.Equal(got, license) {
		t.Fatalf("license output mismatch: %v", err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(firstData))
	if err != nil {
		t.Fatal(err)
	}
	var decoded snapshot
	if err := json.NewDecoder(reader).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if decoded.Source.Commit != testCommit || decoded.Source.SHA256 != base.archiveSHA256 || !strings.HasPrefix(decoded.ID, "ipverse-20240102T030405Z-") {
		t.Fatalf("snapshot provenance = %+v, id=%s", decoded.Source, decoded.ID)
	}

	tampered := base
	tampered.output = filepath.Join(directory, "tampered.json.gz")
	tampered.licenseOutput = filepath.Join(directory, "tampered-license.txt")
	tampered.archiveSHA256 = strings.Repeat("0", 64)
	if err := run(tampered); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("tampered source error = %v", err)
	}
}

func validSourceArchive(t *testing.T, commit string, count int) ([]byte, []byte) {
	t.Helper()
	members, license := validSourceMembers(t, commit, count)
	return gzipBytes(t, testTarArchive(members...)), license
}

func validSourceMembers(t *testing.T, commit string, count int) ([]testArchiveMember, []byte) {
	t.Helper()
	root := "country-ip-blocks-" + commit
	license := []byte("CC0 synthetic test license\n")
	members := []testArchiveMember{
		{name: "pax_global_header", typeFlag: 'g', data: []byte("52 comment=" + commit + "\n")},
		{name: root + "/", typeFlag: '5'},
		{name: root + "/LICENSE", data: license},
		{name: root + "/country/", typeFlag: '5'},
	}
	codes := strings.Fields(iso3166Alpha2)
	if count < 0 || count > len(codes) {
		t.Fatalf("invalid synthetic country count %d", count)
	}
	for _, code := range codes[:count] {
		members = append(members,
			testArchiveMember{name: root + "/country/" + code + "/", typeFlag: '5'},
			testArchiveMember{name: root + "/country/" + code + "/aggregated.json", data: sourceJSON(t, code, []string{"1.0.0.0/8"}, []string{"2400::/12"})},
			testArchiveMember{name: root + "/country/" + code + "/ipv4-aggregated.txt", data: []byte("1.0.0.0/8\n")},
			testArchiveMember{name: root + "/country/" + code + "/ipv6-aggregated.txt", data: []byte("2400::/12\n")},
		)
	}
	return members, license
}

func sourceJSON(t *testing.T, code string, ipv4, ipv6 []string) []byte {
	t.Helper()
	candidate := sourceCountry{
		Country:          "Synthetic country",
		CountryCode:      strings.ToUpper(code),
		DelegationStatus: []string{"allocated", "assigned"},
		ExportMode:       "aggregated",
	}
	candidate.Prefixes.IPv4 = ipv4
	candidate.Prefixes.IPv6 = ipv6
	data, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type testArchiveMember struct {
	name     string
	typeFlag byte
	data     []byte
}

func testTarArchive(members ...testArchiveMember) []byte {
	const blockSize = 512
	var archive []byte
	for _, member := range members {
		header := make([]byte, blockSize)
		copy(header[0:100], member.name)
		copy(header[100:108], "0000644\x00")
		copy(header[108:116], "0000000\x00")
		copy(header[116:124], "0000000\x00")
		copy(header[124:136], fmt.Sprintf("%011o\x00", len(member.data)))
		copy(header[136:148], "00000000000\x00")
		for index := 148; index < 156; index++ {
			header[index] = ' '
		}
		header[156] = member.typeFlag
		copy(header[257:265], "ustar  \x00")
		var checksum int
		for _, value := range header {
			checksum += int(value)
		}
		copy(header[148:156], fmt.Sprintf("%06o\x00 ", checksum))
		archive = append(archive, header...)
		archive = append(archive, member.data...)
		if remainder := len(member.data) % blockSize; remainder != 0 {
			archive = append(archive, make([]byte, blockSize-remainder)...)
		}
	}
	return append(archive, make([]byte, 2*blockSize)...)
}

func gzipBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

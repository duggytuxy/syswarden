package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestParseNftGeoIPSetCountCountsCanonicalLogicalEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		spec nftGeoIPSetSpec
		elem string
		want int
	}{
		{
			name: "IPv4 address prefix and merged range",
			spec: nftGeoIPSetSpecs[0],
			elem: `[
				"8.8.8.8",
				{"prefix":{"addr":"1.1.1.0","len":24}},
				{"range":["9.9.9.1","9.9.9.254"]}
			]`,
			want: 3,
		},
		{
			name: "IPv6 prefix and range",
			spec: nftGeoIPSetSpecs[1],
			elem: `[
				{"prefix":{"addr":"2001:4860::","len":32}},
				{"range":["2606:4700::","2606:4700:ffff:ffff:ffff:ffff:ffff:ffff"]}
			]`,
			want: 2,
		},
		{
			name: "singleton expression permitted by libnftables schema",
			spec: nftGeoIPSetSpecs[0],
			elem: `"8.8.4.4"`,
			want: 1,
		},
		{
			name: "empty element array",
			spec: nftGeoIPSetSpecs[1],
			elem: `[]`,
			want: 0,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire := nftGeoIPSetFixture(test.spec, test.elem, true)
			got, err := parseNftGeoIPSetCount(wire, test.spec)
			if err != nil {
				t.Fatalf("parse valid nftables set fixture: %v", err)
			}
			if got != test.want {
				t.Fatalf("logical set count = %d, want %d", got, test.want)
			}
		})
	}
}

func TestParseNftGeoIPSetCountAcceptsEmptySetWithoutElem(t *testing.T) {
	t.Parallel()
	spec := nftGeoIPSetSpecs[0]
	wire := []byte(fmt.Sprintf(`{
		"nftables":[
			{"metainfo":{"version":"1.1.3","json_schema_version":1}},
			{"set":{"family":"inet","table":"syswarden","name":%q,"type":%q,"handle":17,"flags":["interval"]}}
		]
	}`, spec.name, spec.dataType))
	count, err := parseNftGeoIPSetCount(wire, spec)
	if err != nil {
		t.Fatalf("parse empty set fixture: %v", err)
	}
	if count != 0 {
		t.Fatalf("empty set count = %d, want 0", count)
	}
}

func TestParseNftGeoIPSetCountRejectsUntrustedOrAmbiguousJSON(t *testing.T) {
	t.Parallel()
	spec := nftGeoIPSetSpecs[0]
	valid := string(nftGeoIPSetFixture(spec, `["8.8.8.8"]`, true))
	tests := []struct {
		name string
		wire string
	}{
		{name: "malformed", wire: `{"nftables":[`},
		{name: "trailing JSON", wire: valid + `{}`},
		{name: "duplicate root key", wire: `{"nftables":[],"nftables":[]}`},
		{name: "missing object list", wire: `{}`},
		{name: "null object list", wire: `{"nftables":null}`},
		{name: "no requested set", wire: `{"nftables":[{"metainfo":{}}]}`},
		{name: "unexpected list object", wire: `{"nftables":[{"rule":{}}]}`},
		{name: "multiple set objects", wire: `{"nftables":[` +
			strings.TrimSuffix(strings.TrimPrefix(valid, `{"nftables":[`), `]}`) + `,` +
			`{"set":{"family":"inet","table":"syswarden","name":"syswarden_geoip","type":"ipv4_addr","flags":["interval"]}}]}`},
		{name: "wrong family", wire: strings.Replace(valid, `"family":"inet"`, `"family":"ip"`, 1)},
		{name: "wrong table", wire: strings.Replace(valid, `"table":"syswarden"`, `"table":"filter"`, 1)},
		{name: "wrong name", wire: strings.Replace(valid, `"name":"syswarden_geoip"`, `"name":"other"`, 1)},
		{name: "wrong type", wire: strings.Replace(valid, `"type":"ipv4_addr"`, `"type":"ipv6_addr"`, 1)},
		{name: "missing flags", wire: strings.Replace(valid, `"flags":["interval"],`, ``, 1)},
		{name: "wrong flags", wire: strings.Replace(valid, `["interval"]`, `["interval","timeout"]`, 1)},
		{name: "unknown set field", wire: strings.Replace(valid, `"handle":17`, `"handle":17,"foreign":true`, 1)},
		{name: "duplicate set field", wire: strings.Replace(valid, `"name":"syswarden_geoip"`, `"name":"syswarden_geoip","name":"other"`, 1)},
		{name: "negative handle", wire: strings.Replace(valid, `"handle":17`, `"handle":-1`, 1)},
		{name: "fractional size", wire: strings.Replace(valid, `"handle":17`, `"handle":17,"size":1.5`, 1)},
		{name: "null auto merge", wire: strings.Replace(valid, `"handle":17`, `"handle":17,"auto-merge":null`, 1)},
		{name: "null comment", wire: strings.Replace(valid, `"handle":17`, `"handle":17,"comment":null`, 1)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if count, err := parseNftGeoIPSetCount([]byte(test.wire), spec); err == nil {
				t.Fatalf("untrusted fixture accepted with count %d", count)
			}
		})
	}
}

func TestParseNftGeoIPSetCountRejectsMalformedElements(t *testing.T) {
	t.Parallel()
	spec := nftGeoIPSetSpecs[0]
	tests := []struct {
		name string
		elem string
	}{
		{name: "null", elem: `null`},
		{name: "number", elem: `42`},
		{name: "unknown expression", elem: `{"lookup":"8.8.8.8"}`},
		{name: "element metadata wrapper", elem: `{"elem":{"val":"8.8.8.8"}}`},
		{name: "wrong address family", elem: `"2001:4860::1"`},
		{name: "IPv4 mapped IPv6", elem: `"::ffff:8.8.8.8"`},
		{name: "noncanonical IPv6", elem: `"2001:0db8::1"`},
		{name: "prefix host bits", elem: `{"prefix":{"addr":"8.8.8.1","len":24}}`},
		{name: "prefix missing length", elem: `{"prefix":{"addr":"8.8.8.0"}}`},
		{name: "prefix extra field", elem: `{"prefix":{"addr":"8.8.8.0","len":24,"extra":true}}`},
		{name: "prefix length too large", elem: `{"prefix":{"addr":"8.8.8.0","len":33}}`},
		{name: "fractional prefix length", elem: `{"prefix":{"addr":"8.8.8.0","len":24.5}}`},
		{name: "reversed range", elem: `{"range":["9.9.9.9","9.9.9.1"]}`},
		{name: "short range", elem: `{"range":["9.9.9.1"]}`},
		{name: "overlap", elem: `[{"prefix":{"addr":"8.8.8.0","len":24}},"8.8.8.8"]`},
		{name: "duplicate", elem: `["8.8.8.8","8.8.8.8"]`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire := nftGeoIPSetFixture(spec, test.elem, true)
			if count, err := parseNftGeoIPSetCount(wire, spec); err == nil {
				t.Fatalf("malformed element accepted with count %d", count)
			}
		})
	}
}

func TestParseNftGeoIPSetCountRejectsOversizedWire(t *testing.T) {
	t.Parallel()
	wire := make([]byte, maxNftGeoIPSetJSONBytes+1)
	if count, err := parseNftGeoIPSetCount(wire, nftGeoIPSetSpecs[0]); err == nil {
		t.Fatalf("oversized output accepted with count %d", count)
	}
}

func TestBoundedCommandCaptureRetainsOnlyItsBound(t *testing.T) {
	t.Parallel()
	capture := newBoundedCommandCapture(5)
	if count, err := capture.Write([]byte("abc")); err != nil || count != 3 {
		t.Fatalf("first write = %d, %v", count, err)
	}
	if count, err := capture.Write([]byte("defgh")); err != nil || count != 5 {
		t.Fatalf("overflowing write = %d, %v", count, err)
	}
	if got := string(capture.bytes()); got != "abcde" {
		t.Fatalf("bounded output = %q, want abcde", got)
	}
	if !capture.exceeded {
		t.Fatal("overflow was not recorded")
	}
}

type fixtureNftGeoIPSetJSONSource struct {
	outputs map[string][]byte
	errors  map[string]error
	calls   []nftGeoIPSetSpec
}

func (source *fixtureNftGeoIPSetJSONSource) listGeoIPSet(_ context.Context, spec nftGeoIPSetSpec) ([]byte, error) {
	source.calls = append(source.calls, spec)
	if err := source.errors[spec.name]; err != nil {
		return nil, err
	}
	return append([]byte(nil), source.outputs[spec.name]...), nil
}

func TestCountLiveNftGeoIPEntriesUsesOnlyAllowlistedActiveSets(t *testing.T) {
	source := &fixtureNftGeoIPSetJSONSource{
		outputs: map[string][]byte{
			"syswarden_geoip": nftGeoIPSetFixture(nftGeoIPSetSpecs[0], `[
				{"prefix":{"addr":"8.8.8.0","len":24}},
				"9.9.9.9"
			]`, true),
			"syswarden_geoip6": nftGeoIPSetFixture(nftGeoIPSetSpecs[1], `"2001:4860::1"`, true),
		},
		errors: make(map[string]error),
	}
	if got := countLiveNftGeoIPEntries(source); got != 3 {
		t.Fatalf("live GeoIP count = %d, want 3", got)
	}
	if !reflect.DeepEqual(source.calls, nftGeoIPSetSpecs[:]) {
		t.Fatalf("queried set identities = %#v, want %#v", source.calls, nftGeoIPSetSpecs)
	}
}

func TestCountLiveNftGeoIPEntriesDegradesIncompleteAggregateToZero(t *testing.T) {
	tests := []struct {
		name    string
		outputs map[string][]byte
		errors  map[string]error
		want    int
	}{
		{
			name: "IPv6 unavailable invalidates aggregate",
			outputs: map[string][]byte{
				"syswarden_geoip": nftGeoIPSetFixture(nftGeoIPSetSpecs[0], `"8.8.8.8"`, true),
			},
			errors: map[string]error{"syswarden_geoip6": errors.New("set unavailable")},
			want:   0,
		},
		{
			name: "IPv4 malformed invalidates aggregate",
			outputs: map[string][]byte{
				"syswarden_geoip":  []byte(`{"nftables":[`),
				"syswarden_geoip6": nftGeoIPSetFixture(nftGeoIPSetSpecs[1], `"2001:4860::1"`, true),
			},
			errors: make(map[string]error),
			want:   0,
		},
		{
			name:    "both unavailable",
			outputs: make(map[string][]byte),
			errors: map[string]error{
				"syswarden_geoip":  errors.New("nft unavailable"),
				"syswarden_geoip6": errors.New("nft unavailable"),
			},
			want: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &fixtureNftGeoIPSetJSONSource{outputs: test.outputs, errors: test.errors}
			if got := countLiveNftGeoIPEntries(source); got != test.want {
				t.Fatalf("live GeoIP count = %d, want %d", got, test.want)
			}
		})
	}
	if got := countLiveNftGeoIPEntries(nil); got != 0 {
		t.Fatalf("nil source count = %d, want 0", got)
	}
}

func TestLayer3TelemetryIgnoresRetainedLegacyCountryFiles(t *testing.T) {
	directory := t.TempDir()
	writeTelemetryLines(t, filepath.Join(directory, "syswarden_blacklist.ipv4"), 2)
	writeTelemetryLines(t, filepath.Join(directory, "syswarden_blacklist.ipv6"), 1)
	writeTelemetryLines(t, filepath.Join(directory, "syswarden_threatintel.ipv4"), 4)
	writeTelemetryLines(t, filepath.Join(directory, "AS64500.ipv4"), 5)
	writeTelemetryLines(t, filepath.Join(directory, "ru.ipv4"), 97)
	writeTelemetryLines(t, filepath.Join(directory, "cn.ipv6"), 89)

	stats := collectLayer3Stats(directory, func() int { return 7 })
	if stats.L7Banned != 3 || stats.GlobalBlocked != 7 || stats.ASNBlocked != 5 {
		t.Fatalf("retained Layer 3 counters changed: %#v", stats)
	}
	if stats.GeoIPBlocked != 7 {
		t.Fatalf("GeoIP count = %d, want live kernel count 7", stats.GeoIPBlocked)
	}
	stats = collectLayer3Stats(directory, nil)
	if stats.GeoIPBlocked != 0 {
		t.Fatalf("unavailable live GeoIP telemetry counted legacy files: %d", stats.GeoIPBlocked)
	}
}

func TestCommandNftGeoIPSourceRejectsNonAllowlistedIdentityBeforeExecution(t *testing.T) {
	t.Parallel()
	source := commandNftGeoIPSetJSONSource{executable: os.Args[0]}
	_, err := source.listGeoIPSet(context.Background(), nftGeoIPSetSpec{name: "foreign", dataType: "ipv4_addr"})
	if err == nil {
		t.Fatal("non-allowlisted nftables set identity reached command execution")
	}
}

func TestCommandNftGeoIPSourcePinsCanonicalTrustedExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pinned executable descriptors require Linux procfs")
	}
	root := newNftGeoIPTrustedRoot(t)
	executable := writeNftGeoIPExecutable(t, root, "bin/nft.real", `#!/bin/sh
printf '%s' '{"nftables":[]}'
`)
	alias := filepath.Join(root, "bin", "nft")
	if err := os.Symlink("nft.real", alias); err != nil {
		t.Fatalf("create nftables executable alias: %v", err)
	}

	source, err := newCommandNftGeoIPSetJSONSourceForCandidate(alias, nftGeoIPTestAttestor(root))
	if err != nil {
		t.Fatalf("pin trusted nftables executable: %v", err)
	}
	if source.executable != executable {
		t.Fatalf("canonical executable = %q, want %q", source.executable, executable)
	}
	if source.identity.uid != uint32(os.Geteuid()) || source.identity.size <= 0 || source.identity.inode == 0 {
		t.Fatalf("incomplete executable identity: %#v", source.identity)
	}
	if source.identity.mode.Perm() != 0755 {
		t.Fatalf("attested executable mode = %o, want 755", source.identity.mode.Perm())
	}
}

func TestCommandNftGeoIPSourceExecutesOnlyPinnedIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pinned executable descriptors require Linux procfs")
	}
	root := newNftGeoIPTrustedRoot(t)
	executable := writeNftGeoIPExecutable(t, root, "bin/nft", `#!/bin/sh
if [ "$#" -ne 7 ] || [ "$1" != "--json" ] || [ "$2" != "--numeric" ] ||
   [ "$3" != "list" ] || [ "$4" != "set" ] || [ "$5" != "inet" ] ||
   [ "$6" != "syswarden" ] || [ "$7" != "syswarden_geoip" ]; then
  exit 41
fi
printf '%s' '{"nftables":[]}'
`)
	source, err := newCommandNftGeoIPSetJSONSourceForCandidate(executable, nftGeoIPTestAttestor(root))
	if err != nil {
		t.Fatalf("pin trusted nftables executable: %v", err)
	}

	wire, err := source.listGeoIPSet(context.Background(), nftGeoIPSetSpecs[0])
	if err != nil {
		t.Fatalf("execute pinned nftables identity: %v", err)
	}
	if got, want := string(wire), `{"nftables":[]}`; got != want {
		t.Fatalf("nftables output = %q, want %q", got, want)
	}
}

func TestCommandNftGeoIPSourceRejectsUnsafeExecutableIdentity(t *testing.T) {
	tests := []struct {
		name        string
		mode        os.FileMode
		expectedUID uint32
	}{
		{name: "not executable", mode: 0644, expectedUID: uint32(os.Geteuid())},
		{name: "group writable", mode: 0775, expectedUID: uint32(os.Geteuid())},
		{name: "other writable", mode: 0757, expectedUID: uint32(os.Geteuid())},
		{name: "wrong owner", mode: 0755, expectedUID: uint32(os.Geteuid()) + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := newNftGeoIPTrustedRoot(t)
			executable := writeNftGeoIPExecutable(t, root, "bin/nft", "#!/bin/sh\nexit 0\n")
			if err := os.Chmod(executable, test.mode); err != nil {
				t.Fatalf("set unsafe executable mode: %v", err)
			}
			attestor := nftGeoIPTestAttestor(root)
			attestor.expectedUID = test.expectedUID
			if _, err := newCommandNftGeoIPSetJSONSourceForCandidate(executable, attestor); err == nil {
				t.Fatal("unsafe nftables executable identity was accepted")
			}
		})
	}
}

func TestCommandNftGeoIPSourceRejectsUnsafeParent(t *testing.T) {
	root := newNftGeoIPTrustedRoot(t)
	executable := writeNftGeoIPExecutable(t, root, "bin/nft", "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Dir(executable), 0775); err != nil {
		t.Fatalf("make executable parent group writable: %v", err)
	}
	if _, err := newCommandNftGeoIPSetJSONSourceForCandidate(executable, nftGeoIPTestAttestor(root)); err == nil {
		t.Fatal("nftables executable below an unsafe parent was accepted")
	}
}

func TestCommandNftGeoIPSourceReattestsIdentityImmediatelyBeforeExecution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pinned executable descriptors require Linux procfs")
	}
	root := newNftGeoIPTrustedRoot(t)
	executable := writeNftGeoIPExecutable(t, root, "bin/nft", `#!/bin/sh
printf '%s' '{"nftables":[]}'
`)
	source, err := newCommandNftGeoIPSetJSONSourceForCandidate(executable, nftGeoIPTestAttestor(root))
	if err != nil {
		t.Fatalf("pin trusted nftables executable: %v", err)
	}

	replacement := writeNftGeoIPExecutable(t, root, "bin/nft.replacement", `#!/bin/sh
printf '%s' '{"foreign":true}'
`)
	if err := os.Rename(replacement, executable); err != nil {
		t.Fatalf("replace nftables executable after attestation: %v", err)
	}
	if _, err := source.listGeoIPSet(context.Background(), nftGeoIPSetSpecs[0]); err == nil ||
		!strings.Contains(err.Error(), "changed identity before start") {
		t.Fatalf("replaced nftables executable was not rejected before start: %v", err)
	}
}

func TestCommandNftGeoIPSourceReattestsParentsImmediatelyBeforeExecution(t *testing.T) {
	root := newNftGeoIPTrustedRoot(t)
	executable := writeNftGeoIPExecutable(t, root, "bin/nft", "#!/bin/sh\nexit 0\n")
	source, err := newCommandNftGeoIPSetJSONSourceForCandidate(executable, nftGeoIPTestAttestor(root))
	if err != nil {
		t.Fatalf("pin trusted nftables executable: %v", err)
	}
	if err := os.Chmod(filepath.Dir(executable), 0775); err != nil {
		t.Fatalf("make executable parent group writable: %v", err)
	}
	if _, err := source.listGeoIPSet(context.Background(), nftGeoIPSetSpecs[0]); err == nil ||
		!strings.Contains(err.Error(), "immediately before start") {
		t.Fatalf("unsafe executable parent was not rejected before start: %v", err)
	}
}

func newNftGeoIPTrustedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatalf("secure trusted root: %v", err)
	}
	return root
}

func nftGeoIPTestAttestor(root string) nftGeoIPExecutableAttestor {
	return nftGeoIPExecutableAttestor{
		expectedUID: uint32(os.Geteuid()),
		trustedRoot: root,
	}
}

func writeNftGeoIPExecutable(t *testing.T, root, relative, content string) string {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create nftables executable parent: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("secure nftables executable parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write nftables executable: %v", err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatalf("secure nftables executable: %v", err)
	}
	return path
}

func nftGeoIPSetFixture(spec nftGeoIPSetSpec, elem string, includeMetainfo bool) []byte {
	objects := ""
	if includeMetainfo {
		objects = `{"metainfo":{"version":"1.1.3","release_name":"Commodore Bullmoose #4","json_schema_version":1}},`
	}
	return []byte(fmt.Sprintf(`{"nftables":[%s{"set":{
		"family":"inet",
		"table":"syswarden",
		"name":%q,
		"type":%q,
		"handle":17,
		"policy":"performance",
		"flags":["interval"],
		"auto-merge":true,
		"elem":%s
	}}]}`, objects, spec.name, spec.dataType, elem))
}

func writeTelemetryLines(t *testing.T, path string, count int) {
	t.Helper()
	lines := make([]string, count)
	for index := range lines {
		lines[index] = fmt.Sprintf("entry-%d", index)
	}
	content := strings.Join(lines, "\n")
	if count > 0 {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNftGeoIPFixtureHelperProducesValidJSON(t *testing.T) {
	t.Parallel()
	wire := nftGeoIPSetFixture(nftGeoIPSetSpecs[0], `[]`, true)
	if !json.Valid(wire) {
		t.Fatalf("test helper produced invalid JSON: %s", wire)
	}
}

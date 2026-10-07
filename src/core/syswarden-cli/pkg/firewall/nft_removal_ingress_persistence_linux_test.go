//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type nftIngressPersistenceFixture struct {
	nftNetdevTemplateFixture
	Serialized  string
	Populations map[string][]string
}

func fixtureNFTIngressPersistence(t *testing.T) []nftIngressPersistenceFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/netdev_persistence.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Cases []nftIngressPersistenceFixture
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Cases) != 16 {
		t.Fatal("incomplete ingress persistence fixture coverage")
	}
	for index := range document.Cases {
		document.Cases[index].Serialized = strings.TrimSuffix(document.Cases[index].Serialized, "\n")
	}
	return document.Cases
}

func TestNFTIngressPersistenceIndependentFixtures(t *testing.T) {
	for index, fixture := range fixtureNFTIngressPersistence(t) {
		t.Run(fmt.Sprintf("case-%02d", index), func(t *testing.T) {
			before := bytes.Clone(fixture.JSON)
			evidence, err := inspectNFTHistoricalIngressPersistence([]byte(fixture.Serialized), fixture.JSON, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.profile != "shell-pre-v2-netdev" || !validLegacyRetirementDigest(evidence.populationSHA256) || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.topologySHA256) {
				t.Fatal("incomplete persistence and population binding")
			}
			if !bytes.Equal(before, fixture.JSON) {
				t.Fatal("original kernel evidence changed")
			}
		})
	}
}

func TestNFTIngressPersistenceRefusesPopulationAndSourceDrift(t *testing.T) {
	fixture := fixtureNFTIngressPersistence(t)[15]
	mutations := []string{
		fixture.Serialized + "\ninclude \"/etc/operator.nft\"",
		fixture.Serialized + "\ntable inet custom {}",
		strings.Replace(fixture.Serialized, "192.0.2.0/24", "192.0.2.0/25", 1),
		strings.Replace(fixture.Serialized, "198.51.100.3-198.51.100.5", "198.51.100.3-198.51.100.6", 1),
		strings.Replace(fixture.Serialized, "2001:db8::/120", "2001:db8::/119", 1),
		strings.Replace(fixture.Serialized, "elements = { 203.0.113.1, 203.0.113.3 }", "elements = { 203.0.113.1 comment \"custom\", 203.0.113.3 }", 1),
		strings.Replace(fixture.Serialized, "auto-merge", "auto-merge\n\t\tcomment \"administrator\"", 1),
		strings.Replace(fixture.Serialized, "policy accept", "policy drop", 1),
		strings.Replace(fixture.Serialized, "packets 0 bytes 0", "packets -1 bytes 0", 1),
		strings.Replace(fixture.Serialized, "counter packets 0 bytes 0", "counter name custom", 1),
		strings.Replace(fixture.Serialized, "packets 0 bytes 0", "packets 18446744073709551616 bytes 0", 1),
		strings.Replace(fixture.Serialized, "\tchain ingress_frontline {", "\tchain custom { ip saddr 203.0.113.1 drop; }\n\tchain ingress_frontline {", 1),
	}
	for index, changed := range mutations {
		if changed == fixture.Serialized {
			t.Fatal("mutation did not change source", index)
		}
		if _, err := inspectNFTHistoricalIngressPersistence([]byte(changed), fixture.JSON, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations); err == nil {
			t.Fatal("changed persistence accepted", index)
		}
	}
	for _, kind := range []string{"missing", "extra", "changed", "unmasked", "wrong-family", "metadata", "oversized"} {
		claims := make(map[string][]string)
		for name, entries := range fixture.Populations {
			claims[name] = append([]string{}, entries...)
		}
		switch kind {
		case "missing":
			delete(claims, "syswarden_whitelist")
		case "extra":
			claims["custom"] = []string{}
		case "changed":
			claims["syswarden_blacklist"] = append(claims["syswarden_blacklist"], "203.0.113.99")
		case "unmasked":
			claims["syswarden_blacklist"] = []string{"192.0.2.1/24"}
		case "wrong-family":
			claims["syswarden_whitelist6"] = []string{"192.0.2.1"}
		case "metadata":
			claims["syswarden_whitelist"] = []string{"203.0.113.1 timeout 1s"}
		case "oversized":
			claims["syswarden_whitelist"] = make([]string, maximumNFTRetirementPopulationEntries+1)
		}
		if _, err := inspectNFTHistoricalIngressPersistence([]byte(fixture.Serialized), fixture.JSON, fixture.Interfaces[0], fixture.Geo, fixture.ASN, claims); err == nil {
			t.Fatal("unbound population claims accepted", kind)
		}
	}
}

func TestNFTIngressPersistenceRefusesKernelDrift(t *testing.T) {
	fixture := fixtureNFTIngressPersistence(t)[15]
	for _, kind := range []string{"missing-element", "extra-element", "element-metadata", "wrong-family", "set-comment", "set-type", "duplicate-set", "extra-rule"} {
		t.Run(kind, func(t *testing.T) {
			document, err := decodeLegacyFail2banNFTJSON(fixture.JSON)
			if err != nil {
				t.Fatal(err)
			}
			objects := document["nftables"].([]any)
			changed := false
			if kind == "extra-rule" {
				document["nftables"] = append(objects, map[string]any{"rule": map[string]any{"family": "netdev", "table": "syswarden_hw_drop", "chain": "ingress_frontline", "handle": json.Number("99999"), "expr": []any{map[string]any{"drop": nil}}}})
				changed = true
			}
			for _, entry := range objects {
				if changed {
					break
				}
				object, ok := entry.(map[string]any)["set"].(map[string]any)
				if !ok || object["name"] != "syswarden_blacklist" {
					continue
				}
				elements := object["elem"].([]any)
				switch kind {
				case "missing-element":
					object["elem"] = elements[:1]
				case "extra-element":
					object["elem"] = append(elements, "203.0.113.99")
				case "element-metadata":
					object["elem"] = []any{map[string]any{"elem": map[string]any{"val": "192.0.2.1", "comment": "administrator"}}}
				case "wrong-family":
					object["elem"] = []any{"2001:db8::1"}
				case "set-comment":
					object["comment"] = "administrator"
				case "set-type":
					object["type"] = "ipv6_addr"
				case "duplicate-set":
					document["nftables"] = append(objects, map[string]any{"set": object})
				}
				changed = true
			}
			if !changed {
				t.Fatal("kernel fixture not changed")
			}
			wire, _ := json.Marshal(document)
			if _, err := inspectNFTHistoricalIngressPersistence([]byte(fixture.Serialized), wire, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations); err == nil {
				t.Fatal("changed live population or topology accepted")
			}
		})
	}
	// A consistent source/live edit must still fail against independently
	// supplied populations. Two agreeing observations are not ownership proof.
	changedSource := strings.Replace(fixture.Serialized, "198.51.100.3-198.51.100.5", "198.51.100.3-198.51.100.6", 1)
	changedLive := bytes.Replace(fixture.JSON, []byte(`"198.51.100.5"`), []byte(`"198.51.100.6"`), 1)
	if bytes.Equal(changedLive, fixture.JSON) {
		t.Fatal("coupled mutation did not change runtime")
	}
	if _, err := inspectNFTHistoricalIngressPersistence([]byte(changedSource), changedLive, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations); err == nil {
		t.Fatal("two agreeing modified observations bypassed independent claims")
	}
}

func TestNFTIngressPersistenceCounterAndPopulationEquivalence(t *testing.T) {
	fixture := fixtureNFTIngressPersistence(t)[15]
	before, err := inspectNFTHistoricalIngressPersistence([]byte(fixture.Serialized), fixture.JSON, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.ReplaceAll(fixture.Serialized, "packets 0 bytes 0", "packets 123 bytes 7890")
	changed = strings.Replace(changed, "203.0.113.1, 203.0.113.3", "203.0.113.3, 203.0.113.1", 1)
	after, err := inspectNFTHistoricalIngressPersistence([]byte(changed), fixture.JSON, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations)
	if err != nil || before.populationSHA256 != after.populationSHA256 || before.topologySHA256 != after.topologySHA256 || before.sourceSHA256 == after.sourceSHA256 {
		t.Fatal("counter progress or equivalent set order lost the original byte binding", err)
	}
	if _, err := normalizeNFTRetirementCounterText(strings.Repeat("x", 32769)); err == nil {
		t.Fatal("unbounded counter text accepted")
	}
}

func TestNFTIngressPersistenceLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_INGRESS_PERSISTENCE_LIVE") != "1" {
		t.Skip("requires a disposable populated persistence namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	nft := func(input []byte, args ...string) []byte {
		command := exec.CommandContext(ctx, "/usr/bin/nft", args...) // #nosec G204 -- Fixed fixture binary and synthetic arguments in a verified disposable network namespace.
		command.Stdin = bytes.NewReader(input)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture nft failed: %v: %s", err, output)
		}
		return output
	}
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	if output, err := exec.CommandContext(ctx, "/usr/bin/ip", "link", "add", "swv0", "type", "veth", "peer", "name", "swv1").CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	fixtures := fixtureNFTIngressPersistence(t)
	for _, fixture := range fixtures {
		nft([]byte(fixture.Serialized+"\n"), "-f", "-")
		live := nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")
		if _, err := inspectNFTHistoricalIngressPersistence([]byte(fixture.Serialized), live, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(live, nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")) {
			t.Fatal("inspection changed fixture population")
		}
		nft(nil, "delete", "table", "netdev", "syswarden_hw_drop")
	}
	t.Log("All sixteen historical empty and populated persistent tables reload with exact topology and interval-union population equality.")
	fixture := fixtures[15]
	nft([]byte(fixture.Serialized+"\n"), "-f", "-")
	nft(nil, "add", "element", "netdev", "syswarden_hw_drop", "syswarden_blacklist", "{ 203.0.113.99 }")
	before := nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")
	for _, source := range [][]byte{[]byte(fixture.Serialized), bytes.TrimSuffix(nft(nil, "list", "table", "netdev", "syswarden_hw_drop"), []byte("\n"))} {
		if _, err := inspectNFTHistoricalIngressPersistence(source, before, fixture.Interfaces[0], fixture.Geo, fixture.ASN, fixture.Populations); err == nil {
			t.Fatal("administrator addition was adopted")
		}
	}
	if !bytes.Equal(before, nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")) {
		t.Fatal("administrator population changed")
	}
	t.Log("An additional administrator address remains intact and is refused even when persistent and live observations both contain it.")
}

func FuzzNFTIngressPersistencePopulationEntry(f *testing.F) {
	for _, seed := range []string{"192.0.2.1", "192.0.2.0/24", "198.51.100.3-198.51.100.5", "2001:db8::/120", "2001:db8::1-2001:db8::3", "192.0.2.1; accept", "::ffff:192.0.2.1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1024 {
			t.Skip()
		}
		for _, kind := range []string{"addr4", "addr6"} {
			intervals, err := nftRetirementPopulationEntry(value, kind)
			if err == nil {
				if len(intervals) != 1 || intervals[0].first == nil || intervals[0].last == nil || intervals[0].first.Sign() < 0 || intervals[0].first.Cmp(intervals[0].last) > 0 {
					t.Fatal("invalid accepted population entry")
				}
			}
		}
	})
}

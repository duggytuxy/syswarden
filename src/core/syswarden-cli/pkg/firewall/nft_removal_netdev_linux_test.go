//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

type nftNetdevTemplateFixture struct {
	Profile    string
	Geo, ASN   bool
	Interfaces []string
	Source     string
	JSON       json.RawMessage
}

func fixtureNFTNetdevTemplates(t *testing.T) []nftNetdevTemplateFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/netdev_templates.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct{ Cases []nftNetdevTemplateFixture }
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Cases) != 24 {
		t.Fatal("incomplete independent kernel fixture coverage")
	}
	for index := range document.Cases {
		document.Cases[index].Source = strings.TrimRight(document.Cases[index].Source, "\n")
	}
	return document.Cases
}

func TestNFTNetdevTemplateIndependentKernelFixtures(t *testing.T) {
	for _, fixture := range fixtureNFTNetdevTemplates(t) {
		t.Run(fmt.Sprintf("%s/geo=%t/asn=%t/devices=%d", fixture.Profile, fixture.Geo, fixture.ASN, len(fixture.Interfaces)), func(t *testing.T) {
			original := bytes.Clone(fixture.JSON)
			evidence, err := inspectNFTNetdevTemplateTopology([]byte(fixture.Source), fixture.JSON)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.profile != fixture.Profile || evidence.geo != fixture.Geo || evidence.asn != fixture.ASN || !reflect.DeepEqual(evidence.interfaces, fixture.Interfaces) || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.topologySHA256) {
				t.Fatal("template lost its complete source/topology binding", evidence)
			}
			if !bytes.Equal(original, fixture.JSON) {
				t.Fatal("inspection modified its original evidence")
			}
		})
	}
}

func TestNFTNetdevTemplatePreservesUnknownObjectsAndRules(t *testing.T) {
	fixture := fixtureNFTNetdevTemplates(t)[15]
	object := func(entries []any, kind string) map[string]any {
		for _, entry := range entries {
			if value, ok := entry.(map[string]any)[kind].(map[string]any); ok {
				return value
			}
		}
		t.Fatal("missing fixture object", kind)
		return nil
	}
	type mutation func(map[string]any, []any)
	cases := map[string]mutation{
		"table comment":  func(_ map[string]any, e []any) { object(e, "table")["comment"] = "administrator table" },
		"table flags":    func(_ map[string]any, e []any) { object(e, "table")["flags"] = []any{"dormant"} },
		"chain policy":   func(_ map[string]any, e []any) { object(e, "chain")["policy"] = "drop" },
		"chain priority": func(_ map[string]any, e []any) { object(e, "chain")["prio"] = json.Number("-499") },
		"chain comment":  func(_ map[string]any, e []any) { object(e, "chain")["comment"] = "keep this protection" },
		"extra rule": func(d map[string]any, e []any) {
			d["nftables"] = append(e, map[string]any{"rule": map[string]any{"family": "netdev", "table": "syswarden_hw_drop", "chain": "ingress_frontline", "handle": json.Number("9999"), "expr": []any{map[string]any{"drop": nil}}}})
		},
		"missing rule": func(d map[string]any, e []any) { d["nftables"] = e[:len(e)-1] },
		"rule order":   func(_ map[string]any, e []any) { e[len(e)-1], e[len(e)-2] = e[len(e)-2], e[len(e)-1] },
		"rule comment": func(_ map[string]any, e []any) { object(e, "rule")["comment"] = "SYSWARDEN custom policy" },
		"rule verdict": func(_ map[string]any, e []any) {
			rule := object(e, "rule")
			expressions := rule["expr"].([]any)
			expressions[len(expressions)-1] = map[string]any{"drop": nil}
		},
		"set type":                       func(_ map[string]any, e []any) { object(e, "set")["type"] = "ipv6_addr" },
		"set metadata":                   func(_ map[string]any, e []any) { object(e, "set")["comment"] = "administrator set" },
		"unattested populated set":       func(_ map[string]any, e []any) { object(e, "set")["elem"] = []any{"192.0.2.1"} },
		"empty but unrequested elements": func(_ map[string]any, e []any) { object(e, "set")["elem"] = []any{} },
		"foreign object": func(d map[string]any, e []any) {
			d["nftables"] = append(e, map[string]any{"counter": map[string]any{"name": "custom"}})
		},
		"duplicate object handle": func(_ map[string]any, e []any) { object(e, "rule")["handle"] = object(e, "set")["handle"] },
		"duplicate interface":     func(_ map[string]any, e []any) { object(e, "chain")["dev"] = []any{"swv0", "swv0"} },
		"unrecognized interface":  func(_ map[string]any, e []any) { object(e, "chain")["dev"] = []any{"swv0", "other0"} },
		"ambiguous wrapper":       func(_ map[string]any, e []any) { e[1].(map[string]any)["extra"] = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			document, err := decodeLegacyFail2banNFTJSON(fixture.JSON)
			if err != nil {
				t.Fatal(err)
			}
			mutate(document, document["nftables"].([]any))
			wire, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inspectNFTNetdevTemplateTopology([]byte(fixture.Source), wire); err == nil {
				t.Fatal("modified topology was adopted")
			}
		})
	}
}

func TestNFTNetdevTemplateSetInventoryOrderDoesNotChangeTopology(t *testing.T) {
	for _, fixture := range fixtureNFTNetdevTemplates(t) {
		document, err := decodeLegacyFail2banNFTJSON(fixture.JSON)
		if err != nil {
			t.Fatal(err)
		}
		var sets, other []any
		for _, entry := range document["nftables"].([]any) {
			if _, ok := entry.(map[string]any)["set"]; ok {
				sets = append(sets, entry)
			} else {
				other = append(other, entry)
			}
		}
		for left, right := 0, len(sets)-1; left < right; left, right = left+1, right-1 {
			sets[left], sets[right] = sets[right], sets[left]
		}
		// Move declarations across the chain and rule inventory as well as
		// reversing them. References and rule evaluation order stay exact.
		document["nftables"] = append(other, sets...)
		wire, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		before, err := inspectNFTNetdevTemplateTopology([]byte(fixture.Source), fixture.JSON)
		if err != nil {
			t.Fatal(err)
		}
		after, err := inspectNFTNetdevTemplateTopology([]byte(fixture.Source), wire)
		if err != nil || before.topologySHA256 != after.topologySHA256 {
			t.Fatalf("set inventory order changed exact topology for %s: %v", fixture.Profile, err)
		}
		duplicate := make(map[string]any)
		for key, value := range sets[0].(map[string]any)["set"].(map[string]any) {
			duplicate[key] = value
		}
		duplicate["handle"] = json.Number("99999")
		document["nftables"] = append(document["nftables"].([]any), map[string]any{"set": duplicate})
		wire, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inspectNFTNetdevTemplateTopology([]byte(fixture.Source), wire); err == nil {
			t.Fatal("duplicate set was accepted")
		}
	}
}

func TestNFTNetdevTemplateSourceRejectsPartialProfiles(t *testing.T) {
	fixture := fixtureNFTNetdevTemplates(t)[15]
	cases := []string{
		fixture.Source + "\n", "# SysWarden\n" + fixture.Source,
		strings.Replace(fixture.Source, "priority -500", "priority -499", 1),
		strings.Replace(fixture.Source, "policy accept", "policy drop", 1),
		strings.Replace(fixture.Source, "ip saddr @syswarden_blacklist drop", "ip saddr @syswarden_blacklist accept", 1),
		strings.Replace(fixture.Source, "flags interval,timeout", "flags timeout", 1),
		strings.Replace(fixture.Source, `"swv0", "swv1"`, `"swv0", "swv0"`, 1),
		strings.Replace(fixture.Source, `"swv0", "swv1"`, `"swv0"`, 1),
		strings.Replace(fixture.Source, "\t}\n}", "\t\tip saddr 203.0.113.1 drop\n\t}\n}", 1),
		strings.ReplaceAll(fixture.Source, "\n", "\r\n"),
	}
	for _, source := range cases {
		if _, err := inspectNFTNetdevTemplateTopology([]byte(source), fixture.JSON); err == nil {
			t.Fatal("partial or customized source profile was accepted")
		}
	}
	document, err := decodeLegacyFail2banNFTJSON(fixture.JSON)
	if err != nil {
		t.Fatal(err)
	}
	entries := document["nftables"].([]any)
	for _, entry := range entries {
		wrapper := entry.(map[string]any)
		if chain, ok := wrapper["chain"].(map[string]any); ok {
			chain["dev"] = []any{"swv1", "swv0"}
		}
		if rule, ok := wrapper["rule"].(map[string]any); ok {
			for _, expression := range rule["expr"].([]any) {
				if counter, ok := expression.(map[string]any)["counter"].(map[string]any); ok {
					counter["bytes"] = json.Number("100000")
					counter["packets"] = json.Number("500")
				}
			}
		}
	}
	changed, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	before, err := inspectNFTNetdevTemplateTopology([]byte(fixture.Source), fixture.JSON)
	if err != nil {
		t.Fatal(err)
	}
	after, err := inspectNFTNetdevTemplateTopology([]byte(fixture.Source), changed)
	if err != nil || after.topologySHA256 != before.topologySHA256 {
		t.Fatal("device-set order or counter progress changed effective topology", err)
	}
}

// This fixture deliberately demonstrates the limit of terse observations:
// matching topology says nothing about who supplied the set populations.
func TestNFTNetdevTemplateLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_NETDEV_TEMPLATE_LIVE") != "1" {
		t.Skip("requires a disposable ingress template namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nft := func(input []byte, args ...string) []byte {
		command := exec.CommandContext(ctx, "/usr/bin/nft", args...) // #nosec G204 -- Fixed fixture binary and synthetic arguments in a verified disposable network namespace.
		command.Stdin = bytes.NewReader(input)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture nft command failed: %v: %s", err, output)
		}
		return output
	}
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	if output, err := exec.CommandContext(ctx, "/usr/bin/ip", "link", "add", "swv0", "type", "veth", "peer", "name", "swv1").CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	fixtures := fixtureNFTNetdevTemplates(t)
	for _, fixture := range fixtures {
		source := []byte(fixture.Source)
		nft(append(bytes.Clone(source), '\n'), "-f", "-")
		if _, err := inspectNFTNetdevTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "netdev", "syswarden_hw_drop")); err != nil {
			t.Fatal(fixture.Profile, err)
		}
		nft(nil, "delete", "table", "netdev", "syswarden_hw_drop")
	}
	t.Log("All twenty-four independently generated ingress variants match their actual kernel topology.")
	fixture := fixtures[len(fixtures)-1]
	source := []byte(fixture.Source)
	nft(append(bytes.Clone(source), '\n'), "-f", "-")
	nft(nil, "add", "element", "netdev", "syswarden_hw_drop", "syswarden_blacklist", "{ 192.0.2.0/24 }")
	full := nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")
	if _, err := inspectNFTNetdevTemplateTopology(source, full); err == nil {
		t.Fatal("populated observation was incorrectly treated as complete ownership evidence")
	}
	if _, err := inspectNFTNetdevTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "netdev", "syswarden_hw_drop")); err != nil {
		t.Fatal("terse topology recognition failed", err)
	}
	if !bytes.Equal(full, nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop")) {
		t.Fatal("read-only topology inspection changed set contents")
	}
	nft(nil, "add", "rule", "netdev", "syswarden_hw_drop", "ingress_frontline", "ip", "saddr", "203.0.113.1", "drop")
	before := nft(nil, "-j", "list", "ruleset")
	if _, err := inspectNFTNetdevTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "netdev", "syswarden_hw_drop")); err == nil {
		t.Fatal("administrator rule was adopted into the official template")
	}
	if !bytes.Equal(before, nft(nil, "-j", "list", "ruleset")) {
		t.Fatal("administrator rule or set content changed")
	}
	t.Log("Unattested populations remain separate; administrator rule addition is refused and the full ruleset remains unchanged.")
}

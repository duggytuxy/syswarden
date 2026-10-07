//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type nftARPTemplateFixture struct {
	Case      string
	Addresses []string
	Source    string
	JSON      json.RawMessage
}

func fixtureNFTARPTemplates(t *testing.T) []nftARPTemplateFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/arp_templates.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct{ Cases []nftARPTemplateFixture }
	if err := json.Unmarshal(content, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Cases) != 3 {
		t.Fatal("incomplete official ARP fixtures")
	}
	for index := range fixtures.Cases {
		fixtures.Cases[index].Source = strings.TrimSuffix(fixtures.Cases[index].Source, "\n\n")
	}
	return fixtures.Cases
}

func TestNFTARPTemplateExactCompleteFixtures(t *testing.T) {
	for _, fixture := range fixtureNFTARPTemplates(t) {
		t.Run(fixture.Case, func(t *testing.T) {
			source := []byte(fixture.Source)
			live := bytes.Clone(fixture.JSON)
			evidence, err := inspectNFTARPTemplate(source, live)
			if err != nil {
				t.Fatal(err)
			}
			if !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.topologySHA256) || !reflect.DeepEqual(evidence.localAddresses, fixture.Addresses) && len(fixture.Addresses) != 0 {
				t.Fatal("incomplete template binding", evidence)
			}
			if !bytes.Equal(live, fixture.JSON) || string(source) != fixture.Source {
				t.Fatal("inspection changed source bytes")
			}
			document, err := decodeLegacyFail2banNFTJSON(live)
			if err != nil {
				t.Fatal(err)
			}
			entries := document["nftables"].([]any)
			for _, entry := range entries {
				wrapper := entry.(map[string]any)
				if rule, found := wrapper["rule"].(map[string]any); found {
					for _, expression := range rule["expr"].([]any) {
						if counter, found := expression.(map[string]any)["counter"].(map[string]any); found {
							counter["packets"] = json.Number("18446744073709551615")
							counter["bytes"] = json.Number("1024")
						}
					}
				}
			}
			changed, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			after, err := inspectNFTARPTemplate(source, changed)
			if err != nil || after.topologySHA256 != evidence.topologySHA256 {
				t.Fatal("legitimate counter progress changed topology", err)
			}
		})
	}
}

func TestNFTARPTemplateRejectsAdministratorChanges(t *testing.T) {
	fixture := fixtureNFTARPTemplates(t)[2]
	type mutation func(map[string]any, []any)
	table := func(entries []any) map[string]any { return entries[1].(map[string]any)["table"].(map[string]any) }
	chain := func(entries []any) map[string]any { return entries[2].(map[string]any)["chain"].(map[string]any) }
	rule := func(entries []any, index int) map[string]any {
		return entries[index].(map[string]any)["rule"].(map[string]any)
	}
	expression := func(entries []any, index, offset int, key string) map[string]any {
		return rule(entries, index)["expr"].([]any)[offset].(map[string]any)[key].(map[string]any)
	}
	cases := map[string]mutation{
		"table comment":          func(_ map[string]any, e []any) { table(e)["comment"] = "administrator table" },
		"table flags":            func(_ map[string]any, e []any) { table(e)["flags"] = []any{"dormant"} },
		"different table":        func(_ map[string]any, e []any) { table(e)["name"] = "administrator" },
		"chain policy":           func(_ map[string]any, e []any) { chain(e)["policy"] = "drop" },
		"chain priority":         func(_ map[string]any, e []any) { chain(e)["prio"] = json.Number("-1") },
		"chain extra field":      func(_ map[string]any, e []any) { chain(e)["comment"] = "preserve" },
		"chain replacement":      func(_ map[string]any, e []any) { chain(e)["name"] = "custom" },
		"extra object":           func(d map[string]any, e []any) { d["nftables"] = append(e, e[3]) },
		"missing rule":           func(d map[string]any, e []any) { d["nftables"] = e[:len(e)-1] },
		"reordered rules":        func(_ map[string]any, e []any) { e[3], e[4] = e[4], e[3] },
		"chain handle collision": func(_ map[string]any, e []any) { rule(e, 3)["handle"] = chain(e)["handle"] },
		"duplicate handle":       func(_ map[string]any, e []any) { rule(e, 4)["handle"] = rule(e, 3)["handle"] },
		"rule comment":           func(_ map[string]any, e []any) { rule(e, 3)["comment"] = "SYSWARDEN administrator custom rule" },
		"different expression":   func(_ map[string]any, e []any) { expression(e, 3, 0, "match")["op"] = "!=" },
		"foreign address": func(_ map[string]any, e []any) {
			expression(e, 3, 0, "match")["right"] = map[string]any{"set": []any{"192.0.2.1", "203.0.113.1"}}
		},
		"duplicate address": func(_ map[string]any, e []any) {
			expression(e, 3, 0, "match")["right"] = map[string]any{"set": []any{"192.0.2.1", "192.0.2.1"}}
		},
		"extra set field": func(_ map[string]any, e []any) {
			expression(e, 3, 0, "match")["right"].(map[string]any)["extra"] = true
		},
		"modified rate":           func(_ map[string]any, e []any) { expression(e, 4, 1, "limit")["rate"] = json.Number("501") },
		"modified rate direction": func(_ map[string]any, e []any) { expression(e, 4, 1, "limit")["inv"] = false },
		"modified log":            func(_ map[string]any, e []any) { expression(e, 4, 3, "log")["prefix"] = "[ADMIN] " },
		"extra expression": func(_ map[string]any, e []any) {
			rule(e, 3)["expr"] = append(rule(e, 3)["expr"].([]any), map[string]any{"accept": nil})
		},
		"counter overflow": func(_ map[string]any, e []any) {
			expression(e, 3, 1, "counter")["packets"] = json.Number("18446744073709551616")
		},
		"negative counter":    func(_ map[string]any, e []any) { expression(e, 3, 1, "counter")["packets"] = json.Number("-1") },
		"fractional counter":  func(_ map[string]any, e []any) { expression(e, 3, 1, "counter")["packets"] = json.Number("1.5") },
		"string counter":      func(_ map[string]any, e []any) { expression(e, 3, 1, "counter")["packets"] = "1" },
		"counter extra field": func(_ map[string]any, e []any) { expression(e, 3, 1, "counter")["comment"] = "private" },
		"named counter": func(_ map[string]any, e []any) {
			rule(e, 3)["expr"].([]any)[1] = map[string]any{"counter": "administrator-counter"}
		},
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
			if _, err := inspectNFTARPTemplate([]byte(fixture.Source), wire); err == nil {
				t.Fatal("administrator-modified table matched the product template")
			}
		})
	}
}

func TestNFTARPTemplateSourceRequiresExactOutput(t *testing.T) {
	fixture := fixtureNFTARPTemplates(t)[2]
	cases := []string{
		fixture.Source + "\n", "# SysWarden\n" + fixture.Source,
		strings.ReplaceAll(fixture.Source, "\n", "\r\n"),
		strings.Replace(fixture.Source, "198.51.100.2", "192.0.2.1", 1),
		strings.Replace(fixture.Source, "192.0.2.1", "192.0.2.0/24", 1),
		strings.Replace(fixture.Source, "192.0.2.1", "2001:db8::1", 1),
		strings.Replace(fixture.Source, "192.0.2.1", "0.0.0.0", 1),
		strings.Replace(fixture.Source, "192.0.2.1", "224.0.0.1", 1),
		strings.Replace(fixture.Source, "192.0.2.1", "example.invalid", 1),
		strings.Replace(fixture.Source, "192.0.2.1", "192.0.2.1; accept", 1),
		strings.Replace(fixture.Source, "500/second", "600/second", 1),
		strings.Replace(fixture.Source, "policy accept", "policy drop", 1),
		strings.Replace(fixture.Source, "\t}\n}", "\t\tarp saddr ip 203.0.113.1 drop\n\t}\n}", 1),
	}
	for _, source := range cases {
		if _, err := inspectNFTARPTemplate([]byte(source), fixture.JSON); err == nil {
			t.Fatal("modified source accepted")
		}
	}
	original, err := inspectNFTARPTemplate([]byte(fixture.Source), fixture.JSON)
	if err != nil {
		t.Fatal(err)
	}
	reordered := strings.Replace(fixture.Source, "192.0.2.1, 198.51.100.2", "198.51.100.2, 192.0.2.1", 1)
	after, err := inspectNFTARPTemplate([]byte(reordered), fixture.JSON)
	if err != nil || after.topologySHA256 != original.topologySHA256 || after.sourceSHA256 == original.sourceSHA256 {
		t.Fatal("unordered literal set comparison lost source or topology binding", err)
	}
	duplicate := bytes.Replace(fixture.JSON, []byte(`"policy": "accept"`), []byte(`"policy": "drop", "policy": "accept"`), 1)
	if bytes.Equal(duplicate, fixture.JSON) {
		t.Fatal("duplicate-key fixture did not change")
	}
	if _, err := inspectNFTARPTemplate([]byte(fixture.Source), duplicate); err == nil {
		t.Fatal("duplicate JSON keys accepted")
	}
}

// Only synthetic official renderer inputs are installed in this disposable
// namespace. No table name or fixture flag authorizes host firewall mutation.
func TestNFTARPTemplateLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_ARP_TEMPLATE_LIVE") != "1" {
		t.Skip("requires a disposable ARP template namespace")
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
	target := nftTableTarget{family: "arp", name: "syswarden_arp"}
	for _, fixture := range fixtureNFTARPTemplates(t) {
		source := []byte(fixture.Source)
		nft(append(bytes.Clone(source), '\n'), "-f", "-")
		inspect := func(context.Context) ([]nftTableTarget, error) {
			_, err := inspectNFTARPTemplate(source, nft(nil, "-j", "list", "table", "arp", "syswarden_arp"))
			if err != nil {
				return nil, err
			}
			return []nftTableTarget{target}, nil
		}
		fence, err := newNFTGenerationFence(ctx, inspect)
		if err != nil {
			t.Fatal(err)
		}
		if err := fence.apply(ctx, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(nft(nil, "-j", "list", "tables")), target.name) {
			t.Fatal("exact synthetic table remains")
		}
	}
	t.Log("All three complete official ARP variants matched and were removed through the nonzero generation fence.")
	source := []byte(fixtureNFTARPTemplates(t)[2].Source)
	nft(append(bytes.Clone(source), '\n'), "-f", "-")
	inspect := func(context.Context) ([]nftTableTarget, error) {
		_, err := inspectNFTARPTemplate(source, nft(nil, "-j", "list", "table", "arp", "syswarden_arp"))
		if err != nil {
			return nil, err
		}
		return []nftTableTarget{target}, nil
	}
	fence, err := newNFTGenerationFence(ctx, inspect)
	if err != nil {
		t.Fatal(err)
	}
	nft(nil, "add", "rule", "arp", "syswarden_arp", "input", "arp", "saddr", "ip", "203.0.113.1", "drop")
	before := nft(nil, "-j", "list", "ruleset")
	if err := fence.apply(ctx, func() error { return nil }); !errors.Is(err, unix.ERESTART) {
		t.Fatal("concurrent administrator ARP rule was not protected", err)
	}
	if !bytes.Equal(before, nft(nil, "-j", "list", "ruleset")) {
		t.Fatal("generation refusal changed administrator rules")
	}
	if candidate, err := newNFTGenerationFence(ctx, inspect); err == nil {
		candidate.close()
		t.Fatal("administrator-modified table received a new fence")
	}
	if !bytes.Equal(before, nft(nil, "-j", "list", "ruleset")) {
		t.Fatal("template refusal changed administrator rules")
	}
	t.Log("A concurrent administrator rule caused atomic refusal; a new inspection also refused the modified complete template.")
}

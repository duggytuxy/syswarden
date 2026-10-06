//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type nftShellFixture struct {
	Inputs nftShellInputs
	Source string
	JSON   json.RawMessage
}

func fixtureNFTShellTemplates(t *testing.T) []nftShellFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/shell_templates.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct{ Cases []nftShellFixture }
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Cases) != 40 {
		t.Fatal("incomplete historical fixture coverage")
	}
	for index := range document.Cases {
		document.Cases[index].Source = strings.TrimSuffix(document.Cases[index].Source, "\n")
	}
	return document.Cases
}

func TestNFTShellTemplateIndependentKernelFixtures(t *testing.T) {
	for index, fixture := range fixtureNFTShellTemplates(t) {
		t.Run(fmt.Sprintf("case-%02d", index), func(t *testing.T) {
			original := bytes.Clone(fixture.JSON)
			evidence, err := inspectNFTShellTemplateTopology([]byte(fixture.Source), fixture.JSON, fixture.Inputs)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.profile != "shell-pre-v2" || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.inputSHA256) || !validLegacyRetirementDigest(evidence.topologySHA256) {
				t.Fatal("incomplete historical template binding")
			}
			if !bytes.Equal(original, fixture.JSON) {
				t.Fatal("inspection changed original evidence")
			}
		})
	}
}

func TestNFTShellTemplateRefusesModifiedRulesAndSources(t *testing.T) {
	fixture := fixtureNFTShellTemplates(t)[34]
	for _, mutation := range []string{"extra-rule", "extra-chain", "table-comment", "unknown-expression-field", "changed-port", "changed-address", "rule-order", "chain-policy"} {
		t.Run(mutation, func(t *testing.T) {
			document, err := decodeLegacyFail2banNFTJSON(fixture.JSON)
			if err != nil {
				t.Fatal(err)
			}
			entries := document["nftables"].([]any)
			changed := false
			switch mutation {
			case "extra-rule":
				document["nftables"] = append(entries, map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden_table", "chain": "input_backend", "handle": json.Number("99999"), "expr": []any{map[string]any{"drop": nil}}}})
				changed = true
			case "extra-chain":
				document["nftables"] = append(entries, map[string]any{"chain": map[string]any{"family": "inet", "table": "syswarden_table", "name": "custom", "handle": json.Number("99999")}})
				changed = true
			case "rule-order":
				entries[len(entries)-1], entries[len(entries)-2] = entries[len(entries)-2], entries[len(entries)-1]
				changed = true
			default:
				for _, entry := range entries {
					wrapper := entry.(map[string]any)
					if table, ok := wrapper["table"].(map[string]any); ok && mutation == "table-comment" {
						table["comment"] = "administrator"
						changed = true
						break
					}
					if chain, ok := wrapper["chain"].(map[string]any); ok && mutation == "chain-policy" {
						chain["policy"] = "drop"
						changed = true
						break
					}
					rule, ok := wrapper["rule"].(map[string]any)
					if !ok {
						continue
					}
					for _, raw := range rule["expr"].([]any) {
						expression := raw.(map[string]any)
						match, ok := expression["match"].(map[string]any)
						if !ok {
							continue
						}
						if mutation == "unknown-expression-field" {
							match["extra"] = true
							changed = true
							break
						}
						left, ok := match["left"].(map[string]any)
						if !ok {
							continue
						}
						payload, ok := left["payload"].(map[string]any)
						if !ok {
							continue
						}
						if mutation == "changed-port" && payload["field"] == "dport" {
							match["right"] = json.Number("65535")
							changed = true
							break
						}
						if mutation == "changed-address" && payload["field"] == "saddr" {
							match["right"] = "203.0.113.1"
							changed = true
							break
						}
					}
					if changed {
						break
					}
				}
			}
			if !changed {
				t.Fatal("mutation did not change fixture")
			}
			wire, _ := json.Marshal(document)
			if _, err := inspectNFTShellTemplateTopology([]byte(fixture.Source), wire, fixture.Inputs); err == nil {
				t.Fatal("custom historical topology accepted")
			}
		})
	}
	for _, source := range []string{fixture.Source + "\n", "# Generated\n" + fixture.Source, strings.Replace(fixture.Source, "policy drop", "policy accept", 1), strings.Replace(fixture.Source, "[SysWarden-SSH-DROP]", "[ADMINISTRATOR]", 1), strings.Replace(fixture.Source, "    chain input_backend {", "    chain custom { ip saddr 203.0.113.1 drop; }\n    chain input_backend {", 1)} {
		if source == fixture.Source {
			t.Fatal("source mutation did not change fixture")
		}
		if _, err := inspectNFTShellTemplateTopology([]byte(source), fixture.JSON, fixture.Inputs); err == nil {
			t.Fatal("modified source accepted")
		}
	}
	for _, mutate := range []func(*nftShellInputs){
		func(p *nftShellInputs) { p.WireGuard = !p.WireGuard }, func(p *nftShellInputs) { p.WireGuardPort = "51820" }, func(p *nftShellInputs) { p.SSHPort = "22223" }, func(p *nftShellInputs) { p.ActivePorts = "443" }, func(p *nftShellInputs) { p.Whitelist = []string{"192.0.2.2"} }, func(p *nftShellInputs) { p.ActivePorts = "443; accept" }, func(p *nftShellInputs) { p.Whitelist = []string{"192.0.2.1; accept"} },
	} {
		input := fixture.Inputs
		mutate(&input)
		if _, err := inspectNFTShellTemplateTopology([]byte(fixture.Source), fixture.JSON, input); err == nil {
			t.Fatal("unbound parameter accepted")
		}
	}
}

func TestNFTShellTemplateInertProgramAndBounds(t *testing.T) {
	input := fixtureNFTShellTemplates(t)[0].Inputs
	cases := []nftShellNode{{Literal: "missing"}, {If: "unbound"}, {Whitelist: true, Literal: "front"}, {}}
	for _, node := range cases {
		profile := nftShellProfile{Program: []nftShellNode{node}}
		if _, err := renderNFTShellTemplate(profile, input, nil); err == nil {
			t.Fatal("unsupported program accepted")
		}
	}
	profile, err := loadNFTShellProfile()
	if err != nil {
		t.Fatal(err)
	}
	for _, ports := range []string{"0", "65536", "80,,443", "080", "80\n443", strings.Repeat("80,", 513) + "443"} {
		changed := input
		changed.ActivePorts = ports
		if _, err := renderNFTShellTemplate(profile, changed, nil); err == nil {
			t.Fatal("invalid port input accepted")
		}
	}
	changed := input
	changed.Whitelist = make([]string, 257)
	if _, err := renderNFTShellTemplate(profile, changed, nil); err == nil {
		t.Fatal("unbounded whitelist accepted")
	}
}

func TestNFTShellTemplateLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_SHELL_TEMPLATE_LIVE") != "1" {
		t.Skip("requires a disposable historical template namespace")
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
	fixtures := fixtureNFTShellTemplates(t)
	target := nftTableTarget{family: "inet", name: "syswarden_table"}
	for _, fixture := range fixtures {
		source := []byte(fixture.Source)
		nft(append(bytes.Clone(source), '\n'), "-f", "-")
		// This fixture created the entire table from independently captured
		// synthetic inputs. Production source ownership is not inferred here.
		inspect := func(context.Context) ([]nftTableTarget, error) {
			_, err := inspectNFTShellTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "inet", "syswarden_table"), fixture.Inputs)
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
			t.Fatal("synthetic table remains")
		}
	}
	t.Log("All forty official historical shell variants match their actual kernel topology and complete generation-bound fixture removal.")
	fixture := fixtures[34]
	source := []byte(fixture.Source)
	nft(append(bytes.Clone(source), '\n'), "-f", "-")
	inspect := func(context.Context) ([]nftTableTarget, error) {
		_, err := inspectNFTShellTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "inet", "syswarden_table"), fixture.Inputs)
		if err != nil {
			return nil, err
		}
		return []nftTableTarget{target}, nil
	}
	fence, err := newNFTGenerationFence(ctx, inspect)
	if err != nil {
		t.Fatal(err)
	}
	nft(nil, "add", "rule", "inet", "syswarden_table", "input_backend", "ip", "saddr", "203.0.113.1", "drop")
	before := nft(nil, "-j", "list", "ruleset")
	if err := fence.apply(ctx, func() error { return nil }); !errors.Is(err, unix.ERESTART) {
		t.Fatal("concurrent administrator rule was not protected", err)
	}
	if candidate, err := newNFTGenerationFence(ctx, inspect); err == nil {
		candidate.close()
		t.Fatal("modified historical table received a new fence")
	}
	if !bytes.Equal(before, nft(nil, "-j", "list", "ruleset")) {
		t.Fatal("administrator rules changed")
	}
	t.Log("A concurrent administrator rule causes atomic refusal; repeated inspection refuses the modified table and preserves it unchanged.")
}

//go:build linux

package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type nftInetSourceFixture struct {
	Profile    string
	Flags      struct{ Geo, ASN, Strict, WG, Honey bool }
	Parameters map[string]string
	Source     string
}

func fixtureNFTInetSources(t *testing.T) []nftInetSourceFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/inet_sources.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct{ Cases []nftInetSourceFixture }
	if err := json.Unmarshal(content, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Cases) != 72 {
		t.Fatal("incomplete independent inet fixture coverage")
	}
	return fixtures.Cases
}

func fixtureNFTInetInputs(fixture nftInetSourceFixture) nftInetTemplateInputs {
	list := func(key string) []string {
		if fixture.Parameters[key] == "" {
			return nil
		}
		fields := strings.Split(fixture.Parameters[key], ",")
		for index := range fields {
			fields[index] = strings.TrimSpace(fields[index])
		}
		return fields
	}
	input := nftInetTemplateInputs{Geo: fixture.Flags.Geo, ASN: fixture.Flags.ASN, Strict: fixture.Flags.Strict, WireGuard: fixture.Flags.WG, Honey: fixture.Flags.Honey, SSHPort: fixture.Parameters["sshPort"], WireGuardSubnet: fixture.Parameters["wireGuardSubnet"], TCPPorts: list(`strings.Join(tcpPorts, ", ")`), UDPPorts: list(`strings.Join(udpPorts, ", ")`), HoneyPorts: list("ports"), LAN4: list(`strings.Join(validLANSubnets4, ", ")`)}
	if fixture.Profile == "current" {
		input.LAN6 = list(`strings.Join(validLANSubnets6, ", ")`)
	}
	return input
}

func TestNFTInetTemplateSourceIndependentFixtures(t *testing.T) {
	for index, fixture := range fixtureNFTInetSources(t) {
		t.Run(fmt.Sprintf("%s/%02d", fixture.Profile, index), func(t *testing.T) {
			source := []byte(strings.TrimSuffix(fixture.Source, "\n\n"))
			evidence, err := inspectNFTInetTemplateSource(source, fixtureNFTInetInputs(fixture))
			if err != nil {
				t.Fatal(err)
			}
			if evidence.profile != fixture.Profile || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.inputSHA256) {
				t.Fatal("inet source or input binding missing", evidence)
			}
			extra := strings.Replace(string(source), "\tchain docker_protect {", "\tchain custom { ip saddr 203.0.113.1 drop; }\n\tchain docker_protect {", 1)
			if extra == string(source) {
				t.Fatal("custom chain fixture did not change")
			}
			if _, err := inspectNFTInetTemplateSource([]byte(extra), fixtureNFTInetInputs(fixture)); err == nil {
				t.Fatal("administrator chain was adopted")
			}
		})
	}
}

func TestNFTInetTemplateSourceRefusesCustomizationsAndInputDrift(t *testing.T) {
	fixtures := fixtureNFTInetSources(t)
	for _, fixture := range []nftInetSourceFixture{fixtures[31], fixtures[67]} {
		original := strings.TrimSuffix(fixture.Source, "\n\n")
		input := fixtureNFTInetInputs(fixture)
		cases := []string{
			original + "\n", "# SysWarden\n" + original,
			strings.Replace(original, "policy drop", "policy accept", 1),
			strings.Replace(original, "priority -10", "priority -11", 1),
			strings.Replace(original, "iifname \"lo\" accept", "iifname \"lo\" drop", 1),
			strings.Replace(original, "ct state invalid counter drop", "ct state invalid counter accept", 1),
			strings.Replace(original, "22222", "22223", 1),
			strings.Replace(original, "[SYSWARDEN-HONEYPORT] ", "[ADMINISTRATOR] ", 1),
			strings.Replace(original, "\t}\n}", "\t\tip saddr 203.0.113.1 drop\n\t}\n}", 1),
			strings.ReplaceAll(original, "\n", "\r\n"),
		}
		for _, source := range cases {
			if source == original {
				t.Fatal("mutation fixture did not change")
			}
			if _, err := inspectNFTInetTemplateSource([]byte(source), input); err == nil {
				t.Fatal("customized inet source was adopted")
			}
		}
		mutations := []func(*nftInetTemplateInputs){
			func(p *nftInetTemplateInputs) { p.SSHPort = "22223" },
			func(p *nftInetTemplateInputs) { p.SSHPort = "22222; accept" },
			func(p *nftInetTemplateInputs) { p.WireGuardSubnet = "198.51.100.0/24" },
			func(p *nftInetTemplateInputs) { p.WireGuardSubnet = "0.0.0.0/0" },
			func(p *nftInetTemplateInputs) { p.Geo = !p.Geo },
			func(p *nftInetTemplateInputs) { p.Strict = !p.Strict },
			func(p *nftInetTemplateInputs) { p.TCPPorts = []string{"80", "443"} },
			func(p *nftInetTemplateInputs) { p.TCPPorts = []string{"80", "80", "62027"} },
			func(p *nftInetTemplateInputs) { p.LAN4 = []string{"10.0.0.0/8"} },
			func(p *nftInetTemplateInputs) { p.HoneyPorts = []string{"0"} },
		}
		for _, mutate := range mutations {
			changed := fixtureNFTInetInputs(fixture)
			mutate(&changed)
			if _, err := inspectNFTInetTemplateSource([]byte(original), changed); err == nil {
				t.Fatal("changed input evidence was accepted")
			}
		}
	}
}

func TestNFTInetTemplateProgramIsBoundedAndInert(t *testing.T) {
	input := fixtureNFTInetInputs(fixtureNFTInetSources(t)[67])
	cases := [][]nftInetTemplateNode{
		{{Kind: "shell", Arguments: []string{"untrusted"}}},
		{{Kind: "if", Condition: "unrecognized", Then: []nftInetTemplateNode{{Kind: "return"}}}},
		{{Kind: "literal", Arguments: []string{"os.ReadFile()"}}},
		{{Kind: "format", Arguments: []string{`"%s"`, "unbound"}}},
		{{Kind: "format", Arguments: []string{`"%q"`, "sshPort"}}},
		{{Kind: "appendStrictAllowInputRules"}},
		{{Kind: "return"}},
	}
	for _, nodes := range cases {
		profile := nftInetTemplateProfile{Profile: "current", Programs: map[string][]nftInetTemplateNode{"applyPolicies": nodes}}
		if _, err := renderNFTInetTemplate(profile, input); err == nil {
			t.Fatal("unsupported renderer operation was accepted")
		}
	}
	recursive := []nftInetTemplateNode{{Kind: "appendStrictAllowInputRules"}}
	profile := nftInetTemplateProfile{Profile: "current", Programs: map[string][]nftInetTemplateNode{"applyPolicies": recursive, "appendStrictAllowInputRules": recursive}}
	if _, err := renderNFTInetTemplate(profile, input); err == nil {
		t.Fatal("unbounded compiled helper recursion accepted")
	}
}

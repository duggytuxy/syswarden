//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type nftV4028FileFixture struct {
	input  nftV4028PersistenceInputs
	source string
}

// Compose independently captured official blocks in the exact original write
// order. The v4.02.8 installer wrote these empty sets before runtime streaming.
func fixtureNFTV4028Files(t *testing.T) []nftV4028FileFixture {
	t.Helper()
	var fixtures []nftV4028FileFixture
	ingressFixtures := fixtureNFTNetdevTemplates(t)
	arpFixtures := fixtureNFTARPTemplates(t)
	for _, inet := range fixtureNFTInetSources(t) {
		if inet.Profile != "v4028" {
			continue
		}
		for _, ingress := range ingressFixtures {
			if ingress.Profile != "go-v4028" || ingress.Geo != inet.Flags.Geo || ingress.ASN != inet.Flags.ASN {
				continue
			}
			for option := -1; option < len(arpFixtures); option++ {
				input := nftV4028PersistenceInputs{Inet: fixtureNFTInetInputs(inet), Interfaces: append([]string{}, ingress.Interfaces...), ARP: option >= 0}
				source := ingress.Source + "\n\n" + inet.Source
				if option >= 0 {
					input.ARPAddresses = append([]string{}, arpFixtures[option].Addresses...)
					source += arpFixtures[option].Source + "\n\n"
				}
				fixtures = append(fixtures, nftV4028FileFixture{input, source})
			}
		}
	}
	if len(fixtures) != 288 {
		t.Fatal("incomplete v4.02.8 whole-file coverage", len(fixtures))
	}
	return fixtures
}

func TestNFTV4028FileIndependentBlocks(t *testing.T) {
	for index, fixture := range fixtureNFTV4028Files(t) {
		t.Run(fmt.Sprintf("case-%03d", index), func(t *testing.T) {
			wire := []byte(fixture.source)
			evidence, err := inspectNFTV4028PersistentFile(wire, fixture.input)
			if err != nil || evidence.inet.profile != "v4028" || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.inputsSHA256) {
				t.Fatal("complete official base file not recognized", err)
			}
			if string(wire) != fixture.source {
				t.Fatal("inspection changed original source")
			}
		})
	}
}

func TestNFTV4028FileRefusesUnboundSourceAndInputs(t *testing.T) {
	fixture := fixtureNFTV4028Files(t)[255]
	for index, source := range []string{
		"", "\n" + fixture.source, fixture.source + "\n",
		"flush ruleset\n" + fixture.source,
		fixture.source + "include \"/etc/operator.nft\"\n",
		fixture.source + "table inet administrator {}\n",
		fixture.source + "add element inet syswarden syswarden_blacklist { 203.0.113.99 }\n",
		strings.Replace(fixture.source, "\n\ntable inet", "\ntable inet", 1),
		strings.Replace(fixture.source, "62027", "62028", 1),
		strings.Replace(fixture.source, "priority -500", "priority -499", 1),
		strings.Replace(fixture.source, "\tchain data_leak_protect {", "\tchain administrator {}\n\tchain data_leak_protect {", 1),
	} {
		if source == fixture.source {
			t.Fatal("fixture mutation did not change bytes", index)
		}
		if _, err := inspectNFTV4028PersistentFile([]byte(source), fixture.input); err == nil {
			t.Fatal("unrecognized source accepted", index)
		}
	}
	for _, change := range []func(*nftV4028PersistenceInputs){
		func(p *nftV4028PersistenceInputs) { p.Interfaces = []string{"different"} },
		func(p *nftV4028PersistenceInputs) { p.Interfaces = []string{"swv0", "swv0"} },
		func(p *nftV4028PersistenceInputs) { p.Interfaces = []string{"bad;interface"} },
		func(p *nftV4028PersistenceInputs) { p.Inet.Geo = !p.Inet.Geo },
		func(p *nftV4028PersistenceInputs) { p.Inet.TCPPorts = []string{"80", "443"} },
		func(p *nftV4028PersistenceInputs) { p.Inet.SSHPort = "42424" },
		func(p *nftV4028PersistenceInputs) { p.ARP = false },
		func(p *nftV4028PersistenceInputs) { p.ARPAddresses = []string{"203.0.113.99"} },
	} {
		changed := fixture.input
		change(&changed)
		if _, err := inspectNFTV4028PersistentFile([]byte(fixture.source), changed); err == nil {
			t.Fatal("changed independent inputs accepted")
		}
	}
	// A current table cannot be substituted even when its own source is exact.
	current := fixtureNFTInetSources(t)[67]
	document, err := inspectNFTPersistence([]byte(fixture.source))
	if err != nil {
		t.Fatal(err)
	}
	part := document.tables[1]
	mixed := fixture.source[:part.start] + strings.TrimSuffix(current.Source, "\n\n") + fixture.source[part.end:]
	input := fixture.input
	input.Inet = fixtureNFTInetInputs(current)
	if _, err := inspectNFTV4028PersistentFile([]byte(mixed), input); err == nil {
		t.Fatal("mixed renderer generations accepted")
	}
}

func TestNFTV4028FileLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_V4028_FILE_LIVE") != "1" {
		t.Skip("requires a disposable v4.02.8 persistence namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := func(binary string, input []byte, args ...string) []byte {
		t.Helper()
		if binary != "/usr/bin/nft" && binary != "/usr/bin/ip" {
			t.Fatal("unsupported fixture executable")
		}
		cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- Fixed binaries and synthetic arguments in a verified disposable network namespace.
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command failed: %v: %s", err, out)
		}
		return out
	}
	nft := func(input []byte, args ...string) []byte { return command("/usr/bin/nft", input, args...) }
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	command("/usr/bin/ip", nil, "link", "add", "swv0", "type", "veth", "peer", "name", "swv1")
	for _, fixture := range fixtureNFTV4028Files(t) {
		if _, err := inspectNFTV4028PersistentFile([]byte(fixture.source), fixture.input); err != nil {
			t.Fatal(err)
		}
		nft([]byte(fixture.source), "-f", "-")
		document, err := inspectNFTPersistence([]byte(fixture.source))
		if err != nil {
			t.Fatal(err)
		}
		part := document.tables[0]
		if _, err := inspectNFTNetdevTemplateTopology([]byte(fixture.source[part.start:part.end]), nft(nil, "-t", "-j", "list", "table", "netdev", "syswarden_hw_drop")); err != nil {
			t.Fatal(err)
		}
		part = document.tables[1]
		if _, err := inspectNFTInetTemplateTopology([]byte(fixture.source[part.start:part.end]), nft(nil, "-t", "-j", "list", "table", "inet", "syswarden"), fixture.input.Inet); err != nil {
			t.Fatal(err)
		}
		if fixture.input.ARP {
			part = document.tables[2]
			if _, err := inspectNFTARPTemplate([]byte(fixture.source[part.start:part.end]), nft(nil, "-j", "list", "table", "arp", "syswarden_arp")); err != nil {
				t.Fatal(err)
			}
			nft(nil, "delete", "table", "arp", "syswarden_arp")
		}
		nft(nil, "delete", "table", "inet", "syswarden")
		nft(nil, "delete", "table", "netdev", "syswarden_hw_drop")
	}
	t.Log("All 288 composed v4.02.8 base files load with the exact separately verified ingress, inet and optional ARP topology. Runtime populations remain outside this source-only proof.")
}

func TestNFTV4028FileGraphRetirement(t *testing.T) {
	fixtures := fixtureNFTV4028Files(t)
	for _, index := range []int{0, 7, 255, 287} {
		t.Run(fmt.Sprintf("case-%03d", index), func(t *testing.T) {
			host, _, _ := fixtureNFTPersistenceGraphRecord(t)
			fixture := fixtures[index]
			if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.source), 0600); err != nil {
				t.Fatal(err)
			}
			if err := host.root.MkdirAll("var/backups", 0700); err != nil {
				t.Fatal(err)
			}
			origins, producers := strings.Repeat("a", 64), strings.Repeat("b", 64)
			plan, err := prepareNFTV4028PersistencePlan(host, []string{nftSharedFixturePath}, fixture.input, origins, producers)
			if err != nil {
				t.Fatal(err)
			}
			// This fixture authority covers only these independently captured
			// synthetic sources. It is not a production origin or producer proof.
			guard := func(a, b string) error {
				if a != origins || b != producers {
					return fmt.Errorf("fixture authority changed")
				}
				return nil
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			assertNFTPersistenceRecoveryComplete(t, host, plan.graph, plan.sha256)
			recovered, err := readNFTHistoricalPersistencePlan(host, plan.sha256)
			if err != nil || recovered.binding.V4028 == nil {
				t.Fatal("generation evidence did not survive recovery", err)
			}
			if err := applyNFTHistoricalPersistencePlan(host, recovered, recovered.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			// Mixed-generation evidence must not acquire a second interpretation.
			recovered.binding.Inet.SSHPort = "22"
			if err := verifyNFTHistoricalPersistencePlan(host, recovered); err == nil {
				t.Fatal("mixed-generation source binding accepted")
			}
		})
	}
}

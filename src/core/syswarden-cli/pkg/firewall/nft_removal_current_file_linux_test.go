//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type nftCurrentFileFixture struct {
	InetFixture  nftInetSourceFixture   `json:"inet_fixture"`
	Interfaces   []string               `json:"interfaces"`
	ARP          bool                   `json:"arp"`
	ARPAddresses []string               `json:"arp_addresses"`
	Populations  []nftCurrentPopulation `json:"populations"`
	Source       string                 `json:"source"`
	InetJSON     json.RawMessage        `json:"inet_json"`
	NetdevJSON   json.RawMessage        `json:"netdev_json"`
	ARPJSON      json.RawMessage        `json:"arp_json"`
}

func fixtureNFTCurrentFiles(t *testing.T) []nftCurrentFileFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/current_files.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct{ Cases []nftCurrentFileFixture }
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Cases) != 8 {
		t.Fatal("incomplete current persistence fixture coverage")
	}
	for index := range document.Cases {
		if !document.Cases[index].ARP {
			document.Cases[index].ARPJSON = nil
		}
	}
	return document.Cases
}

func (fixture nftCurrentFileFixture) inputs() nftCurrentPersistenceInputs {
	return nftCurrentPersistenceInputs{Base: nftV4028PersistenceInputs{Inet: fixtureNFTInetInputs(fixture.InetFixture), Interfaces: fixture.Interfaces, ARP: fixture.ARP, ARPAddresses: fixture.ARPAddresses}, Populations: fixture.Populations}
}

func TestNFTCurrentFileIndependentSourceAndKernel(t *testing.T) {
	for index, fixture := range fixtureNFTCurrentFiles(t) {
		t.Run(fmt.Sprintf("case-%02d", index), func(t *testing.T) {
			before := bytes.Clone(fixture.InetJSON)
			evidence, err := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), fixture.InetJSON, fixture.NetdevJSON, fixture.ARPJSON, fixture.inputs())
			if err != nil {
				t.Fatal(err)
			}
			if !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.inputSHA256) || !bytes.Equal(before, fixture.InetJSON) {
				t.Fatal("source binding incomplete or original kernel evidence changed")
			}
		})
	}
}

func TestNFTCurrentFileRefusesUnboundSource(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[7]
	for _, source := range []string{
		fixture.Source + "\n", "flush ruleset\n" + fixture.Source,
		fixture.Source + "include \"/etc/operator.nft\"\n",
		strings.Replace(fixture.Source, "192.0.2.0/24", "192.0.2.0/25", 1),
		strings.Replace(fixture.Source, " . 443", " . 444", 1),
		strings.Replace(fixture.Source, "add element netdev", "add element inet", 1),
		strings.Replace(fixture.Source, "policy drop", "policy accept", 1),
		strings.Replace(fixture.Source, "\n\ntable inet", "\ntable inet", 1),
	} {
		if source == fixture.Source {
			t.Fatal("fixture mutation did not change source")
		}
		if _, err := inspectNFTCurrentPersistentFile([]byte(source), fixture.inputs()); err == nil {
			t.Fatal("changed source accepted")
		}
	}
	for _, change := range []func(*nftCurrentPersistenceInputs){
		func(p *nftCurrentPersistenceInputs) { p.Populations = p.Populations[:len(p.Populations)-1] },
		func(p *nftCurrentPersistenceInputs) { p.Populations[0].Name = "administrator" },
		func(p *nftCurrentPersistenceInputs) { p.Populations[0].Entries = []string{"192.0.2.0/25"} },
		func(p *nftCurrentPersistenceInputs) { p.Populations[0].Entries = []string{"2001:db8::/120"} },
		func(p *nftCurrentPersistenceInputs) { p.Populations[2].Entries = []string{"192.0.2.0/24 . 0443"} },
		func(p *nftCurrentPersistenceInputs) { p.Base.Interfaces = []string{"other"} },
		func(p *nftCurrentPersistenceInputs) { p.Base.Inet.Geo = false },
	} {
		wire, _ := json.Marshal(fixture.inputs())
		var input nftCurrentPersistenceInputs
		if err := json.Unmarshal(wire, &input); err != nil {
			t.Fatal(err)
		}
		change(&input)
		if _, err := inspectNFTCurrentPersistentFile([]byte(fixture.Source), input); err == nil {
			t.Fatal("unbound input accepted")
		}
	}
}

func mutateNFTCurrentSet(t *testing.T, original []byte, name string, change func(map[string]any)) []byte {
	t.Helper()
	document, err := decodeLegacyFail2banNFTJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range document["nftables"].([]any) {
		if object, ok := entry.(map[string]any)["set"].(map[string]any); ok && object["name"] == name {
			change(object)
			found = true
		}
	}
	if !found {
		t.Fatal("fixture set missing", name)
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestNFTCurrentFileRefusesKernelChanges(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[7]
	for _, family := range []string{"inet", "netdev"} {
		original := fixture.InetJSON
		if family == "netdev" {
			original = fixture.NetdevJSON
		}
		for _, change := range []func(map[string]any){
			func(s map[string]any) { s["elem"] = append(s["elem"].([]any), "203.0.113.99") },
			func(s map[string]any) { s["elem"] = []any{} },
			func(s map[string]any) { s["comment"] = "administrator" },
			func(s map[string]any) {
				s["elem"] = []any{map[string]any{"elem": map[string]any{"val": "192.0.2.1", "comment": "administrator"}}}
			},
		} {
			changed := mutateNFTCurrentSet(t, original, "syswarden_whitelist", change)
			inet, ingress := fixture.InetJSON, fixture.NetdevJSON
			if family == "inet" {
				inet = changed
			} else {
				ingress = changed
			}
			if _, err := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), inet, ingress, fixture.ARPJSON, fixture.inputs()); err == nil {
				t.Fatal("changed live population accepted", family)
			}
		}
		for _, entry := range []any{
			map[string]any{"concat": []any{"192.0.2.1", json.Number("444")}},
			map[string]any{"concat": []any{"192.0.2.1", json.Number("443")}, "comment": "custom"},
			map[string]any{"concat": []any{"192.0.2.1", map[string]any{"range": []any{json.Number("80"), json.Number("443")}}}},
		} {
			changed := mutateNFTCurrentSet(t, original, "syswarden_whitelist_ports", func(s map[string]any) { s["elem"] = []any{entry} })
			inet, ingress := fixture.InetJSON, fixture.NetdevJSON
			if family == "inet" {
				inet = changed
			} else {
				ingress = changed
			}
			if _, err := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), inet, ingress, fixture.ARPJSON, fixture.inputs()); err == nil {
				t.Fatal("changed concatenated population accepted", family)
			}
		}
	}
	if _, err := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), fixture.InetJSON, fixture.NetdevJSON, nil, fixture.inputs()); err == nil {
		t.Fatal("missing ARP observation accepted")
	}
}

func TestNFTCurrentFileGraphRecovery(t *testing.T) {
	for _, fixture := range fixtureNFTCurrentFiles(t) {
		host, _, _ := fixtureNFTPersistenceGraphRecord(t)
		if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.Source), 0600); err != nil {
			t.Fatal(err)
		}
		if err := host.root.MkdirAll("var/backups", 0700); err != nil {
			t.Fatal(err)
		}
		origins, producers := strings.Repeat("a", 64), strings.Repeat("b", 64)
		input := fixture.inputs()
		plan, err := prepareNFTCurrentPersistencePlan(host, []string{nftSharedFixturePath}, input, origins, producers)
		if err != nil {
			t.Fatal(err)
		}
		// This guard authorizes only synthetic fixture inputs, not host state.
		guard := func(a, b string) error {
			if a != origins || b != producers {
				return fmt.Errorf("fixture authority changed")
			}
			return nil
		}
		if len(input.Populations[0].Entries) > 0 {
			input.Populations[0].Entries[0] = "203.0.113.99"
		}
		if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
			t.Fatal(err)
		}
		assertNFTPersistenceRecoveryComplete(t, host, plan.graph, plan.sha256)
		recovered, err := readNFTHistoricalPersistencePlan(host, plan.sha256)
		if err != nil || recovered.binding.Current == nil {
			t.Fatal("current source evidence lost", err)
		}
		if err := applyNFTHistoricalPersistencePlan(host, recovered, recovered.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
			t.Fatal(err)
		}
		recovered.binding.V4028 = &nftV4028PersistenceInputs{}
		if err := verifyNFTHistoricalPersistencePlan(host, recovered); err == nil {
			t.Fatal("mixed-generation journal accepted")
		}
	}
}

func TestNFTCurrentFileChunkBoundaryAndDynamicRefusal(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[0]
	input := fixture.inputs()
	entries := make([]string, 4097)
	for index := range entries {
		entries[index] = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", index)).String()
	}
	input.Populations[len(input.Populations)-1].Entries = entries
	var tail strings.Builder
	for _, chunk := range [][]string{entries[:4096], entries[4096:]} {
		for _, target := range []string{"netdev syswarden_hw_drop", "inet syswarden"} {
			fmt.Fprintf(&tail, "add element %s syswarden_blacklist6 { %s }\n", target, strings.Join(chunk, ", "))
		}
	}
	source := fixture.Source + tail.String()
	if _, err := inspectNFTCurrentPersistentFile([]byte(source), input); err != nil {
		t.Fatal("official chunk boundary not recognized", err)
	}
	combined := fixture.Source + fmt.Sprintf("add element netdev syswarden_hw_drop syswarden_blacklist6 { %s }\nadd element inet syswarden syswarden_blacklist6 { %s }\n", strings.Join(entries, ", "), strings.Join(entries, ", "))
	if _, err := inspectNFTCurrentPersistentFile([]byte(combined), input); err == nil {
		t.Fatal("nonofficial chunking accepted")
	}
	fixture = fixtureNFTCurrentFiles(t)[1]
	changed := mutateNFTCurrentSet(t, fixture.InetJSON, "banned_ips", func(s map[string]any) { s["elem"] = []any{"203.0.113.99"} })
	if _, err := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), changed, fixture.NetdevJSON, fixture.ARPJSON, fixture.inputs()); err == nil {
		t.Fatal("dynamic state adopted without independent runtime attestation")
	}
}

func TestNFTCurrentFileLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_CURRENT_FILE_LIVE") != "1" {
		t.Skip("requires a disposable current-persistence namespace")
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
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command failed: %v: %s", err, output)
		}
		return output
	}
	nft := func(input []byte, args ...string) []byte { return command("/usr/bin/nft", input, args...) }
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	command("/usr/bin/ip", nil, "link", "add", "swv0", "type", "veth", "peer", "name", "swv1")
	for _, fixture := range fixtureNFTCurrentFiles(t) {
		nft([]byte(fixture.Source), "-f", "-")
		observe := func() ([]byte, []byte, []byte) {
			var arp []byte
			if fixture.ARP {
				arp = nft(nil, "-j", "list", "table", "arp", "syswarden_arp")
			}
			return nft(nil, "-j", "list", "table", "inet", "syswarden"), nft(nil, "-j", "list", "table", "netdev", "syswarden_hw_drop"), arp
		}
		inet, ingress, arp := observe()
		if _, err := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), inet, ingress, arp, fixture.inputs()); err != nil {
			t.Fatal(err)
		}
		nft(nil, "add", "element", "inet", "syswarden", "syswarden_whitelist", "{", "203.0.113.99", "}")
		inet, ingress, arp = observe()
		if _, err := inspectNFTCurrentPersistenceRuntime([]byte(fixture.Source), inet, ingress, arp, fixture.inputs()); err == nil {
			t.Fatal("administrator address accepted as product population")
		}
		// Teardown applies only to the synthetic fixture tables in this namespace.
		nft(nil, "delete", "table", "inet", "syswarden")
		nft(nil, "delete", "table", "netdev", "syswarden_hw_drop")
		if fixture.ARP {
			nft(nil, "delete", "table", "arp", "syswarden_arp")
		}
	}
}

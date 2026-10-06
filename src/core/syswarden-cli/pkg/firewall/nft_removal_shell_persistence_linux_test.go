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

func fixtureNFTShellSerialized(t *testing.T) []string {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/shell_serialized.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Cases []struct {
			Inputs     nftShellInputs
			Serialized string
		}
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	fixtures := fixtureNFTShellTemplates(t)
	if len(document.Cases) != len(fixtures) {
		t.Fatal("incomplete historical serialization fixtures")
	}
	result := make([]string, len(fixtures))
	for index, row := range document.Cases {
		actual, _ := json.Marshal(row.Inputs)
		expected, _ := json.Marshal(fixtures[index].Inputs)
		if !bytes.Equal(actual, expected) {
			t.Fatal("misaligned serialization inputs")
		}
		result[index] = strings.TrimSuffix(row.Serialized, "\n")
	}
	return result
}

func TestNFTShellPersistenceIndependentSerializedFixtures(t *testing.T) {
	serialized := fixtureNFTShellSerialized(t)
	for index, fixture := range fixtureNFTShellTemplates(t) {
		t.Run(fmt.Sprintf("case-%02d", index), func(t *testing.T) {
			expected, err := renderNFTShellPersistence(fixture.Inputs)
			if err != nil || expected != serialized[index] {
				t.Fatal("serialization differs from independent kernel output", err)
			}
			evidence, err := inspectNFTShellPersistentTable([]byte(serialized[index]), fixture.JSON, fixture.Inputs)
			if err != nil || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.topologySHA256) {
				t.Fatal("persistent table and live topology were not bound", err)
			}
			if _, err := inspectNFTShellPersistentTable([]byte(fixture.Source), fixture.JSON, fixture.Inputs); err == nil {
				t.Fatal("renderer text was mistaken for persistent nft list output")
			}
		})
	}
}

func TestNFTShellPersistencePreservesAdditionalSourceAndRuntimeRules(t *testing.T) {
	fixture := fixtureNFTShellTemplates(t)[34]
	source := fixtureNFTShellSerialized(t)[34]
	for _, changed := range []string{
		source + "\n", source + "\ntable inet custom {}", source + "\ninclude \"/etc/operator.nft\"", strings.Replace(source, "\tchain input_backend {", "\tchain custom { ip saddr 203.0.113.1 drop; }\n\tchain input_backend {", 1), strings.Replace(source, "\t\tdrop\n", "\t\taccept\n", 1), strings.Replace(source, "policy drop", "policy accept", 1), strings.Replace(source, "22222", "22223", 1), strings.Replace(source, "192.0.2.0/24", "198.51.100.0/24", 1), strings.Replace(source, "[Catch-All]", "[Custom]", 1), strings.Replace(source, "\t\tdrop\n", "\t\tip saddr 203.0.113.1 drop\n\t\tdrop\n", 1),
	} {
		if changed == source {
			t.Fatal("source mutation did not change fixture")
		}
		if _, err := inspectNFTShellPersistentTable([]byte(changed), fixture.JSON, fixture.Inputs); err == nil {
			t.Fatal("custom persistent content accepted")
		}
	}
	document, err := decodeLegacyFail2banNFTJSON(fixture.JSON)
	if err != nil {
		t.Fatal(err)
	}
	document["nftables"] = append(document["nftables"].([]any), map[string]any{"chain": map[string]any{"family": "inet", "table": "syswarden_table", "name": "administrator", "handle": json.Number("99999")}})
	changed, _ := json.Marshal(document)
	if _, err := inspectNFTShellPersistentTable([]byte(source), changed, fixture.Inputs); err == nil {
		t.Fatal("matching persistent bytes concealed a custom runtime chain")
	}
}

func TestNFTShellPersistenceLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_SHELL_PERSISTENCE_LIVE") != "1" {
		t.Skip("requires a disposable historical persistence namespace")
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
	profile, err := loadNFTShellProfile()
	if err != nil {
		t.Fatal(err)
	}
	// Supplement the independent forty cases with real-kernel edge cases for
	// printer singleton collapse, duplicate ports, ordering and host prefixes.
	for _, active := range []string{"22222", "22222,22222", "81,80,82", " 443 , 80 "} {
		input := nftShellInputs{WireGuard: true, SSHPort: "22222", WireGuardPort: "51821", ActivePorts: active, Whitelist: []string{"192.0.2.1/32", "2001:db8::1/128"}}
		source, err := renderNFTShellTemplate(profile, input, nil)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, nftShellFixture{Inputs: input, Source: source})
	}
	for _, fixture := range fixtures {
		nft([]byte(fixture.Source+"\n"), "-f", "-")
		dump := bytes.TrimSuffix(nft(nil, "list", "table", "inet", "syswarden_table"), []byte("\n"))
		live := nft(nil, "-t", "-j", "list", "table", "inet", "syswarden_table")
		if _, err := inspectNFTShellPersistentTable(dump, live, fixture.Inputs); err != nil {
			t.Fatal("actual persistence serialization refused", fixture.Inputs.ActivePorts, err)
		}
		nft(nil, "delete", "table", "inet", "syswarden_table")
		// Reload the exact old-style persistent dump and reattest its complete
		// live topology. Only this disposable fixture namespace is affected.
		nft(append(bytes.Clone(dump), '\n'), "-f", "-")
		if _, err := inspectNFTShellPersistentTable(dump, nft(nil, "-t", "-j", "list", "table", "inet", "syswarden_table"), fixture.Inputs); err != nil {
			t.Fatal("persistent reload changed the expected topology", err)
		}
		nft(nil, "delete", "table", "inet", "syswarden_table")
	}
	t.Log("Forty independent historical dumps and four printer edge cases match before and after exact persistent reload.")
}

func TestNFTShellPersistenceDuplicatePortPrinterBehavior(t *testing.T) {
	// These three distinct outputs were observed with nft list in an isolated
	// kernel namespace, including singleton collapse before deduplication.
	for _, row := range []struct {
		input    []string
		expected string
	}{
		{[]string{"22222"}, "22222"},
		{[]string{"22222", "22222"}, "{ 22222 }"},
		{[]string{"82", "80", "81"}, "{ 80, 81, 82 }"},
	} {
		if actual := nftShellSerializedPortSet(row.input); actual != row.expected {
			t.Fatal("nft printer representation changed", actual, row.expected)
		}
	}
}

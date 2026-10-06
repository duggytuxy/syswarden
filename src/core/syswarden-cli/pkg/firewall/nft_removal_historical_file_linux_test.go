//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type nftHistoricalFileFixture struct {
	Inet    nftShellInputs             `json:"inet_inputs"`
	Ingress nftHistoricalIngressInputs `json:"ingress_inputs"`
	Source  string                     `json:"source"`
}

func fixtureNFTHistoricalFiles(t *testing.T) []nftHistoricalFileFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/historical_files.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Cases []nftHistoricalFileFixture
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Cases) != 40 {
		t.Fatal("incomplete whole-file fixture coverage")
	}
	return document.Cases
}

func TestNFTHistoricalFileIndependentCaptures(t *testing.T) {
	for index, fixture := range fixtureNFTHistoricalFiles(t) {
		t.Run(fmt.Sprintf("case-%02d", index), func(t *testing.T) {
			input := []byte(fixture.Source)
			before, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := inspectNFTHistoricalPersistentFile(input, fixture.Inet, &fixture.Ingress)
			if err != nil || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.inet.inputSHA256) || evidence.ingress == nil || !validLegacyRetirementDigest(evidence.ingress.populationSHA256) {
				t.Fatal("complete historical file was not bound", err)
			}
			document, err := inspectNFTPersistence(input)
			if err != nil {
				t.Fatal(err)
			}
			first := input[:document.tables[0].end+1]
			one, err := inspectNFTHistoricalPersistentFile(first, fixture.Inet, nil)
			if err != nil || one.ingress != nil || one.inet != evidence.inet || one.sourceSHA256 == evidence.sourceSHA256 {
				t.Fatal("inet-only historical file was not independently bound", err)
			}
			if _, err := inspectNFTHistoricalPersistentFile(input, fixture.Inet, nil); err == nil {
				t.Fatal("ingress block without its input evidence accepted")
			}
			if _, err := inspectNFTHistoricalPersistentFile(first, fixture.Inet, &fixture.Ingress); err == nil {
				t.Fatal("missing ingress block accepted")
			}
			after, _ := json.Marshal(fixture)
			if !bytes.Equal(before, after) || string(input) != fixture.Source {
				t.Fatal("original input evidence changed")
			}
		})
	}
}

func TestNFTHistoricalFilePreservesUnboundContent(t *testing.T) {
	fixture := fixtureNFTHistoricalFiles(t)[39]
	document, err := inspectNFTPersistence([]byte(fixture.Source))
	if err != nil {
		t.Fatal(err)
	}
	first := fixture.Source[:document.tables[0].end+1]
	second := fixture.Source[document.tables[1].start:]
	for index, source := range []string{
		"", "\n" + fixture.Source, "# Custom file\n" + fixture.Source,
		"flush ruleset\n" + fixture.Source, fixture.Source + "\n",
		fixture.Source + "# Keep administrator policy\n",
		fixture.Source + "table inet administrator {}\n",
		fixture.Source + "include \"/etc/operator.nft\"\n",
		first + "include \"/etc/operator.nft\"\n" + second,
		first + "\n" + second, second + first, first + first, second,
		strings.TrimSuffix(fixture.Source, "\n"),
		strings.Replace(fixture.Source, "policy drop", "policy accept", 1),
		strings.Replace(fixture.Source, "198.51.100.3-198.51.100.5", "198.51.100.3-198.51.100.6", 1),
		strings.Replace(fixture.Source, "\tchain input_backend {", "\tchain administrator {}\n\tchain input_backend {", 1),
		strings.ReplaceAll(fixture.Source, "\n", "\r\n"),
	} {
		if source == fixture.Source {
			t.Fatal("fixture mutation did not change bytes", index)
		}
		if _, err := inspectNFTHistoricalPersistentFile([]byte(source), fixture.Inet, &fixture.Ingress); err == nil {
			t.Fatal("unbound file content accepted", index)
		}
	}
}

func TestNFTHistoricalFileRequiresSharedWhitelist(t *testing.T) {
	fixture := fixtureNFTHistoricalFiles(t)[39]
	document, err := inspectNFTPersistence([]byte(fixture.Source))
	if err != nil {
		t.Fatal(err)
	}
	// The two parts independently match official templates but cannot share
	// their declared whitelist input. Whole-file validation must reject them.
	fixture.Inet.Whitelist = []string{"203.0.113.199", "2001:db8:9::/64"}
	first, err := renderNFTShellPersistence(fixture.Inet)
	if err != nil {
		t.Fatal(err)
	}
	second := fixture.Source[document.tables[1].start:document.tables[1].end]
	if _, err := inspectNFTShellPersistentSource([]byte(first), fixture.Inet); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectNFTHistoricalIngressPersistentSource([]byte(second), fixture.Ingress.Interface, fixture.Ingress.Geo, fixture.Ingress.ASN, fixture.Ingress.Populations); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectNFTHistoricalPersistentFile([]byte(first+"\n"+second+"\n"), fixture.Inet, &fixture.Ingress); err == nil {
		t.Fatal("inconsistent independently valid table fragments accepted")
	}
}

func TestNFTHistoricalFileSourceEvidenceIsIndependentOfRuntime(t *testing.T) {
	fixture := fixtureNFTHistoricalFiles(t)[39]
	source := []byte(fixture.Source)
	evidence, err := inspectNFTHistoricalPersistentFile(source, fixture.Inet, &fixture.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	document, err := inspectNFTPersistence(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, live := range [][]byte{[]byte(`{"nftables":[]}`), []byte(`{"nftables":[{"table":{"family":"inet","name":"syswarden","handle":1}}]}`)} {
		part := document.tables[0]
		if _, err := inspectNFTShellPersistentTable(source[part.start:part.end], live, fixture.Inet); err == nil {
			t.Fatal("absent or replaced live table was mistaken for historical runtime proof")
		}
		part = document.tables[1]
		if _, err := inspectNFTHistoricalIngressPersistence(source[part.start:part.end], live, fixture.Ingress.Interface, fixture.Ingress.Geo, fixture.Ingress.ASN, fixture.Ingress.Populations); err == nil {
			t.Fatal("absent or replaced ingress accepted as historical runtime proof")
		}
	}
	// Later changes to the caller's population map cannot alter prior evidence.
	before, _ := json.Marshal(evidence.ingress.populations)
	fixture.Ingress.Populations["syswarden_whitelist"] = []string{"203.0.113.199"}
	after, _ := json.Marshal(evidence.ingress.populations)
	if !bytes.Equal(before, after) {
		t.Fatal("source evidence retained mutable caller population aliases")
	}
	if _, err := inspectNFTHistoricalPersistentFile(source, fixture.Inet, &fixture.Ingress); err == nil {
		t.Fatal("changed independent population inputs accepted")
	}
}

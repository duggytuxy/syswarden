//go:build linux

package firewall

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPopulateSetListGrammarContract_SW_LIST_001(t *testing.T) {
	root := t.TempDir()
	listPath := filepath.Join(root, "mixed.list")
	content := `# Full-line comments are ignored.

192.0.2.10
198.51.100.0/24
2001:db8::10
2001:db8:1::/48
192.0.2.11:443
192.0.2.12 # inline comments are not part of the accepted grammar
invalid.example
`
	if err := os.WriteFile(listPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := populateSet(context.Background(), []nftListSource{{path: listPath, required: true}}, "fixture_set")
	if err == nil {
		t.Fatal("mixed-family and malformed entries must be rejected instead of silently filtered")
	}

	ipv4Path := filepath.Join(root, "fixture.ipv4")
	if err := os.WriteFile(ipv4Path, []byte("192.0.2.10\n198.51.100.0/24\n192.0.2.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	population, err := populateSet(context.Background(), []nftListSource{{path: ipv4Path, required: true}}, "fixture_set")
	if err != nil {
		t.Fatalf("populateSet() rejected a valid IPv4 list: %v", err)
	}
	want := []string{"192.0.2.10", "198.51.100.0/24"}
	if !reflect.DeepEqual(population.entries, want) {
		t.Fatalf("parsed entries = %#v, want %#v", population.entries, want)
	}
}

func TestPopulateSetNormalizesAutoMergeIntervals_SW_FW_002(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{name: "overlapping prefix and address", content: "192.0.2.0/24\n192.0.2.42\n", want: []string{"192.0.2.0/24"}},
		{name: "adjacent addresses", content: "198.51.100.1\n198.51.100.2\n", want: []string{"198.51.100.1-198.51.100.2"}},
		{name: "nested interval after another nested entry", content: "203.0.113.0/24\n203.0.113.1\n203.0.113.128/25\n", want: []string{"203.0.113.0/24"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ambiguous.ipv4")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			population, err := populateSet(
				context.Background(),
				[]nftListSource{{path: path, required: true}},
				"syswarden_blacklist",
			)
			if err != nil {
				t.Fatalf("populateSet() rejected a normalizable union: %v", err)
			}
			if !reflect.DeepEqual(population.entries, test.want) {
				t.Fatalf("normalized entries = %#v, want %#v", population.entries, test.want)
			}
		})
	}
}

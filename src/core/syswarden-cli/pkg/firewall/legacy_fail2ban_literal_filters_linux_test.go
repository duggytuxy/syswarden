//go:build linux

package firewall

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type legacyFail2banLiteralFilterFixture struct {
	Path          string `json:"path"`
	Source        string `json:"source"`
	SourceSHA256  string `json:"source_sha256"`
	ContentSHA256 string `json:"content_sha256"`
	Content       string `json:"content"`
}

func readLegacyFail2banLiteralFilterFixtures(t *testing.T) []legacyFail2banLiteralFilterFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/legacy_fail2ban/literal_filters.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalogue struct {
		Schema   string                               `json:"schema"`
		Revision string                               `json:"revision"`
		Filters  []legacyFail2banLiteralFilterFixture `json:"filters"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalogue); err != nil {
		t.Fatal(err)
	}
	if catalogue.Schema != "syswarden-official-literal-filter-fixtures-v1" || catalogue.Revision != legacyFail2banTemplateRevision || len(catalogue.Filters) != 49 {
		t.Fatal("historical filter catalogue lost its exact revision or scope")
	}
	seen := make(map[string]bool)
	for _, fixture := range catalogue.Filters {
		if seen[fixture.Path] || !validLegacyRetirementDigest(fixture.SourceSHA256) || fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.Content))) != fixture.ContentSHA256 {
			t.Fatal("historical filter fixture lost its exact source evidence")
		}
		seen[fixture.Path] = true
	}
	return catalogue.Filters
}

func TestLegacyFail2banLiteralFiltersRequireCompleteExactOfficialOutputs(t *testing.T) {
	fixtures := readLegacyFail2banLiteralFilterFixtures(t)
	if len(fixtures) != len(legacyFail2banLiteralFilters) {
		t.Fatal("literal filter matcher differs from the reviewed catalogue")
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Path, func(t *testing.T) {
			match, exact := matchLegacyFail2banTemplate(fixture.Path, []byte(fixture.Content))
			if !exact || match.kind != "filter" || match.templateRevision != legacyFail2banTemplateRevision || match.templateSource != fixture.Source || fmt.Sprintf("%x", match.sha256) != fixture.ContentSHA256 {
				t.Fatal("complete official output was not recognized")
			}
			for _, modified := range []string{fixture.Content + "\n", "# Administrator custom filter.\n" + fixture.Content, fixture.Content[:len(fixture.Content)-1], strings.ReplaceAll(fixture.Content, "\n", "\r\n")} {
				if _, exact := matchLegacyFail2banTemplate(fixture.Path, []byte(modified)); exact {
					t.Fatal("modified or incomplete filter was accepted")
				}
			}
			for _, path := range []string{strings.Replace(fixture.Path, "/filter.d/", "/action.d/", 1), fixture.Path + ".local", "/etc/fail2ban/filter.d/syswarden-lookalike.conf"} {
				if _, exact := matchLegacyFail2banTemplate(path, []byte(fixture.Content)); exact {
					t.Fatal("an unproven destination was accepted")
				}
			}
		})
	}
}

func TestLegacyFail2banLiteralFiltersPreserveEnabledAndDormantConsumers(t *testing.T) {
	for _, profile := range []string{"unused", "enabled-consumer", "disabled-consumer", "modified-filter"} {
		t.Run(profile, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInstalledParser(t)
			fixtures := readLegacyFail2banLiteralFilterFixtures(t)
			var paths []string
			for _, fixture := range fixtures {
				writeNFTPersistenceFixture(t, root, fixture.Path, fixture.Content)
				paths = append(paths, fixture.Path)
			}
			switch profile {
			case "enabled-consumer", "disabled-consumer":
				enabled := "false"
				if profile == "enabled-consumer" {
					enabled = "true"
				}
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/admin-extra.conf", "[administrator-extra]\nenabled = "+enabled+"\nfilter = syswarden-wordpress-auth\n")
			case "modified-filter":
				writeNFTPersistenceFixture(t, root, fixtures[0].Path, fixtures[0].Content+"\n# Administrator adjustment.\n")
			}
			inventory := readLegacyFail2banInventoryFixture(t, host)
			probe, err := newLegacyFail2banConfigurationProbe(host)
			if err != nil {
				t.Fatal(err)
			}
			// The unmodified original configuration must itself be valid, so a
			// dependency refusal cannot merely be an unrelated parser failure.
			if _, err := probe(inventory, nil); err != nil {
				t.Fatal("original fixture configuration is invalid", err)
			}
			plan, err := prepareLegacyFail2banRetirement(host, paths, probe)
			if profile == "unused" {
				if err != nil || len(plan.records) != 49 || plan.binding.Views[0] != plan.binding.Views[2] || plan.binding.Views[1] != plan.binding.Views[3] {
					t.Fatal("unused complete historical filters did not produce an unchanged configuration plan", err)
				}
			} else {
				assertEmptyLegacyFail2banPlan(t, plan, err)
			}
			if err := reattestLegacyFail2banPlanInventory(host, inventory); err != nil {
				t.Fatal("filter inspection changed administrator or product files", err)
			}
		})
	}
}

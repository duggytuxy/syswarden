//go:build linux

package firewall

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyFail2banConfigParsesIncludesWithoutEvaluatingActionText(t *testing.T) {
	content := "# retained source\n[DEFAULT]\nbefore: defaults.conf\n\n[INCLUDES]\nAfter = first.conf ; inline comment\n        second.local\n# a comment does not end a continuation\n        third.conf\n\n[Definition]\nactionban = echo one;two ; removed comment\n            [INCLUDES]\n            before = /outside/the/tree.conf\nregex = %(known/regex)s # literal hash\n"
	document, err := parseLegacyFail2banConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if document["INCLUDES"]["after"] != "first.conf\nsecond.local\nthird.conf" || document["DEFAULT"]["before"] != "defaults.conf" ||
		document["Definition"]["actionban"] != "echo one;two\n[INCLUDES]\nbefore = /outside/the/tree.conf" ||
		document["Definition"]["regex"] != "%(known/regex)s # literal hash" {
		t.Fatalf("unexpected INI structure: %#v", document)
	}
}

func TestLegacyFail2banConfigRejectsAmbiguousAndUnboundedInput(t *testing.T) {
	for _, content := range []string{
		"before = x.conf\n", "[INCLUDES]\nbefore=x.conf\nBEFORE=y.conf\n",
		"[INCLUDES]\n[INCLUDES]\n", "[INCLUDES] trailing text\n",
		"[INCLUDES]\nno option delimiter\n", "[INCLUDES]\n=x.conf\n",
		"[INCLUDES]\nbefore=x.conf\rmore\n", "[INCLUDES]\nbefore=x\x00.conf\n",
		"\xff", strings.Repeat("\n", maximumLegacyFail2banDumpLines+1),
		strings.Repeat("x", maximumNFTPersistenceBytes+1),
	} {
		if _, err := parseLegacyFail2banConfig([]byte(content)); err == nil {
			t.Fatal("unsupported INI input accepted")
		}
	}
}

func TestLegacyFail2banConfigBoundsLargeMultilineValues(t *testing.T) {
	content := "[Definition]\nregex = first\n" + strings.Repeat("  continued\n", maximumLegacyFail2banDumpLines-3)
	document, err := parseLegacyFail2banConfig([]byte(content))
	if err != nil || strings.Count(document["Definition"]["regex"], "continued") != maximumLegacyFail2banDumpLines-3 {
		t.Fatal("bounded multiline value was not preserved", err)
	}
}

func TestLegacyFail2banLocalVariantMatchesPythonSplitext(t *testing.T) {
	for path, expected := range map[string]string{
		"/etc/fail2ban/common.conf":      "/etc/fail2ban/common.local",
		"/etc/fail2ban/common.local":     "/etc/fail2ban/common.local",
		"/etc/fail2ban/common":           "/etc/fail2ban/common.local",
		"/etc/fail2ban/.hidden":          "/etc/fail2ban/.hidden.local",
		"/etc/fail2ban/..hidden":         "/etc/fail2ban/..hidden.local",
		"/etc/fail2ban/.hidden.conf":     "/etc/fail2ban/.hidden.local",
		"/etc/fail2ban/config.with.dots": "/etc/fail2ban/config.with.local",
		"/etc/fail2ban/config.":          "/etc/fail2ban/config.local",
	} {
		if actual := legacyFail2banLocalVariant(path); actual != expected {
			t.Fatalf("local variant of %q = %q, want %q", path, actual, expected)
		}
	}
}

func writeLegacyFail2banDependencyFixture(t *testing.T, root, path, content string) {
	t.Helper()
	path = legacyFail2banDirectory + "/" + path
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
		t.Fatal(err)
	}
	writeNFTPersistenceFixture(t, root, path, content)
}

func TestLegacyFail2banDependenciesPreserveMissingLocalAndDormantIncludes(t *testing.T) {
	root, host := fixtureLegacyFail2banInventory(t)
	for path, content := range map[string]string{
		"action.d/administrator.conf":   "[DEFAULT]\nbefore = shared.inc\n[INCLUDES]\nafter = .hidden\n[Definition]\nactionstop =\n",
		"action.d/shared.inc":           "[INCLUDES]\nbefore = administrator.conf\n[Definition]\nactionban = true\n",
		"action.d/.hidden.local":        "[INCLUDES]\nbefore = syswarden-nft.conf\n",
		"action.d/syswarden-nft.conf":   string(readLegacyFail2banFixture(t, "syswarden-nft.conf")),
		"jail.d/disabled-consumer.conf": "[INCLUDES]\nbefore = ../action.d/administrator.conf\n[administrator-disabled]\nenabled = false\n",
	} {
		writeLegacyFail2banDependencyFixture(t, root, path, content)
	}
	inventory := readLegacyFail2banInventoryFixture(t, host)
	graph, err := inspectLegacyFail2banDependencies(inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []legacyFail2banDependency{
		{legacyFail2banDirectory + "/action.d/administrator.conf", legacyFail2banDirectory + "/action.d/shared.inc", "before", true},
		{legacyFail2banDirectory + "/action.d/administrator.conf", legacyFail2banDirectory + "/action.d/.hidden", "after", false},
		{legacyFail2banDirectory + "/action.d/administrator.conf", legacyFail2banDirectory + "/action.d/.hidden.local", "after-local", true},
		{legacyFail2banDirectory + "/action.d/shared.inc", legacyFail2banDirectory + "/action.d/shared.local", "local", false},
		{legacyFail2banDirectory + "/action.d/.hidden.local", legacyFail2banDirectory + "/action.d/syswarden-nft.conf", "before", true},
	} {
		found := false
		for _, actual := range graph.edges {
			found = found || actual == expected
		}
		if !found {
			t.Fatalf("missing dependency evidence: %#v", expected)
		}
	}
	target := nftPersistenceRetiredSource{legacyFail2banDirectory + "/action.d/syswarden-nft.conf", sha256.Sum256(readLegacyFail2banFixture(t, "syswarden-nft.conf"))}
	if err := verifyLegacyFail2banIncludeRetirement(inventory, []nftPersistenceRetiredSource{target}); err == nil || !strings.Contains(err.Error(), "still includes") {
		t.Fatalf("dormant dependency did not prevent retirement: %v", err)
	}
	again, err := inspectLegacyFail2banDependencies(inventory)
	if err != nil || !reflect.DeepEqual(graph, again) {
		t.Fatal("dependency inspection is not deterministic", err)
	}
}

func TestLegacyFail2banDependenciesRejectExternalAndInterpolatedIncludes(t *testing.T) {
	for _, target := range []string{"/etc/custom/shared.conf", "../../outside.conf", "%(shared)s", "$HOME/config", "*.conf", `escaped\name.conf`, "filter.d"} {
		t.Run(target, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			writeLegacyFail2banDependencyFixture(t, root, "jail.local", "[INCLUDES]\nbefore = "+target+"\n")
			graph, err := inspectLegacyFail2banDependencies(readLegacyFail2banInventoryFixture(t, host))
			if err == nil || len(graph.edges) != 0 || len(graph.sources) != 0 {
				t.Fatal("unsupported include returned usable partial evidence")
			}
		})
	}
}

func TestLegacyFail2banDependenciesPermitCanonicalInternalAbsoluteIncludes(t *testing.T) {
	root, host := fixtureLegacyFail2banInventory(t)
	writeLegacyFail2banDependencyFixture(t, root, "jail.local", "[INCLUDES]\nbefore = /etc/fail2ban/filter.d/../jail.conf\n")
	graph, err := inspectLegacyFail2banDependencies(readLegacyFail2banInventoryFixture(t, host))
	if err != nil {
		t.Fatal(err)
	}
	for _, edge := range graph.edges {
		if edge.source == legacyFail2banDirectory+"/jail.local" && edge.kind == "before" {
			if edge.target != legacyFail2banDirectory+"/jail.conf" || !edge.present {
				t.Fatal("internal absolute include was resolved incorrectly")
			}
			return
		}
	}
	t.Fatal("internal absolute include was omitted")
}

func TestLegacyFail2banIncludeRetirementPreservesLocalOverrides(t *testing.T) {
	root, host := fixtureLegacyFail2banInventory(t)
	writeLegacyFail2banDependencyFixture(t, root, "jail.d/syswarden-portscan.local", "[syswarden-portscan]\nbantime = 2h\n")
	inventory := readLegacyFail2banInventoryFixture(t, host)
	target := nftPersistenceRetiredSource{legacyFail2banDirectory + "/jail.d/syswarden-portscan.conf", sha256.Sum256(readLegacyFail2banFixture(t, "portscan-pre_v2.conf"))}
	if err := verifyLegacyFail2banIncludeRetirement(inventory, []nftPersistenceRetiredSource{target}); err == nil || !strings.Contains(err.Error(), "retained local override") {
		t.Fatalf("administrator override did not prevent retirement: %v", err)
	}
	if err := os.Remove(filepath.Join(root, legacyFail2banDirectory, "jail.d/syswarden-portscan.local")); err != nil {
		t.Fatal(err)
	}
	inventory = readLegacyFail2banInventoryFixture(t, host)
	if err := verifyLegacyFail2banIncludeRetirement(inventory, []nftPersistenceRetiredSource{target}); err != nil {
		t.Fatal(err)
	}
	for _, plan := range [][]nftPersistenceRetiredSource{{target, target}, {{target.path, sha256.Sum256([]byte("wrong"))}}, {{target.path + ".missing", target.sha256}}} {
		if err := verifyLegacyFail2banIncludeRetirement(inventory, plan); err == nil {
			t.Fatal("unbound retirement accepted")
		}
	}
}

func TestLegacyFail2banDependenciesRejectUnboundAndExcessiveEvidence(t *testing.T) {
	root, host := fixtureLegacyFail2banInventory(t)
	inventory := readLegacyFail2banInventoryFixture(t, host)
	inventory.sources[0].sha256[0] ^= 1
	if _, err := inspectLegacyFail2banDependencies(inventory); err == nil {
		t.Fatal("changed source digest accepted")
	}
	writeLegacyFail2banDependencyFixture(t, root, "jail.local", "[INCLUDES]\nbefore = optional.conf\n"+strings.Repeat("         optional.conf\n", maximumLegacyFail2banDependencies/2))
	graph, err := inspectLegacyFail2banDependencies(readLegacyFail2banInventoryFixture(t, host))
	if err == nil || len(graph.edges) != 0 || len(graph.sources) != 0 {
		t.Fatal("unbounded include graph accepted")
	}
}

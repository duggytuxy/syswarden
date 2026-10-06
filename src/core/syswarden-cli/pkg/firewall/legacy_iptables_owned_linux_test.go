//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyIPTablesOwnedFixture(t *testing.T, rules []linuxWrapperRule) (legacyIPTablesObservation, map[string]linuxWrapperRule) {
	t.Helper()
	var lines []string
	var handles []uint64
	var expressions [][]any
	owned := make(map[string]linuxWrapperRule)
	for index, rule := range rules {
		line, expression, err := legacyIPTablesOwnedRuleProfile(rule)
		if err != nil {
			t.Fatal(err)
		}
		lines, handles, expressions = append(lines, line), append(handles, uint64(index+2)), append(expressions, expression)
		owned[rule.key()] = rule
	}
	// Build the common table and chain independently of the wrapper profile.
	nft, _ := legacyIPTablesFixture(t, nil, nil)
	var document map[string]any
	if err := json.Unmarshal(nft, &document); err != nil {
		t.Fatal(err)
	}
	entries := document["nftables"].([]any)
	for index := range rules {
		entries = append(entries, map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "INPUT", "handle": handles[index], "expr": expressions[index]}})
	}
	document["nftables"] = entries
	nft, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	save := []byte("*filter\n:INPUT ACCEPT [0:0]\n" + strings.Join(lines, "\n") + "\nCOMMIT\n")
	observation, err := observeLegacyIPTables(nft, save)
	if err != nil {
		t.Fatal(err)
	}
	return observation, owned
}

func TestLegacyIPTablesPreflightPreservesExistingOwnedCleanupRoute(t *testing.T) {
	for _, value := range []struct{ kind, value string }{{"port", "62027"}, {"port", "62026"}, {"source", "192.0.2.0/24"}, {"source", "192.0.2.1"}, {"source", "0.0.0.0/0"}} {
		t.Run(value.kind+"_"+value.value, func(t *testing.T) {
			rule, err := canonicalLinuxWrapperRule("iptables", value.kind, value.value, "-")
			if err != nil {
				t.Fatal(err)
			}
			observation, owned := legacyIPTablesOwnedFixture(t, []linuxWrapperRule{rule})
			if err := preflightOwnedLegacyIPTablesObservation(observation, owned); err != nil {
				t.Fatal("committed exact compatibility ownership was blocked", err)
			}
			if err := preflightOwnedLegacyIPTablesObservation(observation, nil); err == nil {
				t.Fatal("marker was treated as ownership after the manifest disappeared")
			}
		})
	}
}

func TestLegacyIPTablesPreflightRefusesAmbiguousOwnedRules(t *testing.T) {
	for _, kind := range []string{"duplicate", "pending", "changed expression", "unknown attribute", "wrong manifest", "partial historical generation"} {
		t.Run(kind, func(t *testing.T) {
			rule, err := canonicalLinuxWrapperRule("iptables", "port", "62027", "-")
			if err != nil {
				t.Fatal(err)
			}
			observation, owned := legacyIPTablesOwnedFixture(t, []linuxWrapperRule{rule})
			switch kind {
			case "duplicate":
				observation, owned = legacyIPTablesOwnedFixture(t, []linuxWrapperRule{rule, rule})
			case "pending":
				rule.pending = true
				owned[rule.key()] = rule
			case "changed expression":
				observation.rules[0].entry.(map[string]any)["rule"].(map[string]any)["expr"] = []any{map[string]any{"drop": nil}}
			case "unknown attribute":
				observation.rules[0].entry.(map[string]any)["rule"].(map[string]any)["userdata"] = "operator"
			case "wrong manifest":
				owned = nil
			case "partial historical generation":
				observation = legacyIPTablesTestObservation(t, []string{"-A INPUT -p tcp -m tcp --dport 62026 -m comment --comment SYSWARDEN_CORE -j ACCEPT"}, []uint64{91})
			}
			if err := preflightOwnedLegacyIPTablesObservation(observation, owned); err == nil {
				t.Fatal("ambiguous compatibility state passed removal preflight")
			}
		})
	}
}

func TestLegacyIPTablesPreflightReadsOpaqueAdministratorComments(t *testing.T) {
	nft, save := legacyIPTablesFixture(t, []string{"-A INPUT -p tcp -m tcp --dport 62026 -m comment --comment SYSWARDEN_CORE -j ACCEPT"}, []uint64{7})
	document, err := decodeNFTJSON(nft)
	if err != nil || preflightLegacyIPTablesRules(document) == nil {
		t.Fatal("a partial historical peer permission escaped inspection", err)
	}
	save = bytes.ReplaceAll(save, []byte("SYSWARDEN_CORE"), []byte("operator-allow"))
	observation, err := observeLegacyIPTables(nft, save)
	if err != nil || preflightOwnedLegacyIPTablesObservation(observation, nil) != nil {
		t.Fatal("an independently observed administrator comment was adopted", err)
	}
}

func TestLegacyIPTablesSourceBoundarySerialization(t *testing.T) {
	block, err := legacyIPTablesExpectedBlock(legacyIPTablesInputs{LANSubnets: []string{"192.0.2.1/32", "0.0.0.0/0"}})
	if err != nil || block[0] != "-A INPUT -j ACCEPT" || block[1] != "-A INPUT -s 192.0.2.1/32 -j ACCEPT" {
		t.Fatal("IPv4 boundary serialization differs from the native observer", err)
	}
	for _, test := range []struct{ line, expected string }{
		{block[0], `[{"counter":{"bytes":0,"packets":0}},{"accept":null}]`},
		{block[1], `[{"match":{"left":{"payload":{"field":"saddr","protocol":"ip"}},"op":"==","right":"192.0.2.1"}},{"counter":{"bytes":0,"packets":0}},{"accept":null}]`},
	} {
		expressions, err := legacyIPTablesGeneratedExpression(test.line)
		encoded, marshalErr := json.Marshal(expressions)
		if err != nil || marshalErr != nil || string(encoded) != test.expected {
			t.Fatal("source boundary expressions changed", err, marshalErr, string(encoded))
		}
	}
}

func TestLegacyIPTablesBackendPreflightKeepsIndependentRules(t *testing.T) {
	rule, err := canonicalLinuxWrapperRule("iptables", "port", "62027", "-")
	if err != nil {
		t.Fatal(err)
	}
	line := "-A INPUT -p tcp -m tcp --dport 62027 -m comment --comment SYSWARDEN_CORE -j ACCEPT"
	wrap := func(lines string) []byte { return []byte("*filter\n:INPUT ACCEPT [0:0]\n" + lines + "\nCOMMIT\n") }
	owned := map[string]linuxWrapperRule{rule.key(): rule}
	if needsCleanup, err := preflightLegacyIPTablesBackendSave(wrap(line), owned); err != nil || !needsCleanup {
		t.Fatal("exact owned legacy rule was blocked", err)
	}
	if _, err := preflightLegacyIPTablesBackendSave(wrap(line), nil); err == nil {
		t.Fatal("unowned legacy marker passed")
	}
	if _, err := preflightLegacyIPTablesBackendSave(wrap(line+"\n"+line), owned); err == nil {
		t.Fatal("duplicate legacy rule passed")
	}
	admin := strings.ReplaceAll(line, "SYSWARDEN_CORE", "operator")
	if needsCleanup, err := preflightLegacyIPTablesBackendSave(wrap(admin), nil); err != nil || needsCleanup {
		t.Fatal("administrator legacy rule was adopted", err)
	}
	if _, err := preflightLegacyIPTablesBackendSave(wrap(strings.ReplaceAll(line, "ACCEPT", "DROP")), owned); err == nil {
		t.Fatal("modified legacy rule passed")
	}
}

func TestLegacyIPTablesPreflightPinsTheActiveCleanupBackend(t *testing.T) {
	oldNFT, oldWrapper := nftExecutableValidator, linuxWrapperExecutableValidator
	nftExecutableValidator, linuxWrapperExecutableValidator = validateTestLinuxWrapperExecutable, validateTestLinuxWrapperExecutable
	t.Cleanup(func() { nftExecutableValidator, linuxWrapperExecutableValidator = oldNFT, oldWrapper })
	directory := t.TempDir()
	active := filepath.Join(directory, "iptables")
	first, second := filepath.Join(directory, "first"), filepath.Join(directory, "second")
	// These fixtures are inspected but never executed.
	for _, path := range []string{first, second} {
		writeRootedExecutableTestFile(t, path, []byte("#!/bin/sh\nexit 97\n"))
	}
	if err := os.Symlink(first, active); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	identity, err := captureNFTExecutableIdentity(first)
	if err != nil || requireLegacyIPTablesCleanupBackend(identity) != nil {
		t.Fatal("matching backend was not recognized", err)
	}
	if err := os.Remove(active); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, active); err != nil {
		t.Fatal(err)
	}
	if requireLegacyIPTablesCleanupBackend(identity) == nil {
		t.Fatal("a different active executable consumed the observed backend identity")
	}
}

func TestLegacyIPTablesPreflightRefusesCollidingOwnershipAliases(t *testing.T) {
	plain, err := canonicalLinuxWrapperRule("iptables", "source", "192.0.2.1", "-")
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := canonicalLinuxWrapperRule("iptables", "source", "192.0.2.1/32", "-")
	if err != nil {
		t.Fatal(err)
	}
	observation, owned := legacyIPTablesOwnedFixture(t, []linuxWrapperRule{plain})
	owned[prefix.key()] = prefix
	if preflightOwnedLegacyIPTablesObservation(observation, owned) == nil {
		t.Fatal("multiple manifest entries claimed the same kernel rule")
	}
}

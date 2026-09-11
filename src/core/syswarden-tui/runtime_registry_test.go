package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestActiveBlockRegistryDistinguishesRuntimeAndAttackEvidence(t *testing.T) {
	entries := []BannedIP{
		{IP: "192.0.2.10", Action: "BANNED", EnforcementState: "active", Jail: "native-runtime"},
		{IP: "192.0.2.11", Action: "BANNED", EnforcementState: "active", Jail: "ssh-auth"},
		{IP: "192.0.2.12", Action: "BANNED", EnforcementState: "deleted"},
		{IP: "192.0.2.13", Action: "BANNED", EnforcementState: "expired"},
		{IP: "192.0.2.14", Action: "BANNED", EnforcementState: "tombstoned"},
		{IP: "192.0.2.15", Action: "SHADOW-ALERT"},
		{IP: "192.0.2.16", Action: "BANNED", EnforcementState: "unknown"},
	}
	var output bytes.Buffer
	printActiveBlockRegistry(&output, entries)
	expected := "[ACTIVE BLOCK REGISTRY]\n - 192.0.2.10 | state=active | source=native-runtime\n - 192.0.2.11 | state=active | source=ssh-auth\n"
	if output.String() != expected {
		t.Fatalf("current registry includes a historical or unverified block: %s", output.String())
	}
	output.Reset()
	printActiveBlockRegistry(&output, entries[2:])
	if !strings.Contains(output.String(), "No active entries in the current registry snapshot.") {
		t.Fatal("empty current registry was not identified")
	}
}

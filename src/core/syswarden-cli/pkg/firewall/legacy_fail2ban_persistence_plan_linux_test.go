//go:build linux

package firewall

import (
	"bytes"
	"strings"
	"testing"
)

const legacyFail2banPersistenceFixture = `#!/usr/sbin/nft -f
flush ruleset
include "/etc/administrator.nft"
table inet f2b-table {
    set addr-set-syswarden-portscan {
        type ipv4_addr
        elements = { 127.0.0.2 }
    }
    # Keep this administrator comment and definition exactly.
    set administrator-ban {
        type ipv4_addr
        elements = { 127.0.0.3 }
    }
    chain f2b-chain {
        type filter hook input priority filter - 1; policy accept;
        meta l4proto tcp ip saddr @addr-set-syswarden-portscan reject with icmp port-unreachable
        ip saddr @administrator-ban drop
    }
}
`

func TestLegacyFail2banPersistentPlannerPreservesUnrelatedBytes(t *testing.T) {
	_, _, record := fixtureLegacyFail2banNFTJournal(t, true)
	before := []byte(legacyFail2banPersistenceFixture)
	edit, err := planLegacyFail2banPersistence(before, record)
	if err != nil || len(edit.removed) != 2 {
		t.Fatal("exact independently attested persistent targets refused", err)
	}
	set := "set addr-set-syswarden-portscan {\n        type ipv4_addr\n        elements = { 127.0.0.2 }\n    }"
	rule := "meta l4proto tcp ip saddr @addr-set-syswarden-portscan reject with icmp port-unreachable"
	expected := strings.ReplaceAll(strings.ReplaceAll(legacyFail2banPersistenceFixture, set, ""), rule, "")
	if string(edit.content) != expected || string(before) != legacyFail2banPersistenceFixture {
		t.Fatal("planner changed bytes outside the exact target ranges")
	}
	again, err := planLegacyFail2banPersistence(edit.content, record)
	if err != nil || len(again.removed) != 0 || !bytes.Equal(again.content, edit.content) {
		t.Fatal("exact settled source is not a read-only acknowledgement", err)
	}
}

func TestLegacyFail2banPersistentPlannerRefusesAmbiguity(t *testing.T) {
	_, _, original := fixtureLegacyFail2banNFTJournal(t, true)
	for _, change := range []string{"unbound", "foreign-ban", "split-address", "set-type", "set-flags", "set-comment", "set-annotation", "counter", "verdict", "missing-rule", "duplicate-rule", "duplicate-set", "foreign-reference", "quoted-reference", "continued-reference", "escaped-reference", "nested-include", "macro", "command", "wrong-table", "quoted-table", "duplicate-table", "include-fragment"} {
		t.Run(change, func(t *testing.T) {
			record := original
			content := legacyFail2banPersistenceFixture
			rule := "meta l4proto tcp ip saddr @addr-set-syswarden-portscan reject with icmp port-unreachable"
			switch change {
			case "unbound":
				record.Quiescence.FilePlan = strings.Repeat("f", 64)
			case "foreign-ban":
				content = strings.Replace(content, "127.0.0.2", "127.0.0.4", 1)
			case "split-address":
				content = strings.Replace(content, "127.0.0.2", "127.0.0. 2", 1)
			case "set-type":
				content = strings.Replace(content, "type ipv4_addr", "type ipv6_addr", 1)
			case "set-flags":
				content = strings.Replace(content, "type ipv4_addr", "type ipv4_addr; flags interval", 1)
			case "set-comment":
				content = strings.Replace(content, "type ipv4_addr", "type ipv4_addr; comment \"custom\"", 1)
			case "set-annotation":
				content = strings.Replace(content, "type ipv4_addr", "# administrator annotation\n type ipv4_addr", 1)
			case "counter":
				content = strings.Replace(content, rule, rule+" counter", 1)
			case "verdict":
				content = strings.Replace(content, "reject with icmp port-unreachable", "accept", 1)
			case "missing-rule":
				content = strings.Replace(content, rule, "", 1)
			case "duplicate-rule":
				content = strings.Replace(content, rule, rule+"\n"+rule, 1)
			case "duplicate-set":
				content = strings.Replace(content, "    # Keep", "    set addr-set-syswarden-portscan { type ipv4_addr; elements = { 127.0.0.2 } }\n    # Keep", 1)
			case "foreign-reference":
				content = strings.Replace(content, "ip saddr @administrator-ban drop", "ip saddr @addr-set-syswarden-portscan log", 1)
			case "quoted-reference":
				content = strings.Replace(content, "ip saddr @administrator-ban drop", "ip saddr @\"addr-set-syswarden-portscan\" drop", 1)
			case "continued-reference":
				content = strings.Replace(content, "ip saddr @administrator-ban drop", "ip saddr @addr-set-syswarden-\\\nportscan drop", 1)
			case "escaped-reference":
				content = strings.Replace(content, "ip saddr @administrator-ban drop", `ip saddr @"addr-set-syswarden-\x70ortscan" drop`, 1)
			case "nested-include":
				content = strings.Replace(content, rule, rule+"\n include \"/etc/extra.nft\"", 1)
			case "macro":
				content = "define name = addr-set-syswarden-portscan\n" + content
			case "command":
				content += "add set inet f2b-table addr-set-syswarden-portscan { type ipv4_addr; }\n"
			case "wrong-table":
				content = strings.Replace(content, "table inet f2b-table", "table ip f2b-table", 1)
			case "quoted-table":
				content = strings.Replace(content, "table inet f2b-table", "table inet \"f2b-table\"", 1)
			case "duplicate-table":
				content += "table inet f2b-table { }\n"
			case "include-fragment":
				content = "set addr-set-syswarden-portscan { type ipv4_addr; }\n"
			}
			edit, err := planLegacyFail2banPersistence([]byte(content), record)
			if err == nil || edit.content != nil || edit.removed != nil {
				t.Fatal("ambiguous source returned a partial authorized edit", change, err)
			}
		})
	}
}

func TestLegacyFail2banPersistentPlannerRequiresCompleteDedicatedChain(t *testing.T) {
	_, _, record := fixtureLegacyFail2banNFTJournal(t, false)
	const set = "set f2b-syswarden-portscan { type ipv4_addr; elements = { 127.0.0.2 } }"
	const chain = "chain syswarden-portscan { type filter hook input priority filter - 1; policy accept; ip saddr @f2b-syswarden-portscan drop; }"
	const administrator = "chain administrator { type filter hook input priority -2; policy accept; ip saddr 127.0.0.3 drop; }"
	before := "table inet syswarden_f2b {\n" + set + "\n" + chain + "\n" + administrator + "\n}\n"
	for _, change := range []string{"none", "extra-rule", "annotation", "chain-reference", "priority", "policy"} {
		t.Run(change, func(t *testing.T) {
			content := before
			switch change {
			case "extra-rule":
				content = strings.Replace(content, "@f2b-syswarden-portscan drop;", "@f2b-syswarden-portscan drop; ip saddr 127.0.0.4 drop;", 1)
			case "annotation":
				content = strings.Replace(content, "policy accept;", "policy accept; # administrator annotation\n", 1)
			case "chain-reference":
				content = strings.Replace(content, "ip saddr 127.0.0.3 drop;", "jump syswarden-portscan;", 1)
			case "priority":
				content = strings.Replace(content, "priority filter - 1", "priority 0", 1)
			case "policy":
				content = strings.Replace(content, "policy accept", "policy drop", 1)
			}
			edit, err := planLegacyFail2banPersistence([]byte(content), record)
			if change == "none" {
				if err != nil || string(edit.content) != strings.ReplaceAll(strings.ReplaceAll(before, set, ""), chain, "") {
					t.Fatal("dedicated exact chain retirement changed administrator bytes", err)
				}
			} else if err == nil || edit.content != nil {
				t.Fatal("modified or shared historical chain was accepted", change)
			}
		})
	}
}

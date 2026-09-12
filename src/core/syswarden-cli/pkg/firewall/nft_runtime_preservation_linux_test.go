//go:build linux

package firewall

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func runtimePreservationFixture(t *testing.T) ([]byte, nftDynamicSnapshot) {
	t.Helper()
	var entries []any
	for _, key := range nftDynamicBanSets {
		dataType := "ipv4_addr"
		if strings.HasSuffix(key.name, "6") {
			dataType = "ipv6_addr"
		}
		entries = append(entries, map[string]any{"set": map[string]any{
			"family": key.family, "table": key.table, "name": key.name,
			"type": dataType, "flags": []string{"timeout", "interval"},
		}})
	}
	for _, family := range []string{"inet", "netdev"} {
		table := "syswarden"
		if family == "netdev" {
			table = "syswarden_hw_drop"
		}
		for kind, name := range map[string]string{"chain": "old_policy", "set": "old_feed", "counter": "old_counter"} {
			entries = append(entries, map[string]any{kind: map[string]any{"family": family, "table": table, "name": name}})
		}
	}
	entries = append(entries, map[string]any{"chain": map[string]any{"family": "inet", "table": "operator", "name": "untouched"}})
	wire, err := json.Marshal(map[string]any{"nftables": entries})
	if err != nil {
		t.Fatal(err)
	}
	document, err := decodeNFTJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := extractNFTDynamicSnapshot(document, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return wire, snapshot
}

func TestNFTReloadKeepsLiveRuntimeSetsInTheKernel(t *testing.T) {
	wire, snapshot := runtimePreservationFixture(t)
	rules, err := nftRuntimePreservationRules(wire, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"flush table inet syswarden\n", "flush table netdev syswarden_hw_drop\n",
		"delete chain inet syswarden old_policy\n", "delete set inet syswarden old_feed\n",
		"delete counter netdev syswarden_hw_drop old_counter\n",
	} {
		if !strings.Contains(rules, required) {
			t.Fatalf("policy replacement is incomplete: missing %q in %s", required, rules)
		}
	}
	for _, forbidden := range []string{"banned_ips", "delete table", "add element", "operator", "untouched", "syswarden_table"} {
		if strings.Contains(rules, forbidden) {
			t.Fatalf("runtime or unrelated policy would be changed: %s", rules)
		}
	}
	if strings.Index(rules, "delete chain inet") > strings.Index(rules, "delete set inet") {
		t.Fatal("referenced sets are deleted before their chains")
	}
}

func TestNFTRuntimePreservationAcceptsOwnedOperatorPolicyChain(t *testing.T) {
	wire, snapshot := runtimePreservationFixture(t)
	var document map[string][]json.RawMessage
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatal(err)
	}
	chain, err := json.Marshal(map[string]any{"chain": map[string]any{
		"family": "inet", "table": "syswarden", "name": operatorPolicyChainName,
	}})
	if err != nil {
		t.Fatal(err)
	}
	document["nftables"] = append(document["nftables"], chain)
	wire, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := nftRuntimePreservationRules(wire, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := "delete chain inet syswarden " + operatorPolicyChainName + "\n"
	if strings.Count(rules, want) != 1 || strings.Contains(rules, "banned_ips") {
		t.Fatalf("owned operator chain was not safely replaced: %s", rules)
	}
	for _, replacement := range [][2]string{
		{`"chain":`, `"set":`},
		{`"inet"`, `"netdev"`},
		{`"operator-policy"`, `"operator-policy-other"`},
		{`"operator-policy"`, `"operator-policy; flush ruleset"`},
	} {
		changed := strings.Replace(string(chain), replacement[0], replacement[1], 1)
		if replacement[1] == `"netdev"` {
			changed = strings.Replace(changed, `"syswarden"`, `"syswarden_hw_drop"`, 1)
		}
		document["nftables"][len(document["nftables"])-1] = json.RawMessage(changed)
		wire, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if rules, err := nftRuntimePreservationRules(wire, snapshot); err == nil || rules != "" {
			t.Fatalf("operator chain exception accepted unsupported object %s: %q, %v", changed, rules, err)
		}
	}
}

func TestNFTRuntimePreservationRequiresCompatibleCompleteSets(t *testing.T) {
	wire, snapshot := runtimePreservationFixture(t)
	for _, replacement := range [][2]string{
		{`"ipv4_addr"`, `"ipv6_addr"`},
		{`["timeout","interval"]`, `["timeout"]`},
		{`"type":"ipv4_addr"`, `"type":"ipv4_addr","timeout":60`},
		{`"name":"banned_ips"`, `"name":"old_runtime"`},
	} {
		changed := strings.Replace(string(wire), replacement[0], replacement[1], 1)
		if changed == string(wire) {
			t.Fatal("fixture replacement did not change the input")
		}
		rules, err := nftRuntimePreservationRules([]byte(changed), snapshot)
		if err != nil || rules != "" {
			t.Fatalf("incompatible runtime definitions were retained: %q, %v", rules, err)
		}
	}
	key := nftDynamicBanSets[0]
	snapshot.present[key] = false
	if rules, err := nftRuntimePreservationRules(wire, snapshot); err != nil || rules != "" {
		t.Fatalf("partial runtime was retained: %q, %v", rules, err)
	}
}

func TestNFTRuntimePreservationRefusesUnsupportedOwnedObjects(t *testing.T) {
	wire, snapshot := runtimePreservationFixture(t)
	for _, replacement := range [][2]string{
		{`"counter":`, `"unknown_object":`},
		{`"old_policy"`, `"bad; flush ruleset"`},
	} {
		changed := strings.Replace(string(wire), replacement[0], replacement[1], 1)
		if rules, err := nftRuntimePreservationRules([]byte(changed), snapshot); err == nil || rules != "" {
			t.Fatalf("unsafe reset plan was produced: %q, %v", rules, err)
		}
	}
}

func canonicalRuntimeRollbackFixture() string {
	var result strings.Builder
	for _, table := range []string{"inet syswarden", "netdev syswarden_hw_drop"} {
		result.WriteString("table " + table + " {\n")
		result.WriteString("\tset banned_ips {\n\t\ttype ipv4_addr\n\t\tflags interval,timeout\n\t\telements = { 192.0.2.44 timeout 1m expires 40s,\n\t\t\t     192.0.2.45 timeout 1m expires 1ms }\n\t}\n")
		result.WriteString("\tset banned_ips6 {\n\t\ttype ipv6_addr\n\t\tflags interval,timeout\n\t\telements = { 2001:db8::44 timeout 1m expires 40s }\n\t}\n")
		result.WriteString("\tset persistent {\n\t\ttype ipv4_addr\n\t\telements = { 198.51.100.1 }\n\t}\n}\n")
	}
	return result.String()
}

func TestNFTRollbackCannotResurrectRetainedRuntimeElements(t *testing.T) {
	snapshot := canonicalRuntimeRollbackFixture()
	cleaned, err := nftRollbackWithoutRuntimeElements(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.44", "192.0.2.45", "2001:db8::44", "expires"} {
		if strings.Contains(cleaned, address) {
			t.Fatalf("historical runtime could be replayed: %s", cleaned)
		}
	}
	if strings.Count(cleaned, "198.51.100.1") != 2 || strings.Count(cleaned, "flags interval,timeout") != 4 {
		t.Fatalf("persistent policy or runtime definitions were lost: %s", cleaned)
	}
	if again, err := nftRollbackWithoutRuntimeElements(cleaned); err != nil || again != cleaned {
		t.Fatalf("recovery cannot safely reuse the journal: %q, %v", again, err)
	}
	for _, malformed := range []string{
		strings.Replace(snapshot, "\tset banned_ips {", "\tset renamed {", 1),
		strings.Replace(snapshot, "\t\telements = { 192.0.2.44", "\t\telements={ 192.0.2.44", 1),
		strings.Replace(snapshot, "192.0.2.44 timeout", "{ 192.0.2.44 timeout", 1),
	} {
		if _, err := nftRollbackWithoutRuntimeElements(malformed); err == nil {
			t.Fatal("ambiguous rollback snapshot was accepted")
		}
	}
}

func TestNFTRetainedFinalSecondMayExpireWithoutBecomingPermanent(t *testing.T) {
	now := time.Now()
	expected := newNFTDynamicSnapshot(now)
	key := nftDynamicBanSets[0]
	ban, err := parseNFTDynamicBan(json.RawMessage(`{"elem":{"val":"192.0.2.44","timeout":60,"expires":0}}`))
	if err != nil {
		t.Fatal(err)
	}
	expected.sets[key][dynamicBanIdentity(ban)] = ban
	observed := newNFTDynamicSnapshot(now.Add(time.Millisecond))
	if err := compareNFTDynamicSnapshots(expected, observed, now.Add(2*time.Millisecond)); err != nil {
		t.Fatalf("legitimate final-second expiry was rejected: %v", err)
	}
	ban.timeout, ban.expires = 0, 0
	observed.sets[key][dynamicBanIdentity(ban)] = ban
	if err := compareNFTDynamicSnapshots(expected, observed, now.Add(2*time.Millisecond)); err == nil {
		t.Fatal("timed claim could become permanent during reload")
	}
}

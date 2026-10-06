//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func fixtureNFTOperatorReceiverRules() []config.OperatorPolicyRule {
	return []config.OperatorPolicyRule{
		{ID: "alpha-v4", Family: config.OperatorPolicyFamilyIPv4, Direction: config.OperatorPolicyDirectionIngress, Protocol: config.OperatorPolicyProtocolICMP, ICMPType: config.OperatorPolicyTypeEchoRequest, Source: "198.51.100.42/32", Action: config.OperatorPolicyActionAccept},
		{ID: "bravo-v6", Family: config.OperatorPolicyFamilyIPv6, Direction: config.OperatorPolicyDirectionIngress, Protocol: config.OperatorPolicyProtocolICMPv6, ICMPType: config.OperatorPolicyTypeEchoRequest, Source: "2001:db8::42/128", Action: config.OperatorPolicyActionAccept},
		{ID: "charlie-tcp", Family: config.OperatorPolicyFamilyIPv4, Direction: config.OperatorPolicyDirectionIngress, Protocol: config.OperatorPolicyProtocolTCP, DestinationPort: 8443, Source: "203.0.113.0/24", Action: config.OperatorPolicyActionAccept},
		{ID: "delta-udp", Family: config.OperatorPolicyFamilyIPv6, Direction: config.OperatorPolicyDirectionIngress, Protocol: config.OperatorPolicyProtocolUDP, DestinationPort: 51820, Source: "2001:db8:1::/64", Action: config.OperatorPolicyActionAccept},
	}
}

func fixtureNFTOperatorReceiverDocument(t *testing.T, model nftOperatorReceiverModel) mutableNFTVerificationDocument {
	t.Helper()
	result := mutableNFTVerificationDocument{NFTables: []map[string]any{
		{"table": map[string]any{"family": "inet", "name": model.table, "handle": 1}},
		{"chain": map[string]any{"family": "inet", "table": model.table, "name": "input", "handle": 2, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
	}}
	for i, rule := range model.rules {
		expr, err := expectedOperatorPolicyExpressions(rule)
		if err != nil {
			t.Fatal(err)
		}
		expr[len(expr)-2] = map[string]any{"counter": map[string]any{"packets": uint64(17 + i), "bytes": uint64(1800 + i)}}
		result.NFTables = append(result.NFTables, map[string]any{"rule": map[string]any{"family": "inet", "table": model.table, "chain": "input", "handle": 10 + i, "comment": rule.comment, "expr": expr}})
	}
	return result
}

func TestNFTOperatorReceiverExactTypedPolicyAndCounterEpoch(t *testing.T) {
	rules := fixtureNFTOperatorReceiverRules()
	model, err := prepareNFTOperatorReceiver(rules)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(model.source, []byte("syswarden")) || bytes.Contains(model.source, []byte("drop")) || !bytes.Contains(model.source, []byte("type filter hook input priority 0; policy accept;")) {
		t.Fatal("receiver is not independent ingress accept policy")
	}
	wire := marshalMutableNFTVerificationFixture(t, fixtureNFTOperatorReceiverDocument(t, model))
	before := bytes.Clone(wire)
	counters, err := model.inspect(wire)
	if err != nil || len(counters) != len(rules) {
		t.Fatal(counters, err)
	}
	for i, counter := range counters {
		if counter.Rule != model.rules[i].comment || counter.Packets != uint64(17+i) || counter.Bytes != uint64(1800+i) {
			t.Fatal("original observed counters were not retained", counter)
		}
	}
	if !bytes.Equal(wire, before) {
		t.Fatal("inspection rewrote evidence")
	}
	reversed := append([]config.OperatorPolicyRule(nil), rules...)
	for a, b := 0, len(reversed)-1; a < b; a, b = a+1, b-1 {
		reversed[a], reversed[b] = reversed[b], reversed[a]
	}
	reordered, err := prepareNFTOperatorReceiver(reversed)
	if err != nil || !bytes.Equal(reordered.source, model.source) || reordered.table != model.table {
		t.Fatal("equivalent input order changed receiver identity", err)
	}
}

func TestNFTOperatorReceiverRefusesAlteredSemanticsAndUnknownState(t *testing.T) {
	model, err := prepareNFTOperatorReceiver(fixtureNFTOperatorReceiverRules())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"table", "table-comment", "extra-table", "chain-type", "hook", "priority", "drop-policy", "regular-chain", "extra-chain", "rule-order", "destination-port", "source", "verdict", "extra-expression", "extra-rule", "missing-rule", "zero-handle", "duplicate-handle", "rule-comment", "named-counter", "negative-counter", "overflow-counter", "extra-counter-field", "unknown-rule-field"} {
		t.Run(kind, func(t *testing.T) {
			doc := fixtureNFTOperatorReceiverDocument(t, model)
			table := doc.NFTables[0]["table"].(map[string]any)
			chain := doc.NFTables[1]["chain"].(map[string]any)
			rule := doc.NFTables[2]["rule"].(map[string]any)
			expr := rule["expr"].([]any)
			switch kind {
			case "table":
				table["name"] = "unrelated"
			case "table-comment":
				table["comment"] = "administrator annotation"
			case "extra-table":
				doc.NFTables = append(doc.NFTables, doc.NFTables[0])
			case "chain-type":
				chain["type"] = "nat"
			case "hook":
				chain["hook"] = "forward"
			case "priority":
				chain["prio"] = -1
			case "drop-policy":
				chain["policy"] = "drop"
			case "regular-chain":
				delete(chain, "hook")
			case "extra-chain":
				doc.NFTables = append(doc.NFTables, doc.NFTables[1])
			case "rule-order":
				doc.NFTables[2], doc.NFTables[3] = doc.NFTables[3], doc.NFTables[2]
			case "destination-port":
				r := doc.NFTables[4]["rule"].(map[string]any)
				e := r["expr"].([]any)
				e[1].(map[string]any)["match"].(map[string]any)["right"] = 8444
			case "source":
				expr[0].(map[string]any)["match"].(map[string]any)["right"] = "198.51.100.43"
			case "verdict":
				expr[len(expr)-1] = map[string]any{"drop": nil}
			case "extra-expression":
				rule["expr"] = append(expr, map[string]any{"accept": nil})
			case "extra-rule":
				doc.NFTables = append(doc.NFTables, doc.NFTables[2])
			case "missing-rule":
				doc.NFTables = doc.NFTables[:len(doc.NFTables)-1]
			case "zero-handle":
				rule["handle"] = 0
			case "duplicate-handle":
				doc.NFTables[3]["rule"].(map[string]any)["handle"] = rule["handle"]
			case "rule-comment":
				rule["comment"] = "unrelated"
			case "named-counter":
				expr[len(expr)-2] = map[string]any{"counter": "custom"}
			case "negative-counter":
				expr[len(expr)-2] = map[string]any{"counter": map[string]any{"packets": -1, "bytes": 0}}
			case "overflow-counter":
				expr[len(expr)-2] = map[string]any{"counter": map[string]any{"packets": json.Number("18446744073709551616"), "bytes": 0}}
			case "extra-counter-field":
				expr[len(expr)-2].(map[string]any)["counter"].(map[string]any)["name"] = "custom"
			case "unknown-rule-field":
				rule["userdata"] = "custom"
			}
			wire := marshalMutableNFTVerificationFixture(t, doc)
			if _, err := model.inspect(wire); err == nil {
				t.Fatal("modified receiver accepted", kind)
			}
		})
	}
}

func TestNFTOperatorReceiverAnalysisKeepsOriginalSource(t *testing.T) {
	rules := fixtureNFTOperatorReceiverRules()
	compiled, err := compileOperatorPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("table inet syswarden {\n" + compiled.chain + "}\n")
	before := bytes.Clone(source)
	normalized, err := normalizeNFTOperatorSource(source, rules)
	if err != nil || !bytes.Equal(source, before) || !bytes.Equal(normalized, []byte("table inet syswarden {\n"+empty.chain+"}\n")) {
		t.Fatal("analysis copy changed the original source", err)
	}
	for i, modified := range [][]byte{nil, bytes.Replace(source, []byte("counter accept"), []byte("counter drop"), 1), append(bytes.Clone(source), []byte(compiled.chain)...), []byte(strings.Replace(string(source), "198.51.100.42", "198.51.100.43", 1))} {
		if _, err := normalizeNFTOperatorSource(modified, rules); err == nil {
			t.Fatalf("unbound source accepted at %d", i)
		}
	}
	if _, err := prepareNFTOperatorReceiver(nil); err == nil {
		t.Fatal("empty receiver accepted")
	}
	invalid := fixtureNFTOperatorReceiverRules()
	invalid[0].Action = "drop"
	if _, err := prepareNFTOperatorReceiver(invalid); err == nil {
		t.Fatal("unsupported policy accepted")
	}
}

func TestNFTOperatorReceiverRuntimeAnalysisPreservesOriginalAndRefusesDrift(t *testing.T) {
	rules := fixtureNFTOperatorReceiverRules()
	compiled, err := compileOperatorPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	plan := minimalVerificationPlan(0)
	plan.operatorPolicy = compiled.verification
	plan.chains[nftObjectKey{family: "inet", table: "syswarden", name: "stateful_protect"}] = "input"
	doc := mutableNFTVerificationFixture(t, plan)
	wire := marshalMutableNFTVerificationFixture(t, doc)
	before := bytes.Clone(wire)
	normalized, counters, err := normalizeNFTOperatorRuntime(wire, rules)
	if err != nil || len(counters) != len(rules) || !bytes.Equal(wire, before) {
		t.Fatal("runtime analysis changed original evidence", err)
	}
	reduced, err := decodeNFTJSON(normalized)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOperatorPolicyNFTState(reduced, empty.verification); err != nil {
		t.Fatal("analysis did not leave exact empty scaffolding", err)
	}
	for _, kind := range []string{"changed-policy", "foreign-rule", "unknown-envelope", "extra-reference", "duplicate-handle"} {
		t.Run(kind, func(t *testing.T) {
			changed := mutableNFTVerificationFixture(t, plan)
			indices := nftRuleIndices(t, changed, operatorPolicyChainName)
			selected := changed.NFTables[indices[0]]["rule"].(map[string]any)
			policy := append([]config.OperatorPolicyRule(nil), rules...)
			switch kind {
			case "changed-policy":
				policy[0].Source = "198.51.100.43/32"
			case "foreign-rule":
				selected["expr"] = []any{map[string]any{"drop": nil}}
			case "unknown-envelope":
				selected["userdata"] = "preserve"
			case "extra-reference":
				changed.NFTables = append(changed.NFTables, map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden", "chain": "custom", "handle": 100001, "expr": []any{map[string]any{"jump": map[string]any{"target": operatorPolicyChainName}}}}})
			case "duplicate-handle":
				changed.NFTables[indices[1]]["rule"].(map[string]any)["handle"] = selected["handle"]
			}
			if _, _, err := normalizeNFTOperatorRuntime(marshalMutableNFTVerificationFixture(t, changed), policy); err == nil {
				t.Fatal("changed or foreign operator runtime was accepted")
			}
		})
	}
}

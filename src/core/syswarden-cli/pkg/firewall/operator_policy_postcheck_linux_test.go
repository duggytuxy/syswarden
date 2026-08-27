//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"syswarden-cli/config"
)

type mutableNFTVerificationDocument struct {
	NFTables []map[string]any `json:"nftables"`
}

func operatorPolicyPostcheckPlan(t *testing.T) nftVerificationPlan {
	t.Helper()
	compiled, err := compileOperatorPolicy([]config.OperatorPolicyRule{
		{
			ID:        "alpha-v4",
			Family:    config.OperatorPolicyFamilyIPv4,
			Direction: config.OperatorPolicyDirectionIngress,
			Protocol:  config.OperatorPolicyProtocolICMP,
			ICMPType:  config.OperatorPolicyTypeEchoRequest,
			Source:    "198.51.100.42/32",
			Action:    config.OperatorPolicyActionAccept,
		},
		{
			ID:        "bravo-v6",
			Family:    config.OperatorPolicyFamilyIPv6,
			Direction: config.OperatorPolicyDirectionIngress,
			Protocol:  config.OperatorPolicyProtocolICMPv6,
			ICMPType:  config.OperatorPolicyTypeEchoRequest,
			Source:    "2001:db8::42/128",
			Action:    config.OperatorPolicyActionAccept,
		},
	})
	if err != nil {
		t.Fatalf("compile operator policy postcheck fixture: %v", err)
	}
	plan := minimalVerificationPlan(0)
	plan.chains[nftObjectKey{family: "inet", table: "syswarden", name: "stateful_protect"}] = "input"
	plan.operatorPolicy = compiled.verificationPlan()
	return plan
}

func mutableNFTVerificationFixture(t *testing.T, plan nftVerificationPlan) mutableNFTVerificationDocument {
	t.Helper()
	var document mutableNFTVerificationDocument
	if err := json.Unmarshal(nftVerificationJSON(plan, 0), &document); err != nil {
		t.Fatalf("decode mutable nft verification fixture: %v", err)
	}
	return document
}

func marshalMutableNFTVerificationFixture(t *testing.T, document mutableNFTVerificationDocument) []byte {
	t.Helper()
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal mutable nft verification fixture: %v", err)
	}
	return content
}

func nftRuleIndices(t *testing.T, document mutableNFTVerificationDocument, chain string) []int {
	t.Helper()
	var indices []int
	for index, entry := range document.NFTables {
		raw, exists := entry["rule"]
		if !exists {
			continue
		}
		rule, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("rule entry %d is not an object", index)
		}
		if rule["family"] == "inet" && rule["table"] == "syswarden" && rule["chain"] == chain {
			indices = append(indices, index)
		}
	}
	return indices
}

func nftChainAt(t *testing.T, document mutableNFTVerificationDocument, name string) map[string]any {
	t.Helper()
	for index, entry := range document.NFTables {
		raw, exists := entry["chain"]
		if !exists {
			continue
		}
		chain, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("chain entry %d is not an object", index)
		}
		if chain["family"] == "inet" && chain["table"] == "syswarden" && chain["name"] == name {
			return chain
		}
	}
	t.Fatalf("chain %s was not found", name)
	return nil
}

func nftRuleAt(t *testing.T, document mutableNFTVerificationDocument, chain string, ordinal int) map[string]any {
	t.Helper()
	indices := nftRuleIndices(t, document, chain)
	if ordinal < 0 || ordinal >= len(indices) {
		t.Fatalf("rule ordinal %d for chain %s is outside %d entries", ordinal, chain, len(indices))
	}
	rule, ok := document.NFTables[indices[ordinal]]["rule"].(map[string]any)
	if !ok {
		t.Fatalf("rule ordinal %d for chain %s is not an object", ordinal, chain)
	}
	return rule
}

func nftRuleExpressionsAt(t *testing.T, document mutableNFTVerificationDocument, chain string, ordinal int) []any {
	t.Helper()
	rule := nftRuleAt(t, document, chain, ordinal)
	expressions, ok := rule["expr"].([]any)
	if !ok {
		t.Fatalf("rule ordinal %d for chain %s has no expression array", ordinal, chain)
	}
	return expressions
}

func nftMatchAt(t *testing.T, document mutableNFTVerificationDocument, chain string, ruleOrdinal, expressionOrdinal int) map[string]any {
	t.Helper()
	expressions := nftRuleExpressionsAt(t, document, chain, ruleOrdinal)
	expression, ok := expressions[expressionOrdinal].(map[string]any)
	if !ok {
		t.Fatalf("expression %d is not an object", expressionOrdinal)
	}
	match, ok := expression["match"].(map[string]any)
	if !ok {
		t.Fatalf("expression %d is not a match", expressionOrdinal)
	}
	return match
}

func cloneNFTEntry(t *testing.T, entry map[string]any) map[string]any {
	t.Helper()
	content, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(content, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestOperatorPolicyPostcheckMatchesNFT116HostPrefixNormalization_SW_FW_006(t *testing.T) {
	plan := operatorPolicyPostcheckPlan(t)
	document := mutableNFTVerificationFixture(t, plan)

	v4Right := nftMatchAt(t, document, operatorPolicyChainName, 0, 0)["right"]
	if v4Right != "198.51.100.42" {
		t.Fatalf("IPv4 /32 source JSON = %#v, want the nft host string", v4Right)
	}
	v6Expressions := nftRuleExpressionsAt(t, document, operatorPolicyChainName, 1)
	if len(v6Expressions) != 4 {
		t.Fatalf("IPv6 /128 expression count = %d, want 4", len(v6Expressions))
	}
	v6Right := nftMatchAt(t, document, operatorPolicyChainName, 1, 0)["right"]
	if v6Right != "2001:db8::42" {
		t.Fatalf("IPv6 /128 source JSON = %#v, want the nft host string", v6Right)
	}
	encodedV6, err := json.Marshal(v6Expressions)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedV6), `"meta"`) || strings.Contains(string(encodedV6), `"ipv6-icmp"`) {
		t.Fatalf("IPv6 rule retained nft-elided l4proto expression: %s", encodedV6)
	}

	runner := newFakeNFTRunner(plan)
	runner.rulesetDocuments = [][]byte{marshalMutableNFTVerificationFixture(t, document)}
	if err := verifyNftablesState(context.Background(), runner, plan); err != nil {
		t.Fatalf("nft 1.1.6 host-normalized postcheck fixture was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*mutableNFTVerificationDocument)
	}{
		{
			name: "legacy IPv4 /32 prefix object",
			mutate: func(candidate *mutableNFTVerificationDocument) {
				nftMatchAt(t, *candidate, operatorPolicyChainName, 0, 0)["right"] = map[string]any{
					"prefix": map[string]any{"addr": "198.51.100.42", "len": float64(32)},
				}
			},
		},
		{
			name: "legacy IPv6 /128 prefix and l4proto expression",
			mutate: func(candidate *mutableNFTVerificationDocument) {
				expressions := nftRuleExpressionsAt(t, *candidate, operatorPolicyChainName, 1)
				nftMatchAt(t, *candidate, operatorPolicyChainName, 1, 0)["right"] = map[string]any{
					"prefix": map[string]any{"addr": "2001:db8::42", "len": float64(128)},
				}
				legacyMeta := map[string]any{"match": map[string]any{
					"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": "ipv6-icmp",
				}}
				rule := nftRuleAt(t, *candidate, operatorPolicyChainName, 1)
				rule["expr"] = append(append([]any{}, expressions[:1]...), append([]any{legacyMeta}, expressions[1:]...)...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := mutableNFTVerificationFixture(t, plan)
			test.mutate(&candidate)
			runner := newFakeNFTRunner(plan)
			runner.rulesetDocuments = [][]byte{marshalMutableNFTVerificationFixture(t, candidate)}
			if err := verifyNftablesState(context.Background(), runner, plan); err == nil {
				t.Fatal("legacy non-normalized operator policy unexpectedly passed exact postcheck")
			}
		})
	}
}

func TestOperatorPolicyPostcheckKeepsZeroLengthPrefixes_SW_FW_006(t *testing.T) {
	for _, test := range []operatorPolicyRuleExpectation{
		{family: config.OperatorPolicyFamilyIPv4, source: "0.0.0.0/0"},
		{family: config.OperatorPolicyFamilyIPv6, source: "::/0"},
	} {
		expressions, err := expectedOperatorPolicyExpressions(test)
		if err != nil {
			t.Fatal(err)
		}
		match := expressions[0].(map[string]any)["match"].(map[string]any)
		right, ok := match["right"].(map[string]any)
		if !ok || right["prefix"] == nil {
			t.Fatalf("zero-length source %q normalized to %#v, want a prefix object", test.source, match["right"])
		}
	}
}

func TestOperatorPolicyPostcheckIsExactAndFailClosed_SW_FW_006(t *testing.T) {
	plan := operatorPolicyPostcheckPlan(t)
	baseline := nftVerificationJSON(plan, 0)
	runner := newFakeNFTRunner(plan)
	runner.rulesetDocuments = [][]byte{baseline}
	if err := verifyNftablesState(context.Background(), runner, plan); err != nil {
		t.Fatalf("exact operator policy postcheck fixture was rejected: %v", err)
	}

	positive := mutableNFTVerificationFixture(t, plan)
	first := nftRuleAt(t, positive, operatorPolicyChainName, 0)
	first["handle"] = float64(999999)
	firstCounter := nftRuleExpressionsAt(t, positive, operatorPolicyChainName, 0)[3].(map[string]any)["counter"].(map[string]any)
	firstCounter["packets"] = float64(999999)
	firstCounter["bytes"] = float64(888888)
	runner = newFakeNFTRunner(plan)
	runner.rulesetDocuments = [][]byte{marshalMutableNFTVerificationFixture(t, positive)}
	if err := verifyNftablesState(context.Background(), runner, plan); err != nil {
		t.Fatalf("runtime handle/counter changes were not ignored: %v", err)
	}

	foreignHomonym := mutableNFTVerificationFixture(t, plan)
	foreignHomonym.NFTables = append(
		foreignHomonym.NFTables,
		map[string]any{"chain": map[string]any{
			"family": "inet", "table": "third_party", "name": operatorPolicyChainName, "handle": float64(700),
		}},
		nftVerificationRuleEntry(
			"inet",
			"third_party",
			operatorPolicyChainName,
			701,
			operatorPolicyCommentPrefix+"third-party",
			[]any{map[string]any{"accept": nil}},
		),
		nftVerificationRuleEntry(
			"inet",
			"third_party",
			"input",
			702,
			operatorPolicyDispatchComment,
			[]any{map[string]any{"jump": map[string]any{"target": operatorPolicyChainName}}},
		),
	)
	runner = newFakeNFTRunner(plan)
	runner.rulesetDocuments = [][]byte{marshalMutableNFTVerificationFixture(t, foreignHomonym)}
	if err := verifyNftablesState(context.Background(), runner, plan); err != nil {
		t.Fatalf("table-scoped foreign operator-policy homonym was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*mutableNFTVerificationDocument)
		want   string
	}{
		{
			name: "missing rule handle",
			mutate: func(document *mutableNFTVerificationDocument) {
				delete(nftRuleAt(t, *document, operatorPolicyChainName, 0), "handle")
			},
			want: `rule field "handle" is missing`,
		},
		{
			name: "missing chain handle",
			mutate: func(document *mutableNFTVerificationDocument) {
				delete(nftChainAt(t, *document, operatorPolicyChainName), "handle")
			},
			want: `chain field "handle" is missing`,
		},
		{
			name: "counter missing packets",
			mutate: func(document *mutableNFTVerificationDocument) {
				counter := nftRuleExpressionsAt(t, *document, operatorPolicyChainName, 0)[3].(map[string]any)["counter"].(map[string]any)
				delete(counter, "packets")
			},
			want: "exactly packets and bytes",
		},
		{
			name: "counter missing bytes",
			mutate: func(document *mutableNFTVerificationDocument) {
				counter := nftRuleExpressionsAt(t, *document, operatorPolicyChainName, 0)[3].(map[string]any)["counter"].(map[string]any)
				delete(counter, "bytes")
			},
			want: "exactly packets and bytes",
		},
		{
			name: "counter negative",
			mutate: func(document *mutableNFTVerificationDocument) {
				counter := nftRuleExpressionsAt(t, *document, operatorPolicyChainName, 0)[3].(map[string]any)["counter"].(map[string]any)
				counter["packets"] = float64(-1)
			},
			want: "non-negative integer",
		},
		{
			name: "counter non-numeric",
			mutate: func(document *mutableNFTVerificationDocument) {
				counter := nftRuleExpressionsAt(t, *document, operatorPolicyChainName, 0)[3].(map[string]any)["counter"].(map[string]any)
				counter["bytes"] = "2048"
			},
			want: "non-negative integer",
		},
		{
			name: "missing rule",
			mutate: func(document *mutableNFTVerificationDocument) {
				index := nftRuleIndices(t, *document, operatorPolicyChainName)[0]
				document.NFTables = append(document.NFTables[:index], document.NFTables[index+1:]...)
			},
			want: "chain contains",
		},
		{
			name: "extra rule",
			mutate: func(document *mutableNFTVerificationDocument) {
				index := nftRuleIndices(t, *document, operatorPolicyChainName)[0]
				document.NFTables = append(document.NFTables, cloneNFTEntry(t, document.NFTables[index]))
			},
			want: "chain contains",
		},
		{
			name: "reordered rules",
			mutate: func(document *mutableNFTVerificationDocument) {
				indices := nftRuleIndices(t, *document, operatorPolicyChainName)
				document.NFTables[indices[0]], document.NFTables[indices[1]] = document.NFTables[indices[1]], document.NFTables[indices[0]]
			},
			want: "rule 0 mismatch",
		},
		{
			name: "source",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftMatchAt(t, *document, operatorPolicyChainName, 0, 0)["right"] = "198.51.100.43"
			},
			want: "rule 0 mismatch",
		},
		{
			name: "family",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftRuleAt(t, *document, operatorPolicyChainName, 0)["family"] = "ip"
			},
			want: "chain contains",
		},
		{
			name: "protocol",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftMatchAt(t, *document, operatorPolicyChainName, 0, 1)["right"] = "tcp"
			},
			want: "rule 0 mismatch",
		},
		{
			name: "icmp type",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftMatchAt(t, *document, operatorPolicyChainName, 0, 2)["right"] = "echo-reply"
			},
			want: "rule 0 mismatch",
		},
		{
			name: "accept verdict",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftRuleExpressionsAt(t, *document, operatorPolicyChainName, 0)[4] = map[string]any{"drop": nil}
			},
			want: "rule 0 mismatch",
		},
		{
			name: "comment",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftRuleAt(t, *document, operatorPolicyChainName, 0)["comment"] = operatorPolicyCommentPrefix + "wrong"
			},
			want: "rule 0 mismatch",
		},
		{
			name: "jump target",
			mutate: func(document *mutableNFTVerificationDocument) {
				expression := nftRuleExpressionsAt(t, *document, "stateful_protect", 0)[0].(map[string]any)
				expression["jump"].(map[string]any)["target"] = "elsewhere"
			},
			want: "dispatch mismatch",
		},
		{
			name: "dispatch position",
			mutate: func(document *mutableNFTVerificationDocument) {
				indices := nftRuleIndices(t, *document, "stateful_protect")
				entry := nftVerificationRuleEntry("inet", "syswarden", "stateful_protect", 777, "", []any{map[string]any{"accept": nil}})
				position := indices[0] + 1
				document.NFTables = append(document.NFTables, nil)
				copy(document.NFTables[position+1:], document.NFTables[position:])
				document.NFTables[position] = entry
			},
			want: "dispatch mismatch",
		},
		{
			name: "marker elsewhere in syswarden table",
			mutate: func(document *mutableNFTVerificationDocument) {
				document.NFTables = append(document.NFTables, nftVerificationRuleEntry(
					"inet", "syswarden", "other", 778, operatorPolicyCommentPrefix+"foreign", []any{map[string]any{"accept": nil}},
				))
			},
			want: "comment marker exists outside",
		},
		{
			name: "unexpected syswarden table reference",
			mutate: func(document *mutableNFTVerificationDocument) {
				document.NFTables = append(document.NFTables, nftVerificationRuleEntry(
					"inet",
					"syswarden",
					"other",
					779,
					"",
					[]any{map[string]any{"jump": map[string]any{"target": operatorPolicyChainName}}},
				))
			},
			want: "unexpected jump reference",
		},
		{
			name: "terminal return",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftRuleExpressionsAt(t, *document, operatorPolicyChainName, len(plan.operatorPolicy.rules))[0] = map[string]any{"accept": nil}
			},
			want: "terminal return mismatch",
		},
		{
			name: "catch-all prefix",
			mutate: func(document *mutableNFTVerificationDocument) {
				expression := nftRuleExpressionsAt(t, *document, "stateful_protect", 1)[2].(map[string]any)
				expression["log"].(map[string]any)["prefix"] = "wrong"
			},
			want: "catch-all log mismatch",
		},
		{
			name: "legacy catch-all ct state operator",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftMatchAt(t, *document, "stateful_protect", 1, 0)["op"] = "=="
			},
			want: "catch-all log mismatch",
		},
		{
			name: "drop counter",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftRuleExpressionsAt(t, *document, "stateful_protect", 2)[1] = map[string]any{"accept": nil}
			},
			want: "catch-all drop mismatch",
		},
		{
			name: "unknown top-level rule field",
			mutate: func(document *mutableNFTVerificationDocument) {
				nftRuleAt(t, *document, operatorPolicyChainName, 0)["index"] = float64(1)
			},
			want: "unexpected top-level field",
		},
	}
	for _, field := range []string{"hook", "type", "prio", "policy", "dev", "unknown"} {
		field := field
		tests = append(tests, struct {
			name   string
			mutate func(*mutableNFTVerificationDocument)
			want   string
		}{
			name: "regular chain rejects " + field,
			mutate: func(document *mutableNFTVerificationDocument) {
				value := any("unexpected")
				if field == "prio" {
					value = float64(0)
				}
				nftChainAt(t, *document, operatorPolicyChainName)[field] = value
			},
			want: "regular chain contains unexpected field",
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := mutableNFTVerificationFixture(t, plan)
			test.mutate(&document)
			runner := newFakeNFTRunner(plan)
			runner.rulesetDocuments = [][]byte{marshalMutableNFTVerificationFixture(t, document)}
			err := verifyNftablesState(context.Background(), runner, plan)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("postcheck error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestOperatorPolicyPostcheckFailureRollsBackWithoutPublication_SW_FW_006(t *testing.T) {
	plan := operatorPolicyPostcheckPlan(t)
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := mutableNFTVerificationFixture(t, plan)
	nftMatchAt(t, document, operatorPolicyChainName, 0, 0)["right"] = "198.51.100.43"
	runner := newFakeNFTRunner(plan, nftTableTarget{family: "inet", name: "syswarden"})
	runner.rulesetDocuments = [][]byte{
		nftVerificationJSONWithoutDynamicBans(plan),
		marshalMutableNFTVerificationFixture(t, document),
	}
	_, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), nil, plan)
	if err == nil || !strings.Contains(err.Error(), "post-apply verification failed") {
		t.Fatalf("transaction error = %v, want postcheck failure", err)
	}
	if runner.rollbackApplyCalls != 1 {
		t.Fatalf("rollback apply calls = %d, want 1", runner.rollbackApplyCalls)
	}
	content, readErr := os.ReadFile(statePath) // #nosec G304 -- statePath is the fixed persisted-policy filename beneath this test's private state directory
	if readErr != nil || string(content) != "known-good\n" {
		t.Fatalf("unverified policy was published: content=%q error=%v", content, readErr)
	}
}

//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func fixtureNFTOperatorCurrent(t *testing.T, index int) (nftCurrentFileFixture, []config.OperatorPolicyRule, []byte) {
	t.Helper()
	fixture := fixtureNFTCurrentFiles(t)[index]
	rules := fixtureNFTOperatorReceiverRules()
	empty, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compileOperatorPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(fixture.Source, empty.chain) != 1 {
		t.Fatal("fixture lacks exact empty operator chain")
	}
	fixture.Source = strings.Replace(fixture.Source, empty.chain, compiled.chain, 1)
	var doc mutableNFTVerificationDocument
	if err := json.Unmarshal(fixture.InetJSON, &doc); err != nil {
		t.Fatal(err)
	}
	entries := make([]map[string]any, 0, len(doc.NFTables)+len(rules))
	inserted := false
	for _, entry := range doc.NFTables {
		rule, ok := entry["rule"].(map[string]any)
		if ok && rule["comment"] == operatorPolicyReturnComment {
			if inserted {
				t.Fatal("duplicate operator return")
			}
			for i, expected := range compiled.verification.rules {
				expressions, err := expectedOperatorPolicyExpressions(expected)
				if err != nil {
					t.Fatal(err)
				}
				expressions[len(expressions)-2] = map[string]any{"counter": map[string]any{"packets": 21 + i, "bytes": 4200 + i}}
				entries = append(entries, map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden", "chain": operatorPolicyChainName, "handle": 800000 + i, "comment": expected.comment, "expr": expressions}})
			}
			inserted = true
		}
		entries = append(entries, entry)
	}
	if !inserted {
		t.Fatal("fixture lacks operator return")
	}
	doc.NFTables = entries
	fixture.InetJSON = marshalMutableNFTVerificationFixture(t, doc)
	receipt, err := prepareNFTPolicyOwnership([]byte(fixture.Source), &nftPolicyGeneration{Base: fixture.inputs().Base, OperatorChain: compiled.chain}, recoveryFixtureTransactionID)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, rules, receipt
}

func TestNFTOperatorCurrentIndependentFullSourceAndRuntime(t *testing.T) {
	for index := range fixtureNFTCurrentFiles(t) {
		fixture, rules, receipt := fixtureNFTOperatorCurrent(t, index)
		source, live := []byte(fixture.Source), bytes.Clone(fixture.InetJSON)
		if _, err := currentNFTInputsFromOwnership(source, receipt); err == nil {
			t.Fatal("ordinary retirement adopted embedded administrator policy")
		}
		preservation := &nftPreservedOperatorInputs{Rules: rules, Proof: strings.Repeat("a", 64)}
		input, err := currentNFTInputsFromPreservedOwnership(source, receipt, preservation)
		if err != nil {
			t.Fatal(index, err)
		}
		evidence, err := inspectNFTCurrentPersistenceRuntime(source, live, fixture.NetdevJSON, fixture.ARPJSON, input)
		if err != nil {
			t.Fatal(index, err)
		}
		if evidence.sourceSHA256 != nftSHA256Hex(source) || !bytes.Equal(live, fixture.InetJSON) || !bytes.Equal(source, []byte(fixture.Source)) {
			t.Fatal("analysis changed original evidence or substituted its digest")
		}
		original := input.Operator.Rules[0].Source
		preservation.Rules[0].Source = "192.0.2.12/32"
		if input.Operator.Rules[0].Source != original {
			t.Fatal("caller mutation changed bound typed policy")
		}
	}
}

func TestNFTOperatorCurrentRefusesMissingOrChangedBoundaries(t *testing.T) {
	for _, kind := range []string{"missing-proof", "malformed-proof", "empty-policy", "different-policy", "source-change", "runtime-change", "changed-population", "changed-ingress", "changed-arp"} {
		t.Run(kind, func(t *testing.T) {
			fixture, rules, receipt := fixtureNFTOperatorCurrent(t, 7)
			source := []byte(fixture.Source)
			preservation := &nftPreservedOperatorInputs{Rules: rules, Proof: strings.Repeat("a", 64)}
			switch kind {
			case "missing-proof":
				preservation = nil
			case "malformed-proof":
				preservation.Proof = strings.Repeat("A", 64)
			case "empty-policy":
				preservation.Rules = nil
			case "different-policy":
				preservation.Rules[0].Source = "192.0.2.12/32"
			case "source-change":
				source = bytes.Replace(source, []byte("counter accept"), []byte("counter drop"), 1)
			case "runtime-change":
				fixture.InetJSON = bytes.Replace(fixture.InetJSON, []byte("198.51.100.42"), []byte("198.51.100.43"), 1)
			case "changed-population":
				fixture.InetJSON = bytes.Replace(fixture.InetJSON, []byte("192.0.2.0"), []byte("192.0.3.0"), 1)
			case "changed-ingress":
				fixture.NetdevJSON = bytes.Replace(fixture.NetdevJSON, []byte("drop"), []byte("accept"), 1)
			case "changed-arp":
				fixture.ARPJSON = append(fixture.ARPJSON, []byte("garbage")...)
			}
			input, err := currentNFTInputsFromPreservedOwnership(source, receipt, preservation)
			if err == nil {
				_, err = inspectNFTCurrentPersistenceRuntime(source, fixture.InetJSON, fixture.NetdevJSON, fixture.ARPJSON, input)
			}
			if err == nil {
				t.Fatal("unproven or changed product boundary accepted", kind)
			}
		})
	}
}

func TestNFTOperatorCurrentKeepsOldInputEncoding(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[0]
	before, err := json.Marshal(struct {
		Base        nftV4028PersistenceInputs `json:"base"`
		Populations []nftCurrentPopulation    `json:"populations"`
	}{fixture.inputs().Base, fixture.Populations})
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(fixture.inputs())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("empty optional extension changed old canonical journal bytes", err)
	}
}

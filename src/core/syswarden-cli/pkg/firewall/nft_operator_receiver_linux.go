//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"syswarden-cli/config"
)

const nftOperatorReceiverCommentPrefix = "operator:preserved:v1:"

// This model describes a separately managed receiving policy. Rendering or
// observing it grants no authority to remove the original administrator policy.
// A production handoff must separately bind its owner, loader and configuration.
type nftOperatorReceiverModel struct {
	table  string
	source []byte
	rules  []operatorPolicyRuleExpectation
}

type nftOperatorCounterObservation struct {
	Rule    string `json:"rule"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func prepareNFTOperatorReceiver(rules []config.OperatorPolicyRule) (nftOperatorReceiverModel, error) {
	var empty nftOperatorReceiverModel
	policy, err := compileOperatorPolicy(rules)
	if err != nil || !policy.enabled() {
		return empty, fmt.Errorf("independent operator receiver requires a nonempty supported typed policy")
	}
	table := "operator_preserved_" + nftSHA256Hex([]byte(policy.chain))[:20]
	prefix := "\tchain " + operatorPolicyChainName + " {\n"
	suffix := fmt.Sprintf("\t\treturn comment %q\n\t}\n\n", operatorPolicyReturnComment)
	if !strings.HasPrefix(policy.chain, prefix) || !strings.HasSuffix(policy.chain, suffix) {
		return empty, fmt.Errorf("operator compiler output has an unsupported envelope")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(policy.chain, prefix), suffix)
	body = strings.ReplaceAll(body, operatorPolicyCommentPrefix, nftOperatorReceiverCommentPrefix)
	source := []byte("table inet " + table + " {\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n" + body + "\t}\n}\n")
	expected := append([]operatorPolicyRuleExpectation(nil), policy.verification.rules...)
	for i := range expected {
		expected[i].comment = strings.Replace(expected[i].comment, operatorPolicyCommentPrefix, nftOperatorReceiverCommentPrefix, 1)
	}
	return nftOperatorReceiverModel{table, source, expected}, nil
}

// An input accept chain does not bypass drops in other base chains. This exact
// verifier covers the receiver only; it does not establish whole-host behavior.
// Counter values are captured as observations, never promised to be a continuous
// counter epoch shared with the original chain.
func (model nftOperatorReceiverModel) inspect(content []byte) ([]nftOperatorCounterObservation, error) {
	if len(model.rules) == 0 || len(model.rules) > maximumCompiledOperatorPolicyRules || len(content) > 256<<10 {
		return nil, fmt.Errorf("operator receiver observation exceeds its bound")
	}
	document, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		return nil, err
	}
	entries, ok := document["nftables"].([]any)
	if !ok || len(document) != 1 || len(entries) > len(model.rules)+3 {
		return nil, fmt.Errorf("operator receiver observation has additional objects")
	}
	tableSeen, chainSeen, metaSeen := false, false, false
	index := 0
	handles := map[string]bool{}
	var counters []nftOperatorCounterObservation
	for _, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, fmt.Errorf("operator receiver object is ambiguous")
		}
		if _, exists := wrapper["metainfo"]; exists {
			if metaSeen {
				return nil, fmt.Errorf("duplicate receiver metadata")
			}
			metaSeen = true
			continue
		}
		if object, ok := wrapper["table"].(map[string]any); ok {
			if tableSeen || chainSeen || index != 0 || !legacyFail2banNFTFields(object, "family name handle", "") || object["family"] != "inet" || object["name"] != model.table || !nftOperatorPositiveHandle(object["handle"]) {
				return nil, fmt.Errorf("operator receiver table differs from the independent model")
			}
			tableSeen = true
			continue
		}
		if object, ok := wrapper["chain"].(map[string]any); ok {
			if !tableSeen || chainSeen || index != 0 || !legacyFail2banNFTFields(object, "family table name handle type hook prio policy", "") || object["family"] != "inet" || object["table"] != model.table || object["name"] != "input" || object["type"] != "filter" || object["hook"] != "input" || !nftJSONExactNumber(object["prio"], "0") || object["policy"] != "accept" || !nftOperatorPositiveHandle(object["handle"]) {
				return nil, fmt.Errorf("operator receiver base-chain behavior differs from the independent model")
			}
			chainSeen = true
			continue
		}
		object, ok := wrapper["rule"].(map[string]any)
		if !ok || !chainSeen || index >= len(model.rules) || !nftOperatorPositiveHandle(object["handle"]) {
			return nil, fmt.Errorf("operator receiver has an unexpected object or rule")
		}
		handle := object["handle"].(json.Number).String()
		if handles[handle] {
			return nil, fmt.Errorf("duplicate operator receiver rule handle")
		}
		handles[handle] = true
		wire, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		var rule nftJSONRule
		if err := json.Unmarshal(wire, &rule); err != nil {
			return nil, err
		}
		expected := model.rules[index]
		expressions, err := expectedOperatorPolicyExpressions(expected)
		if err != nil {
			return nil, err
		}
		if err := verifyNFTJSONRuleExact(&rule, "inet", model.table, "input", expected.comment, expressions); err != nil {
			return nil, err
		}
		observation, err := nftOperatorCounterFromRule(rule, expected.comment)
		if err != nil {
			return nil, err
		}
		counters = append(counters, observation)
		index++
	}
	if !tableSeen || !chainSeen || index != len(model.rules) {
		return nil, fmt.Errorf("operator receiver observation is incomplete")
	}
	return counters, nil
}

func nftOperatorPositiveHandle(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	return err == nil && parsed != 0 && strconv.FormatUint(parsed, 10) == number.String()
}

func nftOperatorCounterFromRule(rule nftJSONRule, comment string) (nftOperatorCounterObservation, error) {
	result := nftOperatorCounterObservation{Rule: comment}
	count := 0
	for _, raw := range rule.Expressions {
		object, err := decodeNFTJSONObject(raw)
		if err != nil {
			return result, err
		}
		counter, present := object["counter"]
		if !present {
			continue
		}
		if _, err := canonicalNFTJSONExpression(raw); err != nil {
			return result, err
		}
		fields, ok := counter.(map[string]any)
		if !ok || count != 0 {
			return result, fmt.Errorf("operator counter observation is ambiguous")
		}
		packets, pok := fields["packets"].(json.Number)
		octets, bok := fields["bytes"].(json.Number)
		if !pok || !bok {
			return result, fmt.Errorf("operator counter observation is not integral")
		}
		result.Packets, err = strconv.ParseUint(packets.String(), 10, 64)
		if err != nil {
			return result, err
		}
		result.Bytes, err = strconv.ParseUint(octets.String(), 10, 64)
		if err != nil {
			return result, err
		}
		count++
	}
	if count != 1 {
		return result, fmt.Errorf("operator counter observation is missing")
	}
	return result, nil
}

// Normalize only an analysis copy after the exact typed original chain has been
// matched. The full existing product renderer must still validate the result.
// Original evidence is never rewritten, and this grants no deletion authority.
func normalizeNFTOperatorSource(source []byte, rules []config.OperatorPolicyRule) ([]byte, error) {
	compiled, err := compileOperatorPolicy(rules)
	if err != nil || !compiled.enabled() {
		return nil, fmt.Errorf("operator source analysis requires a supported nonempty policy")
	}
	empty, err := compileOperatorPolicy(nil)
	if err != nil {
		return nil, err
	}
	if len(source) > maximumNFTPersistenceBytes || bytes.Count(source, []byte(compiled.chain)) != 1 {
		return nil, fmt.Errorf("product source does not contain exactly the independently compiled operator policy")
	}
	return bytes.Replace(source, []byte(compiled.chain), []byte(empty.chain), 1), nil
}

// The returned copy omits only rules already verified against independently
// supplied typed policy. The caller must still verify the complete product
// topology and prove independent preservation before using any removal path.
func normalizeNFTOperatorRuntime(content []byte, rules []config.OperatorPolicyRule) ([]byte, []nftOperatorCounterObservation, error) {
	compiled, err := compileOperatorPolicy(rules)
	if err != nil || !compiled.enabled() || len(content) > maximumNFTPersistenceBytes {
		return nil, nil, fmt.Errorf("operator runtime analysis requires a bounded supported policy")
	}
	document, err := decodeNFTJSON(content)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyOperatorPolicyNFTState(document, compiled.verification); err != nil {
		return nil, nil, err
	}
	raw, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		return nil, nil, err
	}
	entries, ok := raw["nftables"].([]any)
	if !ok || len(raw) != 1 {
		return nil, nil, fmt.Errorf("operator runtime document is ambiguous")
	}
	kept := make([]any, 0, len(entries))
	counters := make([]nftOperatorCounterObservation, 0, len(rules))
	seen := map[uint64]bool{}
	for _, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, nil, fmt.Errorf("operator runtime object is ambiguous")
		}
		object, isRule := wrapper["rule"].(map[string]any)
		if !isRule || object["family"] != "inet" || object["table"] != "syswarden" || object["chain"] != operatorPolicyChainName || object["comment"] == operatorPolicyReturnComment {
			kept = append(kept, entry)
			continue
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, nil, err
		}
		var rule nftJSONRule
		if err := json.Unmarshal(encoded, &rule); err != nil {
			return nil, nil, err
		}
		if rule.Handle == 0 || seen[rule.Handle] {
			return nil, nil, fmt.Errorf("operator runtime rule identity is missing or duplicated")
		}
		seen[rule.Handle] = true
		counter, err := nftOperatorCounterFromRule(rule, rule.Comment)
		if err != nil {
			return nil, nil, err
		}
		counters = append(counters, counter)
	}
	if len(counters) != len(compiled.verification.rules) {
		return nil, nil, fmt.Errorf("operator runtime policy coverage changed during analysis")
	}
	raw["nftables"] = kept
	normalized, err := json.Marshal(raw)
	return normalized, counters, err
}

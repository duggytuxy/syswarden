//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const ipv6ControlPlaneVersion = "ipv6-host-v1"
const ipv6ControlPlaneChain = "ipv6-control-plane"
const ipv6ControlPlaneDispatch = "\t\tjump ipv6-control-plane\n"

// IPv6 infrastructure traffic must precede source reputation, strict geographic
// policy and conntrack filtering. ND can be untracked; an ICMP error can describe
// a flow whose conntrack entry has expired. This is not an application allowlist.
// RFC 4861 requires hop limit 255 for ND and a link-local source for RA. DAD NS
// uses ::, while other NS/NA messages may use a global source. MLD uses hop 1.
// RFC 9915 section 7.2 permits nonstandard DHCPv6 source ports, so only the IPv6
// client destination is fixed. Redirects and unsolicited echo remain policy-bound.
func ipv6ControlPlaneSource(family string) string {
	selector := "meta nfproto ipv6"
	if family == "netdev" {
		selector = "meta protocol ip6"
	}
	return "\tchain ipv6-control-plane {\n" +
		"\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept\n" +
		"\t\tip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type nd-router-advert icmpv6 code 0 accept\n" +
		"\t\tip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } icmpv6 code 0 accept\n" +
		"\t\tip6 saddr { ::/128, fe80::/10 } ip6 hoplimit 255 icmpv6 type nd-router-solicit icmpv6 code 0 accept\n" +
		"\t\tip6 saddr fe80::/10 ip6 hoplimit 1 icmpv6 type mld-listener-query icmpv6 code 0 accept\n" +
		"\t\tip6 saddr { ::/128, fe80::/10 } ip6 hoplimit 1 icmpv6 type { mld-listener-report, mld-listener-done, mld2-listener-report } icmpv6 code 0 accept\n" +
		"\t\t" + selector + " udp dport 546 accept\n" +
		"\t\treturn\n\t}\n"
}

// Keep the semantic expectation independent of the textual renderer. The
// isolated kernel tests compare real nft JSON with this complete rule model.
func ipv6ControlPlaneExpressions(family string) [][]any {
	match := func(protocol, field string, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}, "right": right}}
	}
	types := func(names ...string) any { return match("icmpv6", "type", map[string]any{"set": names}) }
	linkLocal := map[string]any{"prefix": map[string]any{"addr": "fe80::", "len": 10}}
	localOrUnspecified := map[string]any{"set": []any{"::", linkLocal}}
	hop := func(n int) any { return match("ip6", "hoplimit", n) }
	code := match("icmpv6", "code", 0)
	accept := map[string]any{"accept": nil}
	key, value := "nfproto", "ipv6"
	if family == "netdev" {
		key, value = "protocol", "ip6"
	}
	return [][]any{
		{types("destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem"), accept},
		{match("ip6", "saddr", linkLocal), hop(255), match("icmpv6", "type", "nd-router-advert"), code, accept},
		{hop(255), types("nd-neighbor-solicit", "nd-neighbor-advert"), code, accept},
		{match("ip6", "saddr", localOrUnspecified), hop(255), match("icmpv6", "type", "nd-router-solicit"), code, accept},
		{match("ip6", "saddr", linkLocal), hop(1), match("icmpv6", "type", "mld-listener-query"), code, accept},
		{match("ip6", "saddr", localOrUnspecified), hop(1), types("mld-listener-report", "mld-listener-done", "mld2-listener-report"), code, accept},
		{map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": key}}, "right": value}}, match("udp", "dport", 546), accept},
		{map[string]any{"return": nil}},
	}
}

const ipv6CodeZeroJSON = `{"match":{"left":{"payload":{"field":"code","protocol":"icmpv6"}},"op":"==","right":0}}`
const ipv6CodeZeroSymbolJSON = `{"match":{"left":{"payload":{"field":"code","protocol":"icmpv6"}},"op":"==","right":"no-route"}}`

func verifyIPv6ControlPlaneRule(rule *nftJSONRule, family, table string, expected []any) error {
	// nftables 1.0.9 renders the generic ICMPv6 code-zero datatype as
	// "no-route", including for ND and MLD. Accept only this exact expression
	// alias. Preserve the original observation and reject all extra fields.
	normalized := *rule
	normalized.Expressions = append([]json.RawMessage(nil), rule.Expressions...)
	for index, expression := range rule.Expressions {
		canonical, err := canonicalNFTJSONExpression(expression)
		if err != nil {
			return err
		}
		if bytes.Equal(canonical, []byte(ipv6CodeZeroSymbolJSON)) {
			normalized.Expressions[index] = json.RawMessage(ipv6CodeZeroJSON)
		}
	}
	return verifyNFTJSONRuleExact(&normalized, family, table, ipv6ControlPlaneChain, "", expected)
}

func ipv6ControlPlaneTarget(family string) (string, string, error) {
	switch family {
	case "inet":
		return "syswarden", "stateful_protect", nil
	case "netdev":
		return "syswarden_hw_drop", "ingress_frontline", nil
	default:
		return "", "", fmt.Errorf("unsupported IPv6 control-plane family")
	}
}

func verifyIPv6ControlPlane(document nftJSONDocument, family string) error {
	table, baseChain, err := ipv6ControlPlaneTarget(family)
	if err != nil {
		return err
	}
	wanted := ipv6ControlPlaneExpressions(family)
	chains, rules, dispatches, baseRules := 0, 0, 0, 0
	for _, entry := range document.NFTables {
		if chain := entry.Chain; chain != nil && chain.Family == family && chain.Table == table && chain.Name == ipv6ControlPlaneChain {
			chains++
			if chain.Handle == 0 {
				return fmt.Errorf("IPv6 control-plane chain has no kernel identity")
			}
			if err := verifyOperatorPolicyChainEnvelope(chain); err != nil {
				return fmt.Errorf("IPv6 control-plane chain: %w", err)
			}
		}
		rule := entry.Rule
		if rule == nil || rule.Family != family || rule.Table != table {
			continue
		}
		if rule.Chain == ipv6ControlPlaneChain {
			if rule.Handle == 0 {
				return fmt.Errorf("IPv6 control-plane rule has no kernel identity")
			}
			if rules >= len(wanted) {
				return fmt.Errorf("extra IPv6 control-plane rule")
			}
			if err := verifyIPv6ControlPlaneRule(rule, family, table, wanted[rules]); err != nil {
				return fmt.Errorf("IPv6 control-plane rule %d: %w", rules, err)
			}
			rules++
			continue
		}
		if rule.Chain == baseChain {
			if baseRules == 0 {
				if rule.Handle == 0 {
					return fmt.Errorf("IPv6 control-plane dispatch has no kernel identity")
				}
				if err := verifyNFTJSONRuleExact(rule, family, table, baseChain, "", []any{map[string]any{"jump": map[string]any{"target": ipv6ControlPlaneChain}}}); err != nil {
					return fmt.Errorf("IPv6 control-plane must be the first base-chain rule: %w", err)
				}
				dispatches++
				baseRules++
				continue
			}
			baseRules++
		}
		for _, expression := range rule.Expressions {
			if bytes.Contains(expression, []byte(ipv6ControlPlaneChain)) {
				return fmt.Errorf("unexpected additional IPv6 control-plane reference")
			}
		}
	}
	if chains != 1 || rules != len(wanted) || dispatches != 1 {
		return fmt.Errorf("incomplete IPv6 control-plane topology")
	}
	return nil
}

// Strip only the exact version-bound extension before checking the unchanged
// historical base model. An absent marker retains the old ownership contract.
func normalizeIPv6ControlPlaneSource(source []byte, version string) ([]byte, error) {
	if version == "" {
		return source, nil
	}
	if version != ipv6ControlPlaneVersion || len(source) > maximumNFTPersistenceBytes {
		return nil, fmt.Errorf("unsupported IPv6 control-plane ownership generation")
	}
	result := bytes.Clone(source)
	for _, family := range []string{"netdev", "inet"} {
		_, baseChain, _ := ipv6ControlPlaneTarget(family)
		start := bytes.Index(result, []byte("\tchain "+baseChain+" {\n"))
		if start < 0 {
			return nil, fmt.Errorf("IPv6 control-plane base chain is absent")
		}
		headerEnd := bytes.IndexByte(result[start+len("\tchain "+baseChain+" {\n"):], '\n')
		if headerEnd < 0 {
			return nil, fmt.Errorf("IPv6 control-plane base chain header is incomplete")
		}
		firstRule := start + len("\tchain "+baseChain+" {\n") + headerEnd + 1
		if !bytes.HasPrefix(result[firstRule:], []byte(ipv6ControlPlaneDispatch)) {
			return nil, fmt.Errorf("IPv6 control-plane dispatch is not first in its base chain")
		}
		chain := []byte(ipv6ControlPlaneSource(family))
		if bytes.Count(result, chain) != 1 || !bytes.Contains(result, append(bytes.Clone(chain), []byte("\tchain "+baseChain+" {\n")...)) {
			return nil, fmt.Errorf("IPv6 control-plane source differs from its exact generation")
		}
		result = bytes.Replace(result, chain, nil, 1)
	}
	if bytes.Count(result, []byte(ipv6ControlPlaneDispatch)) != 2 {
		return nil, fmt.Errorf("IPv6 control-plane dispatch coverage differs")
	}
	return bytes.ReplaceAll(result, []byte(ipv6ControlPlaneDispatch), nil), nil
}

func normalizeIPv6ControlPlaneRuntime(content []byte, family, version string) ([]byte, error) {
	if version == "" {
		return content, nil
	}
	if version != ipv6ControlPlaneVersion || len(content) > maximumNFTPersistenceBytes {
		return nil, fmt.Errorf("unsupported IPv6 control-plane runtime generation")
	}
	document, err := decodeNFTJSON(content)
	if err != nil {
		return nil, err
	}
	if err := verifyIPv6ControlPlane(document, family); err != nil {
		return nil, err
	}
	raw, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		return nil, err
	}
	entries, ok := raw["nftables"].([]any)
	if !ok || len(raw) != 1 {
		return nil, fmt.Errorf("ambiguous IPv6 control-plane runtime document")
	}
	table, baseChain, _ := ipv6ControlPlaneTarget(family)
	kept := make([]any, 0, len(entries))
	seen := make(map[string]bool)
	for _, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, fmt.Errorf("ambiguous IPv6 control-plane runtime object")
		}
		omit := false
		for kind, value := range wrapper {
			object, ok := value.(map[string]any)
			if !ok || object["family"] != family || object["table"] != table {
				continue
			}
			// Validate identities before stripping so a duplicate cannot vanish.
			handle, ok := object["handle"].(json.Number)
			if !ok || !validNFTPositiveHandle(handle) || seen[handle.String()] {
				return nil, fmt.Errorf("missing or duplicate IPv6 control-plane object identity")
			}
			seen[handle.String()] = true
			omit = kind == "chain" && object["name"] == ipv6ControlPlaneChain || kind == "rule" && object["chain"] == ipv6ControlPlaneChain
			if kind == "rule" && object["chain"] == baseChain {
				encoded, err := json.Marshal(object["expr"])
				if err != nil {
					return nil, err
				}
				omit = strings.Contains(string(encoded), ipv6ControlPlaneChain)
			}
		}
		if !omit {
			kept = append(kept, entry)
		}
	}
	raw["nftables"] = kept
	return json.Marshal(raw)
}

func validNFTPositiveHandle(value json.Number) bool {
	number, err := value.Int64()
	return err == nil && number > 0
}

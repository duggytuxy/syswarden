//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const strictAllowForwardVersion = "protected-ingress-v1"

// Only explicitly configured protected ingress interfaces authorize this
// scope. Route discovery must never silently narrow a strict allow policy.
func strictAllowForwardSource(interfaces []string) string {
	interfaces = append([]string(nil), interfaces...)
	sort.Strings(interfaces)
	quoted := make([]string, len(interfaces))
	for index, name := range interfaces {
		quoted[index] = fmt.Sprintf("%q", name)
	}
	selector := "iifname { " + strings.Join(quoted, ", ") + " } "
	return "\t\t" + selector + "ip saddr != @syswarden_zt_allowed counter drop\n" +
		"\t\t" + selector + "ip6 saddr != @syswarden_zt_allowed6 counter drop\n"
}

func validateStrictAllowForwardGeneration(version string, base nftV4028PersistenceInputs) error {
	if version == "" {
		return nil
	}
	if version != strictAllowForwardVersion || !base.Inet.Strict || len(base.Interfaces) == 0 || len(base.Interfaces) > 32 {
		return fmt.Errorf("unsupported strict allow forward generation or missing protected scope")
	}
	seen := make(map[string]bool)
	for _, name := range base.Interfaces {
		canonical, err := canonicalInterfaceName(name)
		if err != nil || canonical != name || seen[name] {
			return fmt.Errorf("strict allow forward scope has a noncanonical or duplicate interface")
		}
		seen[name] = true
	}
	return nil
}

// The receipt binds the exact new source to the historical removal model.
// Unmarked, edited or relocated rules never gain ownership through normalization.
func normalizeStrictAllowForwardSource(source []byte, version string, base nftV4028PersistenceInputs) ([]byte, error) {
	if version == "" {
		return source, nil
	}
	if err := validateStrictAllowForwardGeneration(version, base); err != nil {
		return nil, err
	}
	scoped := []byte(strictAllowForwardSource(base.Interfaces))
	start := bytes.Index(source, []byte("\tchain docker_protect {\n"))
	if len(source) > maximumNFTPersistenceBytes || start < 0 || bytes.Count(source, scoped) != 1 || !bytes.Contains(source[start:], scoped) {
		return nil, fmt.Errorf("strict allow forward source differs from its bound generation")
	}
	var historical strings.Builder
	appendStrictAllowForwardRules(&historical, true)
	return bytes.Replace(source, scoped, []byte(historical.String()), 1), nil
}

func strictAllowForwardExpressions(interfaces []string, ipv6 bool) []any {
	interfaces = append([]string(nil), interfaces...)
	sort.Strings(interfaces)
	protocol, set := "ip", "@syswarden_zt_allowed"
	if ipv6 {
		protocol, set = "ip6", "@syswarden_zt_allowed6"
	}
	var selected any = interfaces[0]
	if len(interfaces) > 1 {
		selected = map[string]any{"set": interfaces}
	}
	return []any{
		map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": selected}},
		map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": "saddr"}}, "right": set}},
		map[string]any{"counter": map[string]any{}}, map[string]any{"drop": nil},
	}
}

func verifyStrictAllowForward(document nftJSONDocument, version string, base nftV4028PersistenceInputs) error {
	if err := validateStrictAllowForwardGeneration(version, base); err != nil {
		return err
	}
	if version == "" {
		return nil
	}
	var rules []*nftJSONRule
	identities := make(map[uint64]bool)
	for _, entry := range document.NFTables {
		if rule := entry.Rule; rule != nil && rule.Family == "inet" && rule.Table == "syswarden" && rule.Chain == "docker_protect" {
			if rule.Handle == 0 || identities[rule.Handle] {
				return fmt.Errorf("strict allow forward runtime has missing or duplicate rule identity")
			}
			identities[rule.Handle] = true
			rules = append(rules, rule)
		}
	}
	if len(rules) < 2 {
		return fmt.Errorf("strict allow forward runtime rules are missing")
	}
	for _, rule := range rules[:len(rules)-2] {
		for _, expression := range rule.Expressions {
			canonical, err := canonicalNFTJSONExpression(expression)
			if err != nil {
				return fmt.Errorf("invalid preceding forward expression: %w", err)
			}
			if bytes.Contains(canonical, []byte(`"@syswarden_zt_allowed"`)) || bytes.Contains(canonical, []byte(`"@syswarden_zt_allowed6"`)) {
				return fmt.Errorf("extra strict allow forward runtime selector")
			}
		}
	}
	for index, rule := range rules[len(rules)-2:] {
		if err := verifyNFTJSONRuleExact(rule, "inet", "syswarden", "docker_protect", "", strictAllowForwardExpressions(base.Interfaces, index == 1)); err != nil {
			return fmt.Errorf("strict allow forward runtime rule %d: %w", index, err)
		}
	}
	return nil
}

func normalizeStrictAllowForwardRuntime(content []byte, version string, base nftV4028PersistenceInputs) ([]byte, error) {
	if version == "" {
		return content, nil
	}
	document, err := decodeNFTJSON(content)
	if err != nil {
		return nil, err
	}
	if err := verifyStrictAllowForward(document, version, base); err != nil {
		return nil, err
	}
	// Preserve every raw object field and identity for the full historical
	// topology verifier. Remove only the attested interface selector.
	raw, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		return nil, err
	}
	entries, ok := raw["nftables"].([]any)
	if !ok || len(raw) != 1 {
		return nil, fmt.Errorf("ambiguous strict allow forward runtime document")
	}
	var rules []map[string]any
	for _, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, fmt.Errorf("ambiguous strict allow forward runtime object")
		}
		rule, ok := wrapper["rule"].(map[string]any)
		if ok && rule["family"] == "inet" && rule["table"] == "syswarden" && rule["chain"] == "docker_protect" {
			rules = append(rules, rule)
		}
	}
	if len(rules) < 2 {
		return nil, fmt.Errorf("strict allow forward runtime coverage is incomplete")
	}
	for _, rule := range rules[len(rules)-2:] {
		expressions, ok := rule["expr"].([]any)
		if !ok || len(expressions) != 4 {
			return nil, fmt.Errorf("strict allow forward runtime shape changed")
		}
		rule["expr"] = expressions[1:]
	}
	return json.Marshal(raw)
}

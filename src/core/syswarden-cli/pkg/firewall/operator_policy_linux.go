//go:build linux

package firewall

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"syswarden-cli/config"
)

const (
	maximumCompiledOperatorPolicyRules = 64
	maximumCompiledOperatorPolicyBytes = 64 << 10
	operatorPolicyChainName            = "operator-policy"
	operatorPolicyCommentPrefix        = "syswarden:operator-policy:v1:"
	operatorPolicyDispatchComment      = operatorPolicyCommentPrefix + "dispatch"
	operatorPolicyReturnComment        = operatorPolicyCommentPrefix + "return"
)

type compiledOperatorPolicy struct {
	chain        string
	verification operatorPolicyVerification
}

type operatorPolicyRuleExpectation struct {
	family  config.OperatorPolicyFamily
	source  string
	comment string
}

type operatorPolicyVerification struct {
	chainName       string
	dispatchComment string
	returnComment   string
	rules           []operatorPolicyRuleExpectation
}

func (policy compiledOperatorPolicy) enabled() bool {
	return len(policy.verification.rules) > 0
}

// verificationPlan returns an isolated, ID-free description for the exact
// post-apply verifier. Callers cannot mutate the compiler's retained plan.
func (policy compiledOperatorPolicy) verificationPlan() operatorPolicyVerification {
	verification := policy.verification
	verification.rules = append([]operatorPolicyRuleExpectation(nil), policy.verification.rules...)
	return verification
}

// compileOperatorPolicy converts the already typed configuration into a
// closed nftables surface. It deliberately validates the security contract a
// second time at the mutation boundary and never accepts raw nftables input.
func compileOperatorPolicy(rules []config.OperatorPolicyRule) (compiledOperatorPolicy, error) {
	return compileOperatorPolicyBounded(rules, maximumCompiledOperatorPolicyBytes)
}

func compileOperatorPolicyBounded(rules []config.OperatorPolicyRule, maximumBytes int) (compiledOperatorPolicy, error) {
	if maximumBytes <= 0 || maximumBytes > maximumCompiledOperatorPolicyBytes {
		return compiledOperatorPolicy{}, fmt.Errorf("operator policy compiler byte limit is invalid")
	}
	if len(rules) > maximumCompiledOperatorPolicyRules {
		return compiledOperatorPolicy{}, fmt.Errorf("operator policy exceeds the %d-rule compiler limit", maximumCompiledOperatorPolicyRules)
	}

	type compiledRule struct {
		id      string
		family  config.OperatorPolicyFamily
		source  string
		comment string
	}
	compiled := make([]compiledRule, 0, len(rules))
	seenIDs := make(map[string]struct{}, len(rules))
	seenPrefixes := make([]struct {
		id     string
		family config.OperatorPolicyFamily
		value  netip.Prefix
	}, 0, len(rules))

	for index, rule := range rules {
		if !canonicalOperatorPolicyID(rule.ID) {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %d has a non-canonical id", index)
		}
		if _, duplicate := seenIDs[rule.ID]; duplicate {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy contains duplicate id %q", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		if rule.Direction != config.OperatorPolicyDirectionIngress {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q has unsupported direction %q", rule.ID, rule.Direction)
		}
		if rule.ICMPType != config.OperatorPolicyTypeEchoRequest {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q has unsupported ICMP type %q", rule.ID, rule.ICMPType)
		}
		if rule.Action != config.OperatorPolicyActionAccept {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q has unsupported action %q", rule.ID, rule.Action)
		}
		switch rule.Family {
		case config.OperatorPolicyFamilyIPv4:
			if rule.Protocol != config.OperatorPolicyProtocolICMP {
				return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q requires protocol %q", rule.ID, config.OperatorPolicyProtocolICMP)
			}
		case config.OperatorPolicyFamilyIPv6:
			if rule.Protocol != config.OperatorPolicyProtocolICMPv6 {
				return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q requires protocol %q", rule.ID, config.OperatorPolicyProtocolICMPv6)
			}
		default:
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q has unsupported family %q", rule.ID, rule.Family)
		}

		canonical, isIPv4, err := canonicalIPOrPrefix(rule.Source)
		if err != nil || canonical != rule.Source {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q source must be a canonical IP address or CIDR", rule.ID)
		}
		if rule.Family == config.OperatorPolicyFamilyIPv4 && !isIPv4 ||
			rule.Family == config.OperatorPolicyFamilyIPv6 && isIPv4 {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q source family does not match %q", rule.ID, rule.Family)
		}
		prefix, _, err := canonicalNetworkPrefix(canonical)
		if err != nil {
			return compiledOperatorPolicy{}, fmt.Errorf("operator policy rule %q source: %w", rule.ID, err)
		}
		for _, existing := range seenPrefixes {
			if existing.family != rule.Family {
				continue
			}
			if networkPrefixesOverlap(existing.value, prefix) {
				return compiledOperatorPolicy{}, fmt.Errorf("operator policy rules %q and %q have equivalent or overlapping sources", existing.id, rule.ID)
			}
		}
		seenPrefixes = append(seenPrefixes, struct {
			id     string
			family config.OperatorPolicyFamily
			value  netip.Prefix
		}{id: rule.ID, family: rule.Family, value: prefix})
		compiled = append(compiled, compiledRule{
			id:      rule.ID,
			family:  rule.Family,
			source:  canonical,
			comment: operatorPolicyRuleComment(rule),
		})
	}

	sort.Slice(compiled, func(left, right int) bool {
		return compiled[left].id < compiled[right].id
	})
	var rendered strings.Builder
	verification := operatorPolicyVerification{
		chainName:       operatorPolicyChainName,
		dispatchComment: operatorPolicyDispatchComment,
		returnComment:   operatorPolicyReturnComment,
		rules:           make([]operatorPolicyRuleExpectation, 0, len(compiled)),
	}
	_, _ = fmt.Fprintf(&rendered, "\tchain %s {\n", operatorPolicyChainName)
	for _, rule := range compiled {
		verification.rules = append(verification.rules, operatorPolicyRuleExpectation{
			family:  rule.family,
			source:  rule.source,
			comment: rule.comment,
		})
		switch rule.family {
		case config.OperatorPolicyFamilyIPv4:
			_, _ = fmt.Fprintf(
				&rendered,
				"\t\tip saddr %s ip protocol icmp icmp type echo-request counter accept comment %q\n",
				rule.source,
				rule.comment,
			)
		case config.OperatorPolicyFamilyIPv6:
			_, _ = fmt.Fprintf(
				&rendered,
				"\t\tip6 saddr %s icmpv6 type echo-request counter accept comment %q\n",
				rule.source,
				rule.comment,
			)
		}
	}
	_, _ = fmt.Fprintf(&rendered, "\t\treturn comment %q\n\t}\n\n", operatorPolicyReturnComment)
	if rendered.Len() > maximumBytes {
		return compiledOperatorPolicy{}, fmt.Errorf("compiled operator policy exceeds the %d-byte limit", maximumBytes)
	}
	return compiledOperatorPolicy{chain: rendered.String(), verification: verification}, nil
}

func operatorPolicyRuleComment(rule config.OperatorPolicyRule) string {
	hash := sha256.New()
	var length [8]byte
	for _, field := range []string{
		rule.ID,
		string(rule.Family),
		string(rule.Direction),
		string(rule.Protocol),
		string(rule.ICMPType),
		rule.Source,
		string(rule.Action),
	} {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	return fmt.Sprintf("%s%x", operatorPolicyCommentPrefix, hash.Sum(nil))
}

func canonicalOperatorPolicyID(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func operatorPolicyDispatchRule() string {
	return fmt.Sprintf("\t\tjump %s comment %q\n", operatorPolicyChainName, operatorPolicyDispatchComment)
}

func validateOperatorPolicyWrapperCompatibility(policy compiledOperatorPolicy, activePaths map[string]string) error {
	if !policy.enabled() || len(activePaths) == 0 {
		return nil
	}
	names := make([]string, 0, len(activePaths))
	for name := range activePaths {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Errorf(
		"operator policy requires nftables to be the sole authoritative firewall; active compatibility frontends are forbidden: %s",
		strings.Join(names, ", "),
	)
}

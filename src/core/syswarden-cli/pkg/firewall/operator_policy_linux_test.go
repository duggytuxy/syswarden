//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"syswarden-cli/config"
)

func validOperatorPolicyRule(id string, family config.OperatorPolicyFamily, source string) config.OperatorPolicyRule {
	protocol := config.OperatorPolicyProtocolICMP
	if family == config.OperatorPolicyFamilyIPv6 {
		protocol = config.OperatorPolicyProtocolICMPv6
	}
	return config.OperatorPolicyRule{
		ID:        id,
		Family:    family,
		Direction: config.OperatorPolicyDirectionIngress,
		Protocol:  protocol,
		ICMPType:  config.OperatorPolicyTypeEchoRequest,
		Source:    source,
		Action:    config.OperatorPolicyActionAccept,
	}
}

func TestCompileOperatorPolicyUsesClosedDeterministicTemplates_SW_FW_005(t *testing.T) {
	rules := []config.OperatorPolicyRule{
		validOperatorPolicyRule("zeta-v6", config.OperatorPolicyFamilyIPv6, "2001:db8:abcd::/48"),
		validOperatorPolicyRule("alpha-v4", config.OperatorPolicyFamilyIPv4, "198.51.100.42/32"),
	}
	policy, err := compileOperatorPolicy(rules)
	if err != nil {
		t.Fatalf("compile operator policy: %v", err)
	}
	verification := policy.verificationPlan()
	if len(verification.rules) != 2 || !policy.enabled() {
		t.Fatalf("compiled operator policy state = %d/%t, want 2/true", len(verification.rules), policy.enabled())
	}
	if verification.chainName != operatorPolicyChainName ||
		verification.dispatchComment != operatorPolicyDispatchComment ||
		verification.returnComment != operatorPolicyReturnComment {
		t.Fatalf("compiled verification markers = %#v", verification)
	}
	wantPath := filepath.Join("..", "..", "..", "..", "..", "testdata", "firewall", "operator-policy-v4.04.0.nft")
	want, err := os.ReadFile(wantPath) // #nosec G304 -- fixed repository fixture
	if err != nil {
		t.Fatalf("read operator policy golden: %v", err)
	}
	if got, expected := policy.chain, string(want)+"\n"; got != expected {
		t.Fatalf("compiled operator policy changed; review and approve %s:\n%s\nwant:\n%s", wantPath, got, expected)
	}
	if rules[0].ID != "zeta-v6" || rules[1].ID != "alpha-v4" {
		t.Fatalf("compiler mutated caller order: %#v", rules)
	}
	for _, line := range []string{
		"\tchain operator-policy {\n",
		"\t\tip saddr 198.51.100.42/32 ip protocol icmp icmp type echo-request counter accept comment \"",
		"\t\tip6 saddr 2001:db8:abcd::/48 icmpv6 type echo-request counter accept comment \"",
		"\t\treturn comment \"syswarden:operator-policy:v1:return\"\n\t}\n\n",
	} {
		if !strings.Contains(policy.chain, line) {
			t.Fatalf("compiled operator policy omitted fixed template %q:\n%s", line, policy.chain)
		}
	}
	if strings.Index(policy.chain, "198.51.100.42/32") > strings.Index(policy.chain, "2001:db8:abcd::/48") {
		t.Fatalf("compiled rules are not ordered by canonical id:\n%s", policy.chain)
	}
	for _, rawID := range []string{"alpha-v4", "zeta-v6"} {
		if strings.Contains(policy.chain, rawID) {
			t.Fatalf("compiled provenance leaked raw operator id %q", rawID)
		}
	}
	comments := regexp.MustCompile(`syswarden:operator-policy:v1:[0-9a-f]{64}`).FindAllString(policy.chain, -1)
	if len(comments) != 2 || comments[0] == comments[1] {
		t.Fatalf("compiled rule provenance comments = %#v, want two distinct full SHA-256 markers", comments)
	}
	for index, expectation := range verification.rules {
		if expectation.comment != comments[index] {
			t.Fatalf("verification rule %d comment = %q, want %q", index, expectation.comment, comments[index])
		}
	}
	verification.rules[0].source = "mutated-by-caller"
	if policy.verificationPlan().rules[0].source == "mutated-by-caller" {
		t.Fatal("verificationPlan returned mutable compiler-owned state")
	}
	second, err := compileOperatorPolicy([]config.OperatorPolicyRule{rules[1], rules[0]})
	if err != nil {
		t.Fatal(err)
	}
	if second.chain != policy.chain {
		t.Fatalf("operator policy rendering depends on input order:\n%s\n---\n%s", policy.chain, second.chain)
	}
}

func TestCompileOperatorPolicyAlwaysRendersReturningChain_SW_FW_005(t *testing.T) {
	policy, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if policy.enabled() || len(policy.verificationPlan().rules) != 0 {
		t.Fatalf("empty operator policy state = %d/%t", len(policy.verificationPlan().rules), policy.enabled())
	}
	want := "\tchain operator-policy {\n\t\treturn comment \"syswarden:operator-policy:v1:return\"\n\t}\n\n"
	if policy.chain != want {
		t.Fatalf("empty operator policy chain:\n%s\nwant:\n%s", policy.chain, want)
	}
	wantDispatch := "\t\tjump operator-policy comment \"syswarden:operator-policy:v1:dispatch\"\n"
	if got := operatorPolicyDispatchRule(); got != wantDispatch {
		t.Fatalf("operator policy dispatch = %q, want %q", got, wantDispatch)
	}
}

func TestOperatorPolicyProvenanceUsesLengthPrefixedSevenFieldSHA256_SW_FW_005(t *testing.T) {
	left := validOperatorPolicyRule("a", config.OperatorPolicyFamily("bc"), "198.51.100.1")
	right := validOperatorPolicyRule("ab", config.OperatorPolicyFamily("c"), "198.51.100.1")
	leftComment := operatorPolicyRuleComment(left)
	rightComment := operatorPolicyRuleComment(right)
	if leftComment == rightComment {
		t.Fatal("length-prefixed provenance serialization collapsed distinct field boundaries")
	}
	pattern := regexp.MustCompile(`^syswarden:operator-policy:v1:[0-9a-f]{64}$`)
	if !pattern.MatchString(leftComment) || !pattern.MatchString(rightComment) {
		t.Fatalf("provenance markers are not fixed-prefix full SHA-256 values: %q / %q", leftComment, rightComment)
	}
}

func TestCompileOperatorPolicyRejectsInvalidTypedValues_SW_FW_005(t *testing.T) {
	valid := validOperatorPolicyRule("allow-v4", config.OperatorPolicyFamilyIPv4, "198.51.100.42/32")
	tests := []struct {
		name  string
		rules func() []config.OperatorPolicyRule
	}{
		{name: "non-canonical id", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.ID = `allow-v4\" counter drop`
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "duplicate id", rules: func() []config.OperatorPolicyRule { return []config.OperatorPolicyRule{valid, valid} }},
		{name: "direction", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.Direction = config.OperatorPolicyDirection("egress")
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "type", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.ICMPType = config.OperatorPolicyICMPType("echo-reply")
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "action", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.Action = config.OperatorPolicyAction("drop")
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "family", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.Family = config.OperatorPolicyFamily("inet")
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "protocol mismatch", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.Protocol = config.OperatorPolicyProtocolICMPv6
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "non-canonical source", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.Source = "198.51.100.42/24"
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "source family mismatch", rules: func() []config.OperatorPolicyRule {
			rule := valid
			rule.Source = "2001:db8::42"
			return []config.OperatorPolicyRule{rule}
		}},
		{name: "overlap", rules: func() []config.OperatorPolicyRule {
			return []config.OperatorPolicyRule{
				validOperatorPolicyRule("allow-net", config.OperatorPolicyFamilyIPv4, "198.51.100.0/24"),
				validOperatorPolicyRule("allow-host", config.OperatorPolicyFamilyIPv4, "198.51.100.42"),
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if policy, err := compileOperatorPolicy(test.rules()); err == nil {
				t.Fatalf("invalid operator policy compiled successfully:\n%s", policy.chain)
			}
		})
	}
}

func TestCompileOperatorPolicyRuleAndByteBounds_SW_FW_005(t *testing.T) {
	rules := make([]config.OperatorPolicyRule, 0, maximumCompiledOperatorPolicyRules+1)
	for index := 0; index < maximumCompiledOperatorPolicyRules; index++ {
		rules = append(rules, validOperatorPolicyRule(
			fmt.Sprintf("rule-%02d", index),
			config.OperatorPolicyFamilyIPv4,
			"198.51.100."+strconv.Itoa(index+1),
		))
	}
	policy, err := compileOperatorPolicy(rules)
	if err != nil {
		t.Fatalf("compile exact maximum rule count: %v", err)
	}
	if len(policy.verificationPlan().rules) != maximumCompiledOperatorPolicyRules {
		t.Fatalf("compiled rule count = %d, want %d", len(policy.verificationPlan().rules), maximumCompiledOperatorPolicyRules)
	}
	rules = append(rules, validOperatorPolicyRule("rule-64", config.OperatorPolicyFamilyIPv4, "198.51.100.65"))
	if _, err := compileOperatorPolicy(rules); err == nil {
		t.Fatal("compiler accepted more than the maximum rule count")
	}

	single := []config.OperatorPolicyRule{validOperatorPolicyRule("bounded", config.OperatorPolicyFamilyIPv4, "198.51.100.42")}
	baseline, err := compileOperatorPolicy(single)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileOperatorPolicyBounded(single, len(baseline.chain)); err != nil {
		t.Fatalf("compiler rejected an exact byte-boundary rendering: %v", err)
	}
	if _, err := compileOperatorPolicyBounded(single, len(baseline.chain)-1); err == nil {
		t.Fatal("compiler accepted a rendering above the configured byte boundary")
	}
	if _, err := compileOperatorPolicyBounded(single, maximumCompiledOperatorPolicyBytes+1); err == nil {
		t.Fatal("compiler accepted a byte limit above the hard ceiling")
	}
}

func TestOperatorPolicyWrapperCompatibilityFailsBeforeNftMutation_SW_FW_005(t *testing.T) {
	policy, err := compileOperatorPolicy([]config.OperatorPolicyRule{
		validOperatorPolicyRule("allow-v4", config.OperatorPolicyFamilyIPv4, "198.51.100.42"),
	})
	if err != nil {
		t.Fatal(err)
	}
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(plan)
	transactionID, err := applyNftablesPolicyWithWrappers(
		t.Context(),
		runner,
		stateDirectory,
		minimalNftRules(),
		nil,
		plan,
		func() error {
			return validateOperatorPolicyWrapperCompatibility(policy, map[string]string{
				"ufw":       "/usr/sbin/ufw",
				"firewalld": "/usr/bin/firewall-cmd",
			})
		},
		nil,
		nil,
	)
	if transactionID == "" {
		t.Fatal("wrapper compatibility refusal omitted transaction id")
	}
	if err == nil || !strings.Contains(err.Error(), "preserved the previous ruleset") ||
		!strings.Contains(err.Error(), "firewalld, ufw") {
		t.Fatalf("wrapper compatibility refusal = %v", err)
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("wrapper compatibility refusal mutated nftables: apply/rollback=%d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(stateDirectory, filepath.Base(nftStateFile))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("wrapper compatibility refusal published state: %v", statErr)
	}

	empty, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOperatorPolicyWrapperCompatibility(empty, map[string]string{"ufw": "/usr/sbin/ufw"}); err != nil {
		t.Fatalf("empty operator policy rejected an active compatibility frontend: %v", err)
	}
	if err := validateOperatorPolicyWrapperCompatibility(policy, nil); err != nil {
		t.Fatalf("operator policy rejected a sole-authority nftables host: %v", err)
	}
}

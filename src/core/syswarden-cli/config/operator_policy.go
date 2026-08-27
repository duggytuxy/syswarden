package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maximumOperatorPolicyRules = 64
	operatorPolicyModulePath   = "modules/99-user.toml"
)

var operatorPolicyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type OperatorPolicyFamily string
type OperatorPolicyDirection string
type OperatorPolicyProtocol string
type OperatorPolicyICMPType string
type OperatorPolicyAction string

const (
	OperatorPolicyFamilyIPv4 OperatorPolicyFamily = "ipv4"
	OperatorPolicyFamilyIPv6 OperatorPolicyFamily = "ipv6"

	OperatorPolicyDirectionIngress OperatorPolicyDirection = "ingress"

	OperatorPolicyProtocolICMP   OperatorPolicyProtocol = "icmp"
	OperatorPolicyProtocolICMPv6 OperatorPolicyProtocol = "icmpv6"

	OperatorPolicyTypeEchoRequest OperatorPolicyICMPType = "echo-request"

	OperatorPolicyActionAccept OperatorPolicyAction = "accept"
)

// OperatorPolicyConfig is the closed, typed operator-owned policy surface.
// Rules are intentionally limited to ICMP echo requests in this schema.
type OperatorPolicyConfig struct {
	Rules []OperatorPolicyRule `mapstructure:"rules"`
}

type OperatorPolicyRule struct {
	ID        string                  `mapstructure:"id"`
	Family    OperatorPolicyFamily    `mapstructure:"family"`
	Direction OperatorPolicyDirection `mapstructure:"direction"`
	Protocol  OperatorPolicyProtocol  `mapstructure:"protocol"`
	ICMPType  OperatorPolicyICMPType  `mapstructure:"type"`
	Source    string                  `mapstructure:"source"`
	Action    OperatorPolicyAction    `mapstructure:"action"`
}

type validatedOperatorPolicyRule struct {
	id     string
	family OperatorPolicyFamily
	source netip.Prefix
}

type operatorPolicySourceAttestation struct {
	modulesDir string
	identity   *secureFileIdentity
	policy     OperatorPolicyConfig
}

func cloneOperatorPolicy(config OperatorPolicyConfig) OperatorPolicyConfig {
	return OperatorPolicyConfig{Rules: append([]OperatorPolicyRule(nil), config.Rules...)}
}

func operatorPoliciesEqual(left, right OperatorPolicyConfig) bool {
	if len(left.Rules) != len(right.Rules) {
		return false
	}
	for index := range left.Rules {
		if left.Rules[index] != right.Rules[index] {
			return false
		}
	}
	return true
}

// validateOperatorPolicyDocument validates the security-sensitive subtree from
// the raw TOML representation before Viper can apply weak type coercions. The
// subtree is accepted only from the exact operator-owned module.
func validateOperatorPolicyDocument(relative string, document map[string]any) error {
	for name := range document {
		if canonicalOperatorPolicyKey(name) == "operator_policy" && name != "operator_policy" {
			return fmt.Errorf("%s contains non-canonical operator_policy key %q", relative, name)
		}
	}

	rawPolicy, present := document["operator_policy"]
	if !present {
		return nil
	}
	if relative != operatorPolicyModulePath {
		return fmt.Errorf("operator_policy may be declared only in %s, not %s", operatorPolicyModulePath, relative)
	}
	policy, ok := rawPolicy.(map[string]any)
	if !ok {
		return fmt.Errorf("%s operator_policy must be a TOML table", relative)
	}
	for key := range policy {
		if key != "rules" {
			return fmt.Errorf("%s operator_policy contains unknown key %q", relative, key)
		}
	}
	rawRules, present := policy["rules"]
	if !present {
		return nil
	}
	rules, ok := rawRules.([]any)
	if !ok {
		return fmt.Errorf("%s operator_policy.rules must be an array of TOML tables", relative)
	}
	if len(rules) > maximumOperatorPolicyRules {
		return fmt.Errorf("%s operator_policy.rules exceeds the %d-rule limit", relative, maximumOperatorPolicyRules)
	}

	typed := OperatorPolicyConfig{Rules: make([]OperatorPolicyRule, 0, len(rules))}
	for index, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			return fmt.Errorf("%s operator_policy.rules[%d] must be a TOML table", relative, index)
		}
		for key := range rule {
			switch key {
			case "id", "family", "direction", "protocol", "type", "source", "action":
			default:
				return fmt.Errorf("%s operator_policy.rules[%d] contains unknown key %q", relative, index, key)
			}
		}
		readString := func(key string) (string, error) {
			value, exists := rule[key]
			if !exists {
				return "", fmt.Errorf("%s operator_policy.rules[%d] is missing required key %q", relative, index, key)
			}
			text, ok := value.(string)
			if !ok {
				return "", fmt.Errorf("%s operator_policy.rules[%d].%s must be a string", relative, index, key)
			}
			return text, nil
		}

		id, err := readString("id")
		if err != nil {
			return err
		}
		family, err := readString("family")
		if err != nil {
			return err
		}
		direction, err := readString("direction")
		if err != nil {
			return err
		}
		protocol, err := readString("protocol")
		if err != nil {
			return err
		}
		icmpType, err := readString("type")
		if err != nil {
			return err
		}
		source, err := readString("source")
		if err != nil {
			return err
		}
		action, err := readString("action")
		if err != nil {
			return err
		}
		typed.Rules = append(typed.Rules, OperatorPolicyRule{
			ID:        id,
			Family:    OperatorPolicyFamily(family),
			Direction: OperatorPolicyDirection(direction),
			Protocol:  OperatorPolicyProtocol(protocol),
			ICMPType:  OperatorPolicyICMPType(icmpType),
			Source:    source,
			Action:    OperatorPolicyAction(action),
		})
	}
	if err := ValidateOperatorPolicy(typed); err != nil {
		return fmt.Errorf("%s: %w", relative, err)
	}
	return nil
}

func canonicalOperatorPolicyKey(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, "-", "_"))
}

func rejectOperatorPolicyEnvironment() error {
	var names []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "SYSWARDEN_OPERATOR_POLICY") {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("operator_policy environment override %s is forbidden; declare rules only in %s", names[0], operatorPolicyModulePath)
}

// ValidateOperatorPolicy revalidates every closed operator policy invariant.
// Firewall compilation must call it defensively before consuming a policy.
func ValidateOperatorPolicy(policy OperatorPolicyConfig) error {
	if len(policy.Rules) > maximumOperatorPolicyRules {
		return fmt.Errorf("operator_policy.rules exceeds the %d-rule limit", maximumOperatorPolicyRules)
	}
	seenIDs := make(map[string]struct{}, len(policy.Rules))
	validated := make([]validatedOperatorPolicyRule, 0, len(policy.Rules))
	for index, rule := range policy.Rules {
		if !operatorPolicyIDPattern.MatchString(rule.ID) {
			return fmt.Errorf("operator_policy.rules[%d].id must match %s", index, operatorPolicyIDPattern.String())
		}
		if _, duplicate := seenIDs[rule.ID]; duplicate {
			return fmt.Errorf("operator_policy.rules contains duplicate id %q", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}

		if rule.Direction != OperatorPolicyDirectionIngress {
			return fmt.Errorf("operator_policy rule %q direction must be %q", rule.ID, OperatorPolicyDirectionIngress)
		}
		if rule.ICMPType != OperatorPolicyTypeEchoRequest {
			return fmt.Errorf("operator_policy rule %q type must be %q", rule.ID, OperatorPolicyTypeEchoRequest)
		}
		if rule.Action != OperatorPolicyActionAccept {
			return fmt.Errorf("operator_policy rule %q action must be %q", rule.ID, OperatorPolicyActionAccept)
		}
		switch rule.Family {
		case OperatorPolicyFamilyIPv4:
			if rule.Protocol != OperatorPolicyProtocolICMP {
				return fmt.Errorf("operator_policy rule %q requires protocol %q for family %q", rule.ID, OperatorPolicyProtocolICMP, rule.Family)
			}
		case OperatorPolicyFamilyIPv6:
			if rule.Protocol != OperatorPolicyProtocolICMPv6 {
				return fmt.Errorf("operator_policy rule %q requires protocol %q for family %q", rule.ID, OperatorPolicyProtocolICMPv6, rule.Family)
			}
		default:
			return fmt.Errorf("operator_policy rule %q family must be %q or %q", rule.ID, OperatorPolicyFamilyIPv4, OperatorPolicyFamilyIPv6)
		}

		source, err := canonicalOperatorPolicySource(rule.Source, rule.Family)
		if err != nil {
			return fmt.Errorf("operator_policy rule %q source: %w", rule.ID, err)
		}
		for _, existing := range validated {
			if existing.family != rule.Family {
				continue
			}
			if existing.source.Contains(source.Addr()) || source.Contains(existing.source.Addr()) {
				return fmt.Errorf("operator_policy rules %q and %q have equivalent or overlapping sources", existing.id, rule.ID)
			}
		}
		validated = append(validated, validatedOperatorPolicyRule{id: rule.ID, family: rule.Family, source: source})
	}
	return nil
}

// ReattestOperatorPolicySource proves that a non-empty policy still comes from
// the exact descriptor-rooted 99-user.toml inode validated during CLI loading.
// Empty policies require no source attestation and are a no-op.
func ReattestOperatorPolicySource(config *Config) error {
	if config == nil {
		return fmt.Errorf("operator policy configuration is nil")
	}
	if len(config.OperatorPolicy.Rules) == 0 {
		return nil
	}
	attestation := config.operatorPolicySource
	if attestation == nil || attestation.identity == nil || attestation.modulesDir == "" {
		return fmt.Errorf("non-empty operator policy has no source attestation")
	}
	if !operatorPoliciesEqual(config.OperatorPolicy, attestation.policy) {
		return fmt.Errorf("operator policy snapshot changed after validation")
	}
	root, err := openConfigDirectory(attestation.modulesDir, false, 0)
	if err != nil {
		return fmt.Errorf("open operator policy source directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	content, current, err := readSecureRegularFileIdentity(
		root,
		userModuleName,
		filepath.Join(attestation.modulesDir, userModuleName),
	)
	if err != nil {
		return fmt.Errorf("reattest operator policy source: %w", err)
	}
	if !attestation.identity.matches(content, current.info) {
		return fmt.Errorf("operator policy source identity changed after validation")
	}
	return nil
}

func canonicalOperatorPolicySource(value string, family OperatorPolicyFamily) (netip.Prefix, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return netip.Prefix{}, fmt.Errorf("must not be empty or whitespace padded")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("must not contain a zone")
		}
		if address.Is4In6() {
			return netip.Prefix{}, fmt.Errorf("must not be an IPv4-mapped IPv6 address")
		}
		if address.String() != value {
			return netip.Prefix{}, fmt.Errorf("must be a canonical IP address or CIDR")
		}
		if family == OperatorPolicyFamilyIPv4 && !address.Is4() || family == OperatorPolicyFamilyIPv6 && !address.Is6() {
			return netip.Prefix{}, fmt.Errorf("address family does not match %q", family)
		}
		return netip.PrefixFrom(address, address.BitLen()), nil
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("must be a canonical IP address or CIDR")
	}
	if prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("must not contain a zone")
	}
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("must not be an IPv4-mapped IPv6 address")
	}
	if prefix.String() != value || prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("must be a canonical IP address or CIDR")
	}
	if family == OperatorPolicyFamilyIPv4 && !prefix.Addr().Is4() || family == OperatorPolicyFamilyIPv6 && !prefix.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("address family does not match %q", family)
	}
	return prefix, nil
}

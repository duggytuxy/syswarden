package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

type operatorPolicyContractCorpus struct {
	SchemaVersion    int                                  `json:"schema_version"`
	ModulePath       string                               `json:"module_path"`
	Limits           operatorPolicyContractLimits         `json:"limits"`
	RawCases         []operatorPolicyContractRawCase      `json:"raw_cases"`
	SemanticCases    []operatorPolicyContractSemanticCase `json:"semantic_cases"`
	RuleCountCases   []operatorPolicyContractCountCase    `json:"rule_count_cases"`
	ModuleSizeCases  []operatorPolicyContractSizeCase     `json:"module_size_cases"`
	EnvironmentNames []string                             `json:"environment_names"`
}

type operatorPolicyContractLimits struct {
	MaximumRules       int `json:"maximum_rules"`
	MaximumModuleBytes int `json:"maximum_module_bytes"`
}

type operatorPolicyContractRawCase struct {
	Name         string `json:"name"`
	RelativePath string `json:"relative_path"`
	TOML         string `json:"toml"`
	WantError    string `json:"want_error"`
}

type operatorPolicyContractSemanticCase struct {
	Name      string                       `json:"name"`
	Rules     []operatorPolicyContractRule `json:"rules"`
	WantError string                       `json:"want_error"`
}

type operatorPolicyContractRule struct {
	ID        string `json:"id"`
	Family    string `json:"family"`
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	ICMPType  string `json:"type"`
	Source    string `json:"source"`
	Action    string `json:"action"`
}

type operatorPolicyContractCountCase struct {
	Name      string `json:"name"`
	Count     int    `json:"count"`
	WantError string `json:"want_error"`
}

type operatorPolicyContractSizeCase struct {
	Name      string `json:"name"`
	Size      int    `json:"size"`
	WantError string `json:"want_error"`
}

func operatorPolicyContractPath(t *testing.T) string {
	t.Helper()
	var starts []string
	if _, source, _, ok := runtime.Caller(0); ok {
		if absolute, err := filepath.Abs(source); err == nil {
			starts = append(starts, filepath.Dir(absolute))
		}
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		starts = append(starts, workingDirectory)
	}
	seen := make(map[string]struct{})
	for _, start := range starts {
		for directory := filepath.Clean(start); ; directory = filepath.Dir(directory) {
			if _, duplicate := seen[directory]; !duplicate {
				seen[directory] = struct{}{}
				markers := []string{
					filepath.Join(directory, "go.work"),
					filepath.Join(directory, "src", "core", "syswarden-cli", "go.mod"),
					filepath.Join(directory, "src", "core", "syswarden-core", "go.mod"),
				}
				valid := true
				for _, marker := range markers {
					info, err := os.Stat(marker)
					if err != nil || !info.Mode().IsRegular() {
						valid = false
						break
					}
				}
				if valid {
					return filepath.Join(directory, "testdata", "contracts", "operator-policy-v1.json")
				}
			}
			parent := filepath.Dir(directory)
			if parent == directory {
				break
			}
		}
	}
	t.Fatal("locate repository root for shared operator policy contract")
	return ""
}

func decodeOperatorPolicyContractCorpus(reader io.Reader) (operatorPolicyContractCorpus, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var corpus operatorPolicyContractCorpus
	if err := decoder.Decode(&corpus); err != nil {
		return operatorPolicyContractCorpus{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return operatorPolicyContractCorpus{}, fmt.Errorf("trailing JSON document")
		}
		return operatorPolicyContractCorpus{}, fmt.Errorf("decode trailing JSON: %w", err)
	}
	return corpus, nil
}

func loadOperatorPolicyContractCorpus(t *testing.T) operatorPolicyContractCorpus {
	t.Helper()
	path := operatorPolicyContractPath(t)
	file, err := os.Open(path) // #nosec G304 -- path is the fixed shared repository corpus resolved by this test helper
	if err != nil {
		t.Fatalf("open shared operator policy contract %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	corpus, err := decodeOperatorPolicyContractCorpus(file)
	if err != nil {
		t.Fatalf("decode shared operator policy contract %s: %v", path, err)
	}
	if corpus.SchemaVersion != 1 {
		t.Fatalf("shared operator policy contract schema = %d, want 1", corpus.SchemaVersion)
	}
	if corpus.ModulePath != operatorPolicyModulePath {
		t.Fatalf("shared operator policy module path = %q, want %q", corpus.ModulePath, operatorPolicyModulePath)
	}
	if corpus.Limits.MaximumRules != maximumOperatorPolicyRules {
		t.Fatalf("shared maximum rules = %d, want %d", corpus.Limits.MaximumRules, maximumOperatorPolicyRules)
	}
	if int64(corpus.Limits.MaximumModuleBytes) != maximumUserModuleSize {
		t.Fatalf("shared maximum module bytes = %d, want %d", corpus.Limits.MaximumModuleBytes, maximumUserModuleSize)
	}
	if len(corpus.RawCases) == 0 || len(corpus.SemanticCases) == 0 || len(corpus.RuleCountCases) == 0 || len(corpus.ModuleSizeCases) == 0 || len(corpus.EnvironmentNames) == 0 {
		t.Fatal("shared operator policy contract contains an empty case family")
	}
	return corpus
}

func (rule operatorPolicyContractRule) typed() OperatorPolicyRule {
	return OperatorPolicyRule{
		ID:        rule.ID,
		Family:    OperatorPolicyFamily(rule.Family),
		Direction: OperatorPolicyDirection(rule.Direction),
		Protocol:  OperatorPolicyProtocol(rule.Protocol),
		ICMPType:  OperatorPolicyICMPType(rule.ICMPType),
		Source:    rule.Source,
		Action:    OperatorPolicyAction(rule.Action),
	}
}

func generatedOperatorPolicyContractRules(count int) []operatorPolicyContractRule {
	rules := make([]operatorPolicyContractRule, 0, count)
	for index := 0; index < count; index++ {
		rules = append(rules, operatorPolicyContractRule{
			ID:        fmt.Sprintf("allow-%02d", index),
			Family:    "ipv4",
			Direction: "ingress",
			Protocol:  "icmp",
			ICMPType:  "echo-request",
			Source:    fmt.Sprintf("192.0.2.%d", index+1),
			Action:    "accept",
		})
	}
	return rules
}

func renderOperatorPolicyContractRules(rules []operatorPolicyContractRule) string {
	var module strings.Builder
	for _, rule := range rules {
		fmt.Fprintf(&module, `[[operator_policy.rules]]
id = %q
family = %q
direction = %q
protocol = %q
type = %q
source = %q
action = %q

`, rule.ID, rule.Family, rule.Direction, rule.Protocol, rule.ICMPType, rule.Source, rule.Action)
	}
	return module.String()
}

func requireOperatorPolicyContractOutcome(t *testing.T, err error, wantError string) {
	t.Helper()
	if wantError == "" {
		if err != nil {
			t.Fatalf("contract case rejected: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantError) {
		t.Fatalf("contract error = %v, want substring %q", err, wantError)
	}
}

const validOperatorPolicyModule = `[[operator_policy.rules]]
id = "allow-icmp-v4"
family = "ipv4"
direction = "ingress"
protocol = "icmp"
type = "echo-request"
source = "192.0.2.10"
action = "accept"

[[operator_policy.rules]]
id = "allow-icmp-v6"
family = "ipv6"
direction = "ingress"
protocol = "icmpv6"
type = "echo-request"
source = "2001:db8::/64"
action = "accept"
`

func operatorPolicyFixture(t *testing.T, userModule string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatalf("InitializeDefaults() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "modules", "99-user.toml"), []byte(userModule), 0o600); err != nil {
		t.Fatalf("write operator policy fixture: %v", err)
	}
	return root
}

func preserveOperatorPolicyGlobals(t *testing.T) {
	t.Helper()
	previousConfig := GlobalConfig
	previousState := CurrentLoadState()
	t.Cleanup(func() {
		GlobalConfig = previousConfig
		loadStateMu.Lock()
		loadState = previousState
		loadStateMu.Unlock()
	})
}

func operatorPolicyModuleAtSize(t *testing.T, size int64) []byte {
	t.Helper()
	content := []byte(validOperatorPolicyModule + "\n#")
	if int64(len(content)) > size {
		t.Fatalf("operator policy fixture length %d exceeds requested size %d", len(content), size)
	}
	return append(content, bytes.Repeat([]byte(" "), int(size)-len(content))...)
}

func TestOperatorPolicyMapsUnderCurrentSchema_SW_OPPOL_001(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	root := operatorPolicyFixture(t, validOperatorPolicyModule)

	report, err := ValidateModularConfig(root)
	if err != nil {
		t.Fatalf("ValidateModularConfig() error: %v", err)
	}
	if report.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, want current %d", report.SchemaVersion, CurrentSchemaVersion)
	}
	if CurrentSchemaVersion != 1 {
		t.Fatalf("this test deliberately requires the operator policy to remain valid under schema version 1, got %d", CurrentSchemaVersion)
	}

	if err := loadModularConfig(root); err != nil {
		t.Fatalf("loadModularConfig() error: %v", err)
	}
	want := OperatorPolicyConfig{Rules: []OperatorPolicyRule{
		{
			ID:        "allow-icmp-v4",
			Family:    OperatorPolicyFamilyIPv4,
			Direction: OperatorPolicyDirectionIngress,
			Protocol:  OperatorPolicyProtocolICMP,
			ICMPType:  OperatorPolicyTypeEchoRequest,
			Source:    "192.0.2.10",
			Action:    OperatorPolicyActionAccept,
		},
		{
			ID:        "allow-icmp-v6",
			Family:    OperatorPolicyFamilyIPv6,
			Direction: OperatorPolicyDirectionIngress,
			Protocol:  OperatorPolicyProtocolICMPv6,
			ICMPType:  OperatorPolicyTypeEchoRequest,
			Source:    "2001:db8::/64",
			Action:    OperatorPolicyActionAccept,
		},
	}}
	if !reflect.DeepEqual(GlobalConfig.OperatorPolicy, want) {
		t.Fatalf("mapped operator policy = %#v, want %#v", GlobalConfig.OperatorPolicy, want)
	}

	value, found, err := GetValidatedModularValue(root, "operator_policy.rules")
	if err != nil {
		t.Fatalf("GetValidatedModularValue() error: %v", err)
	}
	if !found {
		t.Fatal("operator_policy.rules was not found")
	}
	var rules []map[string]any
	if err := json.Unmarshal([]byte(value), &rules); err != nil {
		t.Fatalf("decode returned rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("returned rule count = %d, want 2", len(rules))
	}
}

func TestOperatorPolicyRawDocumentContract_SW_OPPOL_002(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "unknown policy key",
			content: `[operator_policy]
mode = "merge"
`,
			want: "unknown key",
		},
		{
			name: "rules must be an array",
			content: `[operator_policy]
rules = "allow"
`,
			want: "must be an array",
		},
		{
			name: "rule must be a table",
			content: `[operator_policy]
rules = ["allow"]
`,
			want: "must be a TOML table",
		},
		{
			name: "unknown rule key",
			content: validOperatorPolicyModule + `
expression = "ip saddr 0.0.0.0/0 accept"
`,
			want: "unknown key",
		},
		{
			name: "missing required key",
			content: `[[operator_policy.rules]]
id = "missing-action"
family = "ipv4"
direction = "ingress"
protocol = "icmp"
type = "echo-request"
source = "192.0.2.10"
`,
			want: "missing required key \"action\"",
		},
		{
			name: "exact string type",
			content: `[[operator_policy.rules]]
id = "wrong-type"
family = "ipv4"
direction = "ingress"
protocol = "icmp"
type = "echo-request"
source = "192.0.2.10"
action = true
`,
			want: "must be a string",
		},
		{
			name: "case lookalike root",
			content: `[Operator_Policy]
rules = []
`,
			want: "non-canonical operator_policy key",
		},
		{
			name: "hyphen lookalike root",
			content: `[operator-policy]
rules = []
`,
			want: "non-canonical operator_policy key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTOMLDocument([]byte(tc.content), operatorPolicyModulePath)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseTOMLDocument() error = %v, want substring %q", err, tc.want)
			}
		})
	}

	var tooMany strings.Builder
	for i := 0; i <= maximumOperatorPolicyRules; i++ {
		fmt.Fprintf(&tooMany, `[[operator_policy.rules]]
id = "allow-%02d"
family = "ipv4"
direction = "ingress"
protocol = "icmp"
type = "echo-request"
source = "192.0.2.%d"
action = "accept"

`, i, i+1)
	}
	_, err := parseTOMLDocument([]byte(tooMany.String()), operatorPolicyModulePath)
	if err == nil || !strings.Contains(err.Error(), "64-rule limit") {
		t.Fatalf("too many rules error = %v, want 64-rule limit", err)
	}
}

func TestOperatorPolicyProvenanceIsExclusive_SW_OPPOL_003(t *testing.T) {
	paths := []string{
		"config.toml",
		"modules/10-network.toml",
		"modules/99-user-copy.toml",
		"modules/99-USER.toml",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			_, err := parseTOMLDocument([]byte(validOperatorPolicyModule), path)
			if err == nil || !strings.Contains(err.Error(), "may be declared only in modules/99-user.toml") {
				t.Fatalf("parseTOMLDocument(%q) error = %v, want exclusive provenance error", path, err)
			}
		})
	}
	if _, err := parseTOMLDocument([]byte(validOperatorPolicyModule), operatorPolicyModulePath); err != nil {
		t.Fatalf("canonical provenance was rejected: %v", err)
	}
}

func TestOperatorPolicySemanticValidation_SW_OPPOL_004(t *testing.T) {
	valid := OperatorPolicyRule{
		ID:        "allow-icmp-v4",
		Family:    OperatorPolicyFamilyIPv4,
		Direction: OperatorPolicyDirectionIngress,
		Protocol:  OperatorPolicyProtocolICMP,
		ICMPType:  OperatorPolicyTypeEchoRequest,
		Source:    "192.0.2.10",
		Action:    OperatorPolicyActionAccept,
	}

	tests := []struct {
		name   string
		policy OperatorPolicyConfig
		want   string
	}{
		{
			name: "egress is closed",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Direction = OperatorPolicyDirection("egress")
				return rule
			}()}},
			want: `direction must be "ingress"`,
		},
		{
			name: "icmp type is closed",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.ICMPType = OperatorPolicyICMPType("destination-unreachable")
				return rule
			}()}},
			want: `type must be "echo-request"`,
		},
		{
			name: "drop is deliberately outside the MVP",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Action = OperatorPolicyAction("drop")
				return rule
			}()}},
			want: `action must be "accept"`,
		},
		{
			name: "unknown family",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Family = OperatorPolicyFamily("inet")
				return rule
			}()}},
			want: `family must be "ipv4" or "ipv6"`,
		},
		{
			name: "non canonical identifier",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.ID = "Allow_ICMP"
				return rule
			}()}},
			want: "must match",
		},
		{
			name: "whitespace padded source",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Source = " 192.0.2.10"
				return rule
			}()}},
			want: "whitespace padded",
		},
		{
			name: "duplicate identifier",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{valid, func() OperatorPolicyRule {
				rule := valid
				rule.Source = "192.0.2.11"
				return rule
			}()}},
			want: "duplicate id",
		},
		{
			name: "ipv4 protocol mismatch",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Protocol = OperatorPolicyProtocolICMPv6
				return rule
			}()}},
			want: `requires protocol "icmp"`,
		},
		{
			name: "ipv6 protocol mismatch",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Family = OperatorPolicyFamilyIPv6
				rule.Protocol = OperatorPolicyProtocolICMP
				rule.Source = "2001:db8::10"
				return rule
			}()}},
			want: `requires protocol "icmpv6"`,
		},
		{
			name: "family and source mismatch",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Family = OperatorPolicyFamilyIPv6
				rule.Protocol = OperatorPolicyProtocolICMPv6
				return rule
			}()}},
			want: `does not match "ipv6"`,
		},
		{
			name: "non canonical masked prefix",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Source = "192.0.2.10/24"
				return rule
			}()}},
			want: "canonical",
		},
		{
			name: "non canonical ipv6 spelling",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.ID = "allow-icmp-v6"
				rule.Family = OperatorPolicyFamilyIPv6
				rule.Protocol = OperatorPolicyProtocolICMPv6
				rule.Source = "2001:0db8::1"
				return rule
			}()}},
			want: "canonical",
		},
		{
			name: "ipv6 zone",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.ID = "allow-icmp-v6"
				rule.Family = OperatorPolicyFamilyIPv6
				rule.Protocol = OperatorPolicyProtocolICMPv6
				rule.Source = "fe80::1%eth0"
				return rule
			}()}},
			want: "must not contain a zone",
		},
		{
			name: "mapped ipv4",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.ID = "allow-icmp-v6"
				rule.Family = OperatorPolicyFamilyIPv6
				rule.Protocol = OperatorPolicyProtocolICMPv6
				rule.Source = "::ffff:192.0.2.10"
				return rule
			}()}},
			want: "IPv4-mapped IPv6",
		},
		{
			name: "equivalent sources",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{valid, func() OperatorPolicyRule {
				rule := valid
				rule.ID = "allow-equivalent"
				rule.Source = "192.0.2.10/32"
				return rule
			}()}},
			want: "equivalent",
		},
		{
			name: "overlapping sources",
			policy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{func() OperatorPolicyRule {
				rule := valid
				rule.Source = "192.0.2.0/24"
				return rule
			}(), func() OperatorPolicyRule {
				rule := valid
				rule.ID = "allow-host"
				return rule
			}()}},
			want: "overlap",
		},
	}

	if err := ValidateOperatorPolicy(OperatorPolicyConfig{Rules: []OperatorPolicyRule{valid}}); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOperatorPolicy(tc.policy)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateOperatorPolicy() error = %v, want substring %q", err, tc.want)
			}
		})
	}

	tooMany := OperatorPolicyConfig{Rules: make([]OperatorPolicyRule, maximumOperatorPolicyRules+1)}
	if err := ValidateOperatorPolicy(tooMany); err == nil || !strings.Contains(err.Error(), "64-rule limit") {
		t.Fatalf("too many typed rules error = %v, want 64-rule limit", err)
	}

	atLimit := OperatorPolicyConfig{Rules: make([]OperatorPolicyRule, 0, maximumOperatorPolicyRules)}
	for index := 0; index < maximumOperatorPolicyRules; index++ {
		rule := valid
		rule.ID = fmt.Sprintf("allow-%02d", index)
		rule.Source = fmt.Sprintf("192.0.2.%d", index+1)
		atLimit.Rules = append(atLimit.Rules, rule)
	}
	if err := ValidateOperatorPolicy(atLimit); err != nil {
		t.Fatalf("exact 64-rule limit was rejected: %v", err)
	}

	publicOptIn := OperatorPolicyConfig{Rules: []OperatorPolicyRule{
		{
			ID:        "allow-public-v4",
			Family:    OperatorPolicyFamilyIPv4,
			Direction: OperatorPolicyDirectionIngress,
			Protocol:  OperatorPolicyProtocolICMP,
			ICMPType:  OperatorPolicyTypeEchoRequest,
			Source:    "0.0.0.0/0",
			Action:    OperatorPolicyActionAccept,
		},
		{
			ID:        "allow-public-v6",
			Family:    OperatorPolicyFamilyIPv6,
			Direction: OperatorPolicyDirectionIngress,
			Protocol:  OperatorPolicyProtocolICMPv6,
			ICMPType:  OperatorPolicyTypeEchoRequest,
			Source:    "::/0",
			Action:    OperatorPolicyActionAccept,
		},
	}}
	if err := ValidateOperatorPolicy(publicOptIn); err != nil {
		t.Fatalf("explicit public /0 opt-in was rejected: %v", err)
	}
}

func TestOperatorPolicySharedContractParity_SW_OPPOL_010(t *testing.T) {
	corpus := loadOperatorPolicyContractCorpus(t)
	for _, test := range corpus.RawCases {
		t.Run("raw/"+test.Name, func(t *testing.T) {
			_, err := parseTOMLDocument([]byte(test.TOML), test.RelativePath)
			requireOperatorPolicyContractOutcome(t, err, test.WantError)
		})
	}
	for _, test := range corpus.SemanticCases {
		t.Run("semantic/"+test.Name, func(t *testing.T) {
			policy := OperatorPolicyConfig{Rules: make([]OperatorPolicyRule, 0, len(test.Rules))}
			for _, rule := range test.Rules {
				policy.Rules = append(policy.Rules, rule.typed())
			}
			requireOperatorPolicyContractOutcome(t, ValidateOperatorPolicy(policy), test.WantError)
		})
	}
	for _, test := range corpus.RuleCountCases {
		t.Run("rule-count/"+test.Name, func(t *testing.T) {
			rules := generatedOperatorPolicyContractRules(test.Count)
			policy := OperatorPolicyConfig{Rules: make([]OperatorPolicyRule, 0, len(rules))}
			for _, rule := range rules {
				policy.Rules = append(policy.Rules, rule.typed())
			}
			requireOperatorPolicyContractOutcome(t, ValidateOperatorPolicy(policy), test.WantError)
			_, err := parseTOMLDocument([]byte(renderOperatorPolicyContractRules(rules)), corpus.ModulePath)
			requireOperatorPolicyContractOutcome(t, err, test.WantError)
		})
	}
}

func TestOperatorPolicyContractCorpusRejectsUnknownJSONKeys_SW_OPPOL_012(t *testing.T) {
	_, err := decodeOperatorPolicyContractCorpus(strings.NewReader(`{"schema_version":1,"unknown":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown corpus field error = %v, want strict JSON rejection", err)
	}
}

func TestOperatorPolicyEnvironmentOverridesAreRejected_SW_OPPOL_005(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	corpus := loadOperatorPolicyContractCorpus(t)
	root := operatorPolicyFixture(t, validOperatorPolicyModule)
	const secretValue = "must-not-appear-in-errors"
	for _, environmentName := range corpus.EnvironmentNames {
		t.Run(environmentName, func(t *testing.T) {
			t.Setenv(environmentName, secretValue)
			checks := []struct {
				name string
				run  func() error
			}{
				{
					name: "load",
					run: func() error {
						return loadModularConfig(root)
					},
				},
				{
					name: "validate",
					run: func() error {
						_, err := ValidateModularConfig(root)
						return err
					},
				},
				{
					name: "get",
					run: func() error {
						_, _, err := GetValidatedModularValue(root, "operator_policy.rules")
						return err
					},
				},
				{
					name: "write user module",
					run: func() error {
						return WriteValidatedUserModule(root, []byte(validOperatorPolicyModule))
					},
				},
			}
			for _, check := range checks {
				t.Run(check.name, func(t *testing.T) {
					err := check.run()
					if err == nil || !strings.Contains(err.Error(), environmentName) {
						t.Fatalf("%s error = %v, want forbidden environment variable %s", check.name, err, environmentName)
					}
					if strings.Contains(err.Error(), secretValue) {
						t.Fatalf("%s leaked an environment value in error: %v", check.name, err)
					}
				})
			}
		})
	}
}

func TestOperatorPolicySharedModuleSizeContract_SW_OPPOL_011(t *testing.T) {
	corpus := loadOperatorPolicyContractCorpus(t)
	for _, test := range corpus.ModuleSizeCases {
		t.Run(test.Name, func(t *testing.T) {
			root := operatorPolicyFixture(t, validOperatorPolicyModule)
			content := bytes.Repeat([]byte{'#'}, test.Size)
			err := WriteValidatedUserModule(root, content)
			requireOperatorPolicyContractOutcome(t, err, test.WantError)
			if err == nil {
				readBack, readErr := ReadUserModule(root)
				if readErr != nil {
					t.Fatalf("read accepted shared size case: %v", readErr)
				}
				if len(readBack) != test.Size {
					t.Fatalf("shared size read = %d, want %d", len(readBack), test.Size)
				}
			}
		})
	}
}

func TestOperatorPolicyInvalidUserWritePreservesExistingFile_SW_OPPOL_006(t *testing.T) {
	root := operatorPolicyFixture(t, validOperatorPolicyModule)
	path := filepath.Join(root, "modules", "99-user.toml")
	beforeBytes, err := os.ReadFile(path) // #nosec G304 -- path is the fixed user module beneath this test's private temporary root
	if err != nil {
		t.Fatalf("read existing user module: %v", err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat existing user module: %v", err)
	}
	beforeStat, ok := beforeInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("existing user module stat did not expose syscall.Stat_t")
	}

	invalid := []byte(validOperatorPolicyModule + `
raw_nft = "accept"
`)
	if err := WriteValidatedUserModule(root, invalid); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("WriteValidatedUserModule() error = %v, want unknown key", err)
	}

	afterBytes, err := os.ReadFile(path) // #nosec G304 -- path is the fixed user module beneath this test's private temporary root
	if err != nil {
		t.Fatalf("read user module after rejected write: %v", err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat user module after rejected write: %v", err)
	}
	afterStat, ok := afterInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("user module stat after rejected write did not expose syscall.Stat_t")
	}
	if !reflect.DeepEqual(afterBytes, beforeBytes) {
		t.Fatal("rejected user module write changed existing bytes")
	}
	if beforeStat.Ino != afterStat.Ino || beforeStat.Dev != afterStat.Dev {
		t.Fatalf("rejected user module write changed identity: before dev=%d ino=%d after dev=%d ino=%d", beforeStat.Dev, beforeStat.Ino, afterStat.Dev, afterStat.Ino)
	}
}

func TestOperatorPolicyUserModuleExactSizeLimit_SW_OPPOL_007(t *testing.T) {
	root := operatorPolicyFixture(t, validOperatorPolicyModule)
	path := filepath.Join(root, "modules", userModuleName)
	exact := operatorPolicyModuleAtSize(t, maximumUserModuleSize)
	if err := WriteValidatedUserModule(root, exact); err != nil {
		t.Fatalf("WriteValidatedUserModule(exact limit) error: %v", err)
	}
	readBack, err := ReadUserModule(root)
	if err != nil {
		t.Fatalf("ReadUserModule(exact limit) error: %v", err)
	}
	if int64(len(readBack)) != maximumUserModuleSize {
		t.Fatalf("exact-limit read size = %d, want %d", len(readBack), maximumUserModuleSize)
	}

	overLimit := append(bytes.Clone(exact), ' ')
	if err := WriteValidatedUserModule(root, overLimit); err == nil || !strings.Contains(err.Error(), "262144-byte limit") {
		t.Fatalf("WriteValidatedUserModule(max+1) error = %v, want exact byte limit", err)
	}
	unchanged, err := os.ReadFile(path) // #nosec G304 -- path is the fixed user module beneath this test's private temporary root
	if err != nil {
		t.Fatalf("read user module after rejected max+1 write: %v", err)
	}
	if !bytes.Equal(unchanged, exact) {
		t.Fatal("rejected max+1 write changed the exact-limit user module")
	}
	importPath := filepath.Join(t.TempDir(), "candidate.toml")
	if err := os.WriteFile(importPath, overLimit, 0o600); err != nil {
		t.Fatalf("write max+1 import fixture: %v", err)
	}
	if err := ImportValidatedUserModule(root, importPath); err == nil || !strings.Contains(err.Error(), "262144-byte limit") {
		t.Fatalf("ImportValidatedUserModule(max+1) error = %v, want exact byte limit", err)
	}

	if err := os.WriteFile(path, overLimit, 0o600); err != nil {
		t.Fatalf("install max+1 secure-reader fixture: %v", err)
	}
	if _, err := ReadUserModule(root); err == nil || !strings.Contains(err.Error(), "262144-byte limit") {
		t.Fatalf("ReadUserModule(max+1) error = %v, want exact byte limit", err)
	}
}

func TestOperatorPolicySizeLimitDoesNotApplyToOtherModules_SW_OPPOL_008(t *testing.T) {
	root := operatorPolicyFixture(t, validOperatorPolicyModule)
	largeOther := append([]byte("# unrelated module\n"), bytes.Repeat([]byte("# padding\n"), int(maximumUserModuleSize/10)+1)...)
	if int64(len(largeOther)) <= maximumUserModuleSize {
		t.Fatalf("unrelated module fixture size = %d, want over %d", len(largeOther), maximumUserModuleSize)
	}
	path := filepath.Join(root, "modules", "98-large.toml")
	if err := os.WriteFile(path, largeOther, 0o600); err != nil {
		t.Fatalf("write unrelated large module: %v", err)
	}
	if _, err := ValidateModularConfig(root); err != nil {
		t.Fatalf("unrelated module over the user-module limit was rejected: %v", err)
	}
}

func TestOperatorPolicySourceReattestation_SW_OPPOL_009(t *testing.T) {
	load := func(t *testing.T) (*Config, string) {
		t.Helper()
		preserveOperatorPolicyGlobals(t)
		root := operatorPolicyFixture(t, validOperatorPolicyModule)
		if err := loadModularConfig(root); err != nil {
			t.Fatalf("loadModularConfig() error: %v", err)
		}
		return GlobalConfig, filepath.Join(root, "modules", userModuleName)
	}

	t.Run("unchanged source", func(t *testing.T) {
		config, _ := load(t)
		if err := ReattestOperatorPolicySource(config); err != nil {
			t.Fatalf("ReattestOperatorPolicySource() error: %v", err)
		}
	})

	t.Run("same inode content change", func(t *testing.T) {
		config, path := load(t)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304 -- path is returned by the private fixture loader for this adversarial identity test
		if err != nil {
			t.Fatalf("open same-inode mutation fixture: %v", err)
		}
		if _, err := file.WriteString(validOperatorPolicyModule + "# changed\n"); err != nil {
			_ = file.Close()
			t.Fatalf("write same-inode mutation fixture: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close same-inode mutation fixture: %v", err)
		}
		if err := ReattestOperatorPolicySource(config); err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("same-inode content change error = %v, want identity change", err)
		}
	})

	t.Run("inode replacement", func(t *testing.T) {
		config, path := load(t)
		replacement := path + ".replacement"
		if err := os.WriteFile(replacement, []byte(validOperatorPolicyModule), 0o600); err != nil {
			t.Fatalf("write replacement inode: %v", err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatalf("replace source inode: %v", err)
		}
		if err := ReattestOperatorPolicySource(config); err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("inode replacement error = %v, want identity change", err)
		}
	})

	t.Run("mode change", func(t *testing.T) {
		config, path := load(t)
		if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- adversarial fixture deliberately proves a relaxed source mode invalidates attestation
			t.Fatalf("change source mode: %v", err)
		}
		if err := ReattestOperatorPolicySource(config); err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("mode change error = %v, want identity change", err)
		}
	})

	t.Run("typed snapshot mutation", func(t *testing.T) {
		config, _ := load(t)
		config.OperatorPolicy.Rules[0].Source = "192.0.2.11"
		if err := ValidateOperatorPolicy(config.OperatorPolicy); err != nil {
			t.Fatalf("typed mutation fixture must remain semantically valid: %v", err)
		}
		if err := ReattestOperatorPolicySource(config); err == nil || !strings.Contains(err.Error(), "snapshot changed") {
			t.Fatalf("typed snapshot mutation error = %v, want snapshot change", err)
		}
	})

	t.Run("non-empty policy without attestation", func(t *testing.T) {
		config := &Config{OperatorPolicy: OperatorPolicyConfig{Rules: []OperatorPolicyRule{{ID: "allow"}}}}
		if err := ReattestOperatorPolicySource(config); err == nil || !strings.Contains(err.Error(), "no source attestation") {
			t.Fatalf("missing attestation error = %v, want fail closed", err)
		}
	})

	t.Run("empty policy without attestation", func(t *testing.T) {
		if err := ReattestOperatorPolicySource(&Config{}); err != nil {
			t.Fatalf("empty policy reattestation should be a no-op: %v", err)
		}
	})
}

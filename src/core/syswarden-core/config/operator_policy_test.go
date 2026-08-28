package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/viper"
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
	if corpus.Limits.MaximumModuleBytes != maximumOperatorPolicyModuleBytes {
		t.Fatalf("shared maximum module bytes = %d, want %d", corpus.Limits.MaximumModuleBytes, maximumOperatorPolicyModuleBytes)
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

const validCoreOperatorPolicyModule = `[[operator_policy.rules]]
id = "allow-icmp-v4"
family = "ipv4"
direction = "ingress"
protocol = "icmp"
type = "echo-request"
source = "0.0.0.0/0"
action = "accept"

[[operator_policy.rules]]
id = "allow-icmp-v6"
family = "ipv6"
direction = "ingress"
protocol = "icmpv6"
type = "echo-request"
source = "::/0"
action = "accept"
`

func validCoreOperatorPolicyRule() OperatorPolicyRule {
	return OperatorPolicyRule{
		ID:        "allow-icmp-v4",
		Family:    OperatorPolicyFamilyIPv4,
		Direction: OperatorPolicyDirectionIngress,
		Protocol:  OperatorPolicyProtocolICMP,
		ICMPType:  OperatorPolicyTypeEchoRequest,
		Source:    "192.0.2.10",
		Action:    OperatorPolicyActionAccept,
	}
}

func TestCoreOperatorPolicyMapsUnderSchemaOne_SW_OPPOL_001(t *testing.T) {
	t.Cleanup(viper.Reset)
	if CurrentSchemaVersion != 1 {
		t.Fatalf("operator_policy must remain valid under schema version 1, got %d", CurrentSchemaVersion)
	}
	root := writeConfigFixture(
		t,
		validMaster("schema_version = 1"),
		map[string]string{operatorPolicyModuleName: validCoreOperatorPolicyModule},
	)
	diagnostics, err := LoadConfigDirectory(root)
	if err != nil {
		t.Fatalf("LoadConfigDirectory() error = %v", err)
	}
	if diagnostics.SchemaVersion != 1 || diagnostics.Historical {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if len(diagnostics.UnknownKeys) != 0 {
		t.Fatalf("operator policy keys reported as unknown: %v", diagnostics.UnknownKeys)
	}

	var got OperatorPolicyConfig
	if err := viper.UnmarshalKey("operator_policy", &got); err != nil {
		t.Fatalf("decode published operator policy: %v", err)
	}
	want := OperatorPolicyConfig{Rules: []OperatorPolicyRule{
		{
			ID:        "allow-icmp-v4",
			Family:    OperatorPolicyFamilyIPv4,
			Direction: OperatorPolicyDirectionIngress,
			Protocol:  OperatorPolicyProtocolICMP,
			ICMPType:  OperatorPolicyTypeEchoRequest,
			Source:    "0.0.0.0/0",
			Action:    OperatorPolicyActionAccept,
		},
		{
			ID:        "allow-icmp-v6",
			Family:    OperatorPolicyFamilyIPv6,
			Direction: OperatorPolicyDirectionIngress,
			Protocol:  OperatorPolicyProtocolICMPv6,
			ICMPType:  OperatorPolicyTypeEchoRequest,
			Source:    "::/0",
			Action:    OperatorPolicyActionAccept,
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published operator policy = %#v, want %#v", got, want)
	}
}

func TestCoreOperatorPolicyRawContractParity_SW_OPPOL_002(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "unknown policy key",
			content: "[operator_policy]\nmode = \"merge\"\n",
			want:    "unknown key",
		},
		{
			name:    "rules must be an array",
			content: "[operator_policy]\nrules = \"allow\"\n",
			want:    "must be an array",
		},
		{
			name:    "rule must be a table",
			content: "[operator_policy]\nrules = [\"allow\"]\n",
			want:    "must be a TOML table",
		},
		{
			name:    "unknown eighth field",
			content: validCoreOperatorPolicyModule + "expression = \"raw nft\"\n",
			want:    "unknown key",
		},
		{
			name: "missing required field",
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
			name: "field must be an exact string",
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
			name:    "case lookalike root",
			content: "[Operator_Policy]\nrules = []\n",
			want:    "non-canonical operator_policy key",
		},
		{
			name:    "hyphen lookalike root",
			content: "[operator-policy]\nrules = []\n",
			want:    "non-canonical operator_policy key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDocument([]byte(test.content), operatorPolicyModulePath)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseDocument() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCoreOperatorPolicyProvenanceIsExclusive_SW_OPPOL_003(t *testing.T) {
	for _, relative := range []string{
		"config.toml",
		"modules/10-network.toml",
		"modules/99-user-copy.toml",
		"modules/99-USER.toml",
	} {
		t.Run(relative, func(t *testing.T) {
			_, err := parseDocument([]byte(validCoreOperatorPolicyModule), relative)
			if err == nil || !strings.Contains(err.Error(), "only in modules/99-user.toml") {
				t.Fatalf("parseDocument(%q) error = %v, want exclusive provenance error", relative, err)
			}
		})
	}
	if _, err := parseDocument([]byte(validCoreOperatorPolicyModule), operatorPolicyModulePath); err != nil {
		t.Fatalf("canonical provenance was rejected: %v", err)
	}
}

func TestCoreOperatorPolicySemanticParity_SW_OPPOL_004(t *testing.T) {
	valid := validCoreOperatorPolicyRule()
	mutate := func(change func(*OperatorPolicyRule)) OperatorPolicyConfig {
		rule := valid
		change(&rule)
		return OperatorPolicyConfig{Rules: []OperatorPolicyRule{rule}}
	}
	tests := []struct {
		name   string
		policy OperatorPolicyConfig
		want   string
	}{
		{name: "empty id", policy: mutate(func(rule *OperatorPolicyRule) { rule.ID = "" }), want: "must match"},
		{name: "uppercase id", policy: mutate(func(rule *OperatorPolicyRule) { rule.ID = "Allow-icmp" }), want: "must match"},
		{name: "underscore id", policy: mutate(func(rule *OperatorPolicyRule) { rule.ID = "allow_icmp" }), want: "must match"},
		{name: "id 64 bytes", policy: mutate(func(rule *OperatorPolicyRule) { rule.ID = "a" + strings.Repeat("b", 63) }), want: "must match"},
		{name: "wrong direction", policy: mutate(func(rule *OperatorPolicyRule) { rule.Direction = "egress" }), want: `direction must be "ingress"`},
		{name: "wrong type", policy: mutate(func(rule *OperatorPolicyRule) { rule.ICMPType = "echo-reply" }), want: `type must be "echo-request"`},
		{name: "wrong action", policy: mutate(func(rule *OperatorPolicyRule) { rule.Action = "drop" }), want: `action must be "accept"`},
		{name: "ipv4 protocol mismatch", policy: mutate(func(rule *OperatorPolicyRule) { rule.Protocol = OperatorPolicyProtocolICMPv6 }), want: "requires protocol"},
		{name: "unknown family", policy: mutate(func(rule *OperatorPolicyRule) { rule.Family = "ip" }), want: "family must be"},
		{name: "family source mismatch", policy: mutate(func(rule *OperatorPolicyRule) {
			rule.Family = OperatorPolicyFamilyIPv6
			rule.Protocol = OperatorPolicyProtocolICMPv6
		}), want: "does not match"},
		{name: "empty source", policy: mutate(func(rule *OperatorPolicyRule) { rule.Source = "" }), want: "must not be empty"},
		{name: "padded source", policy: mutate(func(rule *OperatorPolicyRule) { rule.Source = " 192.0.2.10" }), want: "whitespace padded"},
		{name: "host bits", policy: mutate(func(rule *OperatorPolicyRule) { rule.Source = "192.0.2.10/24" }), want: "canonical"},
		{name: "noncanonical IPv6", policy: mutate(func(rule *OperatorPolicyRule) {
			rule.ID = "allow-icmp-v6"
			rule.Family = OperatorPolicyFamilyIPv6
			rule.Protocol = OperatorPolicyProtocolICMPv6
			rule.Source = "2001:0db8::1"
		}), want: "canonical"},
		{name: "IPv6 zone", policy: mutate(func(rule *OperatorPolicyRule) {
			rule.ID = "allow-icmp-v6"
			rule.Family = OperatorPolicyFamilyIPv6
			rule.Protocol = OperatorPolicyProtocolICMPv6
			rule.Source = "fe80::1%eth0"
		}), want: "zone"},
		{name: "IPv4-mapped IPv6", policy: mutate(func(rule *OperatorPolicyRule) {
			rule.ID = "allow-icmp-v6"
			rule.Family = OperatorPolicyFamilyIPv6
			rule.Protocol = OperatorPolicyProtocolICMPv6
			rule.Source = "::ffff:192.0.2.10"
		}), want: "IPv4-mapped"},
	}

	if err := validateOperatorPolicy(OperatorPolicyConfig{Rules: []OperatorPolicyRule{valid}}); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	maxID := valid
	maxID.ID = "a" + strings.Repeat("b", 62)
	if err := validateOperatorPolicy(OperatorPolicyConfig{Rules: []OperatorPolicyRule{maxID}}); err != nil {
		t.Fatalf("63-byte identifier rejected: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateOperatorPolicy(test.policy)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateOperatorPolicy() error = %v, want substring %q", err, test.want)
			}
		})
	}

	duplicate := valid
	duplicate.Source = "192.0.2.11"
	if err := validateOperatorPolicy(OperatorPolicyConfig{Rules: []OperatorPolicyRule{valid, duplicate}}); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("duplicate ID error = %v", err)
	}
	equivalent := valid
	equivalent.ID = "allow-equivalent"
	equivalent.Source = "192.0.2.10/32"
	if err := validateOperatorPolicy(OperatorPolicyConfig{Rules: []OperatorPolicyRule{valid, equivalent}}); err == nil || !strings.Contains(err.Error(), "overlapping") {
		t.Fatalf("equivalent source error = %v", err)
	}
	covering := valid
	covering.Source = "192.0.2.0/24"
	covered := valid
	covered.ID = "allow-host"
	if err := validateOperatorPolicy(OperatorPolicyConfig{Rules: []OperatorPolicyRule{covering, covered}}); err == nil || !strings.Contains(err.Error(), "overlapping") {
		t.Fatalf("overlap error = %v", err)
	}
	disjoint := valid
	disjoint.ID = "allow-other"
	disjoint.Source = "198.51.100.10"
	if err := validateOperatorPolicy(OperatorPolicyConfig{Rules: []OperatorPolicyRule{valid, disjoint}}); err != nil {
		t.Fatalf("disjoint rules rejected: %v", err)
	}
}

func TestCoreOperatorPolicySharedContractParity_SW_OPPOL_010(t *testing.T) {
	corpus := loadOperatorPolicyContractCorpus(t)
	for _, test := range corpus.RawCases {
		t.Run("raw/"+test.Name, func(t *testing.T) {
			_, err := parseDocument([]byte(test.TOML), test.RelativePath)
			requireOperatorPolicyContractOutcome(t, err, test.WantError)
		})
	}
	for _, test := range corpus.SemanticCases {
		t.Run("semantic/"+test.Name, func(t *testing.T) {
			policy := OperatorPolicyConfig{Rules: make([]OperatorPolicyRule, 0, len(test.Rules))}
			for _, rule := range test.Rules {
				policy.Rules = append(policy.Rules, rule.typed())
			}
			requireOperatorPolicyContractOutcome(t, validateOperatorPolicy(policy), test.WantError)
		})
	}
	for _, test := range corpus.RuleCountCases {
		t.Run("rule-count/"+test.Name, func(t *testing.T) {
			rules := generatedOperatorPolicyContractRules(test.Count)
			policy := OperatorPolicyConfig{Rules: make([]OperatorPolicyRule, 0, len(rules))}
			for _, rule := range rules {
				policy.Rules = append(policy.Rules, rule.typed())
			}
			requireOperatorPolicyContractOutcome(t, validateOperatorPolicy(policy), test.WantError)
			_, err := parseDocument([]byte(renderOperatorPolicyContractRules(rules)), corpus.ModulePath)
			requireOperatorPolicyContractOutcome(t, err, test.WantError)
		})
	}
}

func TestCoreOperatorPolicyContractCorpusRejectsUnknownJSONKeys_SW_OPPOL_012(t *testing.T) {
	_, err := decodeOperatorPolicyContractCorpus(strings.NewReader(`{"schema_version":1,"unknown":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown corpus field error = %v, want strict JSON rejection", err)
	}
}

func TestCoreOperatorPolicyRuleLimitParity_SW_OPPOL_005(t *testing.T) {
	var module strings.Builder
	for index := 0; index < maximumOperatorPolicyRules; index++ {
		fmt.Fprintf(&module, `[[operator_policy.rules]]
id = "allow-%02d"
family = "ipv4"
direction = "ingress"
protocol = "icmp"
type = "echo-request"
source = "192.0.2.%d"
action = "accept"

`, index, index+1)
	}
	if _, err := parseDocument([]byte(module.String()), operatorPolicyModulePath); err != nil {
		t.Fatalf("64 rules rejected: %v", err)
	}
	fmt.Fprintf(&module, `[[operator_policy.rules]]
id = "allow-64"
family = "ipv4"
direction = "ingress"
protocol = "icmp"
type = "echo-request"
source = "198.51.100.1"
action = "accept"
`)
	if _, err := parseDocument([]byte(module.String()), operatorPolicyModulePath); err == nil || !strings.Contains(err.Error(), "64-rule limit") {
		t.Fatalf("65-rule error = %v, want 64-rule limit", err)
	}
}

func TestCoreOperatorPolicyEnvironmentIsForbidden_SW_OPPOL_006(t *testing.T) {
	corpus := loadOperatorPolicyContractCorpus(t)
	for _, name := range corpus.EnvironmentNames {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			const value = "must-not-appear-in-errors"
			t.Setenv(name, value)
			root := writeConfigFixture(
				t,
				validMaster("schema_version = 1"),
				map[string]string{operatorPolicyModuleName: validCoreOperatorPolicyModule},
			)
			_, err := LoadConfigDirectory(root)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadConfigDirectory() error = %v, want forbidden variable %s", err, name)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatalf("environment value leaked in error: %v", err)
			}
		})
	}
}

func TestCoreOperatorPolicySharedModuleSizeContract_SW_OPPOL_011(t *testing.T) {
	corpus := loadOperatorPolicyContractCorpus(t)
	for _, test := range corpus.ModuleSizeCases {
		t.Run(test.Name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			root := writeConfigFixture(
				t,
				validMaster("schema_version = 1"),
				map[string]string{operatorPolicyModuleName: strings.Repeat("#", test.Size)},
			)
			_, err := LoadConfigDirectory(root)
			requireOperatorPolicyContractOutcome(t, err, test.WantError)
		})
	}
}

func TestCoreOperatorPolicyModuleByteLimit_SW_OPPOL_007(t *testing.T) {
	for _, test := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "exact maximum", size: maximumOperatorPolicyModuleBytes},
		{name: "maximum plus one", size: maximumOperatorPolicyModuleBytes + 1, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			root := writeConfigFixture(
				t,
				validMaster("schema_version = 1"),
				map[string]string{operatorPolicyModuleName: strings.Repeat("#", test.size)},
			)
			_, err := LoadConfigDirectory(root)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%d-byte limit", maximumOperatorPolicyModuleBytes)) {
					t.Fatalf("LoadConfigDirectory() error = %v, want byte-limit failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("exact maximum was rejected: %v", err)
			}
		})
	}
}

func TestCoreInvalidOperatorPolicyIsNotPublished_SW_OPPOL_008(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Set("core.log_level", "SENTINEL")
	root := writeConfigFixture(t, validMaster("schema_version = 1"), map[string]string{
		operatorPolicyModuleName: strings.Replace(validCoreOperatorPolicyModule, `action = "accept"`, `action = "drop"`, 1),
	})
	if _, err := LoadConfigDirectory(root); err == nil {
		t.Fatal("invalid operator policy unexpectedly loaded")
	}
	if got := viper.GetString("core.log_level"); got != "SENTINEL" {
		t.Fatalf("invalid candidate was published: %q", got)
	}
}

func TestCoreOperatorPolicySizeCheckUsesExactUserModuleName_SW_OPPOL_009(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- owner-only directory mode requires execute permission for this private fixture
		t.Fatal(err)
	}
	moduleRoot := filepath.Join(root, "modules")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fileRoot, err := openSecureDirectory(moduleRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer fileRoot.Close()
	path := filepath.Join(moduleRoot, operatorPolicyModuleName)
	if err := os.WriteFile(path, []byte(validCoreOperatorPolicyModule), 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := readSecureRegularFile(fileRoot, operatorPolicyModuleName, path)
	if err != nil {
		t.Fatalf("readSecureRegularFile() error = %v", err)
	}
	if string(content) != validCoreOperatorPolicyModule {
		t.Fatal("bounded user module content changed while reading")
	}
}

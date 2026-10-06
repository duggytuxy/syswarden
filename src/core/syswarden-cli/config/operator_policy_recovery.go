package config

import (
	"bytes"
	"fmt"
	"github.com/spf13/viper"
	"path/filepath"
)

// InspectOperatorPolicyForRecovery reads only the documented administrator
// module, without installing defaults, applying environment values or changing
// process-global configuration. Other product configuration may already have
// been retired. This proves the typed source, not a complete removal handoff.
func InspectOperatorPolicyForRecovery(configDir string) (*Config, error) {
	if err := rejectOperatorPolicyEnvironment(); err != nil {
		return nil, err
	}
	if err := rejectMigrationInProgress(configDir); err != nil {
		return nil, err
	}
	modulesDir, err := filepath.Abs(filepath.Join(configDir, "modules"))
	if err != nil {
		return nil, err
	}
	root, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	content, identity, err := readSecureRegularFileIdentity(root, userModuleName, filepath.Join(modulesDir, userModuleName))
	if err != nil {
		return nil, err
	}
	if _, err := parseTOMLDocument(content, operatorPolicyModulePath); err != nil {
		return nil, err
	}
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(bytes.NewReader(content)); err != nil {
		return nil, err
	}
	var policy OperatorPolicyConfig
	if err := v.UnmarshalKey("operator_policy", &policy); err != nil {
		return nil, err
	}
	if len(policy.Rules) == 0 {
		return nil, fmt.Errorf("administrator recovery requires a nonempty typed operator policy")
	}
	if err := ValidateOperatorPolicy(policy); err != nil {
		return nil, err
	}
	candidate := NewFailSafeConfig()
	candidate.OperatorPolicy = cloneOperatorPolicy(policy)
	candidate.operatorPolicySource = &operatorPolicySourceAttestation{modulesDir: filepath.Clean(modulesDir), identity: identity, policy: cloneOperatorPolicy(policy)}
	if err := ReattestOperatorPolicySource(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

// OperatorPolicySourcePath returns the exact validated path after reattestation.
// It exposes no configuration bytes or credentials to a recovery summary.
func OperatorPolicySourcePath(candidate *Config) (string, error) {
	if candidate == nil || len(candidate.OperatorPolicy.Rules) == 0 {
		return "", fmt.Errorf("administrator policy source is unavailable")
	}
	if err := ReattestOperatorPolicySource(candidate); err != nil {
		return "", err
	}
	return filepath.Join(candidate.operatorPolicySource.modulesDir, userModuleName), nil
}

package config

const CurrentSchemaVersion = 1

// ModularConfig represents the new hierarchical TOML structure
type ModularConfig struct {
	SchemaVersion  int                  `mapstructure:"schema_version"`
	Core           CoreConfig           `mapstructure:"core"`
	Network        NetworkConfig        `mapstructure:"network"`
	Security       SecurityConfig       `mapstructure:"security"`
	WAAP           WAAPConfig           `mapstructure:"waap"`
	Integrations   IntegrationsConfig   `mapstructure:"integrations"`
	OperatorPolicy OperatorPolicyConfig `mapstructure:"operator_policy"`
	User           UserConfig           `mapstructure:"user"`
}

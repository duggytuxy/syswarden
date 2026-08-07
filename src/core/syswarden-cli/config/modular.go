package config

// ModularConfig represents the new hierarchical TOML structure
type ModularConfig struct {
	Core         CoreConfig         `mapstructure:"core"`
	Network      NetworkConfig      `mapstructure:"network"`
	Security     SecurityConfig     `mapstructure:"security"`
	WAAP         WAAPConfig         `mapstructure:"waap"`
	Integrations IntegrationsConfig `mapstructure:"integrations"`
}

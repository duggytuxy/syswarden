package config

type WAAPConfig struct {
	EnforcementMode         string `mapstructure:"enforcement_mode" validate:"required,oneof=enforcing audit"`
	BruteforceLogs          string `mapstructure:"bruteforce_logs"`
	BruteforceThreshold     int    `mapstructure:"bruteforce_threshold" validate:"min=1"`
	BruteforceWindowSeconds int    `mapstructure:"bruteforce_window_seconds" validate:"min=1"`
	ModsecLogs              string `mapstructure:"modsec_logs"`
}

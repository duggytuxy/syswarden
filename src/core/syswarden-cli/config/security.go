package config

type SecurityConfig struct {
	Honeyports []string         `mapstructure:"honeyports"`
	L2         L2Config         `mapstructure:"l2"`
	Compliance ComplianceConfig `mapstructure:"compliance"`
}

type L2Config struct {
	EnableL2   bool `mapstructure:"enable_l2"`
	ARPProtect bool `mapstructure:"arp_protect"`
	LanMode    bool `mapstructure:"lan_mode"`
}

type ComplianceConfig struct {
	EnableWatchdog bool   `mapstructure:"enable_watchdog"`
	CheckInterval  string `mapstructure:"check_interval" validate:"duration"`
}

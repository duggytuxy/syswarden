package config

type IntegrationsConfig struct {
	HA        HAConfig        `mapstructure:"ha"`
	SIEM      SIEMConfig      `mapstructure:"siem"`
	AbuseIPDB AbuseIPDBConfig `mapstructure:"abuseipdb"`
	Webhooks  WebhooksConfig  `mapstructure:"webhooks"`
	BunkerWeb BunkerWebConfig `mapstructure:"bunkerweb"`
	Wazuh     WazuhConfig     `mapstructure:"wazuh"`
}

type HAConfig struct {
	Enabled  bool     `mapstructure:"enabled"`
	PeerIPs  []string `mapstructure:"peer_ips" validate:"ip_or_cidr_slice"`
	PeerPort int      `mapstructure:"peer_port" validate:"min=1,max=65535"`
	Token    string   `mapstructure:"token"`
}

type SIEMConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	IP       string `mapstructure:"ip"`
	Port     string `mapstructure:"port" validate:"port"`
	Protocol string `mapstructure:"protocol"`
	TLSCA    string `mapstructure:"tls_ca"`
}

type AbuseIPDBConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
}

type WebhooksConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	DiscordURL string `mapstructure:"discord_url"`
	TeamsURL   string `mapstructure:"teams_url"`
	SlackURL   string `mapstructure:"slack_url"`
}

type BunkerWebConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type WazuhConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	IP         string `mapstructure:"ip"`
	Name       string `mapstructure:"name"`
	Group      string `mapstructure:"group"`
	CommPort   string `mapstructure:"comm_port" validate:"port"`
	EnrollPort string `mapstructure:"enroll_port" validate:"port"`
}

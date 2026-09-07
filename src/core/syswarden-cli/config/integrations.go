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
	Enabled                  bool     `mapstructure:"enabled"`
	PeerIPs                  []string `mapstructure:"peer_ips" validate:"ha_peer_slice"`
	PeerPort                 int      `mapstructure:"peer_port" validate:"min=1,max=65535"`
	Token                    string   `mapstructure:"token"`
	V2Enabled                bool     `mapstructure:"v2_enabled"`
	ClusterID                string   `mapstructure:"cluster_id"`
	Epoch                    uint64   `mapstructure:"epoch"`
	NodeID                   string   `mapstructure:"node_id"`
	PeerID                   string   `mapstructure:"peer_id"`
	Role                     string   `mapstructure:"role"`
	V2SecretFile             string   `mapstructure:"v2_secret_file"`
	TLSCertFile              string   `mapstructure:"tls_cert_file"`
	TLSKeyFile               string   `mapstructure:"tls_key_file"`
	TLSCAFile                string   `mapstructure:"tls_ca_file"`
	PeerTLSName              string   `mapstructure:"peer_tls_name"`
	PeerCertSHA256           []string `mapstructure:"peer_cert_sha256"`
	StateFile                string   `mapstructure:"state_file"`
	TransactionFile          string   `mapstructure:"transaction_file"`
	HeartbeatIntervalSeconds int      `mapstructure:"heartbeat_interval_seconds"`
	HeartbeatTimeoutSeconds  int      `mapstructure:"heartbeat_timeout_seconds"`
	RequestTimeoutSeconds    int      `mapstructure:"request_timeout_seconds"`
}

type SIEMConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	IP       string `mapstructure:"ip" validate:"ip"`
	Port     string `mapstructure:"port" validate:"port"`
	Protocol string `mapstructure:"protocol" validate:"omitempty,oneof=tls tcp udp"`
	TLSCA    string `mapstructure:"tls_ca" validate:"absolute_path_optional"`
}

type AbuseIPDBConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
}

type WebhooksConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	DiscordURL string `mapstructure:"discord_url" validate:"https_url_optional"`
	TeamsURL   string `mapstructure:"teams_url" validate:"https_url_optional"`
	SlackURL   string `mapstructure:"slack_url" validate:"https_url_optional"`
}

type BunkerWebConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	SchedulerIPs []string `mapstructure:"scheduler_ips" validate:"ha_peer_slice"`
}

type WazuhConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	IP         string `mapstructure:"ip" validate:"ip"`
	Name       string `mapstructure:"name"`
	Group      string `mapstructure:"group"`
	CommPort   string `mapstructure:"comm_port" validate:"port"`
	EnrollPort string `mapstructure:"enroll_port" validate:"port"`
}

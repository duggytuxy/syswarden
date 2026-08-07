package config

type IntegrationsConfig struct {
	HA HAConfig `mapstructure:"ha"`
}

type HAConfig struct {
	Enabled  bool     `mapstructure:"enabled"`
	PeerIPs  []string `mapstructure:"peer_ips"`
	PeerPort int      `mapstructure:"peer_port" validate:"min=1,max=65535"`
	Token    string   `mapstructure:"token"`
}

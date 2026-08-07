package config

type NetworkConfig struct {
	WhitelistInfra bool             `mapstructure:"whitelist_infra"`
	LanSubnets     []string         `mapstructure:"lan_subnets"`
	WhitelistIPs   []string         `mapstructure:"whitelist_ips"`
	Geo            GeoConfig        `mapstructure:"geo"`
	ASN            ASNConfig        `mapstructure:"asn"`
	Saas           SaasConfig       `mapstructure:"saas"`
	Wireguard      WGConfig         `mapstructure:"wireguard"`
	Interfaces     string           `mapstructure:"interfaces"`
	Blocklists     BlocklistsConfig `mapstructure:"blocklists"`
}

type BlocklistsConfig struct {
	ListChoice  string `mapstructure:"list_choice"`
	CustomURL   string `mapstructure:"custom_url"`
	CustomURL6  string `mapstructure:"custom_url_ipv6"`
	CustomHash  string `mapstructure:"custom_hash"`
	CustomHash6 string `mapstructure:"custom_hash_ipv6"`
}

type GeoConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	BlockedCountries []string `mapstructure:"blocked_countries"`
	AllowedCountries []string `mapstructure:"allowed_countries"`
}

type ASNConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	BlockedASNs []string `mapstructure:"blocked_asns"`
	AllowedASNs []string `mapstructure:"allowed_asns"`
}

type SaasConfig struct {
	AllowMonitors bool `mapstructure:"allow_monitors"`
}

type WGConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    string `mapstructure:"port" validate:"port"`
	Subnet  string `mapstructure:"subnet" validate:"cidr"`
}

func (n *NetworkConfig) IsZeroTrustGeo() bool {
	return len(n.Geo.AllowedCountries) > 0
}

func (n *NetworkConfig) IsZeroTrustASN() bool {
	return len(n.ASN.AllowedASNs) > 0
}

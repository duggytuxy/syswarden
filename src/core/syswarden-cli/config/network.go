package config

type NetworkConfig struct {
	WhitelistInfra bool             `mapstructure:"whitelist_infra"`
	LanSubnets     []string         `mapstructure:"lan_subnets" validate:"canonical_cidr_slice"`
	WhitelistIPs   []string         `mapstructure:"whitelist_ips" validate:"ip_or_cidr_slice"`
	Geo            GeoConfig        `mapstructure:"geo"`
	ASN            ASNConfig        `mapstructure:"asn"`
	Saas           SaasConfig       `mapstructure:"saas"`
	Wireguard      WGConfig         `mapstructure:"wireguard"`
	Interfaces     string           `mapstructure:"interfaces" validate:"interface_list"`
	Blocklists     BlocklistsConfig `mapstructure:"blocklists"`
}

type BlocklistsConfig struct {
	ListChoice  string `mapstructure:"list_choice" validate:"omitempty,oneof=1 2 3 4"`
	CustomURL   string `mapstructure:"custom_url" validate:"https_url_optional"`
	CustomURL6  string `mapstructure:"custom_url_ipv6" validate:"https_url_optional"`
	CustomHash  string `mapstructure:"custom_hash" validate:"sha256_optional"`
	CustomHash6 string `mapstructure:"custom_hash_ipv6" validate:"sha256_optional"`
	UseSpamhaus bool   `mapstructure:"use_spamhaus"`
}

type GeoConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	BlockedCountries []string `mapstructure:"blocked_countries" validate:"country_code_slice"`
	AllowedCountries []string `mapstructure:"allowed_countries" validate:"country_code_slice"`
}

type ASNConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	BlockedASNs []string `mapstructure:"blocked_asns" validate:"asn_slice"`
	AllowedASNs []string `mapstructure:"allowed_asns" validate:"asn_slice"`
}

type SaasConfig struct {
	AllowMonitors bool `mapstructure:"allow_monitors"`
}

type WGConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    string `mapstructure:"port" validate:"port"`
	Subnet  string `mapstructure:"subnet" validate:"canonical_cidr"`
}

func (n *NetworkConfig) IsZeroTrustGeo() bool {
	return len(n.Geo.AllowedCountries) > 0
}

func (n *NetworkConfig) IsZeroTrustASN() bool {
	return len(n.ASN.AllowedASNs) > 0
}

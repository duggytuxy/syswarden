package config

// Config represents the parsed syswarden-auto.conf file securely mapped to memory
type Config struct {
	EnterpriseMode      bool
	SSHPort             string
	FirewallBackend     string
	Interfaces          string
	WhitelistInfra      bool
	WhitelistIPs        string
	EnableWG            bool
	WGPort              string
	WGSubnet            string
	ModsecLogs          string
	BruteforceLogs      string
	BruteforceThreshold string
	BruteforceWindow    string
	HoneyPorts          string
	Hardening           bool
	CISL2Hardening      bool
	ListChoice          string
	CustomURL           string
	CustomURLIPv6       string
	CustomHash          string
	CustomHashIPv6      string
	EnableGeo           bool
	GeoCodes            string
	GeoAllowed          string
	EnableASN           bool
	ASNList             string
	ASNAllowed          string
	UseSpamhaus         bool
	HAEnabled           bool
	HAPeerIP            string
	HAPeerPort          string
	SiemEnabled         bool
	SiemIP              string
	SiemPort            string
	SiemProto           string
	SiemTLSCA           string
	EnableAbuse         bool
	AbuseAPIKey         string
	EnableWebhook       bool
	WebhookURLDiscord   string
	WebhookURLTeams     string
	WebhookURLSlack     string
	EnableWazuh         bool
	WazuhIP             string
	WazuhName           string
	WazuhGroup          string
	WazuhCommPort       string
	WazuhEnrollPort     string
	SecureWipeConf      bool
	EnableL2            bool
	ArpProtect          bool
	LANMode             bool
	LANSubnets          string
}

// GlobalConfig is the singleton instance holding the parsed configuration
var GlobalConfig *Config

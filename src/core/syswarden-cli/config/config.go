package config

import "sync"

// Config represents the parsed syswarden-auto.conf file securely mapped to memory
type Config struct {
	EnterpriseMode       bool
	EnforcementMode      string
	SSHPort              string
	FirewallBackend      string
	Interfaces           string
	WhitelistInfra       bool
	WhitelistIPs         string
	EnableWG             bool
	WGPort               string
	WGSubnet             string
	ModsecLogs           string
	BruteforceLogs       string
	BruteforceThreshold  string
	BruteforceWindow     string
	HoneyPorts           string
	Hardening            bool
	CISL2Hardening       bool
	ListChoice           string
	CustomURL            string
	CustomURLIPv6        string
	CustomHash           string
	CustomHashIPv6       string
	EnableGeo            bool
	GeoCodes             string
	GeoAllowed           string
	EnableASN            bool
	ASNList              string
	ASNAllowed           string
	UseSpamhaus          bool
	AllowSaaSMonitors    bool
	HAEnabled            bool
	HAToken              string
	HAPeerIP             string
	HAPeerPort           string
	SiemEnabled          bool
	SiemIP               string
	SiemPort             string
	SiemProto            string
	SiemTLSCA            string
	EnableAbuse          bool
	AbuseAPIKey          string
	EnableWebhook        bool
	WebhookURLDiscord    string
	WebhookURLTeams      string
	WebhookURLSlack      string
	BunkerWebEnabled     bool
	EnableWazuh          bool
	WazuhIP              string
	WazuhName            string
	WazuhGroup           string
	WazuhCommPort        string
	WazuhEnrollPort      string
	SecureWipeConf       bool
	EnableL2             bool
	ArpProtect           bool
	LANMode              bool
	LANSubnets           string
	OperatorPolicy       OperatorPolicyConfig
	operatorPolicySource *operatorPolicySourceAttestation
}

// LoadState describes whether the active configuration came from a validated
// source or from the built-in fail-safe defaults.
type LoadState struct {
	Source   string
	Degraded bool
	Error    string
}

var (
	configLoadMu sync.Mutex
	loadStateMu  sync.RWMutex
	loadState    = LoadState{
		Source:   "built-in fail-safe defaults",
		Degraded: true,
		Error:    "no configuration has been loaded",
	}
)

// NewFailSafeConfig returns a non-nil configuration that keeps optional host
// mutations disabled until a validated configuration has been loaded.
func NewFailSafeConfig() *Config {
	return &Config{
		FirewallBackend:     "keep",
		EnforcementMode:     "enforcing",
		WhitelistInfra:      true,
		BruteforceThreshold: "5",
		BruteforceWindow:    "60s",
		ListChoice:          "4",
		WGPort:              "51820",
		HAPeerPort:          "62026",
		SiemPort:            "6514",
		SiemProto:           "tls",
	}
}

// GlobalConfig is the singleton instance holding the last validated
// configuration. It is initialized eagerly so callers never observe nil.
//
// Configuration loading is deliberately a single-threaded CLI lifecycle step:
// Cobra initialization loads once, and the install preflight may replace that
// snapshot before any background work starts. Runtime reload writers are not
// permitted to assign this pointer. A future long-lived reload facility must
// introduce an atomic snapshot API before adding a concurrent writer.
var GlobalConfig = NewFailSafeConfig()

func commitGlobalConfig(candidate *Config, source string) {
	if candidate == nil {
		candidate = NewFailSafeConfig()
	}
	GlobalConfig = candidate
	loadStateMu.Lock()
	loadState = LoadState{Source: source}
	loadStateMu.Unlock()
}

func recordConfigLoadFailure(source string, err error) {
	if GlobalConfig == nil {
		GlobalConfig = NewFailSafeConfig()
	}
	state := LoadState{Source: source, Degraded: true}
	if err != nil {
		state.Error = err.Error()
	}
	loadStateMu.Lock()
	loadState = state
	loadStateMu.Unlock()
}

// CurrentLoadState returns a copy of the last configuration load state.
func CurrentLoadState() LoadState {
	loadStateMu.RLock()
	defer loadStateMu.RUnlock()
	return loadState
}

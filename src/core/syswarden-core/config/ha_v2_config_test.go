package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestHAV2ConfigurationRequiresExactStaticTwoNodeContract(t *testing.T) {
	t.Cleanup(viper.Reset)
	base := strings.Replace(validMaster("schema_version = 1"), "enabled = false\npeer_port = 62026", `enabled = true
peer_ips = ["192.0.2.10"]
peer_port = 62026
token = "legacy-outer-auth-token"
v2_enabled = true
cluster_id = "cluster-a"
epoch = 1
node_id = "node-a"
peer_id = "node-b"
role = "writer"
v2_secret_file = "/etc/syswarden/ha-v2.secret"`, 1)
	base = strings.Replace(base, `v2_secret_file = "/etc/syswarden/ha-v2.secret"`, `v2_secret_file = "/etc/syswarden/ha-v2.secret"
tls_cert_file = "/etc/syswarden/ha-v2.crt"
tls_key_file = "/etc/syswarden/ha-v2.key"
tls_ca_file = "/etc/syswarden/ha-v2-ca.crt"
peer_tls_name = "node-b"
peer_cert_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]`, 1)
	if _, err := LoadConfigDirectory(writeConfigFixture(t, base, nil)); err != nil {
		t.Fatalf("valid HA v2 mapping rejected: %v", err)
	}
	bunkerWebWithoutScheduler := base + `
[integrations.bunkerweb]
enabled = true
`
	if _, err := LoadConfigDirectory(writeConfigFixture(t, bunkerWebWithoutScheduler, nil)); err == nil {
		t.Fatal("HA v2 BunkerWeb integration reused the static peer identity as scheduler authorization")
	}
	bunkerWebWithScheduler := bunkerWebWithoutScheduler + `scheduler_ips = ["192.0.2.40", "2001:db8:40::/64"]
`
	if diagnostics, err := LoadConfigDirectory(writeConfigFixture(t, bunkerWebWithScheduler, nil)); err != nil {
		t.Fatalf("valid BunkerWeb scheduler allowlist rejected: %v", err)
	} else if len(diagnostics.UnknownKeys) != 0 {
		t.Fatalf("BunkerWeb scheduler allowlist reported as unknown: %v", diagnostics.UnknownKeys)
	}
	overbroadScheduler := strings.Replace(bunkerWebWithScheduler, `"192.0.2.40", "2001:db8:40::/64"`, `"192.0.0.0/16"`, 1)
	if _, err := LoadConfigDirectory(writeConfigFixture(t, overbroadScheduler, nil)); err == nil {
		t.Fatal("overbroad BunkerWeb scheduler allowlist accepted")
	}
	for name, replace := range map[string][2]string{
		"cidr peer":       {`peer_ips = ["192.0.2.10"]`, `peer_ips = ["192.0.2.0/24"]`},
		"three nodes":     {`peer_ips = ["192.0.2.10"]`, `peer_ips = ["192.0.2.10", "192.0.2.11"]`},
		"same identity":   {`peer_id = "node-b"`, `peer_id = "node-a"`},
		"zero epoch":      {`epoch = 1`, `epoch = 0`},
		"dynamic role":    {`role = "writer"`, `role = "auto"`},
		"relative secret": {`v2_secret_file = "/etc/syswarden/ha-v2.secret"`, `v2_secret_file = "ha-v2.secret"`},
		"multicast peer":  {`peer_ips = ["192.0.2.10"]`, `peer_ips = ["ff02::1"]`},
		"loopback peer":   {`peer_ips = ["192.0.2.10"]`, `peer_ips = ["127.0.0.1"]`},
		"noncanonical IP": {`peer_ips = ["192.0.2.10"]`, `peer_ips = ["2001:DB8::10"]`},
		"duplicate pin":   {`peer_cert_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]`, `peer_cert_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]`},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := strings.Replace(base, replace[0], replace[1], 1)
			if _, err := LoadConfigDirectory(writeConfigFixture(t, candidate, nil)); err == nil {
				t.Fatal("unsafe HA v2 mapping accepted")
			}
		})
	}
}

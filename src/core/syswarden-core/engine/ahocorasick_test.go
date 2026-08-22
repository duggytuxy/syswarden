package engine

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "signatures.json")
	config := `{
  "rules": [
    {
      "id": "ssh-auth",
      "type": "regex",
      "pattern": "^(?:[0-9A-Fa-f:.]+ )?Failed password .* from <HOST>(?: port [0-9]+)?$",
      "service": "sshd",
      "action": "track",
      "threshold": 3,
      "window": 60,
      "trusted_host_capture": true
    },
    {
      "id": "encoded-probe",
      "type": "aho-corasick",
      "patterns": ["../etc/passwd", "sqlmap"],
      "service": "http",
      "action": "ban"
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(configPath, 5, 60)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func newProductionTestEngine(t *testing.T) *Engine {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve engine test source path")
	}
	engine, err := NewEngine(filepath.Join(filepath.Dir(sourceFile), "..", "signatures.json"), 5, 60)
	if err != nil {
		t.Fatalf("load production signatures: %v", err)
	}
	return engine
}

func TestNewEngineRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewEngine(filepath.Join(t.TempDir(), "missing.json"), 5, 60); err == nil {
		t.Fatal("NewEngine() succeeded with a missing signature file")
	}

	invalidJSON := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalidJSON, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(invalidJSON, 5, 60); err == nil {
		t.Fatal("NewEngine() succeeded with invalid JSON")
	}

	invalidRegex := filepath.Join(t.TempDir(), "invalid-regex.json")
	if err := os.WriteFile(
		invalidRegex,
		[]byte(`{"rules":[{"id":"bad","type":"regex","pattern":"(","service":"test"}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(invalidRegex, 5, 60); err == nil {
		t.Fatal("NewEngine() succeeded with an invalid regular expression")
	}

	unanchoredTrustedCapture := filepath.Join(t.TempDir(), "unanchored-trusted-capture.json")
	if err := os.WriteFile(
		unanchoredTrustedCapture,
		[]byte(`{"rules":[{"id":"bad-trust","type":"regex","pattern":"from <HOST>","service":"test","trusted_host_capture":true}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(unanchoredTrustedCapture, 5, 60); err == nil {
		t.Fatal("NewEngine() accepted an unanchored trusted host capture")
	}

	duplicateTrustedCapture := filepath.Join(t.TempDir(), "duplicate-trusted-capture.json")
	if err := os.WriteFile(
		duplicateTrustedCapture,
		[]byte(`{"rules":[{"id":"bad-duplicate-trust","type":"regex","pattern":"^(?P<host>[0-9.]+) from <HOST>$","service":"test","trusted_host_capture":true}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(duplicateTrustedCapture, 5, 60); err == nil {
		t.Fatal("NewEngine() accepted multiple trusted host captures")
	}
}

func TestEngineScanCompatibility(t *testing.T) {
	engine := newTestEngine(t)
	if got := engine.RuleCount(); got != 3 {
		t.Fatalf("RuleCount() = %d, want 3 compiled patterns", got)
	}

	tests := []struct {
		name      string
		line      string
		wantRule  string
		wantMatch bool
	}{
		{
			name:      "regex with valid IPv4",
			line:      "Failed password for root from 192.0.2.44 port 22",
			wantRule:  "ssh-auth",
			wantMatch: true,
		},
		{
			name:      "regex rejects invalid host",
			line:      "Failed password for root from 999.0.2.44 port 22",
			wantMatch: false,
		},
		{
			name:      "raw Aho-Corasick",
			line:      "scanner user-agent sqlmap",
			wantRule:  "encoded-probe",
			wantMatch: true,
		},
		{
			name:      "URL-decoded Aho-Corasick",
			line:      "GET /..%2Fetc%2Fpasswd HTTP/1.1",
			wantRule:  "encoded-probe",
			wantMatch: true,
		},
		{name: "no match", line: "GET /health HTTP/1.1", wantMatch: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			match := engine.Scan(test.line)
			if (match != nil) != test.wantMatch {
				t.Fatalf("Scan(%q) match = %#v, wantMatch %t", test.line, match, test.wantMatch)
			}
			if match != nil && match.RuleID != test.wantRule {
				t.Fatalf("Scan(%q) rule = %q, want %q", test.line, match.RuleID, test.wantRule)
			}
		})
	}
}

func TestEvaluateThresholdCompatibility(t *testing.T) {
	engine := newTestEngine(t)
	if engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("first event reached threshold")
	}
	if engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("second event reached threshold")
	}
	if !engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("third event did not reach threshold")
	}
	if engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("tracker was not reset after threshold")
	}
	if !engine.EvaluateThreshold("192.0.2.2", "instant", 1, 60) {
		t.Fatal("threshold 1 did not trigger immediately")
	}
}

func TestEvaluateThresholdSameKeyIsAtomic_SW2_H1(t *testing.T) {
	engine := newTestEngine(t)
	const threshold = 64
	var triggered atomic.Int32
	var group sync.WaitGroup
	for range threshold {
		group.Add(1)
		go func() {
			defer group.Done()
			if engine.EvaluateThreshold("8.8.8.8", "concurrent-threshold", threshold, 60) {
				triggered.Add(1)
			}
		}()
	}
	group.Wait()
	if got := triggered.Load(); got != 1 {
		t.Fatalf("concurrent threshold triggers = %d, want exactly 1", got)
	}
	if engine.EvaluateThreshold("8.8.8.8", "concurrent-threshold", threshold, 60) {
		t.Fatal("threshold state was not reset after the atomic trigger")
	}
}

func TestExtractIPCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "Nginx IPv4", line: "192.0.2.55 - - [date] GET /", want: "192.0.2.55"},
		{name: "JSON IPv4", line: `{"remote_ip":"198.51.100.8","status":403}`, want: "198.51.100.8"},
		{name: "JSON IPv6", line: `{"client_ip":"2001:db8::8","status":403}`, want: "2001:db8::8"},
		{name: "mapped JSON address canonicalized", line: `{"ClientHost":"::ffff:198.51.100.8"}`, want: "198.51.100.8"},
		{
			name: "leading address wins over embedded JSON",
			line: `192.0.2.55 - - GET / HTTP/1.1 referrer="{"client_ip":"198.51.100.8"}"`,
			want: "192.0.2.55",
		},
		{
			name: "embedded JSON rejected",
			line: `2026/08/22 nginx client: 192.0.2.55 referrer="{"client_ip":"198.51.100.8"}"`,
			want: "",
		},
		{name: "trailing text after JSON rejected", line: `{"remote_ip":"198.51.100.8"} suffix`, want: ""},
		{name: "nested address rejected", line: `{"request":{"client_ip":"198.51.100.8"}}`, want: ""},
		{
			name: "conflicting top-level addresses rejected",
			line: `{"remote_ip":"198.51.100.8","client_ip":"192.0.2.55"}`,
			want: "",
		},
		{
			name: "duplicate top-level address rejected",
			line: `{"remote_ip":"198.51.100.8","remote_ip":"192.0.2.55"}`,
			want: "",
		},
		{
			name: "invalid supported field cannot defer to another field",
			line: `{"remote_ip":null,"client_ip":"198.51.100.8"}`,
			want: "",
		},
		{name: "loopback ignored", line: "127.0.0.1 - - GET /", want: ""},
		{name: "mapped loopback ignored", line: `{"client_ip":"::ffff:127.0.0.1"}`, want: ""},
		{name: "invalid IPv4 ignored", line: "999.0.2.1 - - GET /", want: ""},
		{name: "no address", line: "application started", want: ""},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtractIP(test.line); got != test.want {
				t.Fatalf("ExtractIP(%q) = %q, want %q", test.line, got, test.want)
			}
		})
	}
}

func TestStructuralRecordHostPrecedesInjectableRegexCapture_SW2_H1(t *testing.T) {
	engine := newTestEngine(t)
	line := `198.51.100.7 Failed password for invalid user {"client_ip":"192.0.2.99"} from 203.0.113.5 port 22`

	match := engine.Scan(line)
	if match == nil {
		t.Fatal("adversarial SSH line did not match")
	}
	want := netip.MustParseAddr("198.51.100.7")
	if match.Host != want {
		t.Fatalf("Match.Host = %v, want structural record host %v", match.Host, want)
	}
	if fallback := ExtractIP(line); fallback != "198.51.100.7" {
		t.Fatalf("ExtractIP() = %q, want structural record address", fallback)
	}
	if match.Host.String() == "203.0.113.5" {
		t.Fatal("injectable regex capture overrode the structural record host")
	}
}

func TestAccessLogCannotRedirectHostThroughAnotherServiceSignature_SW2_H1(t *testing.T) {
	engine := newProductionTestEngine(t)
	line := `8.8.4.4 - - [22/Aug/2026:10:00:00 +0000] "GET / HTTP/1.1" 404 0 "-" "wireguard: test Handshake for peer injected (1.1.1.1:22) did not complete"`
	match := engine.Scan(line)
	if match == nil {
		t.Fatal("injected cross-service signature did not match")
	}
	want := netip.MustParseAddr("8.8.4.4")
	if match.Host != want {
		t.Fatalf("Match.Host = %v, want access-log client %v", match.Host, want)
	}
	if match.Host == netip.MustParseAddr("1.1.1.1") {
		t.Fatal("injectable cross-service capture redirected the enforcement target")
	}
}

func TestDetectionOnlySignatureCannotMaskInstantBan_SW2_H1(t *testing.T) {
	engine := newProductionTestEngine(t)
	line := `8.8.4.4 - - [22/Aug/2026:10:00:00 +0000] "GET /phpmyadmin HTTP/1.1" 404 0 "-" "Nmap"`
	match := engine.Scan(line)
	if match == nil {
		t.Fatal("combined detect and ban signatures did not match")
	}
	if match.Action == "detect" || match.Action == "track" {
		t.Fatalf("lower-impact signature masked an instant ban: %#v", match)
	}
	if match.Host != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("Match.Host = %v, want structural access-log host", match.Host)
	}
}

func TestHostlessBanCannotMaskValidatedSyslogCapture_SW2_H5(t *testing.T) {
	engine := newProductionTestEngine(t)
	line := "Aug 22 10:00:00 gateway sshd[1842]: Failed password for invalid user phpmyadmin from 8.8.8.8 port 2222 ssh2"

	match := engine.Scan(line)
	if match == nil {
		t.Fatal("adversarial SSH line did not match")
	}
	if match.RuleID != "ssh-auth" || match.Action != "track" {
		t.Fatalf("hostless ban masked the validated SSH match: %#v", match)
	}
	if match.Host != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("Match.Host = %v, want validated SSH host", match.Host)
	}
}

func TestLaterCrossServiceCaptureCannotReplaceSyslogAuthority_SW2_H5(t *testing.T) {
	engine := newProductionTestEngine(t)
	line := "Aug 22 10:00:00 gateway sshd[1842]: Failed password for invalid user wireguard: x Handshake for peer y (1.1.1.1:22) did not complete from 8.8.8.8 port 22 ssh2"

	match := engine.Scan(line)
	if match == nil {
		t.Fatal("adversarial SSH line did not match")
	}
	if match.RuleID != "ssh-auth" || match.Action != "track" {
		t.Fatalf("cross-service capture replaced the SSH match: %#v", match)
	}
	if match.Host != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("Match.Host = %v, want validated SSH host", match.Host)
	}
}

func TestSSHUsernameCannotInjectEarlierSourceAddress_SW2_H5(t *testing.T) {
	engine := newProductionTestEngine(t)
	line := "Aug 22 10:00:00 gateway sshd[1]: Failed password for invalid user alice from 1.1.1.1 from 8.8.8.8 port 22 ssh2"

	match := engine.Scan(line)
	if match == nil {
		t.Fatal("adversarial SSH line did not match")
	}
	if match.RuleID != "ssh-auth" || match.Action != "track" {
		t.Fatalf("injected username changed the SSH rule: %#v", match)
	}
	if match.Host != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("Match.Host = %v, want terminal SSH source host", match.Host)
	}
}

func TestServiceIdentityCannotInjectEarlierCapturedAddress_SW2_H1(t *testing.T) {
	engine := newProductionTestEngine(t)
	tests := []struct {
		name     string
		line     string
		wantRule string
	}{
		{
			name:     "Zabbix username",
			line:     "failed login of user alice from 1.1.1.1 from 8.8.8.8",
			wantRule: "zabbix-login",
		},
		{
			name:     "Nextcloud username",
			line:     `{"remoteAddr":"8.8.8.8","message":"Login failed: alice (Remote IP: '8.8.8.8')","userAgent":"(Remote IP: '1.1.1.1')"}`,
			wantRule: "nextcloud-login",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := engine.Scan(test.line)
			if match == nil {
				t.Fatal("adversarial service line did not match")
			}
			if match.RuleID != test.wantRule || match.Action != "track" {
				t.Fatalf("injected identity changed the service rule: %#v", match)
			}
			if match.Host != netip.MustParseAddr("8.8.8.8") {
				t.Fatalf("Match.Host = %v, want structured service source host", match.Host)
			}
		})
	}
}

func TestTrustedCaptureRequiresAnchoredServiceRecord_SW2_H1(t *testing.T) {
	engine := newProductionTestEngine(t)
	line := "Aug 22 10:00:00 gateway zabbix_server[1]: failed login of user SSL_do_handshake() failed x client: 1.1.1.1 from 8.8.8.8"

	match := engine.Scan(line)
	if match == nil || match.RuleID != "zabbix-login" {
		t.Fatalf("cross-service line match = %#v, want hostless Zabbix detection", match)
	}
	if match.Host != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("cross-service payload redirected trusted host authority: %v", match.Host)
	}
}

func TestDuplicateAhoPatternRetainsHigherImpactRule_SW2_H1(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "signatures.json")
	configuration := `{"rules":[
  {"id":"ban-first","type":"aho-corasick","patterns":["duplicate-pattern"],"service":"http","action":"ban"},
  {"id":"detect-last","type":"aho-corasick","patterns":["duplicate-pattern"],"service":"http","action":"detect"}
]}`
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := NewEngine(path, 1, 60)
	if err != nil {
		t.Fatal(err)
	}
	match := detector.Scan("8.8.8.8 duplicate-pattern")
	if match == nil || match.RuleID != "ban-first" || match.Action != "ban" {
		t.Fatalf("duplicate pattern arbitration = %#v", match)
	}
}

func TestRegexMatchHostIsCanonicalNetip(t *testing.T) {
	engine := newTestEngine(t)
	match := engine.Scan("Failed password for root from 2001:0DB8:0:0::5 port 22")
	if match == nil {
		t.Fatal("IPv6 SSH line did not match")
	}
	want := netip.MustParseAddr("2001:db8::5")
	if match.Host != want {
		t.Fatalf("Match.Host = %v, want %v", match.Host, want)
	}
	if match.Host.String() != "2001:db8::5" {
		t.Fatalf("Match.Host.String() = %q, want canonical IPv6", match.Host.String())
	}
}

func TestNginxInjectedJSONCannotOverrideHost_SW2_H1(t *testing.T) {
	engine := newProductionTestEngine(t)
	tests := []struct {
		name     string
		line     string
		wantRule string
		wantHost netip.Addr
	}{
		{
			name:     "regex signature retains nginx client",
			line:     `2026/08/22 12:00:00 [crit] SSL_do_handshake() failed attacker client: 1.1.1.1 while SSL handshaking, client: 203.0.113.5, server: 0.0.0.0:443, referrer: "{"client_ip":"198.51.100.7"}"`,
			wantRule: "nginx-tls",
			wantHost: netip.MustParseAddr("203.0.113.5"),
		},
		{
			name:     "hostless Aho-Corasick signature fails closed",
			line:     `2026/08/22 12:00:00 [error] open() "/usr/share/nginx/html/wp-login.php" failed, client: 203.0.113.5, referrer: "{"client_ip":"198.51.100.7"}"`,
			wantRule: "cms-wordpress",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			match := engine.Scan(test.line)
			if match == nil {
				t.Fatal("adversarial nginx line did not match")
			}
			if match.RuleID != test.wantRule {
				t.Fatalf("Match.RuleID = %q, want %q", match.RuleID, test.wantRule)
			}
			if match.Host != test.wantHost {
				t.Fatalf("Match.Host = %v, want %v", match.Host, test.wantHost)
			}
			if got := ExtractIP(test.line); got != "" {
				t.Fatalf("ExtractIP() trusted embedded JSON address %q", got)
			}
		})
	}
}

func TestAhoMatchUsesOnlyAuthoritativeRecordHost_SW2_H1(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "signatures.json")
	configuration := `{"rules":[{"id":"aho-test","type":"aho-corasick","patterns":["wp-login.php"],"service":"http","action":"ban"}]}`
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := NewEngine(path, 1, 60)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		line string
		want netip.Addr
	}{
		{
			name: "leading access-log address",
			line: `8.8.8.8 - - "GET /wp-login.php HTTP/1.1" 404 0`,
			want: netip.MustParseAddr("8.8.8.8"),
		},
		{
			name: "whole JSON object address",
			line: `{"client_ip":"1.1.1.1","path":"/wp-login.php"}`,
			want: netip.MustParseAddr("1.1.1.1"),
		},
		{
			name: "embedded JSON injection",
			line: `nginx request /wp-login.php referrer="{"client_ip":"9.9.9.9"}"`,
		},
		{
			name: "conflicting JSON fields",
			line: `{"client_ip":"1.1.1.1","remote_ip":"9.9.9.9","path":"/wp-login.php"}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			match := detector.Scan(test.line)
			if match == nil {
				t.Fatal("Aho-Corasick rule did not match")
			}
			if match.Host != test.want {
				t.Fatalf("Match.Host = %v, want %v", match.Host, test.want)
			}
		})
	}
}

func TestHostlessRegexUsesOnlyAuthoritativeRecordHost_SW2_H1(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "signatures.json")
	configuration := `{"rules":[{"id":"regex-test","type":"regex","pattern":"wp-login\\.php","service":"http","action":"ban"}]}`
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := NewEngine(path, 1, 60)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		line string
		want netip.Addr
	}{
		{
			name: "leading access log address",
			line: `8.8.8.8 - - "GET /wp-login.php HTTP/1.1" 404 0`,
			want: netip.MustParseAddr("8.8.8.8"),
		},
		{
			name: "whole JSON object address",
			line: `{"client_ip":"1.1.1.1","path":"/wp-login.php"}`,
			want: netip.MustParseAddr("1.1.1.1"),
		},
		{
			name: "embedded JSON injection",
			line: `nginx request /wp-login.php referrer="{"client_ip":"9.9.9.9"}"`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			match := detector.Scan(test.line)
			if match == nil {
				t.Fatal("hostless regex rule did not match")
			}
			if match.Host != test.want {
				t.Fatalf("Match.Host = %v, want %v", match.Host, test.want)
			}
		})
	}
}

func TestProductionSyslogMatchesCarryCanonicalHost_SW2_H5(t *testing.T) {
	engine := newProductionTestEngine(t)
	tests := []struct {
		name     string
		line     string
		wantRule string
		wantHost netip.Addr
	}{
		{
			name:     "sshd",
			line:     "Aug 20 10:00:00 gateway sshd[1842]: Failed password for root from 203.0.113.5 port 2222 ssh2",
			wantRule: "ssh-auth",
			wantHost: netip.MustParseAddr("203.0.113.5"),
		},
		{
			name:     "PAM sudo",
			line:     "Aug 20 10:01:00 gateway sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=198.51.100.24 user=root",
			wantRule: "privesc",
			wantHost: netip.MustParseAddr("198.51.100.24"),
		},
		{
			name:     "Dovecot mail",
			line:     "Aug 20 10:02:00 mail dovecot: imap-login: Aborted login (auth failed, 1 attempts): user=<alice>, method=PLAIN, rip=192.0.2.77, lip=192.0.2.10, TLS",
			wantRule: "dovecot-auth",
			wantHost: netip.MustParseAddr("192.0.2.77"),
		},
		{
			name:     "Proxmox panel",
			line:     "Aug 20 10:03:00 node pvedaemon[1932]: authentication failure; rhost=8.8.8.8 user=root@pam",
			wantRule: "proxmox-auth",
			wantHost: netip.MustParseAddr("8.8.8.8"),
		},
		{
			name:     "Zabbix panel",
			line:     "Aug 20 10:04:00 node zabbix_server[2010]: failed login of user Admin from 8.8.4.4",
			wantRule: "zabbix-login",
			wantHost: netip.MustParseAddr("8.8.4.4"),
		},
		{
			name:     "WireGuard VPN",
			line:     "Aug 20 10:05:00 gateway kernel: wireguard: wg0: Handshake for peer test (1.1.1.1:51820) did not complete",
			wantRule: "wireguard-handshake",
			wantHost: netip.MustParseAddr("1.1.1.1"),
		},
		{
			name:     "OpenVPN",
			line:     "Aug 20 10:06:00 gateway openvpn[2210]: 9.9.9.9:1194 TLS Error: TLS handshake failed",
			wantRule: "openvpn-tls",
			wantHost: netip.MustParseAddr("9.9.9.9"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			match := engine.Scan(test.line)
			if match == nil {
				t.Fatal("production syslog line did not match")
			}
			if match.RuleID != test.wantRule {
				t.Fatalf("Match.RuleID = %q, want %q", match.RuleID, test.wantRule)
			}
			if match.Host != test.wantHost {
				t.Fatalf("Match.Host = %v, want %v", match.Host, test.wantHost)
			}
			if got := ExtractIP(test.line); got != "" {
				t.Fatalf("legacy fallback unexpectedly extracted %q from syslog", got)
			}
		})
	}
}

func TestDetectionPipelineContract_SW_WAAP_001(t *testing.T) {
	engine := newTestEngine(t)
	line := "192.0.2.44 Failed password for root from 192.0.2.44 port 22"
	match := engine.Scan(line)
	if match == nil {
		t.Fatal("realistic SSH log did not match")
	}
	if match.RuleID != "ssh-auth" || match.Service != "sshd" || match.Action != "track" || match.Threshold != 3 || match.Window != 60 {
		t.Fatalf("match contract changed: %#v", match)
	}
	if match.Host != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("Match.Host = %v, want 192.0.2.44", match.Host)
	}
	ip := ExtractIP(line)
	if ip != "192.0.2.44" {
		t.Fatalf("ExtractIP() = %q, want 192.0.2.44", ip)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		triggered := engine.EvaluateThreshold(ip, match.RuleID, match.Threshold, match.Window)
		if triggered != (attempt == 3) {
			t.Fatalf("attempt %d triggered=%t", attempt, triggered)
		}
	}
	if engine.EvaluateThreshold("198.51.100.9", match.RuleID, match.Threshold, match.Window) {
		t.Fatal("threshold state leaked between source IPs")
	}
	if engine.EvaluateThreshold(ip, "different-rule", match.Threshold, match.Window) {
		t.Fatal("threshold state leaked between rules")
	}

	// Distinct keys exercise concurrent access under go test -race without
	// hiding the non-atomic same-key behavior tracked by SW-WAAP-001.
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			engine.EvaluateThreshold(
				fmt.Sprintf("203.0.113.%d", index+1),
				"concurrent-rule",
				2,
				60,
			)
		}(index)
	}
	group.Wait()
}

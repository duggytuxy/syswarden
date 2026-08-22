//go:build linux

package integration

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

func TestRsyslogContextEncodingAndTargetValidation_SW_CFG_002(t *testing.T) {
	quoted, err := quoteRsyslogString(`/var/log/modsec/a"b\c.log`)
	if err != nil {
		t.Fatal(err)
	}
	if quoted != `"/var/log/modsec/a\"b\\c.log"` {
		t.Fatalf("quoted rsyslog string = %q", quoted)
	}
	if _, err := quoteRsyslogString("/var/log/access.log\nmodule(load=\"evil\")"); err == nil {
		t.Fatal("rsyslog encoder accepted a control-character breakout")
	}
	if got, err := rsyslogTarget("2001:db8::10", "06514"); err != nil || got != "[2001:db8::10]:6514" {
		t.Fatalf("IPv6 rsyslog target = %q, %v", got, err)
	}
	for _, input := range [][2]string{{"192.0.2.1\n*.* @evil", "6514"}, {"192.0.2.1", "6514\n*.* @evil"}} {
		if _, err := rsyslogTarget(input[0], input[1]); err == nil {
			t.Fatalf("rsyslog target accepted injection input %#v", input)
		}
	}
}

func TestConfiguredRsyslogPatternsRequireRealRegularMatches_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, `mod"sec.log`)
	if err := os.WriteFile(regular, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	patterns, err := validatedRsyslogLogPatterns(regular)
	if err != nil || len(patterns) != 1 || patterns[0] != regular {
		t.Fatalf("validated patterns = %#v, %v", patterns, err)
	}
	missing := filepath.Join(root, "missing-*.log")
	patterns, err = validatedRsyslogLogPatterns(missing)
	if err != nil || len(patterns) != 0 {
		t.Fatalf("missing pattern = %#v, %v", patterns, err)
	}
	patterns, err = validatedRsyslogLogPatterns(filepath.Join(root, "*.log"))
	if err != nil || len(patterns) != 1 || patterns[0] != regular {
		t.Fatalf("glob was not reduced to its verified exact match: %#v, %v", patterns, err)
	}
	if _, err := validatedRsyslogLogPatterns(regular + " " + regular); err == nil {
		t.Fatal("duplicate rsyslog pattern was accepted")
	}

	directory := filepath.Join(root, "directory.log")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.log")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo.log")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, link, fifo} {
		if _, err := validatedRsyslogLogPatterns(path); err == nil {
			t.Fatalf("non-regular rsyslog input %s was accepted", path)
		}
	}
}

func TestRsyslogRenderersDoNotPermitContextBreakout_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	pattern := filepath.Join(root, `mod"sec.log`)
	if err := os.WriteFile(pattern, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waf, active, err := renderWAFRsyslogConfig(pattern)
	if err != nil || active != 1 {
		t.Fatalf("renderWAFRsyslogConfig() active=%d error=%v", active, err)
	}
	if !strings.Contains(waf, `File="`+strings.ReplaceAll(pattern, `"`, `\"`)+`" Tag="syswarden-waf"`) {
		t.Fatalf("WAF rsyslog config did not context-encode the path:\n%s", waf)
	}
	if strings.Contains(waf, pattern+`" Tag="attacker`) {
		t.Fatalf("WAF rsyslog config contains an unescaped context breakout:\n%s", waf)
	}

	siem, err := renderSIEMRsyslogConfig("2001:db8::10", "6514", "tls", `/etc/ssl/a"b\ca.pem`)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`$DefaultNetstreamDriverCAFile "/etc/ssl/a\"b\\ca.pem"`,
		`*.* @@[2001:db8::10]:6514`,
	} {
		if !strings.Contains(siem, fragment) {
			t.Fatalf("SIEM rsyslog config missing %q:\n%s", fragment, siem)
		}
	}
	if _, err := renderSIEMRsyslogConfig("192.0.2.10", "6514", "unsupported", "/etc/ca.pem"); err == nil {
		t.Fatal("SIEM renderer accepted an unsupported transport")
	}
}

func TestWAFRsyslogBridgeStopsAllSysWardenOwnedMarkers_SW2_H2(t *testing.T) {
	waf, active, err := renderWAFRsyslogConfig("")
	if err != nil || active != 0 {
		t.Fatalf("renderWAFRsyslogConfig() active=%d error=%v", active, err)
	}
	forwardIndex := strings.Index(waf, "*.* :omuxsock:;SYSWARDENRaw")
	if forwardIndex < 0 {
		t.Fatalf("WAF rsyslog config omitted its forwarding action:\n%s", waf)
	}
	trustedStop := `if $programname == "syswarden-core" and re_match($msg, '` + rsyslogDirectInternalLogPattern + `') then stop`
	stopIndex := strings.Index(waf, trustedStop)
	if stopIndex < 0 {
		t.Fatalf("WAF rsyslog config omitted its process-identity record stop %q:\n%s", trustedStop, waf)
	}
	if stopIndex > forwardIndex {
		t.Fatalf("process-identity record stop appears after forwarding action:\n%s", waf)
	}
	if strings.Contains(waf, `if $msg contains`) {
		t.Fatalf("WAF rsyslog config retained a spoofable substring stop:\n%s", waf)
	}
	if strings.Contains(waf, `if re_match($msg`) || strings.Contains(waf, `if $programname == "syswarden-core" then stop`) {
		t.Fatalf("WAF rsyslog config contains a record stop without trusted process identity:\n%s", waf)
	}

	directPattern := regexp.MustCompile(rsyslogDirectInternalLogPattern)
	record := syswardenInternalLogMarker +
		" action=DETECTED ip=203.0.113.77 scope=recursion-regression payload_sha256=" +
		strings.Repeat("0", 64) + " payload_bytes=42 auth=" + strings.Repeat("1", 64)
	if !directPattern.MatchString("2026/08/22 12:34:56 " + record) {
		t.Fatal("direct product record does not satisfy the rendered rsyslog guard")
	}
	for _, attackerLine := range []string{
		"198.51.100.42 attack from 198.51.100.42 request=" + syswardenInternalLogMarker,
		"GET /?message=" + syswardenInternalLogMarker + " HTTP/1.1",
		"198.51.100.42 payload=[SYSWARDEN-DETECTED] attack from 198.51.100.42",
		"198.51.100.42 payload=[SOC-ALERT] attack from 198.51.100.42",
		"2026/08/22 12:34:56 " + strings.TrimSuffix(record, strings.Repeat("1", 64)) + "not-an-authenticator",
	} {
		if directPattern.MatchString(attackerLine) {
			t.Fatalf("attacker-controlled marker matched an rsyslog product guard: %q", attackerLine)
		}
	}
}

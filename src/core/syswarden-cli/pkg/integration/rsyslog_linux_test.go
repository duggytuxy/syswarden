//go:build linux

package integration

import (
	"os"
	"path/filepath"
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

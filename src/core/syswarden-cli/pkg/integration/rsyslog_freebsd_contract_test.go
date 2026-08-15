package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readIntegrationSource(t *testing.T, name string) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration source directory")
	}
	root, err := os.OpenRoot(filepath.Dir(current))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestFreeBSDRsyslogIntegrationIsEnabledAndFailClosed(t *testing.T) {
	helper := readIntegrationSource(t, "rsyslog_freebsd.go")
	if !strings.Contains(helper, "system.EnsureFreeBSDRsyslogRunning()") {
		t.Fatal("FreeBSD rsyslog integration bypasses the owned service transition")
	}
	for _, sourceName := range []string{"waf_logs_freebsd.go", "siem_freebsd.go"} {
		source := readIntegrationSource(t, sourceName)
		if !strings.Contains(source, "ensureFreeBSDRsyslogRunning()") ||
			strings.Contains(source, "[WARN] Failed to restart rsyslogd") {
			t.Fatalf("%s does not propagate rsyslog activation failure", sourceName)
		}
	}
	waf := readIntegrationSource(t, "waf_logs_freebsd.go")
	siem := readIntegrationSource(t, "siem_freebsd.go")
	if strings.Count(waf, `module(load="imfile")`) != 1 {
		t.Fatal("WAF fragment must own the single shared imfile declaration")
	}
	if strings.Contains(siem, `rsyslogConf += "module(load=\"imfile\"`) ||
		!strings.Contains(siem, "read required WAF rsyslog module fragment") {
		t.Fatal("SIEM fragment duplicates or does not require the shared imfile module")
	}
}

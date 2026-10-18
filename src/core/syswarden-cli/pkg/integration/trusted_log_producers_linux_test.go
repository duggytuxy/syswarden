//go:build linux

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProducerBridgeLeavesHistoricalRendererUnchanged(t *testing.T) {
	for _, siem := range []bool{false, true} {
		before, count, err := renderWAFRsyslogConfig("", siem)
		if err != nil {
			t.Fatal(err)
		}
		after, got, err := renderWAFRsyslogWithProducers("", siem, "")
		if err != nil || before != after || count != got {
			t.Fatalf("historical bytes changed: %v", err)
		}
	}
	if _, _, err := renderWAFRsyslogWithProducers("", false, "/var/log/waf/*.log=999"); err == nil {
		t.Fatal("malformed policy accepted")
	}
}

func TestProducerBridgeTransfersAllInputsWithoutGenericImfileBypass(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("audit.log", []byte("producer\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := root.Open("audit.log")
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root.Name(), "audit.log")
	for _, siem := range []bool{false, true} {
		rendered, count, err := renderDirectProducerBridge(path, siem, map[string]uint32{path: stat.Uid}, []string{path})
		if err != nil || count != 1 {
			t.Fatalf("count=%d error=%v", count, err)
		}
		for _, unsafe := range []string{path, "/var/log/nginx/", "/var/log/apache2/", "/var/log/httpd/", "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages"} {
			if strings.Contains(rendered, unsafe) {
				t.Fatalf("imfile bypass: %s", unsafe)
			}
		}
		if strings.Contains(rendered, `File="/var/log/syswarden/waf.json"`) != siem {
			t.Fatal("SIEM telemetry policy changed")
		}
		if !strings.Contains(rendered, rsyslogWAFRuleset) {
			t.Fatal("bridge loop guard changed")
		}
	}
	if err := root.Chmod("audit.log", 0666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := renderDirectProducerBridge(path, false, map[string]uint32{path: stat.Uid}, nil); err == nil {
		t.Fatal("unsafe explicit source accepted")
	}
}

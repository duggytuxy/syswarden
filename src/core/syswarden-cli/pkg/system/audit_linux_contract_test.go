//go:build linux

package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxAuditUsesOwnedAndLegacyFailClosedCronContract(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	auditSource, err := root.ReadFile("audit_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`cronstate.Inspect(cronOptions)`,
		`cronstate.DefaultOptions(ReadOnlyRootCrontabEvidence)`,
		`cronOptions.AttestCronDProvider = AttestCronDProvider`,
		`InspectCronDProvider()`,
		`Cron Daemon FAILED: /etc/cron.d is not backed by a fully attested provider`,
		`no live daemon is claimed`,
		`Cron Orchestration FAILED: scheduling state is not safely attestable`,
		`feed updates use /etc/cron.d/syswarden`,
		`HA synchronization remains scheduled while HA is disabled`,
	} {
		if !strings.Contains(string(auditSource), required) {
			t.Fatalf("Linux audit lacks %q", required)
		}
	}
	if strings.Contains(string(auditSource), `strings.Count(string(out), "syswarden-cli update-feeds")`) ||
		strings.Contains(string(auditSource), `out, _ := exec.Command("crontab", "-l").Output()`) {
		t.Fatal("Linux audit still accepts substring matches or ignores crontab read errors")
	}

	uninstallSource, err := root.ReadFile("uninstall_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(uninstallSource), `strings.Contains(line, "syswarden-cli")`) ||
		strings.Contains(string(uninstallSource), `out, _ := exec.Command("crontab", "-l").Output()`) {
		t.Fatal("Linux uninstall still broadens cron deletion or ignores read errors")
	}
	if strings.Contains(string(uninstallSource), `exec.Command("iptables", "-S")`) ||
		strings.Contains(string(uninstallSource), `--comment SYSWARDEN_CORE`) {
		t.Fatal("Linux uninstall still scans unowned iptables rules outside the ownership manifest")
	}
	if strings.Contains(string(uninstallSource), `exec.Command("nft"`) {
		t.Fatal("Linux uninstall still performs best-effort nftables cleanup outside the verified firewall transaction")
	}
}

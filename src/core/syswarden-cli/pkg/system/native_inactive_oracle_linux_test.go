//go:build linux

package system_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/system"
	"testing"
	"time"
)

// This oracle exercises read-only admission under real publication exclusion.
// It does not qualify package provenance, native replacement or terminal closure.
func TestNativeInactiveOpenRCOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_INACTIVE_OPENRC_ORACLE") != "1" {
		t.Skip("requires the explicit isolated inactive Alpine observer laboratory")
	}
	if runtime.GOARCH != "amd64" || os.Geteuid() != 0 || os.Getpid() <= 1 {
		t.Fatal("isolated AMD64 child process required")
	}
	marker, err := os.ReadFile("/tmp/inactive-admission-oracle")
	if err != nil || string(marker) != "syswarden-inactive-observer-v1\n" {
		t.Fatal("explicit disposable fixture marker required")
	}
	if info, err := os.Lstat("/run/.containerenv"); err != nil || !info.Mode().IsRegular() {
		t.Fatal("disposable container required")
	}
	init, err := os.Readlink("/proc/1/exe")
	if err != nil || init != "/sbin/openrc-init" {
		t.Fatal("real OpenRC PID1 required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	// Prepare real default TOML only inside this disposable fixture. The
	// production observer neither initializes nor changes it.
	if err := config.InitializeDefaults("/etc/syswarden/config"); err != nil {
		t.Fatal(err)
	}
	policy, err := config.CaptureActivationPolicy(ctx, "/etc/syswarden/config")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := policy.HoldActivationAbsent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	independent, err := config.CaptureActivationPolicy(ctx, "/etc/syswarden/config")
	if err != nil {
		t.Fatal(err)
	}
	absence, err := independent.ObserveActivationAbsent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if absence.SHA256() != lease.SHA256() {
		t.Fatal("independent reader lost original absent authority")
	}
	if err := absence.Close(); err != nil {
		t.Fatal(err)
	}
	if competing, err := independent.HoldActivationAbsent(ctx); err == nil {
		_ = competing.Close()
		t.Fatal("independent observer released the original publication lease")
	}
	if err := lease.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	observe := func() (string, error) {
		return system.ObserveNativeInactiveHost(ctx, firewall.ObserveInactiveNativeNFT)
	}
	original, err := observe()
	if err != nil {
		t.Fatal(err)
	}
	same, err := observe()
	if err != nil || same != original {
		t.Fatal("inactive admission is unstable", err)
	}
	adminRoot, err := os.OpenRoot("/etc/cron.d")
	if err != nil {
		t.Fatal(err)
	}
	defer adminRoot.Close()
	before, err := adminRoot.ReadFile("administrator")
	if err != nil {
		t.Fatal(err)
	}
	if err := adminRoot.WriteFile("administrator", append(bytes.Clone(before), []byte("# administrator review\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := observe()
	if err != nil || changed == original {
		t.Fatal("administrator schedule drift was lost", err)
	}
	if err := adminRoot.WriteFile("administrator", before, 0600); err != nil {
		t.Fatal(err)
	}
	// The only command that mutates nftables is this fixed disposable-namespace
	// test stimulus. Production admission dispatches only list ruleset.
	command := exec.CommandContext(ctx, "/usr/sbin/nft", "add", "table", "inet", "syswarden_oracle_refusal")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated test stimulus: %v %s", err, output)
	}
	if _, err := observe(); err == nil || !strings.Contains(err.Error(), "possible SysWarden state") {
		t.Fatal("product-looking kernel state accepted", err)
	}
	command = exec.CommandContext(ctx, "/usr/sbin/nft", "delete", "table", "inet", "syswarden_oracle_refusal")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated stimulus cleanup: %v %s", err, output)
	}
	if _, err := observe(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/var/lib/syswarden", "/var/log/syswarden", "/run/openrc/started/cronie", "/run/openrc/started/nftables", "/run/openrc/started/syswarden-core", "/etc/init.d/syswarden-core"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatal("admission created or activated state", p, err)
		}
	}
	if err := lease.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := policy.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("real TOML absence and publication exclusion with OpenRC admission preserved inactive services and administrator state; schedule drift and product-looking nftables state were detected")
}

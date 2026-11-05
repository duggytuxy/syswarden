//go:build linux

package system

import (
	"context"
	"os"
	"runtime"
	"syswarden-cli/config"
	"testing"
	"time"
)

// This opt-in test runs only inside a disposable real OpenRC container. It
// validates actual source-process custody and publication exclusion, not signed
// package provenance, a native transaction or final product qualification.
func TestAPKInactiveCoordinatorPublicationOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_INACTIVE_CUSTODY_ORACLE") != "1" {
		t.Skip("requires the explicit isolated inactive coordinator laboratory")
	}
	if runtime.GOARCH != "amd64" || os.Geteuid() != 0 || os.Getpid() <= 1 {
		t.Fatal("isolated root AMD64 child process required")
	}
	marker, err := os.ReadFile("/tmp/inactive-custody-oracle")
	if err != nil || string(marker) != "syswarden-inactive-custody-v1\n" {
		t.Fatal("explicit disposable fixture marker required")
	}
	if info, err := os.Lstat("/run/.containerenv"); err != nil || !info.Mode().IsRegular() {
		t.Fatal("disposable container required")
	}
	init, err := os.Readlink("/proc/1/exe")
	if err != nil || init != "/sbin/openrc-init" {
		t.Fatal("real OpenRC PID1 required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	services := productionAPKInactiveCustodyServices(nil)
	if err := config.InitializeDefaults("/etc/syswarden/config"); err != nil {
		t.Fatal(err)
	}
	originalPolicy, err := captureAPKInactivePolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := services.hold(ctx, originalPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	if lease.SHA256() != originalPolicy.AbsenceSHA256 {
		t.Fatal("actual lease differs from original absence witness")
	}
	independent, err := captureAPKInactivePolicy(ctx)
	if err != nil || independent != originalPolicy {
		t.Fatal("independent reader changed original policy", err)
	}
	if competing, err := services.hold(ctx, originalPolicy); err == nil {
		_ = competing.Close()
		t.Fatal("independent reader released publication exclusion")
	}
	originalRuntime, err := captureNativeActivationRuntime(ctx, "/opt/syswarden/bin", 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(originalRuntime.CLI.SHA256, originalRuntime.Core.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile(nativeActivationDescriptorPath, raw, 0644); err != nil {
		t.Fatal(err)
	}
	capability, err := parseNativeActivationDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	original := nativeActivationBindingPlan{Installed: originalRuntime, SourcePublicationSHA256: capability.SHA256()}
	verify, err := services.source(ctx, original, capability)
	if err != nil {
		t.Fatal("actual original coordinator was not attested", err)
	}
	if err := verify(ctx, false); err != nil {
		t.Fatal(err)
	}
	// The runner stages a byte-identical second inode inside this disposable
	// installation. Replacement unlinks the running original executable only.
	if err := root.Rename("opt/syswarden/bin/coordinator-replacement", qualificationPackageCLIPath); err != nil {
		t.Fatal(err)
	}
	if err := verify(ctx, false); err == nil {
		t.Fatal("source replacement accepted before native replacement phase")
	}
	if err := verify(ctx, true); err != nil {
		t.Fatal("original running inode was lost after replacement", err)
	}
	if _, err := services.source(ctx, original, capability); err == nil {
		t.Fatal("replacement source was adopted as original coordinator")
	}
	if err := lease.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	independent, err = captureAPKInactivePolicy(ctx)
	if err != nil || independent != originalPolicy {
		t.Fatal("original policy changed across executable replacement", err)
	}
	if _, err := services.observe(ctx); err == nil {
		t.Fatal("missing firewall observer granted complete inactivity evidence")
	}
	t.Log("actual root coordinator PID/start/executable remained bound across unlink; original TOML absence and publication exclusion remained intact")
}

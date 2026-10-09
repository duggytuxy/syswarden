package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"syswarden-cli/config"
)

type unexpectedInstallProbe struct{ t *testing.T }

func (probe unexpectedInstallProbe) RoundTrip(request *http.Request) (*http.Response, error) {
	probe.t.Errorf("unexpected pre-download network request: %s %s", request.Method, request.URL)
	return nil, errors.New("unexpected network probe")
}

func rejectInstallNetworkProbes(t *testing.T) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = unexpectedInstallProbe{t: t}
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func TestOfflineQualificationActivationMigratesLegacyConfigurationBeforeDefaults(t *testing.T) {
	root := t.TempDir()
	legacyDirectory := filepath.Join(root, "opt", "syswarden")
	configRoot := filepath.Join(root, "etc", "syswarden", "config")
	if err := os.MkdirAll(legacyDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(legacyDirectory, "syswarden-auto.conf")
	legacy := strings.Replace(config.DefaultConfig, `SYSWARDEN_SSH_PORT=""`, `SYSWARDEN_SSH_PORT="2222"`, 1)
	if err := os.WriteFile(legacyPath, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareOfflineQualificationActivationConfiguration(legacyPath, configRoot); err != nil {
		t.Fatalf("deferred legacy migration failed: %v", err)
	}
	complete, err := config.ModularConfigurationComplete(configRoot)
	if err != nil || !complete {
		t.Fatalf("modular configuration completeness = %t, %v", complete, err)
	}
	if _, err := os.Lstat(legacyPath + ".bak"); err != nil {
		t.Fatalf("legacy source was not archived after migration: %v", err)
	}
	if _, err := os.Lstat(legacyPath + ".migrated"); !os.IsNotExist(err) {
		t.Fatalf("noncanonical retained migration source remains: %v", err)
	}
	if err := config.ParseConfig(configRoot); err != nil {
		t.Fatalf("parse migrated configuration: %v", err)
	}
	if config.GlobalConfig == nil || config.GlobalConfig.SSHPort != "2222" {
		t.Fatalf("legacy operator SSH port was not preserved: %#v", config.GlobalConfig)
	}
}

func TestOfflineQualificationActivationRefusesAmbiguousLegacySources(t *testing.T) {
	root := t.TempDir()
	legacyDirectory := filepath.Join(root, "opt", "syswarden")
	if err := os.MkdirAll(legacyDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(legacyDirectory, "syswarden-auto.conf")
	for _, path := range []string{legacyPath, legacyPath + ".migration_backup"} {
		if err := os.WriteFile(path, []byte(config.DefaultConfig), 0600); err != nil {
			t.Fatal(err)
		}
	}
	err := prepareOfflineQualificationActivationConfiguration(
		legacyPath,
		filepath.Join(root, "etc", "syswarden", "config"),
	)
	if err == nil || !strings.Contains(err.Error(), "ambiguous legacy configuration sources") {
		t.Fatalf("ambiguous legacy sources error = %v", err)
	}
}

func TestOfflineQualificationPackageStageDoesNotEnterActivationPipeline(t *testing.T) {
	previousDependencies := installDependenciesForInstall
	previousConfig := config.GlobalConfig
	t.Cleanup(func() {
		installDependenciesForInstall = previousDependencies
		config.GlobalConfig = previousConfig
	})
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "1")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	config.GlobalConfig = nil
	dependencyCalls := 0
	installDependenciesForInstall = func() error {
		dependencyCalls++
		return nil
	}
	if err := installCmd.RunE(installCmd, nil); err != nil {
		t.Fatalf("offline package stage failed: %v", err)
	}
	if dependencyCalls != 1 {
		t.Fatalf("offline package dependency attestations = %d, want 1", dependencyCalls)
	}
}

func TestOfflineQualificationPackageStageFailsClosedOnDependencyAttestation(t *testing.T) {
	previousDependencies := installDependenciesForInstall
	t.Cleanup(func() { installDependenciesForInstall = previousDependencies })
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "1")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	installDependenciesForInstall = func() error { return errors.New("missing nft") }
	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "offline package dependency attestation failed") {
		t.Fatalf("offline dependency stage error = %v", err)
	}
}

func TestOfflineQualificationInstallAttestsFeedsWithoutNetworkCalls(t *testing.T) {
	rejectInstallNetworkProbes(t)
	previousConfig := config.GlobalConfig
	previousDownload := downloadFeedsForInstall
	previousAttest := attestOfflineQualificationFeedsForInstall
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		downloadFeedsForInstall = previousDownload
		attestOfflineQualificationFeedsForInstall = previousAttest
	})
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "1")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	config.GlobalConfig = &config.Config{ListChoice: "4", GeoCodes: "be", GeoAllowed: "fr"}
	downloadFeedsForInstall = func(string, string, string, string, string, string, string, string, string, bool, bool) error {
		t.Fatal("offline qualification invoked the feed downloader")
		return nil
	}
	attestCalls := 0
	attestOfflineQualificationFeedsForInstall = func(
		mirrorURL, customURLIPv6, customHash, customHashIPv6, listChoice, geoCodes, geoAllowed string,
		lanMode bool,
	) error {
		attestCalls++
		if mirrorURL != "https://codeberg.org/" || customURLIPv6 != "" || customHash != "" ||
			customHashIPv6 != "" || listChoice != "4" || geoCodes != "be" || geoAllowed != "fr" || lanMode {
			return fmt.Errorf("unexpected offline feed selection")
		}
		return nil
	}

	if err := prepareNetworkIntelligenceForInstall(); err != nil {
		t.Fatalf("offline network intelligence preparation failed: %v", err)
	}
	if attestCalls != 1 {
		t.Fatalf("offline feed attestation calls = %d, want 1", attestCalls)
	}
}

func TestOrdinaryPackageInstallDownloadsFeedsWithoutHomepageProbe(t *testing.T) {
	rejectInstallNetworkProbes(t)
	previousConfig := config.GlobalConfig
	previousDownload := downloadFeedsForInstall
	previousAttest := attestOfflineQualificationFeedsForInstall
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		downloadFeedsForInstall = previousDownload
		attestOfflineQualificationFeedsForInstall = previousAttest
	})
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	config.GlobalConfig = &config.Config{ListChoice: "4"}
	downloadCalls := 0
	downloadFeedsForInstall = func(mirror string, _ string, _ string, _ string, choice string, _ string, _ string, _ string, _ string, _ bool, _ bool) error {
		downloadCalls++
		if mirror != "https://codeberg.org/" || choice != "4" {
			t.Fatalf("feed selection changed: mirror=%q choice=%q", mirror, choice)
		}
		return nil
	}
	attestOfflineQualificationFeedsForInstall = func(string, string, string, string, string, string, string, bool) error {
		t.Fatal("ordinary package install entered the offline qualification path")
		return nil
	}

	if err := prepareNetworkIntelligenceForInstall(); err != nil {
		t.Fatalf("ordinary network intelligence preparation failed: %v", err)
	}
	if downloadCalls != 1 {
		t.Fatalf("ordinary path downloads=%d, want 1", downloadCalls)
	}
	downloadFeedsForInstall = func(string, string, string, string, string, string, string, string, string, bool, bool) error {
		return errors.New("feed mirror quorum unavailable")
	}
	if err := prepareNetworkIntelligenceForInstall(); err == nil || !strings.Contains(err.Error(), "feed mirror quorum unavailable") {
		t.Fatalf("actual feed failure was not retained: %v", err)
	}
}

func TestOfflineQualificationInstallSuppressesWebhookAndWireGuardEgress(t *testing.T) {
	previousWebhooks := setupWebhooksForInstall
	previousWireGuard := setupWireGuardForInstall
	t.Cleanup(func() {
		setupWebhooksForInstall = previousWebhooks
		setupWireGuardForInstall = previousWireGuard
	})
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "1")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	setupWebhooksForInstall = func() error {
		t.Fatal("offline qualification invoked webhook connectivity verification")
		return nil
	}
	setupWireGuardForInstall = func() error {
		t.Fatal("offline qualification invoked WireGuard endpoint discovery or activation")
		return nil
	}

	if err := setupWebhooksWithoutQualificationEgress(); err != nil {
		t.Fatalf("offline webhook preservation failed: %v", err)
	}
	if err := setupWireGuardWithoutQualificationEgress(); err != nil {
		t.Fatalf("offline WireGuard preservation failed: %v", err)
	}
}

func TestProductionInstallRetainsWebhookAndWireGuardSetup(t *testing.T) {
	previousWebhooks := setupWebhooksForInstall
	previousWireGuard := setupWireGuardForInstall
	t.Cleanup(func() {
		setupWebhooksForInstall = previousWebhooks
		setupWireGuardForInstall = previousWireGuard
	})
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	webhookCalls := 0
	wireGuardCalls := 0
	setupWebhooksForInstall = func() error {
		webhookCalls++
		return nil
	}
	setupWireGuardForInstall = func() error {
		wireGuardCalls++
		return nil
	}

	if err := setupWebhooksWithoutQualificationEgress(); err != nil {
		t.Fatalf("production webhook setup failed: %v", err)
	}
	if err := setupWireGuardWithoutQualificationEgress(); err != nil {
		t.Fatalf("production WireGuard setup failed: %v", err)
	}
	if webhookCalls != 1 || wireGuardCalls != 1 {
		t.Fatalf("production webhook calls=%d WireGuard calls=%d, want 1 each", webhookCalls, wireGuardCalls)
	}
}

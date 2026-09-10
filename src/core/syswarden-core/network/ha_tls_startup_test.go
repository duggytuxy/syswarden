package network

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestRuntimeLifecycleHAFencePreservesTLSIdentityAcrossRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ha")
	ledger := filepath.Join(directory, "bans.json")
	if _, err := prepareRuntimeLifecycleHAFence(directory, ledger, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	first, err := loadOrCreateHATLSCertificate(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRuntimeLifecycleHAFence(directory, ledger, os.Geteuid()); err != nil {
		t.Fatalf("runtime restart rejected the retained identity and fence: %v", err)
	}
	second, err := loadOrCreateHATLSCertificate(directory)
	if err != nil || !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatalf("runtime restart replaced the peer's trusted identity: %v", err)
	}
}

func TestRuntimeLifecycleHAFenceRefusesIncompleteIdentityBeforeFence(t *testing.T) {
	for _, missing := range []string{haTLSCertificateName, haTLSPrivateKeyName} {
		t.Run(missing, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "ha")
			if _, err := loadOrCreateHATLSCertificate(directory); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := root.Remove(missing); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareRuntimeLifecycleHAFence(directory, filepath.Join(directory, "bans.json"), os.Geteuid()); err == nil {
				t.Fatal("incomplete identity was silently replaced")
			}
			for _, name := range []string{missing, "fence"} {
				if _, err := root.Lstat(name); !os.IsNotExist(err) {
					t.Fatalf("failed TLS attestation created %s: %v", name, err)
				}
			}
		})
	}
}

func TestHALegacyStartupCreatesIdentityBeforeSharedFence(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	originalTLS, originalLedger := haTLSDir, haRuntimeBanLedgerFile
	t.Cleanup(func() {
		haTLSDir, haRuntimeBanLedgerFile = originalTLS, originalLedger
	})
	haTLSDir = filepath.Join(t.TempDir(), "ha")
	haRuntimeBanLedgerFile = filepath.Join(haTLSDir, "bans.json")
	viper.Set("integrations.ha.enabled", true)
	viper.Set("integrations.ha.token", strings.Repeat("f", 64))
	viper.Set("integrations.ha.peer_ips", []string{"127.0.0.1/32"})
	// Stop at listener validation after real identity and fence initialization.
	// No socket or host firewall is required for this startup regression.
	viper.Set("integrations.ha.peer_port", 65536)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := StartHAServerContext(ctx, noOpFirewallManager{})
	if err == nil || !strings.Contains(err.Error(), "bind HA listener:") {
		t.Fatalf("fresh shared HA directory failed before listener validation: %v", err)
	}
	if _, err := loadOrCreateHATLSCertificate(haTLSDir); err != nil {
		t.Fatalf("startup did not persist a complete TLS identity: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(haTLSDir, "fence")); err != nil || !info.IsDir() {
		t.Fatalf("startup did not initialize the shared fence after TLS: %v", err)
	}
}

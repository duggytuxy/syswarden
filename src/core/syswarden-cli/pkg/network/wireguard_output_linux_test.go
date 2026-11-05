//go:build linux

package network

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func TestWireGuardSetupNeverPrintsCredentialsOnCreationOrReuse(t *testing.T) {
	for _, phase := range []string{"", "fresh", "upgrade", "unknown"} {
		t.Run("native-phase-"+phase, func(t *testing.T) {
			t.Setenv("SYSWARDEN_NATIVE_INSTALL_PHASE", phase)
			t.Setenv("SYSWARDEN_PKG_INSTALL", "")
			if phase != "" {
				t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
			}
			harness := installWireGuardTransactionHarness(t)
			outputPath := filepath.Join(t.TempDir(), "installation-output")
			output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600) // #nosec G304 -- fixed filename in a private test directory
			if err != nil {
				t.Fatal(err)
			}
			originalStdout, originalStderr := os.Stdout, os.Stderr
			os.Stdout, os.Stderr = output, output
			t.Cleanup(func() {
				os.Stdout, os.Stderr = originalStdout, originalStderr
				_ = output.Close()
			})
			var originalClient []byte
			for attempt := range 2 {
				harness.expectTransaction = attempt == 0
				if err := SetupWireguard(); err != nil {
					t.Fatalf("setup attempt %d failed: %v", attempt, err)
				}
				manifest, err := wireguardstate.ReadAndVerify(harness.root, networkTestUID(t), networkTestGID(t))
				if err != nil {
					t.Fatal(err)
				}
				client, err := wireguardstate.ReadVerifiedArtifact(harness.root, manifest,
					wireguardstate.ClientConfigurationPath, networkTestUID(t), networkTestGID(t))
				if err != nil {
					t.Fatal(err)
				}
				if attempt == 0 {
					originalClient = append([]byte(nil), client...)
				} else if !bytes.Equal(originalClient, client) {
					t.Fatal("reactivation replaced the protected client credentials")
				}
				captured, err := os.ReadFile(outputPath) // #nosec G304 -- output is produced only by the isolated setup harness
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(string(client), "\n") {
					key, value, ok := strings.Cut(line, "=")
					if ok && (strings.TrimSpace(key) == "PrivateKey" || strings.TrimSpace(key) == "PresharedKey") {
						if bytes.Contains(captured, []byte(strings.TrimSpace(value))) {
							t.Fatal("installation output contains a client secret")
						}
					}
				}
				if strings.ContainsAny(string(captured), "█▀▄") || bytes.Contains(captured, []byte("QR")) {
					t.Fatal("installation output contains a credential QR rendering")
				}
				if !bytes.Contains(captured, []byte(wireguardstate.ClientConfigurationPath)) {
					t.Fatal("installation output does not identify the protected client file")
				}
			}
		})
	}
}

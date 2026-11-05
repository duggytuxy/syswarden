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

func TestScopedMigrationResumesOnlyTheSealedPolicyVersion(t *testing.T) {
	for _, kind := range []string{"v1", "v2", "changed-target"} {
		t.Run(kind, func(t *testing.T) {
			host, runner, originals := migrationTestHost(t)
			snapshot, err := wireguardstate.InspectLegacyMigration(host.filesystemRoot, host.expectedUID, host.expectedGID)
			if err != nil {
				t.Fatal(err)
			}
			generated, err := generatedStateFromMigration(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			input := generated.input
			input.NFTPath, input.TruePath = "/usr/sbin/nft", "/usr/bin/true"
			input.OwnershipToken, input.SharedForward = strings.Repeat("b", 64), true
			input.LegacyPolicy = kind == "v1"
			if kind == "changed-target" {
				input.ActiveIf = "another0"
			}
			server, _, err := renderWireGuardConfigurations(input)
			if err != nil {
				t.Fatal(err)
			}
			if err := wireguardstate.BeginLegacyMigration(host.filesystemRoot, snapshot, []byte(server), host.expectedUID, host.expectedGID); err != nil {
				t.Fatal(err)
			}
			journalPath := filepath.Join(host.filesystemRoot, wireguardstate.LegacyMigrationPath)
			journal, err := os.ReadFile(journalPath) // #nosec G304 -- fixed journal filename below the isolated test fixture root
			if err != nil {
				t.Fatal(err)
			}
			plan, err := host.inspectMigration()
			if kind == "changed-target" {
				if err == nil {
					t.Fatal("accepted a sealed target with a different egress")
				}
				if len(runner.state.batches) != 0 {
					t.Fatal("modified runtime before resolving the sealed policy")
				}
				retained, err := os.ReadFile(journalPath) // #nosec G304 -- rereads the same private fixture journal to prove unchanged bytes
				if err != nil || !bytes.Equal(retained, journal) {
					t.Fatal("modified the unknown sealed journal")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			digest, err := LegacyWireGuardMigrationPlanSHA256(plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := host.applyMigration(digest); err != nil {
				t.Fatal(err)
			}
			manifest, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := wireguardstate.ReadVerifiedArtifact(host.filesystemRoot, manifest, wireguardstate.ServerConfigurationPath, host.expectedUID, host.expectedGID)
			if err != nil || !bytes.Equal(actual, []byte(server)) {
				t.Fatal("sealed target bytes changed", err)
			}
			receipt, err := os.ReadFile(filepath.Join(host.filesystemRoot, wireguardstate.LegacyMigrationReceiptPath))
			if err != nil || !bytes.Equal(receipt, journal) {
				t.Fatal("sealed journal bytes changed during completion")
			}
			for path, original := range originals {
				backup, err := os.ReadFile(filepath.Join(host.filesystemRoot, wireguardstate.LegacyMigrationBackupPath(path)))
				if err != nil || !bytes.Equal(backup, original) {
					t.Fatal("original recovery bytes changed")
				}
			}
		})
	}
}

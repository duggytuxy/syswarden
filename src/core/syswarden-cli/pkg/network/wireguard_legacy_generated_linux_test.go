//go:build linux

package network

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func historicalGeneratedTestState(t *testing.T, host legacyWireGuardRecoveryHost) map[string][]byte {
	t.Helper()
	input := wireGuardRenderInput{
		Backend: "nftables", Subnet: "10.66.66.0/24", Port: "51820", ActiveIf: "ens3",
		EndpointIP: "192.0.2.15", NFTPath: "/usr/sbin/nft", TruePath: "/usr/bin/true",
		OwnershipToken: strings.Repeat("a", 64),
		ServerPriv:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		ClientPriv:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		PresharedKey:   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
	}
	var err error
	input.ServerPub, err = legacyWireGuardPublicKey(input.ServerPriv)
	if err != nil {
		t.Fatal(err)
	}
	input.ClientPub, err = legacyWireGuardPublicKey(input.ClientPriv)
	if err != nil {
		t.Fatal(err)
	}
	server, client, err := renderWireGuardConfigurations(input)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(server, "\n")
	lines[4] = "PostUp = " + legacyWireGuardPostUp("wg-syswarden", "ens3", true)
	lines[5] = "PostDown = " + legacyWireGuardPostDown("wg-syswarden")
	contents := map[string][]byte{
		wireguardstate.ServerConfigurationPath:     []byte(strings.Join(lines, "\n")),
		wireguardstate.ClientConfigurationPath:     []byte(client),
		wireguardstate.ForwardingConfigurationPath: []byte(wireGuardForwardingSetting),
	}
	for path, content := range contents {
		target := filepath.Join(host.filesystemRoot, path)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return contents
}

func TestRetirementPreservesProvenUnmanifestedHistoricalGeneratedState(t *testing.T) {
	for _, tablePresent := range []bool{true, false} {
		host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
		host.nftRunner = &retirementNFTRunner{state: state}
		state.tablePresent = tablePresent
		state.forwardRules["wg-syswarden"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 23}}
		contents := historicalGeneratedTestState(t, host)
		before, err := inspectLegacyWireGuardGeneratedState(host.filesystemRoot, host.expectedUID, host.expectedGID)
		if err != nil {
			t.Fatal(err)
		}
		plan := retirementApply(t, host)
		if len(plan.LegacyGenerated) != 3 || plan.Ownership.State != "no-manifest" {
			t.Fatal("historical provenance missing from plan")
		}
		after, err := inspectLegacyWireGuardGeneratedState(host.filesystemRoot, host.expectedUID, host.expectedGID)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("historical generated files changed", err)
		}
		wire, err := RenderLegacyWireGuardRetirementPlan(plan)
		if err != nil || bytes.Contains(wire, []byte(before.input.ServerPriv)) || bytes.Contains(wire, []byte(before.input.ClientPriv)) || bytes.Contains(wire, []byte(before.input.PresharedKey)) {
			t.Fatal("plan disclosed key material")
		}
		for path, expected := range contents {
			actual, err := legacyTestFiles(t, host.filesystemRoot).ReadFile(strings.TrimPrefix(path, "/"))
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatal("original artifact changed", err)
			}
		}
		retirementApply(t, host)
	}
}

func TestHistoricalGeneratedProofRejectsPartialCustomizedAndMismatchedState(t *testing.T) {
	for _, kind := range []string{"missing-client", "client-key", "server-key", "psk", "client-address", "endpoint-port", "custom-dns", "extra-peer", "custom-forwarding", "hardlink", "symlink", "no-newline"} {
		t.Run(kind, func(t *testing.T) {
			host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
			host.nftRunner = &retirementNFTRunner{state: state}
			contents := historicalGeneratedTestState(t, host)
			clientPath := filepath.Join(host.filesystemRoot, wireguardstate.ClientConfigurationPath)
			client := string(contents[wireguardstate.ClientConfigurationPath])
			switch kind {
			case "missing-client":
				if err := os.Remove(clientPath); err != nil {
					t.Fatal(err)
				}
			case "client-key":
				client = strings.Replace(client, "PrivateKey = ", "PrivateKey = A", 1)
			case "server-key":
				client = strings.Replace(client, "PublicKey = ", "PublicKey = A", 1)
			case "psk":
				client = strings.Replace(client, "PresharedKey = ", "PresharedKey = A", 1)
			case "client-address":
				client = strings.Replace(client, "10.66.66.2/24", "10.66.66.3/24", 1)
			case "endpoint-port":
				client = strings.Replace(client, ":51820", ":51821", 1)
			case "custom-dns":
				client = strings.Replace(client, "1.0.0.1", "9.9.9.9", 1)
			case "extra-peer":
				client += "\n[Peer]\n"
			case "custom-forwarding":
				if err := os.WriteFile(filepath.Join(host.filesystemRoot, wireguardstate.ForwardingConfigurationPath), []byte("net.ipv4.ip_forward = 0\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(clientPath, filepath.Join(host.filesystemRoot, "alias")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(clientPath, clientPath+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(clientPath+".saved", clientPath); err != nil {
					t.Fatal(err)
				}
			case "no-newline":
				client = strings.TrimSuffix(client, "\n")
			}
			if client != string(contents[wireguardstate.ClientConfigurationPath]) {
				if err := os.WriteFile(clientPath, []byte(client), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := host.inspectRetirement(); err == nil {
				t.Fatal("accepted unproven generated state")
			}
			requireHistoricalConfigRetained(t, host)
			if len(state.batches) != 0 {
				t.Fatal("inspection changed runtime")
			}
		})
	}
}

func TestRetirementRejectsHistoricalClientDriftAfterPlan(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	host.nftRunner = &retirementNFTRunner{state: state}
	historicalGeneratedTestState(t, host)
	plan, err := host.inspectRetirement()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	host.guard = func() (func() error, error) {
		path := strings.TrimPrefix(wireguardstate.ClientConfigurationPath, "/")
		files := legacyTestFiles(t, host.filesystemRoot)
		wire, err := files.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		wire = bytes.Replace(wire, []byte("192.0.2.15"), []byte("192.0.2.16"), 1)
		if err := files.WriteFile(path, wire, 0600); err != nil {
			t.Fatal(err)
		}
		return func() error { return nil }, nil
	}
	if _, err := host.applyRetirement(digest); err == nil {
		t.Fatal("accepted stale retirement digest")
	}
	if len(state.batches) != 0 {
		t.Fatal("changed kernel after client drift")
	}
	requireHistoricalConfigRetained(t, host)
}

func TestReportedFailedOldAndActiveCurrentServicesRemainReadOnly(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	host.nftRunner = &retirementNFTRunner{state: state}
	historicalGeneratedTestState(t, host)
	inactive := host.commandOutput
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		if name == "wg" {
			return []byte("wg-syswarden\n"), nil
		}
		if strings.Contains(command, "--property=ActiveState") {
			if strings.Contains(command, "wg-quick@wg0.service") {
				return []byte("failed\n"), nil
			}
			return []byte("active\n"), nil
		}
		if strings.Contains(command, "--property=UnitFileState") {
			return []byte("enabled\n"), nil
		}
		return inactive(name, args...)
	}
	plan, err := host.inspectRetirement()
	if err != nil {
		t.Fatal(err)
	}
	if plan.SafeToApply || len(plan.Blockers) != 5 || len(plan.LegacyGenerated) != 3 {
		t.Fatalf("reported coexistence did not produce all runtime blockers: %v", plan.Blockers)
	}
	digest, err := LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.applyRetirement(digest); err == nil {
		t.Fatal("applied retirement with failed/enabled and active/enabled VPNs")
	}
	if len(state.batches) != 0 {
		t.Fatal("blocked retirement changed the firewall")
	}
	requireHistoricalConfigRetained(t, host)
}

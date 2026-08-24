//go:build linux

package network

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
	"time"
)

func TestSetupWireguardOfflineRefusesBeforeMutation(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousClassifier := wireGuardManagerRuntimeState
	previousPreflight := wireGuardFirewallBackendPreflight
	config.GlobalConfig = &config.Config{EnableWG: true, FirewallBackend: "nftables"}
	wireGuardFirewallBackendPreflight = func(string) error { return nil }
	classifierCalls := 0
	wireGuardManagerRuntimeState = func() (string, error) {
		classifierCalls++
		return "OFFLINE", nil
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		wireGuardManagerRuntimeState = previousClassifier
		wireGuardFirewallBackendPreflight = previousPreflight
	})
	if err := SetupWireguard(); err == nil || !strings.Contains(err.Error(), "attestable active service manager") {
		t.Fatalf("offline WireGuard result = %v", err)
	}
	if classifierCalls != 1 {
		t.Fatalf("service-manager classifier calls = %d, want 1", classifierCalls)
	}
}

func TestSetupWireguardRejectsBackendBeforeMutation_SW2_FWBACKEND_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousClassifier := wireGuardManagerRuntimeState
	previousPreflight := wireGuardFirewallBackendPreflight
	config.GlobalConfig = &config.Config{EnableWG: true, FirewallBackend: "iptables"}
	classifierCalls := 0
	wireGuardManagerRuntimeState = func() (string, error) {
		classifierCalls++
		return "ACTIVE", nil
	}
	sentinel := errors.New("iptables is not operational")
	preflightCalls := 0
	wireGuardFirewallBackendPreflight = func(backend string) error {
		preflightCalls++
		return sentinel
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		wireGuardManagerRuntimeState = previousClassifier
		wireGuardFirewallBackendPreflight = previousPreflight
	})

	err := SetupWireguard()
	if err == nil || !strings.Contains(err.Error(), "requires core.firewall_backend=nftables") {
		t.Fatalf("SetupWireguard() error = %v", err)
	}
	if preflightCalls != 0 {
		t.Fatalf("backend preflight ran for a rejected parse-only backend: %d", preflightCalls)
	}
	if classifierCalls != 0 {
		t.Fatalf("service-manager classification occurred after backend refusal: %d", classifierCalls)
	}
}

func TestSetupWireguardPreflightFailurePreventsMutation_SW2_FWBACKEND_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousClassifier := wireGuardManagerRuntimeState
	previousPreflight := wireGuardFirewallBackendPreflight
	config.GlobalConfig = &config.Config{EnableWG: true, FirewallBackend: "nftables"}
	classifierCalls := 0
	wireGuardManagerRuntimeState = func() (string, error) {
		classifierCalls++
		return "ACTIVE", nil
	}
	sentinel := errors.New("firewalld became active")
	wireGuardFirewallBackendPreflight = func(backend string) error {
		if backend != "nftables" {
			t.Fatalf("backend = %q, want nftables", backend)
		}
		return sentinel
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		wireGuardManagerRuntimeState = previousClassifier
		wireGuardFirewallBackendPreflight = previousPreflight
	})

	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "before WireGuard mutation") {
		t.Fatalf("SetupWireguard() error = %v", err)
	}
	if classifierCalls != 0 {
		t.Fatalf("service-manager classification occurred after backend preflight failure: %d", classifierCalls)
	}
}

func TestWireGuardActivationReattestsBackendBeforeServiceStart_SW2_FWBACKEND_001(t *testing.T) {
	previousPreflight := wireGuardFirewallBackendPreflight
	previousPrepare := wireGuardServicePrepare
	previousActivator := wireGuardServiceActivator
	previousInspector := wireGuardServiceInspector
	previousIdentity := wireGuardServerIdentityInspector
	previousGuard := wireGuardNFTActivationGuard
	previousNFTPreflight := wireGuardNFTActivationPreflight
	sentinel := errors.New("firewalld became active")
	activatorCalls := 0
	preflightCalls := 0
	wireGuardFirewallBackendPreflight = func(backend string) error {
		preflightCalls++
		if backend != "nftables" {
			t.Fatalf("backend = %q, want nftables", backend)
		}
		if preflightCalls == 2 {
			return sentinel
		}
		return nil
	}
	wireGuardServicePrepare = func() error { return nil }
	wireGuardServiceActivator = func(_ wireGuardServiceState) error {
		activatorCalls++
		return nil
	}
	baseline := wireGuardServiceState{Alpine: false}
	wireGuardServiceInspector = func() (wireGuardServiceState, error) { return baseline, nil }
	identity := wireguardstate.ServerConfigurationIdentity{
		NFTPath: "/usr/sbin/nft", TruePath: "/usr/bin/true",
		OwnershipToken: strings.Repeat("a", 64), ActiveInterface: "ens3",
	}
	wireGuardServerIdentityInspector = func() (wireguardstate.ServerConfigurationIdentity, error) { return identity, nil }
	wireGuardNFTActivationGuard = func() (func() error, error) {
		return func() error { return nil }, nil
	}
	wireGuardNFTActivationPreflight = func(expectation wireGuardNFTExpectation) error {
		if expectation.Identity != identity || expectation.AllowExisting || expectation.RequirePresent {
			t.Fatalf("unexpected nftables expectation: %#v", expectation)
		}
		return nil
	}
	t.Cleanup(func() {
		wireGuardFirewallBackendPreflight = previousPreflight
		wireGuardServicePrepare = previousPrepare
		wireGuardServiceActivator = previousActivator
		wireGuardServiceInspector = previousInspector
		wireGuardServerIdentityInspector = previousIdentity
		wireGuardNFTActivationGuard = previousGuard
		wireGuardNFTActivationPreflight = previousNFTPreflight
	})

	forwarding := &testWireGuardForwardingTransaction{}
	err := activateWireGuardAfterBackendPreflight(
		"nftables", wireGuardNFTExpectation{Identity: identity}, baseline, forwarding,
	)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "before WireGuard activation") {
		t.Fatalf("activation reattestation error = %v", err)
	}
	if activatorCalls != 0 {
		t.Fatalf("WireGuard service started after backend drift: %d", activatorCalls)
	}
}

func TestWireGuardPostActivationTruthIsAttestedWhileNFTLockIsHeld_SW2_WGSTATE_001(t *testing.T) {
	previousPreflight := wireGuardFirewallBackendPreflight
	previousPrepare := wireGuardServicePrepare
	previousActivator := wireGuardServiceActivator
	previousInspector := wireGuardServiceInspector
	previousIdentity := wireGuardServerIdentityInspector
	previousGuard := wireGuardNFTActivationGuard
	previousNFTPreflight := wireGuardNFTActivationPreflight
	previousRollback := wireGuardServiceRollback
	previousCleanup := wireGuardReservedNFTCleanup
	t.Cleanup(func() {
		wireGuardFirewallBackendPreflight = previousPreflight
		wireGuardServicePrepare = previousPrepare
		wireGuardServiceActivator = previousActivator
		wireGuardServiceInspector = previousInspector
		wireGuardServerIdentityInspector = previousIdentity
		wireGuardNFTActivationGuard = previousGuard
		wireGuardNFTActivationPreflight = previousNFTPreflight
		wireGuardServiceRollback = previousRollback
		wireGuardReservedNFTCleanup = previousCleanup
	})

	locked := false
	assertLocked := func(operation string) {
		if !locked {
			t.Fatalf("%s ran outside the shared nftables lock", operation)
		}
	}
	wireGuardNFTActivationGuard = func() (func() error, error) {
		if locked {
			t.Fatal("activation lock was acquired recursively")
		}
		locked = true
		return func() error {
			if !locked {
				t.Fatal("activation lock was released twice")
			}
			locked = false
			return nil
		}, nil
	}
	identity := exactWireGuardNFTIdentity()
	baseline := wireGuardServiceState{Alpine: false}
	state := baseline
	nftAttestations := 0
	wireGuardNFTActivationPreflight = func(expectation wireGuardNFTExpectation) error {
		assertLocked("nftables provenance attestation")
		nftAttestations++
		if expectation.Identity != identity {
			t.Fatalf("unexpected nftables identity: %#v", expectation.Identity)
		}
		return nil
	}
	wireGuardFirewallBackendPreflight = func(backend string) error {
		assertLocked("firewall backend attestation")
		if backend != "nftables" {
			t.Fatalf("backend = %q", backend)
		}
		return nil
	}
	wireGuardServicePrepare = func() error {
		assertLocked("service preparation")
		return nil
	}
	wireGuardServiceInspector = func() (wireGuardServiceState, error) {
		assertLocked("service state attestation")
		return state, nil
	}
	wireGuardServerIdentityInspector = func() (wireguardstate.ServerConfigurationIdentity, error) {
		assertLocked("configuration provenance attestation")
		return identity, nil
	}
	wireGuardServiceActivator = func(got wireGuardServiceState) error {
		assertLocked("service activation")
		if got != baseline {
			t.Fatalf("activation baseline = %#v, want %#v", got, baseline)
		}
		state = wireGuardServiceState{Alpine: false, Active: true, Enabled: true, Interface: true}
		return nil
	}
	wireGuardServiceRollback = func(wireGuardServiceState) error {
		t.Fatal("successful activation attempted rollback")
		return nil
	}
	wireGuardReservedNFTCleanup = func(wireguardstate.ServerConfigurationIdentity) error {
		t.Fatal("successful activation attempted cleanup")
		return nil
	}
	forwarding := &testWireGuardForwardingTransaction{}
	if err := activateWireGuardAfterBackendPreflight(
		"nftables", wireGuardNFTExpectation{Identity: identity}, baseline, forwarding,
	); err != nil {
		t.Fatal(err)
	}
	if locked || nftAttestations != 2 || !state.ready() || !forwarding.applied {
		t.Fatalf("post-activation truth: locked=%v nft=%d state=%#v forwarding=%v", locked, nftAttestations, state, forwarding.applied)
	}
}

type testWireGuardForwardingTransaction struct{ applied bool }

func (transaction *testWireGuardForwardingTransaction) Apply() error {
	transaction.applied = true
	return nil
}
func (*testWireGuardForwardingTransaction) Restore() error { return nil }
func (*testWireGuardForwardingTransaction) Close() error   { return nil }

func testWireGuardKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func validWireGuardRenderInput() wireGuardRenderInput {
	return wireGuardRenderInput{
		Subnet:         "10.66.0.0/16",
		Port:           "51820",
		Backend:        "nftables",
		NFTPath:        "/usr/sbin/nft",
		TruePath:       "/usr/bin/true",
		OwnershipToken: strings.Repeat("a", 64),
		ActiveIf:       "ens3.100",
		EndpointIP:     "2001:db8::10",
		ServerPriv:     testWireGuardKey(1),
		ServerPub:      testWireGuardKey(2),
		ClientPriv:     testWireGuardKey(3),
		ClientPub:      testWireGuardKey(4),
		PresharedKey:   testWireGuardKey(5),
	}
}

func TestWireGuardRendererUsesValidatedContextValues_SW_CFG_002(t *testing.T) {
	server, client, err := renderWireGuardConfigurations(validWireGuardRenderInput())
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"Address = 10.66.0.1/16",
		"AllowedIPs = 10.66.0.2/32",
		`oifname "ens3.100" masquerade`,
	} {
		if !strings.Contains(server, fragment) {
			t.Fatalf("server configuration missing %q:\n%s", fragment, server)
		}
	}
	for _, fragment := range []string{
		"Address = 10.66.0.2/16",
		"Endpoint = [2001:db8::10]:51820",
	} {
		if !strings.Contains(client, fragment) {
			t.Fatalf("client configuration missing %q:\n%s", fragment, client)
		}
	}
}

func TestWireGuardKeepRefusesUnmanagedFrontendMutation_SW_FW_004(t *testing.T) {
	input := validWireGuardRenderInput()
	input.Backend = "keep"
	if _, _, err := renderWireGuardConfigurations(input); err == nil || !strings.Contains(err.Error(), "explicit nftables backend") {
		t.Fatalf("keep mode result = %v, want an explicit non-mutation refusal", err)
	}
}

func TestWireGuardNftablesRulesStayInReservedTable_SW_FW_004(t *testing.T) {
	server, _, err := renderWireGuardConfigurations(validWireGuardRenderInput())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(server, "table inet filter") || strings.Contains(server, "inet filter forward") {
		t.Fatalf("nftables mode emitted rules outside the reserved syswarden_wg table:\n%s", server)
	}
	if !strings.Contains(server, `add chain inet syswarden_wg forward`) ||
		!strings.Contains(server, `PostDown = /usr/bin/true`) || strings.Contains(server, `delete table inet syswarden_wg`) {
		t.Fatalf("nftables mode does not keep all WireGuard rules in the removable reserved table:\n%s", server)
	}
}

func TestWireGuardRejectsNonOperationalIptablesMode_SW_FW_004(t *testing.T) {
	input := validWireGuardRenderInput()
	input.Backend = "iptables"
	if _, _, err := renderWireGuardConfigurations(input); err == nil || !strings.Contains(err.Error(), "not an operational") {
		t.Fatalf("iptables mode result = %v, want an explicit refusal", err)
	}
}

func TestWireGuardRendererRejectsContextInjection_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*wireGuardRenderInput)
	}{
		{name: "interface breakout", mutate: func(value *wireGuardRenderInput) { value.ActiveIf = "eth0\"; touch /tmp/x" }},
		{name: "nft path breakout", mutate: func(value *wireGuardRenderInput) { value.NFTPath = "/usr/sbin/nft;touch" }},
		{name: "true path breakout", mutate: func(value *wireGuardRenderInput) { value.TruePath = "/usr/bin/true;touch" }},
		{name: "ownership token", mutate: func(value *wireGuardRenderInput) { value.OwnershipToken = strings.Repeat("g", 64) }},
		{name: "subnet command", mutate: func(value *wireGuardRenderInput) { value.Subnet = "10.66.0.0/16;touch" }},
		{name: "IPv6 subnet", mutate: func(value *wireGuardRenderInput) { value.Subnet = "2001:db8::/64" }},
		{name: "subnet too small", mutate: func(value *wireGuardRenderInput) { value.Subnet = "10.66.0.0/31" }},
		{name: "port breakout", mutate: func(value *wireGuardRenderInput) { value.Port = "51820\nPostUp = evil" }},
		{name: "endpoint breakout", mutate: func(value *wireGuardRenderInput) { value.EndpointIP = "192.0.2.1\nPostUp = evil" }},
		{name: "key breakout", mutate: func(value *wireGuardRenderInput) { value.ClientPub += "\nPostUp = evil" }},
		{name: "unknown backend", mutate: func(value *wireGuardRenderInput) { value.Backend = "firewalld;touch" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validWireGuardRenderInput()
			test.mutate(&input)
			if _, _, err := renderWireGuardConfigurations(input); err == nil {
				t.Fatal("WireGuard renderer accepted an injection or unsupported value")
			}
		})
	}
}

func TestWireGuardRetainedFDHelper(t *testing.T) {
	helper := false
	grandchildMarker := ""
	for _, argument := range os.Args {
		if argument == "--wireguard-retained-fd-helper" {
			helper = true
		}
		if strings.HasPrefix(argument, "--wireguard-retained-grandchild=") {
			grandchildMarker = strings.TrimPrefix(argument, "--wireguard-retained-grandchild=")
		}
	}
	if grandchildMarker != "" {
		time.Sleep(4 * time.Second)
		if err := os.WriteFile(grandchildMarker, []byte("survived\n"), 0600); err != nil { // #nosec G703 -- marker is an absolute path created beneath the private helper test root
			os.Exit(2)
		}
		os.Exit(0)
	}
	if !helper {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := ""
	for _, argument := range os.Args {
		if strings.HasPrefix(argument, "--wireguard-retained-marker=") {
			marker = strings.TrimPrefix(argument, "--wireguard-retained-marker=")
		}
	}
	if marker == "" || !filepath.IsAbs(marker) {
		t.Fatal("retained descriptor helper marker is invalid")
	}
	child := exec.Command( // #nosec G204 G702 -- current test executable, fixed helper selector and private absolute marker
		executable,
		"-test.run=^TestWireGuardRetainedFDHelper$", "--",
		"--wireguard-retained-grandchild="+marker,
	)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
}

func TestWireGuardCommandWaitDelayBoundsChildRetainedDescriptors_SW2_WGSTATE_001(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	previousResolver := wireGuardExecutableResolver
	previousCapture := wireGuardExecutableIdentityCapture
	wireGuardExecutableResolver = func(name string) (string, error) {
		if name != "retained-fd-helper" {
			return "", fmt.Errorf("unexpected helper command %s", name)
		}
		return executable, nil
	}
	wireGuardExecutableIdentityCapture = func(path string) (wireGuardExecutableIdentity, error) {
		return captureWireGuardExecutableIdentityForOwner(path, networkTestUID(t), false)
	}
	t.Cleanup(func() {
		wireGuardExecutableResolver = previousResolver
		wireGuardExecutableIdentityCapture = previousCapture
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	marker := filepath.Join(t.TempDir(), "grandchild-survived")
	started := time.Now()
	_, err = runBoundedWireGuardCommandContext(ctx, "retained-fd-helper", []string{
		"-test.run=^TestWireGuardRetainedFDHelper$", "--",
		"--wireguard-retained-fd-helper", "--wireguard-retained-marker=" + marker,
	}, "", 1024)
	if err == nil || !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("retained descriptor was not bounded by WaitDelay: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("retained descriptor cleanup took %s", elapsed)
	}
	time.Sleep(3 * time.Second)
	if _, statErr := os.Lstat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("retained descriptor child survived process-group cleanup: %v", statErr)
	}
}

func TestWireGuardCommandReattestsExecutableIdentityImmediatelyBeforeStart_SW2_WGSTATE_001(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("streaming-%v", streaming), func(t *testing.T) {
			directory := t.TempDir()
			executable := filepath.Join(directory, "wireguard-helper")
			backup := executable + ".original"
			marker := filepath.Join(directory, "replacement-ran")
			original := []byte("#!/bin/sh\nexit 0\n")
			replacement := []byte("#!/bin/sh\nprintf replaced > '" + marker + "'\n")
			if err := os.WriteFile(executable, original, 0700); err != nil { // #nosec G306 -- owner-only executable is an isolated test fixture
				t.Fatal(err)
			}
			previousResolver := wireGuardExecutableResolver
			previousCapture := wireGuardExecutableIdentityCapture
			previousPreStart := wireGuardExecutablePreStartAttestor
			wireGuardExecutableResolver = func(name string) (string, error) {
				if name != "identity-swap-helper" {
					return "", fmt.Errorf("unexpected helper command %s", name)
				}
				return executable, nil
			}
			wireGuardExecutableIdentityCapture = func(path string) (wireGuardExecutableIdentity, error) {
				return captureWireGuardExecutableIdentityForOwner(path, networkTestUID(t), false)
			}
			swapped := false
			wireGuardExecutablePreStartAttestor = func(identity wireGuardExecutableIdentity) error {
				if err := os.Rename(executable, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(executable, replacement, 0700); err != nil { // #nosec G306 -- owner-only replacement is an isolated adversarial fixture
					t.Fatal(err)
				}
				swapped = true
				return previousPreStart(identity)
			}
			t.Cleanup(func() {
				wireGuardExecutableResolver = previousResolver
				wireGuardExecutableIdentityCapture = previousCapture
				wireGuardExecutablePreStartAttestor = previousPreStart
			})

			var err error
			if streaming {
				stdout, openErr := os.OpenFile(filepath.Join(directory, "stdout"), os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- fixed output name is beneath the private test root
				if openErr != nil {
					t.Fatal(openErr)
				}
				err = runWireGuardStreamingCommand("identity-swap-helper", nil, "", stdout, time.Second)
				if closeErr := stdout.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			} else {
				_, err = runBoundedWireGuardCommand(
					"identity-swap-helper", nil, "", 1024, time.Second,
				)
			}
			if err == nil || !strings.Contains(err.Error(), "changed identity before start") || !swapped {
				t.Fatalf("executable swap result: swapped=%v err=%v", swapped, err)
			}
			if _, statErr := os.Lstat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("replacement executable ran despite failed attestation: %v", statErr)
			}
			content, readErr := os.ReadFile(backup) // #nosec G304 -- backup is a fixed path beneath the private test root
			if readErr != nil || !bytes.Equal(content, original) {
				t.Fatalf("original executable identity was not preserved: bytes=%q err=%v", content, readErr)
			}
		})
	}
}

func TestWireGuardExecutableCaptureRejectsNonRootBaseline_SW2_WGSTATE_001(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root ownership proof requires an unprivileged test process")
	}
	path := filepath.Join(t.TempDir(), "untrusted-helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil { // #nosec G306 -- owner-only executable is an isolated untrusted fixture
		t.Fatal(err)
	}
	if _, err := captureWireGuardExecutableIdentityForOwner(path, 0, false); err == nil ||
		!strings.Contains(err.Error(), "unsafe identity") {
		t.Fatalf("non-root executable was captured as trusted: %v", err)
	}
}

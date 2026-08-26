//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"syswarden-cli/pkg/wireguardstate"
)

type fakeFirewallRemovalExitError int

func (err fakeFirewallRemovalExitError) Error() string {
	return fmt.Sprintf("exit status %d", int(err))
}

func (err fakeFirewallRemovalExitError) ExitCode() int {
	return int(err)
}

func exactRemovalWireGuardServerFixture() []byte {
	key := strings.Repeat("A", 43) + "="
	token := strings.Repeat("a", 64)
	postUp := fmt.Sprintf(`/usr/sbin/nft 'create table inet syswarden_wg { comment \"syswarden-wg-v1:%s\"; }; add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }; add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }; add chain inet syswarden_wg forward { type filter hook forward priority 0; policy accept; }; add rule inet syswarden_wg postrouting oifname \"ens3\" masquerade; add rule inet syswarden_wg forward iifname \"wg-syswarden\" accept; add rule inet syswarden_wg forward oifname \"wg-syswarden\" accept'`, token)
	postUp = strings.ReplaceAll(postUp, `\`, "")
	return []byte(strings.Join([]string{
		"[Interface]",
		"Address = 10.66.0.1/16",
		"ListenPort = 51820",
		"PrivateKey = " + key,
		"PostUp = " + postUp,
		"PostDown = /usr/bin/true",
		"",
		"[Peer]",
		"PublicKey = " + key,
		"PresharedKey = " + key,
		"AllowedIPs = 10.66.0.2/32",
		"",
	}, "\n"))
}

func TestWireGuardStopReattestsConfigurationHookExecutables_SW2_WGSTATE_001(t *testing.T) {
	previousReader := readWireGuardServerBeforeRemovalStop
	previousAttestor := attestWireGuardStopHookExecutables
	t.Cleanup(func() {
		readWireGuardServerBeforeRemovalStop = previousReader
		attestWireGuardStopHookExecutables = previousAttestor
	})

	readWireGuardServerBeforeRemovalStop = func() ([]byte, error) {
		server := exactRemovalWireGuardServerFixture()
		if !strings.Contains(string(server), `comment "syswarden-wg-v1:`) {
			t.Fatalf("WireGuard server fixture lacks ownership token marker: %q", server)
		}
		return server, nil
	}
	called := false
	attestWireGuardStopHookExecutables = func(identity wireguardstate.ServerConfigurationIdentity) error {
		called = true
		if identity.NFTPath != "/usr/sbin/nft" || identity.TruePath != "/usr/bin/true" || identity.ActiveInterface != "ens3" {
			return fmt.Errorf("unexpected hook identity %#v", identity)
		}
		return nil
	}
	if err := verifyWireGuardServerBeforeRemovalStop(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("WireGuard stop hook executable attestor was not called")
	}

	sentinel := errors.New("hook executable replaced")
	attestWireGuardStopHookExecutables = func(wireguardstate.ServerConfigurationIdentity) error {
		return sentinel
	}
	if err := verifyWireGuardServerBeforeRemovalStop(); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("WireGuard stop hook replacement error = %v", err)
	}
}

type fakeFirewallRemovalServiceState struct {
	loaded                        bool
	active                        bool
	enabled                       bool
	runtimeEnabled                bool
	runlevels                     []string
	loadStateOverride             string
	activeStateOverride           string
	unitFileStateOverride         string
	fragmentPathOverride          string
	dropInPathsOverride           string
	execStartOverride             string
	execStopOverride              string
	openRCInactiveStatus          int
	stopped                       bool
	restartAfterFirstVerification bool
	verificationQueries           int
}

type fakeFirewallRemovalManager struct {
	alpine              bool
	states              map[string]*fakeFirewallRemovalServiceState
	calls               []string
	stopErrors          map[string]error
	disableErrors       map[string]error
	wireGuardConfigPath string
}

func fakeSystemdRemovalExecution(path string, arguments string) string {
	return fmt.Sprintf(
		"{ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		path, arguments,
	)
}

func (manager *fakeFirewallRemovalManager) output(path string, arguments ...string) ([]byte, error) {
	call := filepath.Base(path) + " " + strings.Join(arguments, " ")
	manager.calls = append(manager.calls, strings.TrimSpace(call))
	if manager.alpine {
		if filepath.Base(path) == "wg-quick" {
			if !reflect.DeepEqual(arguments, []string{"down", "wg-syswarden"}) {
				return nil, fmt.Errorf("unexpected wg-quick arguments %q", arguments)
			}
			if err := manager.stopErrors["wg-quick.wg-syswarden"]; err != nil {
				return nil, err
			}
			manager.states["wg-quick.wg-syswarden"].active = false
			manager.states["wg-quick.wg-syswarden"].stopped = true
			return nil, nil
		}
		return manager.openRCOutput(filepath.Base(path), arguments...)
	}
	return manager.systemdOutput(arguments...)
}

func (manager *fakeFirewallRemovalManager) systemdOutput(arguments ...string) ([]byte, error) {
	if len(arguments) == 4 && arguments[0] == "show" && arguments[2] == "--value" {
		state := manager.states[arguments[3]]
		if state == nil {
			state = &fakeFirewallRemovalServiceState{}
		}
		property := strings.TrimPrefix(arguments[1], "--property=")
		switch property {
		case "LoadState":
			if state.loadStateOverride != "" {
				return []byte(state.loadStateOverride + "\n"), nil
			}
			if state.loaded {
				return []byte("loaded\n"), nil
			}
			return []byte("not-found\n"), nil
		case "ActiveState":
			if state.activeStateOverride != "" {
				return []byte(state.activeStateOverride + "\n"), nil
			}
			if state.active {
				return []byte("active\n"), nil
			}
			if state.stopped && state.restartAfterFirstVerification {
				state.verificationQueries++
				if state.verificationQueries == 1 {
					state.active = true
					return []byte("inactive\n"), nil
				}
			}
			return []byte("inactive\n"), nil
		case "UnitFileState":
			if state.unitFileStateOverride != "" {
				return []byte(state.unitFileStateOverride + "\n"), nil
			}
			if state.enabled {
				if state.runtimeEnabled {
					return []byte("enabled-runtime\n"), nil
				}
				return []byte("enabled\n"), nil
			}
			return []byte("disabled\n"), nil
		case "FragmentPath":
			if state.fragmentPathOverride != "" {
				return []byte(state.fragmentPathOverride + "\n"), nil
			}
			switch arguments[3] {
			case "syswarden-core.service", "syswarden-firewall.service":
				return []byte("/etc/systemd/system/" + arguments[3] + "\n"), nil
			case "wg-quick@wg-syswarden.service":
				return []byte("/usr/lib/systemd/system/wg-quick@.service\n"), nil
			default:
				return nil, fmt.Errorf("unexpected fragment query for %s", arguments[3])
			}
		case "DropInPaths":
			return []byte(state.dropInPathsOverride + "\n"), nil
		case "ExecStart":
			if state.execStartOverride != "" {
				return []byte(state.execStartOverride + "\n"), nil
			}
			path := "/opt/syswarden/bin/syswarden-core"
			argv := path
			switch arguments[3] {
			case "syswarden-firewall.service":
				path = "/opt/syswarden/bin/syswarden-cli"
				argv = path + " reload --no-restart"
			case "wg-quick@wg-syswarden.service":
				path = "/usr/bin/wg-quick"
				argv = path + " up wg-syswarden"
			}
			return []byte(fakeSystemdRemovalExecution(path, argv) + "\n"), nil
		case "ExecStop":
			if state.execStopOverride != "" {
				return []byte(state.execStopOverride + "\n"), nil
			}
			if arguments[3] == "wg-quick@wg-syswarden.service" {
				path := "/usr/bin/wg-quick"
				return []byte(fakeSystemdRemovalExecution(path, path+" down wg-syswarden") + "\n"), nil
			}
			return []byte("\n"), nil
		default:
			return nil, fmt.Errorf("unexpected systemd property %q", property)
		}
	}
	if len(arguments) == 2 && arguments[0] == "disable" {
		unit := arguments[1]
		if err := manager.disableErrors[unit]; err != nil {
			return nil, err
		}
		manager.states[unit].enabled = false
		return nil, nil
	}
	if len(arguments) == 3 && arguments[0] == "disable" && arguments[1] == "--runtime" {
		unit := arguments[2]
		if err := manager.disableErrors[unit]; err != nil {
			return nil, err
		}
		manager.states[unit].enabled = false
		manager.states[unit].runtimeEnabled = false
		return nil, nil
	}
	if len(arguments) == 2 && arguments[0] == "stop" {
		unit := arguments[1]
		if err := manager.stopErrors[unit]; err != nil {
			return nil, err
		}
		manager.states[unit].active = false
		manager.states[unit].stopped = true
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected systemd arguments %q", arguments)
}

func (manager *fakeFirewallRemovalManager) openRCOutput(executable string, arguments ...string) ([]byte, error) {
	if executable == "rc-update" {
		if len(arguments) == 1 && arguments[0] == "show" {
			var output strings.Builder
			for _, service := range []string{
				"syswarden-core", "syswarden-firewall", "syswarden", "syswarden-reporter", "wg-quick.wg-syswarden",
			} {
				state := manager.states[service]
				if state == nil || len(state.runlevels) == 0 {
					continue
				}
				fmt.Fprintf(&output, " %26s | %s\n", service, strings.Join(state.runlevels, " "))
			}
			return []byte(output.String()), nil
		}
		if len(arguments) == 3 && arguments[0] == "del" {
			service := arguments[1]
			if err := manager.disableErrors[service]; err != nil {
				return nil, err
			}
			state := manager.states[service]
			if state == nil {
				return nil, fmt.Errorf("unexpected OpenRC disable target %q", arguments)
			}
			index := -1
			for candidate, runlevel := range state.runlevels {
				if runlevel == arguments[2] {
					index = candidate
					break
				}
			}
			if index < 0 {
				return nil, fmt.Errorf("unexpected OpenRC disable target %q", arguments)
			}
			state.runlevels = append(state.runlevels[:index], state.runlevels[index+1:]...)
			state.enabled = len(state.runlevels) != 0
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected rc-update arguments %q", arguments)
	}
	if executable != "rc-service" {
		return nil, fmt.Errorf("unexpected OpenRC executable %q", executable)
	}
	if len(arguments) == 2 && arguments[0] == "--exists" {
		state := manager.states[arguments[1]]
		if state == nil || !state.loaded {
			return nil, fakeFirewallRemovalExitError(1)
		}
		return nil, nil
	}
	if len(arguments) == 2 && arguments[1] == "status" {
		state := manager.states[arguments[0]]
		if state.active {
			return []byte("status: started\n"), nil
		}
		code := state.openRCInactiveStatus
		if code == 0 {
			code = 3
		}
		return []byte("status: stopped\n"), fakeFirewallRemovalExitError(code)
	}
	if len(arguments) == 2 && arguments[1] == "stop" {
		service := arguments[0]
		if err := manager.stopErrors[service]; err != nil {
			return nil, err
		}
		manager.states[service].active = false
		manager.states[service].stopped = true
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected rc-service arguments %q", arguments)
}

func (manager *fakeFirewallRemovalManager) mutationCalls() []string {
	mutations := make([]string, 0)
	for _, call := range manager.calls {
		if strings.Contains(call, " disable ") || strings.Contains(call, " stop ") ||
			strings.HasSuffix(call, " stop") || strings.Contains(call, " del ") || strings.HasPrefix(call, "wg-quick down ") {
			mutations = append(mutations, call)
		}
	}
	return mutations
}

func newFirewallRemovalTestHost(
	t *testing.T,
	manager *fakeFirewallRemovalManager,
	configPresent bool,
) firewallRemovalPreparationHost {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string)
	for _, name := range []string{"systemctl", "rc-service", "rc-update", "wg-quick"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("test executable\n"), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for isolated command fixtures
			t.Fatal(err)
		}
		paths[name] = path
	}
	configPath := filepath.Join(directory, "wg-syswarden.conf")
	if configPresent {
		if err := os.WriteFile(configPath, []byte("[Interface]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	manager.wireGuardConfigPath = configPath
	return firewallRemovalPreparationHost{
		effectiveUID: 0,
		alpine:       manager.alpine,
		classifyRuntime: func(alpine bool) (serviceManagerState, error) {
			if alpine != manager.alpine {
				return serviceManagerAmbiguous, fmt.Errorf("unexpected platform")
			}
			return serviceManagerActive, nil
		},
		executor: firewallManagerExecutor{
			lookPath: func(name string) (string, error) {
				path, ok := paths[name]
				if !ok {
					return "", fmt.Errorf("unexpected executable %q", name)
				}
				return path, nil
			},
			validate: func(string) error { return nil },
			output:   manager.output,
		},
		processScan:         func() error { return nil },
		postStopProcessScan: func() error { return nil },
		attestWireGuard: func() (firewallRemovalWireGuardEvidence, error) {
			return firewallRemovalWireGuardEvidence{present: configPresent}, nil
		},
		verifyWireGuardStopConfig: func() error { return nil },
		resolveWireGuardExe:       func() (string, error) { return paths["wg-quick"], nil },
		wireGuardInterface: func() (bool, error) {
			name := "wg-quick@wg-syswarden.service"
			if manager.alpine {
				name = "wg-quick.wg-syswarden"
			}
			state := manager.states[name]
			return state != nil && state.active, nil
		},
		attestSystemdUnit: func(string) error { return nil },
		attestSystemdDropIns: func(_ firewallManagerExecutor, dropIns string) (string, error) {
			if dropIns != "" {
				return "", errors.New("unapproved systemd service drop-in")
			}
			return "", nil
		},
		attestOpenRCUnit: func(firewallRemovalService) error { return nil },
		openRCUnitPresent: func(service firewallRemovalService) (bool, error) {
			name := openRCFirewallRemovalServiceName(service)
			state := manager.states[name]
			return state != nil && state.loaded, nil
		},
		attestOpenRCRunlevel: func(service firewallRemovalService, runlevel string) error {
			state := manager.states[openRCFirewallRemovalServiceName(service)]
			for _, current := range state.runlevels {
				if current == runlevel {
					return nil
				}
			}
			return fmt.Errorf("runlevel %s is not enabled", runlevel)
		},
		verifyOpenRCRunlevelAbsent: func(service firewallRemovalService, runlevel string) error {
			state := manager.states[openRCFirewallRemovalServiceName(service)]
			for _, current := range state.runlevels {
				if current == runlevel {
					return fmt.Errorf("runlevel %s remains enabled", runlevel)
				}
			}
			return nil
		},
	}
}

func TestOfflinePackageRemovalUsesBarrierScansWithoutManagerCalls_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{states: map[string]*fakeFirewallRemovalServiceState{}}
	host := newFirewallRemovalTestHost(t, manager, false)
	host.classifyRuntime = func(bool) (serviceManagerState, error) {
		return serviceManagerOffline, nil
	}
	scans := 0
	host.processScan = func() error {
		scans++
		return nil
	}
	host.postStopProcessScan = host.processScan
	managerCalls := 0
	host.executor.output = func(string, ...string) ([]byte, error) {
		managerCalls++
		return nil, errors.New("offline manager invocation")
	}
	if err := host.prepare(); err != nil {
		t.Fatalf("offline preparation: %v", err)
	}
	if scans != 2 || managerCalls != 0 {
		t.Fatalf("offline preparation scans=%d manager-calls=%d", scans, managerCalls)
	}
	if err := host.reattest(); err != nil {
		t.Fatalf("offline reattestation: %v", err)
	}
	if scans != 3 || managerCalls != 0 {
		t.Fatalf("offline reattestation scans=%d manager-calls=%d", scans, managerCalls)
	}
}

func TestOfflinePackageRemovalRefusesActiveWireGuardInterface_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{states: map[string]*fakeFirewallRemovalServiceState{
		"wg-quick@wg-syswarden.service": {active: true},
	}}
	host := newFirewallRemovalTestHost(t, manager, true)
	host.classifyRuntime = func(bool) (serviceManagerState, error) {
		return serviceManagerOffline, nil
	}
	err := host.prepare()
	if err == nil || !strings.Contains(err.Error(), "offline package removal cannot stop") {
		t.Fatalf("active offline WireGuard interface = %v", err)
	}
}

func TestFirewallRemovalWireGuardInventoryFailsClosedOnResidualAndTransactionState_SW2_FWBACKEND_001(t *testing.T) {
	tests := []struct {
		name      string
		inventory wireguardstate.Inventory
		verifyErr error
		want      string
	}{
		{
			name: "client residual without server or manifest",
			inventory: wireguardstate.Inventory{
				Artifacts: []string{wireguardstate.ClientConfigurationPath},
			},
			verifyErr: errors.New("ownership manifest is absent"),
			want:      "ownership manifest is absent",
		},
		{
			name:      "pending transaction",
			inventory: wireguardstate.Inventory{Transaction: true},
			want:      "transaction is pending",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifyCalls := 0
			_, err := attestFirewallRemovalWireGuardStateWith(
				func() (wireguardstate.Inventory, error) { return test.inventory, nil },
				func() (wireguardstate.Manifest, error) {
					verifyCalls++
					return wireguardstate.Manifest{}, test.verifyErr
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("WireGuard residual state result = %v, want %q", err, test.want)
			}
			if test.inventory.Transaction && verifyCalls != 0 {
				t.Fatalf("transaction state reached manifest verification %d times", verifyCalls)
			}
		})
	}
}

func TestFirewallRemovalWireGuardInventoryRequiresStableVerifiedState_SW2_FWBACKEND_001(t *testing.T) {
	inventory := wireguardstate.Inventory{
		Manifest:  true,
		Artifacts: wireguardstate.ArtifactPaths(),
	}
	manifest := wireguardstate.Manifest{Artifacts: []wireguardstate.Artifact{{Path: wireguardstate.ServerConfigurationPath}}}
	evidence, err := attestFirewallRemovalWireGuardStateWith(
		func() (wireguardstate.Inventory, error) { return inventory, nil },
		func() (wireguardstate.Manifest, error) { return manifest, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.present || !sameFirewallRemovalWireGuardEvidence(evidence, firewallRemovalWireGuardEvidence{
		present: true, inventory: inventory, manifest: manifest,
	}) {
		t.Fatalf("verified WireGuard evidence = %#v", evidence)
	}

	inspection := 0
	_, err = attestFirewallRemovalWireGuardStateWith(
		func() (wireguardstate.Inventory, error) {
			inspection++
			if inspection == 1 {
				return inventory, nil
			}
			return wireguardstate.Inventory{Manifest: true}, nil
		},
		func() (wireguardstate.Manifest, error) { return manifest, nil },
	)
	if err == nil || !strings.Contains(err.Error(), "changed during attestation") {
		t.Fatalf("WireGuard inventory drift result = %v", err)
	}
}

func TestFirewallRemovalWireGuardRemovalDebtIsOperationAware_SW2_FWBACKEND_001(t *testing.T) {
	inventory := wireguardstate.Inventory{Transaction: true}
	verifyCalls := 0
	transactionCalls := 0
	evidence, err := attestFirewallRemovalWireGuardStateOperationAwareWith(
		func() (wireguardstate.TransactionOperation, bool, error) {
			transactionCalls++
			return wireguardstate.TransactionOperationRemovePendingReload, true, nil
		},
		func() (wireguardstate.Inventory, error) { return inventory, nil },
		func() (wireguardstate.Manifest, error) {
			verifyCalls++
			return wireguardstate.Manifest{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.present || !evidence.transactionPending ||
		evidence.transactionOperation != wireguardstate.TransactionOperationRemovePendingReload {
		t.Fatalf("removal-debt evidence = %#v", evidence)
	}
	if transactionCalls != 2 || verifyCalls != 0 {
		t.Fatalf("transaction calls = %d, manifest verification calls = %d", transactionCalls, verifyCalls)
	}

	for _, operation := range []wireguardstate.TransactionOperation{
		wireguardstate.TransactionOperationPublish,
		wireguardstate.TransactionOperationRemove,
		wireguardstate.TransactionOperationNone,
	} {
		t.Run(string(operation), func(t *testing.T) {
			_, err := attestFirewallRemovalWireGuardStateOperationAwareWith(
				func() (wireguardstate.TransactionOperation, bool, error) { return operation, true, nil },
				func() (wireguardstate.Inventory, error) { return inventory, nil },
				func() (wireguardstate.Manifest, error) {
					t.Fatal("ambiguous transaction reached manifest verification")
					return wireguardstate.Manifest{}, nil
				},
			)
			if err == nil {
				t.Fatalf("transaction operation %q was accepted", operation)
			}
		})
	}

	transactionCalls = 0
	_, err = attestFirewallRemovalWireGuardStateOperationAwareWith(
		func() (wireguardstate.TransactionOperation, bool, error) {
			transactionCalls++
			if transactionCalls == 1 {
				return wireguardstate.TransactionOperationRemovePendingReload, true, nil
			}
			return wireguardstate.TransactionOperationNone, false, nil
		},
		func() (wireguardstate.Inventory, error) { return inventory, nil },
		func() (wireguardstate.Manifest, error) { return wireguardstate.Manifest{}, nil },
	)
	if err == nil || !strings.Contains(err.Error(), "changed during state attestation") {
		t.Fatalf("removal transaction drift = %v", err)
	}
}

func defaultSystemdFirewallRemovalStates() map[string]*fakeFirewallRemovalServiceState {
	return map[string]*fakeFirewallRemovalServiceState{
		"syswarden-core.service":        {loaded: true, active: true, enabled: true},
		"syswarden-firewall.service":    {loaded: true, enabled: true},
		"syswarden.service":             {},
		"syswarden-reporter.service":    {},
		"wg-quick@wg-syswarden.service": {loaded: true, active: true, enabled: true},
	}
}

func defaultOpenRCFirewallRemovalStates() map[string]*fakeFirewallRemovalServiceState {
	return map[string]*fakeFirewallRemovalServiceState{
		"syswarden-core":        {loaded: true, active: true, runlevels: []string{"default"}},
		"syswarden-firewall":    {loaded: true, runlevels: []string{"boot", "default"}},
		"syswarden":             {},
		"syswarden-reporter":    {},
		"wg-quick.wg-syswarden": {loaded: true, active: true, runlevels: []string{"default"}},
	}
}

func TestPrepareFirewallStateForRemovalSystemdStopsDisablesAndReattests_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{states: defaultSystemdFirewallRemovalStates()}
	host := newFirewallRemovalTestHost(t, manager, true)
	if err := host.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := host.reattest(); err != nil {
		t.Fatal(err)
	}

	wantMutations := []string{
		"systemctl disable syswarden-core.service",
		"systemctl disable syswarden-firewall.service",
		"systemctl disable wg-quick@wg-syswarden.service",
		"systemctl stop syswarden-core.service",
		"systemctl stop wg-quick@wg-syswarden.service",
	}
	if got := manager.mutationCalls(); !reflect.DeepEqual(got, wantMutations) {
		t.Fatalf("mutation calls = %#v, want %#v", got, wantMutations)
	}
	for unit, state := range manager.states {
		if !state.loaded {
			continue
		}
		if state.active || state.enabled {
			t.Fatalf("prepared unit %s remains active=%t enabled=%t", unit, state.active, state.enabled)
		}
	}
	if _, err := os.Stat(manager.wireGuardConfigPath); err != nil {
		t.Fatalf("preparation changed WireGuard configuration: %v", err)
	}
}

func TestPrepareFirewallStateForRemovalAcceptsOnlyAttestedVendorSystemdDropIns_SW2_FWBACKEND_001(t *testing.T) {
	states := defaultSystemdFirewallRemovalStates()
	for _, unit := range []string{
		"syswarden-core.service",
		"syswarden-firewall.service",
		"wg-quick@wg-syswarden.service",
	} {
		states[unit].dropInPathsOverride = approvedSystemdServiceDropInPath
	}
	manager := &fakeFirewallRemovalManager{states: states}
	host := newFirewallRemovalTestHost(t, manager, true)
	attestations := 0
	host.attestSystemdDropIns = func(_ firewallManagerExecutor, dropIns string) (string, error) {
		attestations++
		if dropIns != approvedSystemdServiceDropInPath {
			return "", errors.New("unexpected systemd service drop-in")
		}
		return dropIns + "#exact-vendor-provenance", nil
	}
	if err := host.prepare(); err != nil {
		t.Fatal(err)
	}
	if attestations != 10 {
		t.Fatalf("vendor drop-in attestations = %d, want 10", attestations)
	}
	if got := manager.mutationCalls(); len(got) == 0 {
		t.Fatal("approved vendor drop-in prevented the verified removal mutations")
	}
}

func TestPrepareFirewallStateForRemovalSkipsAbsentAndInactiveDisabledSystemdUnits_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{states: map[string]*fakeFirewallRemovalServiceState{
		"syswarden-core.service":        {loaded: true},
		"syswarden-firewall.service":    {},
		"syswarden.service":             {},
		"syswarden-reporter.service":    {},
		"wg-quick@wg-syswarden.service": {loaded: true},
	}}
	host := newFirewallRemovalTestHost(t, manager, false)
	if err := host.prepare(); err != nil {
		t.Fatal(err)
	}
	if got := manager.mutationCalls(); len(got) != 0 {
		t.Fatalf("safe absent/inactive state caused mutations: %#v", got)
	}
}

func TestPrepareFirewallStateForRemovalDisablesRuntimeSystemdEnablement_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{states: map[string]*fakeFirewallRemovalServiceState{
		"syswarden-core.service":        {loaded: true, enabled: true, runtimeEnabled: true},
		"syswarden-firewall.service":    {},
		"syswarden.service":             {},
		"syswarden-reporter.service":    {},
		"wg-quick@wg-syswarden.service": {},
	}}
	host := newFirewallRemovalTestHost(t, manager, false)
	if err := host.prepare(); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl disable --runtime syswarden-core.service"}
	if got := manager.mutationCalls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime disable calls = %#v, want %#v", got, want)
	}
}

func TestPrepareFirewallStateForRemovalReportsRecoverablePartialDisableOnStopFailure_SW2_FWBACKEND_001(t *testing.T) {
	failure := errors.New("stop failed")
	manager := &fakeFirewallRemovalManager{
		states:     defaultSystemdFirewallRemovalStates(),
		stopErrors: map[string]error{"syswarden-core.service": failure},
	}
	host := newFirewallRemovalTestHost(t, manager, true)
	err := host.prepare()
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "may remain disabled") {
		t.Fatalf("stop failure = %v", err)
	}
	if manager.states["syswarden-core.service"].enabled {
		t.Fatal("successful pre-stop disable was not preserved as recoverable state")
	}
	if _, statErr := os.Stat(manager.wireGuardConfigPath); statErr != nil {
		t.Fatalf("stop failure removed WireGuard configuration: %v", statErr)
	}
}

func TestPrepareFirewallStateForRemovalDoesNotStopAfterDisableFailure_SW2_FWBACKEND_001(t *testing.T) {
	failure := errors.New("disable failed")
	manager := &fakeFirewallRemovalManager{
		states:        defaultSystemdFirewallRemovalStates(),
		disableErrors: map[string]error{"syswarden-core.service": failure},
	}
	host := newFirewallRemovalTestHost(t, manager, true)
	err := host.prepare()
	if !errors.Is(err, failure) {
		t.Fatalf("disable failure = %v", err)
	}
	for _, call := range manager.mutationCalls() {
		if strings.Contains(call, " stop ") {
			t.Fatalf("stop ran after disable failure: %s", call)
		}
	}
}

func TestPrepareFirewallStateForRemovalDetectsQueuedRestartDuringConfirmation_SW2_FWBACKEND_001(t *testing.T) {
	states := defaultSystemdFirewallRemovalStates()
	states["syswarden-core.service"].restartAfterFirstVerification = true
	manager := &fakeFirewallRemovalManager{states: states}
	host := newFirewallRemovalTestHost(t, manager, true)
	err := host.prepare()
	if err == nil || !strings.Contains(err.Error(), "still active") || !strings.Contains(err.Error(), "may remain disabled") {
		t.Fatalf("queued restart result = %v", err)
	}
}

func TestReattestFirewallStatePreparedForRemovalRejectsDrift_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{states: map[string]*fakeFirewallRemovalServiceState{
		"syswarden-core.service":        {loaded: true, active: true},
		"syswarden-firewall.service":    {loaded: true},
		"syswarden.service":             {},
		"syswarden-reporter.service":    {},
		"wg-quick@wg-syswarden.service": {},
	}}
	host := newFirewallRemovalTestHost(t, manager, false)
	err := host.reattest()
	if err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("active drift result = %v", err)
	}
	if got := manager.mutationCalls(); len(got) != 0 {
		t.Fatalf("read-only reattestation mutated services: %#v", got)
	}
}

func TestPrepareFirewallStateForRemovalRejectsUnmanagedWireGuardBeforeMutation_SW2_FWBACKEND_001(t *testing.T) {
	states := defaultSystemdFirewallRemovalStates()
	manager := &fakeFirewallRemovalManager{states: states}
	host := newFirewallRemovalTestHost(t, manager, false)
	err := host.prepare()
	if err == nil || !strings.Contains(err.Error(), "unmanaged WireGuard") {
		t.Fatalf("unmanaged WireGuard result = %v", err)
	}
	if got := manager.mutationCalls(); len(got) != 0 {
		t.Fatalf("unmanaged WireGuard caused partial mutations: %#v", got)
	}
}

func TestPrepareFirewallStateForRemovalRejectsUnsafeWireGuardConfiguration_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{states: defaultSystemdFirewallRemovalStates()}
	host := newFirewallRemovalTestHost(t, manager, false)
	host.attestWireGuard = func() (firewallRemovalWireGuardEvidence, error) {
		return firewallRemovalWireGuardEvidence{}, errors.New("unattested WireGuard state")
	}
	err := host.prepare()
	if err == nil || !strings.Contains(err.Error(), "unattested WireGuard") {
		t.Fatalf("unsafe WireGuard configuration result = %v", err)
	}
	if len(manager.calls) != 0 {
		t.Fatalf("manager was queried after unsafe configuration: %#v", manager.calls)
	}
}

func TestPrepareFirewallStateForRemovalReattestsWireGuardServerImmediatelyBeforeStop_SW2_FWBACKEND_001(t *testing.T) {
	tests := []struct {
		name   string
		alpine bool
	}{
		{name: "systemd", alpine: false},
		{name: "openrc", alpine: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			states := defaultSystemdFirewallRemovalStates()
			if test.alpine {
				states = defaultOpenRCFirewallRemovalStates()
			}
			manager := &fakeFirewallRemovalManager{alpine: test.alpine, states: states}
			host := newFirewallRemovalTestHost(t, manager, true)
			sentinel := errors.New("WireGuard server changed before stop")
			host.verifyWireGuardStopConfig = func() error { return sentinel }

			err := host.prepare()
			if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "verify WireGuard server configuration before stop") {
				t.Fatalf("pre-stop WireGuard attestation result = %v", err)
			}
			for _, call := range manager.mutationCalls() {
				if strings.Contains(call, "wg-quick") && (strings.Contains(call, " stop") || strings.Contains(call, " down ")) {
					t.Fatalf("WireGuard stop ran after failed immediate attestation: %s", call)
				}
			}
		})
	}
}

func TestPrepareFirewallStateForRemovalDetectsWireGuardSwapDuringUnitReattestation_SW2_FWBACKEND_001(t *testing.T) {
	tests := []struct {
		name   string
		alpine bool
	}{
		{name: "systemd", alpine: false},
		{name: "openrc", alpine: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			states := defaultSystemdFirewallRemovalStates()
			if test.alpine {
				states = defaultOpenRCFirewallRemovalStates()
			}
			manager := &fakeFirewallRemovalManager{alpine: test.alpine, states: states}
			host := newFirewallRemovalTestHost(t, manager, true)
			changed := false
			if test.alpine {
				wireGuardAttestations := 0
				host.attestOpenRCUnit = func(service firewallRemovalService) error {
					if service.wireGuard {
						wireGuardAttestations++
						if wireGuardAttestations == 3 {
							changed = true
						}
					}
					return nil
				}
			} else {
				wireGuardAttestations := 0
				host.attestSystemdUnit = func(path string) error {
					if strings.Contains(path, "wg-quick@.service") {
						wireGuardAttestations++
						if wireGuardAttestations == 2 {
							changed = true
						}
					}
					return nil
				}
			}
			sentinel := errors.New("WireGuard server changed during unit reattestation")
			host.verifyWireGuardStopConfig = func() error {
				if changed {
					return sentinel
				}
				return nil
			}

			err := host.prepare()
			if !errors.Is(err, sentinel) {
				t.Fatalf("configuration swap result = %v", err)
			}
			for _, call := range manager.mutationCalls() {
				if strings.Contains(call, "wg-quick") && (strings.Contains(call, " stop") || strings.Contains(call, " down ")) {
					t.Fatalf("WireGuard stop ran after configuration swap: %s", call)
				}
			}
		})
	}
}

func TestPrepareFirewallStateForRemovalAttestsUnitsAndWireGuardContentBeforeMutation_SW2_FWBACKEND_001(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*firewallRemovalPreparationHost, map[string]*fakeFirewallRemovalServiceState)
		want    string
	}{
		{
			name: "modified unit fragment",
			prepare: func(_ *firewallRemovalPreparationHost, states map[string]*fakeFirewallRemovalServiceState) {
				states["syswarden-core.service"].fragmentPathOverride = "/etc/systemd/system/operator.service"
			},
			want: "unexpected unit fragment",
		},
		{
			name: "modified native unit bytes",
			prepare: func(host *firewallRemovalPreparationHost, states map[string]*fakeFirewallRemovalServiceState) {
				states["syswarden-core.service"].active = false
				states["syswarden-core.service"].enabled = false
				host.attestSystemdUnit = func(path string) error {
					if path == "/etc/systemd/system/syswarden-core.service" {
						return errors.New("modified native unit bytes")
					}
					return nil
				}
			},
			want: "modified native unit bytes",
		},
		{
			name: "systemd drop-in",
			prepare: func(_ *firewallRemovalPreparationHost, states map[string]*fakeFirewallRemovalServiceState) {
				states["syswarden-firewall.service"].dropInPathsOverride = "/etc/systemd/system/syswarden-firewall.service.d/operator.conf"
			},
			want: "refusing unapproved systemd drop-ins",
		},
		{
			name: "unknown WireGuard ExecStop",
			prepare: func(_ *firewallRemovalPreparationHost, states map[string]*fakeFirewallRemovalServiceState) {
				states["wg-quick@wg-syswarden.service"].execStopOverride =
					"{ path=/bin/sh ; argv[]=/bin/sh -c operator ; ignore_errors=no }"
			},
			want: "unexpected ExecStop",
		},
		{
			name: "modified WireGuard unit bytes",
			prepare: func(host *firewallRemovalPreparationHost, _ map[string]*fakeFirewallRemovalServiceState) {
				host.attestSystemdUnit = func(path string) error {
					if strings.HasSuffix(path, "/wg-quick@.service") {
						return errors.New("modified WireGuard unit bytes")
					}
					return nil
				}
			},
			want: "modified WireGuard unit bytes",
		},
		{
			name: "unverified WireGuard PostDown",
			prepare: func(host *firewallRemovalPreparationHost, _ map[string]*fakeFirewallRemovalServiceState) {
				host.attestWireGuard = func() (firewallRemovalWireGuardEvidence, error) {
					return firewallRemovalWireGuardEvidence{}, errors.New("unexpected PostDown")
				}
			},
			want: "unexpected PostDown",
		},
		{
			name: "ambiguous legacy unit",
			prepare: func(_ *firewallRemovalPreparationHost, states map[string]*fakeFirewallRemovalServiceState) {
				states["syswarden.service"].loaded = true
				states["syswarden.service"].active = true
			},
			want: "ambiguous legacy systemd unit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			states := defaultSystemdFirewallRemovalStates()
			manager := &fakeFirewallRemovalManager{states: states}
			host := newFirewallRemovalTestHost(t, manager, true)
			test.prepare(&host, states)
			err := host.prepare()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("attestation result = %v, want %q", err, test.want)
			}
			if got := manager.mutationCalls(); len(got) != 0 {
				t.Fatalf("attestation failure caused service mutation: %#v", got)
			}
		})
	}
}

func TestPrepareFirewallStateForRemovalRejectsProcessAndInterfaceRacesBeforeManagerMutation_SW2_FWBACKEND_001(t *testing.T) {
	t.Run("active CLI mutator", func(t *testing.T) {
		manager := &fakeFirewallRemovalManager{states: defaultSystemdFirewallRemovalStates()}
		host := newFirewallRemovalTestHost(t, manager, true)
		host.processScan = func() error { return errors.New("update-feeds is active") }
		err := host.prepare()
		if err == nil || !strings.Contains(err.Error(), "update-feeds is active") {
			t.Fatalf("process race result = %v", err)
		}
		if len(manager.calls) != 0 {
			t.Fatalf("process race reached manager: %#v", manager.calls)
		}
	})

	t.Run("unmanaged WireGuard interface", func(t *testing.T) {
		manager := &fakeFirewallRemovalManager{states: defaultSystemdFirewallRemovalStates()}
		manager.states["wg-quick@wg-syswarden.service"] = &fakeFirewallRemovalServiceState{loaded: true}
		host := newFirewallRemovalTestHost(t, manager, false)
		host.wireGuardInterface = func() (bool, error) { return true, nil }
		err := host.prepare()
		if err == nil || !strings.Contains(err.Error(), "unmanaged WireGuard interface") {
			t.Fatalf("interface race result = %v", err)
		}
		if len(manager.calls) != 0 {
			t.Fatalf("interface race reached manager: %#v", manager.calls)
		}
	})
}

func TestPrepareFirewallStateForRemovalRejectsAmbiguousManagerStateAndExecutable_SW2_FWBACKEND_001(t *testing.T) {
	t.Run("ambiguous service state", func(t *testing.T) {
		states := defaultSystemdFirewallRemovalStates()
		states["syswarden-core.service"].activeStateOverride = "failed"
		manager := &fakeFirewallRemovalManager{states: states}
		host := newFirewallRemovalTestHost(t, manager, true)
		err := host.prepare()
		if err == nil || !strings.Contains(err.Error(), "ambiguous ActiveState") {
			t.Fatalf("ambiguous state result = %v", err)
		}
		if got := manager.mutationCalls(); len(got) != 0 {
			t.Fatalf("ambiguous state caused mutations: %#v", got)
		}
	})

	t.Run("relative executable", func(t *testing.T) {
		manager := &fakeFirewallRemovalManager{states: defaultSystemdFirewallRemovalStates()}
		host := newFirewallRemovalTestHost(t, manager, true)
		host.executor.lookPath = func(string) (string, error) { return "systemctl", nil }
		err := host.prepare()
		if err == nil || !strings.Contains(err.Error(), "clean absolute path") {
			t.Fatalf("relative executable result = %v", err)
		}
		if len(manager.calls) != 0 {
			t.Fatalf("relative executable reached manager: %#v", manager.calls)
		}
	})

	t.Run("non-root", func(t *testing.T) {
		manager := &fakeFirewallRemovalManager{states: defaultSystemdFirewallRemovalStates()}
		host := newFirewallRemovalTestHost(t, manager, true)
		host.effectiveUID = 1000
		err := host.prepare()
		if err == nil || !strings.Contains(err.Error(), "executed as root") {
			t.Fatalf("non-root result = %v", err)
		}
		if len(manager.calls) != 0 {
			t.Fatalf("non-root caller reached manager: %#v", manager.calls)
		}
	})
}

func TestPrepareFirewallStateForRemovalOpenRCStopsRemovesRunlevelsAndReattests_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{
		alpine: true,
		states: map[string]*fakeFirewallRemovalServiceState{
			"syswarden-core":        {loaded: true, active: true, runlevels: []string{"default"}},
			"syswarden-firewall":    {loaded: true, runlevels: []string{"boot", "default"}},
			"syswarden":             {},
			"syswarden-reporter":    {},
			"wg-quick.wg-syswarden": {loaded: true, active: true, runlevels: []string{"default"}},
		},
	}
	host := newFirewallRemovalTestHost(t, manager, true)
	if err := host.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := host.reattest(); err != nil {
		t.Fatal(err)
	}
	wantMutations := []string{
		"rc-update del syswarden-core default",
		"rc-update del syswarden-firewall boot",
		"rc-update del syswarden-firewall default",
		"rc-update del wg-quick.wg-syswarden default",
		"rc-service syswarden-core stop",
		"wg-quick down wg-syswarden",
	}
	if got := manager.mutationCalls(); !reflect.DeepEqual(got, wantMutations) {
		t.Fatalf("OpenRC mutation calls = %#v, want %#v", got, wantMutations)
	}
}

func TestPrepareFirewallStateForRemovalRejectsModifiedOpenRCUnitBeforeMutation_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{
		alpine: true,
		states: map[string]*fakeFirewallRemovalServiceState{
			"syswarden-core":        {loaded: true, active: true, runlevels: []string{"default"}},
			"syswarden-firewall":    {loaded: true},
			"syswarden":             {},
			"syswarden-reporter":    {},
			"wg-quick.wg-syswarden": {},
		},
	}
	host := newFirewallRemovalTestHost(t, manager, false)
	host.attestOpenRCUnit = func(service firewallRemovalService) error {
		if service.name == "syswarden-core" {
			return errors.New("modified OpenRC unit")
		}
		return nil
	}
	err := host.prepare()
	if err == nil || !strings.Contains(err.Error(), "modified OpenRC unit") {
		t.Fatalf("modified OpenRC unit result = %v", err)
	}
	if got := manager.mutationCalls(); len(got) != 0 {
		t.Fatalf("modified OpenRC unit caused manager mutation: %#v", got)
	}
}

func TestPrepareFirewallStateForRemovalRejectsModifiedOpenRCRunlevelBeforeMutation_SW2_FWBACKEND_001(t *testing.T) {
	manager := &fakeFirewallRemovalManager{
		alpine: true,
		states: map[string]*fakeFirewallRemovalServiceState{
			"syswarden-core":        {loaded: true, runlevels: []string{"default"}},
			"syswarden-firewall":    {},
			"syswarden":             {},
			"syswarden-reporter":    {},
			"wg-quick.wg-syswarden": {},
		},
	}
	host := newFirewallRemovalTestHost(t, manager, false)
	host.attestOpenRCRunlevel = func(firewallRemovalService, string) error {
		return errors.New("modified OpenRC runlevel link")
	}
	err := host.prepare()
	if err == nil || !strings.Contains(err.Error(), "modified OpenRC runlevel link") {
		t.Fatalf("modified OpenRC runlevel result = %v", err)
	}
	if got := manager.mutationCalls(); len(got) != 0 {
		t.Fatalf("modified OpenRC runlevel caused manager mutation: %#v", got)
	}
}

func TestUninstallSystemHostRemovalDoesNotStopPreparedFirewallMutators_SW2_FWBACKEND_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "uninstall_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	for _, forbidden := range []string{
		`exec.Command("systemctl", "stop"`,
		`exec.Command("rc-service"`,
		`"disable", "--now", "wg-quick@wg-syswarden"`,
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("host-removal phase still stops a prepared mutator with %q", forbidden)
		}
	}
}

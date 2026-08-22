package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
	"testing"
	"time"
)

type firewallTestUnit struct {
	loadState     string
	activeState   string
	unitFileState string
}

func validNftablesTestUnits() map[string]firewallTestUnit {
	return map[string]firewallTestUnit{
		"nftables.service": {
			loadState:     "loaded",
			activeState:   "active",
			unitFileState: "enabled",
		},
		"firewalld.service": {
			loadState:     "loaded",
			activeState:   "inactive",
			unitFileState: "masked",
		},
		"ufw.service": {
			loadState:     "loaded",
			activeState:   "inactive",
			unitFileState: "disabled",
		},
		"iptables.service": {
			loadState:     "loaded",
			activeState:   "inactive",
			unitFileState: "disabled",
		},
		"ip6tables.service": {
			loadState:     "loaded",
			activeState:   "inactive",
			unitFileState: "disabled",
		},
		"netfilter-persistent.service": {
			loadState:     "loaded",
			activeState:   "inactive",
			unitFileState: "disabled",
		},
	}
}

func historicalDefaultDormantNftablesTestUnits() map[string]firewallTestUnit {
	units := validNftablesTestUnits()
	target := units["nftables.service"]
	target.activeState = "inactive"
	target.unitFileState = "disabled"
	units["nftables.service"] = target
	return units
}

func firewallValidationExecutor(
	units map[string]firewallTestUnit,
	lookups *[]string,
	queries *[]string,
) firewallManagerExecutor {
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			if lookups != nil {
				*lookups = append(*lookups, name)
			}
			switch name {
			case "systemctl":
				return "/usr/bin/systemctl", nil
			case "nft":
				return "/usr/sbin/nft", nil
			default:
				return "", exec.ErrNotFound
			}
		},
		validate: func(string) error { return nil },
		output: func(name string, args ...string) ([]byte, error) {
			if name != "/usr/bin/systemctl" {
				return nil, fmt.Errorf("unexpected executable %q", name)
			}
			if len(args) != 4 || args[0] != "show" || args[2] != "--value" {
				return nil, fmt.Errorf("unexpected systemctl arguments %q", args)
			}
			property := strings.TrimPrefix(args[1], "--property=")
			unit := args[3]
			if queries != nil {
				*queries = append(*queries, unit+":"+property)
			}
			state, ok := units[unit]
			if !ok {
				if property == "LoadState" {
					return []byte("not-found\n"), nil
				}
				return nil, fmt.Errorf("queried %s for absent unit %s", property, unit)
			}
			var value string
			switch property {
			case "LoadState":
				value = state.loadState
			case "ActiveState":
				value = state.activeState
			case "UnitFileState":
				value = state.unitFileState
			default:
				return nil, fmt.Errorf("unexpected property %s", property)
			}
			return []byte(value + "\n"), nil
		},
	}
}

func activeSystemd(bool) (serviceManagerState, error) {
	return serviceManagerActive, nil
}

func panicFirewallExecutor() firewallManagerExecutor {
	return firewallManagerExecutor{
		lookPath: func(string) (string, error) {
			panic("lookPath must not be called")
		},
		validate: func(string) error {
			panic("validate must not be called")
		},
		output: func(string, ...string) ([]byte, error) {
			panic("output must not be called")
		},
	}
}

func panicAlpineProbe() bool {
	panic("platform probe must not be called")
}

func panicRuntimeClassifier(bool) (serviceManagerState, error) {
	panic("runtime classifier must not be called")
}

func TestPreflightHostFirewallBackendKeepAttestsLegacyServicesWithoutTransition_SW2_FWBACKEND_001(t *testing.T) {
	for _, backend := range []string{"", "keep"} {
		t.Run(fmt.Sprintf("backend-%q", backend), func(t *testing.T) {
			lookups := []string{}
			queries := []string{}
			if err := preflightHostFirewallBackend(
				backend,
				firewallValidationExecutor(validNftablesTestUnits(), &lookups, &queries),
				func() bool { return false },
				activeSystemd,
			); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(lookups, ","); got != "systemctl" {
				t.Fatalf("keep executable lookups = %q", got)
			}
			if len(queries) != 18 {
				t.Fatalf("keep attestation queries = %d, want 18: %v", len(queries), queries)
			}
		})
	}
}

func TestPreflightHostFirewallBackendKeepRejectsActiveOrEnabledLegacyServices_SW2_FWBACKEND_001(t *testing.T) {
	for _, test := range []struct {
		name     string
		unit     string
		property string
		value    string
	}{
		{name: "active-iptables", unit: "iptables.service", property: "active", value: "active"},
		{name: "enabled-ip6tables", unit: "ip6tables.service", property: "enabled", value: "enabled"},
		{name: "active-netfilter-persistent", unit: "netfilter-persistent.service", property: "active", value: "active"},
	} {
		t.Run(test.name, func(t *testing.T) {
			units := validNftablesTestUnits()
			state := units[test.unit]
			if test.property == "active" {
				state.activeState = test.value
			} else {
				state.unitFileState = test.value
			}
			units[test.unit] = state
			err := preflightHostFirewallBackend(
				"keep",
				firewallValidationExecutor(units, nil, nil),
				func() bool { return false },
				activeSystemd,
			)
			if err == nil || !strings.Contains(err.Error(), "must be inactive and disabled") {
				t.Fatalf("keep preflight error = %v", err)
			}
		})
	}
}

type fakeFirewallPreflightExitError int

func (err fakeFirewallPreflightExitError) Error() string { return fmt.Sprintf("exit %d", int(err)) }
func (err fakeFirewallPreflightExitError) ExitCode() int { return int(err) }

type firewallOpenRCTestServiceState struct {
	exists  bool
	active  bool
	enabled bool
}

func openRCFirewallValidationExecutor(
	services map[string]firewallOpenRCTestServiceState,
	mutateOnSecondSnapshot func(map[string]firewallOpenRCTestServiceState),
) firewallManagerExecutor {
	runlevelQueries := 0
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			switch name {
			case "rc-service", "rc-update":
				return "/usr/bin/true", nil
			default:
				return "", exec.ErrNotFound
			}
		},
		validate: func(string) error { return nil },
		output: func(name string, args ...string) ([]byte, error) {
			if len(args) == 1 && args[0] == "show" {
				if len(args) != 1 || args[0] != "show" {
					return nil, fmt.Errorf("unexpected rc-update arguments %q", args)
				}
				runlevelQueries++
				if runlevelQueries == 2 && mutateOnSecondSnapshot != nil {
					mutateOnSecondSnapshot(services)
				}
				lines := make([]string, 0, len(services))
				for _, service := range []string{"iptables", "ip6tables"} {
					if services[service].enabled {
						lines = append(lines, service+" | default")
					}
				}
				return []byte(strings.Join(lines, "\n")), nil
			}
			if name != "/usr/bin/true" || len(args) < 2 {
				return nil, fmt.Errorf("unexpected OpenRC command %q %q", name, args)
			}
			if args[0] == "--exists" {
				state := services[args[1]]
				if !state.exists {
					return nil, fakeFirewallPreflightExitError(1)
				}
				return nil, nil
			}
			if len(args) == 2 && args[1] == "status" {
				state := services[args[0]]
				if !state.exists {
					return nil, fakeFirewallPreflightExitError(1)
				}
				if !state.active {
					return nil, fakeFirewallPreflightExitError(3)
				}
				return []byte("started\n"), nil
			}
			return nil, fmt.Errorf("unexpected rc-service arguments %q", args)
		},
	}
}

func historicalDefaultOpenRCFirewallTestServices() map[string]firewallOpenRCTestServiceState {
	return map[string]firewallOpenRCTestServiceState{
		"nftables":             {exists: true},
		"firewalld":            {},
		"ufw":                  {},
		"iptables":             {},
		"ip6tables":            {},
		"netfilter-persistent": {},
	}
}

func historicalDefaultOpenRCFirewallValidationExecutor(
	services map[string]firewallOpenRCTestServiceState,
	statusCodes map[string]int,
	runlevelOutput func(int, map[string]firewallOpenRCTestServiceState) ([]byte, error),
	lookups *[]string,
	commands *[]string,
) firewallManagerExecutor {
	runlevelQueries := 0
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			if lookups != nil {
				*lookups = append(*lookups, name)
			}
			switch name {
			case "rc-service", "rc-update", "nft":
				return "/usr/bin/true", nil
			default:
				return "", exec.ErrNotFound
			}
		},
		validate: func(string) error { return nil },
		output: func(_ string, args ...string) ([]byte, error) {
			if commands != nil {
				*commands = append(*commands, strings.Join(args, " "))
			}
			if len(args) == 1 && args[0] == "show" {
				runlevelQueries++
				if runlevelOutput != nil {
					return runlevelOutput(runlevelQueries, services)
				}
				var lines []string
				for _, name := range []string{"nftables", "firewalld", "ufw", "iptables", "ip6tables", "netfilter-persistent"} {
					if services[name].enabled {
						lines = append(lines, name+" | default")
					}
				}
				return []byte(strings.Join(lines, "\n")), nil
			}
			if len(args) == 2 && args[0] == "--exists" {
				if !services[args[1]].exists {
					return nil, fakeFirewallPreflightExitError(1)
				}
				return nil, nil
			}
			if len(args) == 2 && args[1] == "status" {
				state := services[args[0]]
				if !state.exists {
					return nil, fakeFirewallPreflightExitError(1)
				}
				if state.active {
					return []byte("started\n"), nil
				}
				code := statusCodes[args[0]]
				if code == 0 {
					code = 3
				}
				return []byte("stopped\n"), fakeFirewallPreflightExitError(code)
			}
			return nil, fmt.Errorf("unexpected historical default OpenRC command arguments %q", args)
		},
	}
}

func TestPreflightHostFirewallBackendKeepAttestsOpenRCLegacyServices_SW2_FWBACKEND_001(t *testing.T) {
	stable := map[string]firewallOpenRCTestServiceState{
		"iptables":  {exists: true},
		"ip6tables": {exists: false},
	}
	if err := preflightHostFirewallBackend(
		"keep",
		openRCFirewallValidationExecutor(stable, nil),
		func() bool { return true },
		activeSystemd,
	); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		state  map[string]firewallOpenRCTestServiceState
		mutate func(map[string]firewallOpenRCTestServiceState)
		want   string
	}{
		{
			name:  "active",
			state: map[string]firewallOpenRCTestServiceState{"iptables": {exists: true, active: true}, "ip6tables": {}},
			want:  "must be inactive and disabled",
		},
		{
			name:  "enabled",
			state: map[string]firewallOpenRCTestServiceState{"iptables": {exists: true, enabled: true}, "ip6tables": {}},
			want:  "must be inactive and disabled",
		},
		{
			name:  "drift",
			state: map[string]firewallOpenRCTestServiceState{"iptables": {exists: true}, "ip6tables": {}},
			mutate: func(states map[string]firewallOpenRCTestServiceState) {
				states["iptables"] = firewallOpenRCTestServiceState{exists: true, active: true}
			},
			want: "state changed during preflight",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := preflightHostFirewallBackend(
				"keep",
				openRCFirewallValidationExecutor(test.state, test.mutate),
				func() bool { return true },
				activeSystemd,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("OpenRC keep preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPreflightHostFirewallBackendHistoricalDefaultOpenRCMatchesExactProbeState(t *testing.T) {
	services := historicalDefaultOpenRCFirewallTestServices()
	lookups := []string{}
	commands := []string{}
	err := preflightHostFirewallBackend(
		"nftables",
		historicalDefaultOpenRCFirewallValidationExecutor(services, nil, nil, &lookups, &commands),
		func() bool { return true },
		activeSystemd,
	)
	if !IsHistoricalDefaultOpenRCFirewallCompatibilityEligible(err) {
		t.Fatalf("exact historical OpenRC probe model error = %v, want OpenRC typed eligibility", err)
	}
	if IsHistoricalDefaultSystemdFirewallCompatibilityEligible(err) {
		t.Fatalf("OpenRC eligibility also matched the distinct systemd predicate: %v", err)
	}
	if got := strings.Join(lookups, ","); got != "rc-service,rc-update,nft" {
		t.Fatalf("historical OpenRC executable attestations = %q", got)
	}
	wantSnapshot := []string{
		"show",
		"--exists nftables",
		"nftables status",
		"--exists firewalld",
		"--exists ufw",
		"--exists iptables",
		"--exists ip6tables",
		"--exists netfilter-persistent",
	}
	wantCommands := append(append([]string{}, wantSnapshot...), wantSnapshot...)
	if got, want := strings.Join(commands, ","), strings.Join(wantCommands, ","); got != want {
		t.Fatalf("historical OpenRC double snapshot commands = %q, want %q", got, want)
	}
	if len(commands) != 16 {
		t.Fatalf("historical OpenRC command count = %d, want 16", len(commands))
	}
}

func TestHistoricalDefaultFirewallCompatibilitySentinelsAreDistinct(t *testing.T) {
	systemdErr := fmt.Errorf("wrapped systemd: %w", errHistoricalDefaultSystemdFirewallCompatibilityEligible)
	openRCErr := fmt.Errorf("wrapped OpenRC: %w", errHistoricalDefaultOpenRCFirewallCompatibilityEligible)
	if !IsHistoricalDefaultSystemdFirewallCompatibilityEligible(systemdErr) ||
		IsHistoricalDefaultOpenRCFirewallCompatibilityEligible(systemdErr) {
		t.Fatalf("systemd sentinel predicates are not distinct: %v", systemdErr)
	}
	if !IsHistoricalDefaultOpenRCFirewallCompatibilityEligible(openRCErr) ||
		IsHistoricalDefaultSystemdFirewallCompatibilityEligible(openRCErr) {
		t.Fatalf("OpenRC sentinel predicates are not distinct: %v", openRCErr)
	}
	joined := errors.Join(systemdErr, openRCErr)
	if !IsHistoricalDefaultSystemdFirewallCompatibilityEligible(joined) ||
		!IsHistoricalDefaultOpenRCFirewallCompatibilityEligible(joined) {
		t.Fatalf("joined adversarial sentinel error did not expose both classes: %v", joined)
	}
}

func TestPreflightHostFirewallBackendHistoricalDefaultOpenRCRejectsNonExactStates(t *testing.T) {
	for _, test := range []struct {
		name        string
		mutate      func(map[string]firewallOpenRCTestServiceState)
		statusCodes map[string]int
		runlevel    func(int, map[string]firewallOpenRCTestServiceState) ([]byte, error)
		want        string
	}{
		{
			name: "loaded conflict",
			mutate: func(services map[string]firewallOpenRCTestServiceState) {
				services["firewalld"] = firewallOpenRCTestServiceState{exists: true}
			},
			want: "conflict firewalld must be absent",
		},
		{
			name: "active nftables",
			mutate: func(services map[string]firewallOpenRCTestServiceState) {
				services["nftables"] = firewallOpenRCTestServiceState{exists: true, active: true}
			},
			want: "must be stopped and disabled",
		},
		{
			name: "enabled nftables",
			mutate: func(services map[string]firewallOpenRCTestServiceState) {
				services["nftables"] = firewallOpenRCTestServiceState{exists: true, enabled: true}
			},
			want: "must be stopped and disabled",
		},
		{
			name: "missing nftables",
			mutate: func(services map[string]firewallOpenRCTestServiceState) {
				services["nftables"] = firewallOpenRCTestServiceState{}
			},
			want: "nftables is absent",
		},
		{
			name:        "unexpected status rc",
			statusCodes: map[string]int{"nftables": 16},
			want:        "service status for nftables",
		},
		{
			name: "malformed runlevel",
			runlevel: func(int, map[string]firewallOpenRCTestServiceState) ([]byte, error) {
				return []byte("nftables default\n"), nil
			},
			want: "malformed OpenRC runlevel inventory",
		},
		{
			name: "duplicate runlevel",
			runlevel: func(int, map[string]firewallOpenRCTestServiceState) ([]byte, error) {
				return []byte("nftables | default\nnftables | boot\n"), nil
			},
			want: "duplicate OpenRC runlevel inventory",
		},
		{
			name: "double snapshot drift",
			runlevel: func(capture int, services map[string]firewallOpenRCTestServiceState) ([]byte, error) {
				if capture == 2 {
					services["nftables"] = firewallOpenRCTestServiceState{exists: true, active: true}
				}
				return nil, nil
			},
			want: "state changed during preflight",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			services := historicalDefaultOpenRCFirewallTestServices()
			if test.mutate != nil {
				test.mutate(services)
			}
			err := preflightHostFirewallBackend(
				"nftables",
				historicalDefaultOpenRCFirewallValidationExecutor(services, test.statusCodes, test.runlevel, nil, nil),
				func() bool { return true },
				activeSystemd,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("historical OpenRC refusal = %v, want %q", err, test.want)
			}
			if IsHistoricalDefaultOpenRCFirewallCompatibilityEligible(err) ||
				IsHistoricalDefaultSystemdFirewallCompatibilityEligible(err) {
				t.Fatalf("non-exact historical OpenRC state returned typed eligibility: %v", err)
			}
		})
	}

	for _, missing := range []string{"rc-service", "rc-update", "nft"} {
		t.Run("missing "+missing, func(t *testing.T) {
			executor := historicalDefaultOpenRCFirewallValidationExecutor(
				historicalDefaultOpenRCFirewallTestServices(), nil, nil, nil, nil,
			)
			baseLookPath := executor.lookPath
			executor.lookPath = func(name string) (string, error) {
				if name == missing {
					return "", exec.ErrNotFound
				}
				return baseLookPath(name)
			}
			err := preflightHostFirewallBackend("nftables", executor, func() bool { return true }, activeSystemd)
			if err == nil || !strings.Contains(err.Error(), "resolve required "+missing+" executable") ||
				IsHistoricalDefaultOpenRCFirewallCompatibilityEligible(err) {
				t.Fatalf("missing %s refusal = %v", missing, err)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRejectsUnsupportedBeforeHostInspection_SW2_FWBACKEND_002(t *testing.T) {
	tests := []struct {
		backend string
		want    string
	}{
		{backend: "iptables", want: "accepted for configuration compatibility but refused"},
		{backend: "firewalld", want: "unsupported firewall backend"},
	}
	for _, test := range tests {
		t.Run(test.backend, func(t *testing.T) {
			err := preflightHostFirewallBackend(
				test.backend,
				panicFirewallExecutor(),
				panicAlpineProbe,
				panicRuntimeClassifier,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRejectsIncompleteDependencies_SW2_FWBACKEND_003(t *testing.T) {
	tests := []struct {
		name       string
		executor   firewallManagerExecutor
		isAlpine   func() bool
		classifier func(bool) (serviceManagerState, error)
	}{
		{name: "look-path", executor: firewallManagerExecutor{validate: panicFirewallExecutor().validate, output: panicFirewallExecutor().output}, isAlpine: func() bool { return false }, classifier: activeSystemd},
		{name: "validate", executor: firewallManagerExecutor{lookPath: panicFirewallExecutor().lookPath, output: panicFirewallExecutor().output}, isAlpine: func() bool { return false }, classifier: activeSystemd},
		{name: "output", executor: firewallManagerExecutor{lookPath: panicFirewallExecutor().lookPath, validate: panicFirewallExecutor().validate}, isAlpine: func() bool { return false }, classifier: activeSystemd},
		{name: "platform", executor: panicFirewallExecutor(), classifier: activeSystemd},
		{name: "classifier", executor: panicFirewallExecutor(), isAlpine: func() bool { return false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := preflightHostFirewallBackend("nftables", test.executor, test.isAlpine, test.classifier)
			if err == nil || !strings.Contains(err.Error(), "dependencies are incomplete") {
				t.Fatalf("preflight error = %v", err)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRequiresActiveServiceManager_SW2_FWBACKEND_004(t *testing.T) {
	tests := []struct {
		name       string
		isAlpine   func() bool
		classifier func(bool) (serviceManagerState, error)
		want       string
	}{
		{
			name:     "offline-systemd",
			isAlpine: func() bool { return false },
			classifier: func(bool) (serviceManagerState, error) {
				return serviceManagerOffline, nil
			},
			want: "requires an attestable active service manager",
		},
		{
			name:     "offline-openrc",
			isAlpine: func() bool { return true },
			classifier: func(bool) (serviceManagerState, error) {
				return serviceManagerOffline, nil
			},
			want: "requires an attestable active service manager",
		},
		{
			name:     "ambiguous-error",
			isAlpine: func() bool { return false },
			classifier: func(bool) (serviceManagerState, error) {
				return serviceManagerAmbiguous, errors.New("runtime conflict")
			},
			want: "runtime conflict",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := preflightHostFirewallBackend("nftables", panicFirewallExecutor(), test.isAlpine, test.classifier)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRequiresAbsoluteExecutables_SW2_FWBACKEND_005(t *testing.T) {
	tests := []struct {
		name     string
		lookPath func(string) (string, error)
		want     string
	}{
		{
			name: "missing-systemctl",
			lookPath: func(name string) (string, error) {
				return "", exec.ErrNotFound
			},
			want: "resolve required systemctl executable",
		},
		{
			name: "relative-systemctl",
			lookPath: func(name string) (string, error) {
				return "systemctl", nil
			},
			want: "clean absolute path",
		},
		{
			name: "missing-nft",
			lookPath: func(name string) (string, error) {
				if name == "systemctl" {
					return "/usr/bin/systemctl", nil
				}
				return "", exec.ErrNotFound
			},
			want: "resolve required nft executable",
		},
		{
			name: "relative-nft",
			lookPath: func(name string) (string, error) {
				if name == "systemctl" {
					return "/usr/bin/systemctl", nil
				}
				return "../nft", nil
			},
			want: "clean absolute path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := firewallManagerExecutor{
				lookPath: test.lookPath,
				validate: func(string) error {
					return nil
				},
				output: func(string, ...string) ([]byte, error) {
					panic("unit inspection must not start before executable validation")
				},
			}
			err := preflightHostFirewallBackend("nftables", executor, func() bool { return false }, activeSystemd)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func writeFirewallPreflightTestExecutable(t *testing.T, directory, name, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func firewallPreflightTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".firewall-preflight-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- owner-only mode secures the private executable fixture directory
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove firewall preflight test directory: %v", err)
		}
	})
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func TestResolveFirewallExecutableValidatesResolvedTarget_SW2_FWBACKEND_013(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	target := writeFirewallPreflightTestExecutable(t, directory, "systemctl-real", "exit 0", 0700)
	link := filepath.Join(directory, "systemctl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	validated := ""
	resolved, err := resolveFirewallExecutable(firewallManagerExecutor{
		lookPath: func(string) (string, error) { return link, nil },
		validate: func(path string) error {
			validated = path
			return validateResolvedFirewallExecutable(path)
		},
	}, "systemctl")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != target || validated != target {
		t.Fatalf("resolved = %q, validated = %q, want %q", resolved, validated, target)
	}
}

func TestValidateResolvedFirewallExecutableRejectsUnsafeTargets_SW2_FWBACKEND_014(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	tests := []struct {
		name string
		path func(*testing.T) string
		want string
	}{
		{
			name: "writable-executable",
			path: func(t *testing.T) string {
				return writeFirewallPreflightTestExecutable(t, directory, "writable", "exit 0", 0722)
			},
			want: "trusted non-writable regular executable",
		},
		{
			name: "non-executable",
			path: func(t *testing.T) string {
				return writeFirewallPreflightTestExecutable(t, directory, "non-executable", "exit 0", 0600)
			},
			want: "trusted non-writable regular executable",
		},
		{
			name: "directory",
			path: func(t *testing.T) string {
				path := filepath.Join(directory, "directory")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "trusted non-writable regular executable",
		},
		{
			name: "writable-parent",
			path: func(t *testing.T) string {
				parent := filepath.Join(directory, "writable-parent")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(parent, 0777); err != nil { // #nosec G302 -- adversarial fixture deliberately proves writable parents are rejected
					t.Fatal(err)
				}
				return writeFirewallPreflightTestExecutable(t, parent, "systemctl", "exit 0", 0700)
			},
			want: "directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateResolvedFirewallExecutable(test.path(t))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunFirewallPreflightCommandIsTimeAndOutputBounded_SW2_FWBACKEND_015(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	t.Run("output", func(t *testing.T) {
		path := writeFirewallPreflightTestExecutable(
			t,
			directory,
			"oversized",
			"head -c 70000 /dev/zero",
			0700,
		)
		output, err := runFirewallPreflightCommandWithTimeout(path, time.Second)
		if err == nil || !strings.Contains(err.Error(), "output exceeds") {
			t.Fatalf("command error = %v", err)
		}
		if len(output) != maximumFirewallPreflightOutput {
			t.Fatalf("captured output = %d bytes, want %d", len(output), maximumFirewallPreflightOutput)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		path := writeFirewallPreflightTestExecutable(t, directory, "timeout", "while :; do :; done", 0700)
		_, err := runFirewallPreflightCommandWithTimeout(path, 50*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "command exceeded") {
			t.Fatalf("command error = %v", err)
		}
	})
	t.Run("timeout-kills-descendants", func(t *testing.T) {
		marker := filepath.Join(directory, "descendant-survived")
		body := fmt.Sprintf(
			"printf 'stdout-prefix\\n'\nprintf 'stderr-prefix\\n' >&2\n"+
				"(sleep 0.25; printf survived > %q) &\nwhile :; do :; done",
			marker,
		)
		path := writeFirewallPreflightTestExecutable(t, directory, "descendant", body, 0700)
		output, err := runFirewallPreflightCommandWithTimeout(path, 50*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "command exceeded") {
			t.Fatalf("command error = %v", err)
		}
		for _, prefix := range []string{"stdout-prefix\n", "stderr-prefix\n"} {
			if !strings.Contains(string(output), prefix) {
				t.Fatalf("timeout output %q does not retain %q", output, prefix)
			}
		}
		time.Sleep(350 * time.Millisecond)
		if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("descendant marker state = %v, want absent", err)
		}
	})
}

func TestPreflightHostFirewallBackendAcceptsStablePreconfiguredNftables_SW2_FWBACKEND_006(t *testing.T) {
	lookups := []string{}
	queries := []string{}
	err := preflightHostFirewallBackend(
		"nftables",
		firewallValidationExecutor(validNftablesTestUnits(), &lookups, &queries),
		func() bool { return false },
		activeSystemd,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lookups, ","); got != "systemctl,nft" {
		t.Fatalf("executable lookups = %q", got)
	}
	if len(queries) != 36 {
		t.Fatalf("stable attestation query count = %d, want 36: %v", len(queries), queries)
	}
}

func TestPreflightHostFirewallBackendHistoricalDefaultSentinelRequiresExactDoubleAttestation(t *testing.T) {
	t.Run("eligible", func(t *testing.T) {
		lookups := []string{}
		queries := []string{}
		err := preflightHostFirewallBackend(
			"nftables",
			firewallValidationExecutor(historicalDefaultDormantNftablesTestUnits(), &lookups, &queries),
			func() bool { return false },
			activeSystemd,
		)
		if !IsHistoricalDefaultSystemdFirewallCompatibilityEligible(err) {
			t.Fatalf("historical default preflight error = %v, want typed eligibility", err)
		}
		if got := strings.Join(lookups, ","); got != "systemctl,nft" {
			t.Fatalf("historical default executable attestations = %q", got)
		}
		if len(queries) != 36 {
			t.Fatalf("historical default attestation queries = %d, want 36: %v", len(queries), queries)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(map[string]firewallTestUnit)
	}{
		{
			name: "target-missing",
			mutate: func(units map[string]firewallTestUnit) {
				delete(units, "nftables.service")
			},
		},
		{
			name: "target-enabled-inactive",
			mutate: func(units map[string]firewallTestUnit) {
				target := units["nftables.service"]
				target.unitFileState = "enabled"
				units["nftables.service"] = target
			},
		},
		{
			name: "target-disabled-active",
			mutate: func(units map[string]firewallTestUnit) {
				target := units["nftables.service"]
				target.activeState = "active"
				units["nftables.service"] = target
			},
		},
		{
			name: "active-frontend",
			mutate: func(units map[string]firewallTestUnit) {
				frontend := units["firewalld.service"]
				frontend.activeState = "active"
				units["firewalld.service"] = frontend
			},
		},
		{
			name: "enabled-frontend",
			mutate: func(units map[string]firewallTestUnit) {
				frontend := units["ufw.service"]
				frontend.unitFileState = "enabled"
				units["ufw.service"] = frontend
			},
		},
		{
			name: "ambiguous-target",
			mutate: func(units map[string]firewallTestUnit) {
				target := units["nftables.service"]
				target.activeState = "failed"
				units["nftables.service"] = target
			},
		},
		{
			name: "ambiguous-frontend",
			mutate: func(units map[string]firewallTestUnit) {
				frontend := units["firewalld.service"]
				frontend.unitFileState = "generated"
				units["firewalld.service"] = frontend
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			units := historicalDefaultDormantNftablesTestUnits()
			test.mutate(units)
			err := preflightHostFirewallBackend(
				"nftables",
				firewallValidationExecutor(units, nil, nil),
				func() bool { return false },
				activeSystemd,
			)
			if err == nil {
				t.Fatal("non-eligible historical default state passed preflight")
			}
			if IsHistoricalDefaultSystemdFirewallCompatibilityEligible(err) {
				t.Fatalf("non-eligible historical default state returned typed eligibility: %v", err)
			}
		})
	}

	t.Run("nft-validation-failure", func(t *testing.T) {
		queries := []string{}
		executor := firewallValidationExecutor(historicalDefaultDormantNftablesTestUnits(), nil, &queries)
		validatedExecutables := 0
		executor.validate = func(string) error {
			validatedExecutables++
			if validatedExecutables == 2 {
				return errors.New("untrusted nft fixture")
			}
			return nil
		}
		err := preflightHostFirewallBackend("nftables", executor, func() bool { return false }, activeSystemd)
		if err == nil || IsHistoricalDefaultSystemdFirewallCompatibilityEligible(err) {
			t.Fatalf("untrusted nft preflight error = %v", err)
		}
		if len(queries) != 0 {
			t.Fatalf("unit inspection ran before nft attestation: %v", queries)
		}
		if validatedExecutables != 2 {
			t.Fatalf("validated executables = %d, want systemctl then nft", validatedExecutables)
		}
	})

	t.Run("second-snapshot-drift", func(t *testing.T) {
		units := historicalDefaultDormantNftablesTestUnits()
		base := firewallValidationExecutor(units, nil, nil)
		baseOutput := base.output
		activeQueries := 0
		base.output = func(name string, args ...string) ([]byte, error) {
			if len(args) == 4 && args[3] == "nftables.service" && args[1] == "--property=ActiveState" {
				activeQueries++
				if activeQueries == 2 {
					return []byte("active\n"), nil
				}
			}
			return baseOutput(name, args...)
		}
		err := preflightHostFirewallBackend("nftables", base, func() bool { return false }, activeSystemd)
		if err == nil || !strings.Contains(err.Error(), "state changed during preflight") ||
			IsHistoricalDefaultSystemdFirewallCompatibilityEligible(err) {
			t.Fatalf("historical default drift error = %v", err)
		}
	})
}

func TestPreflightHostFirewallBackendHistoricalDefaultSentinelMatchesAlmaProbeState(t *testing.T) {
	units := map[string]firewallTestUnit{
		"nftables.service": {
			loadState:     "loaded",
			activeState:   "inactive",
			unitFileState: "disabled",
		},
	}
	lookups := []string{}
	queries := []string{}
	err := preflightHostFirewallBackend(
		"nftables",
		firewallValidationExecutor(units, &lookups, &queries),
		func() bool { return false },
		activeSystemd,
	)
	if !IsHistoricalDefaultSystemdFirewallCompatibilityEligible(err) {
		t.Fatalf("Alma probe model preflight error = %v, want typed eligibility", err)
	}
	if got := strings.Join(lookups, ","); got != "systemctl,nft" {
		t.Fatalf("Alma probe model executable attestations = %q", got)
	}
	wantSnapshot := []string{
		"nftables.service:LoadState",
		"nftables.service:ActiveState",
		"nftables.service:UnitFileState",
		"firewalld.service:LoadState",
		"ufw.service:LoadState",
		"iptables.service:LoadState",
		"ip6tables.service:LoadState",
		"netfilter-persistent.service:LoadState",
	}
	wantQueries := append(append([]string{}, wantSnapshot...), wantSnapshot...)
	if got, want := strings.Join(queries, ","), strings.Join(wantQueries, ","); got != want {
		t.Fatalf("Alma probe model double snapshot queries = %q, want %q", got, want)
	}
	if len(queries) != 16 {
		t.Fatalf("Alma probe model query count = %d, want 16", len(queries))
	}
}

func TestPreflightHostFirewallBackendRejectsUnreadyTarget_SW2_FWBACKEND_007(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]firewallTestUnit)
		want   string
	}{
		{name: "missing", mutate: func(units map[string]firewallTestUnit) { delete(units, "nftables.service") }, want: "not loaded"},
		{name: "disabled", mutate: func(units map[string]firewallTestUnit) {
			state := units["nftables.service"]
			state.unitFileState = "disabled"
			units["nftables.service"] = state
		}, want: "enabled and active"},
		{name: "inactive", mutate: func(units map[string]firewallTestUnit) {
			state := units["nftables.service"]
			state.activeState = "inactive"
			units["nftables.service"] = state
		}, want: "enabled and active"},
		{name: "failed", mutate: func(units map[string]firewallTestUnit) {
			state := units["nftables.service"]
			state.activeState = "failed"
			units["nftables.service"] = state
		}, want: "ambiguous ActiveState"},
		{name: "static", mutate: func(units map[string]firewallTestUnit) {
			state := units["nftables.service"]
			state.unitFileState = "static"
			units["nftables.service"] = state
		}, want: "ambiguous UnitFileState"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			units := validNftablesTestUnits()
			test.mutate(units)
			err := preflightHostFirewallBackend(
				"nftables",
				firewallValidationExecutor(units, nil, nil),
				func() bool { return false },
				activeSystemd,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRejectsActiveFrontends_SW2_FWBACKEND_008(t *testing.T) {
	tests := []struct {
		name      string
		frontends []string
		want      string
	}{
		{name: "firewalld", frontends: []string{"firewalld.service"}, want: "firewalld.service conflicts"},
		{name: "ufw", frontends: []string{"ufw.service"}, want: "ufw.service conflicts"},
		{name: "iptables-services", frontends: []string{"iptables.service"}, want: "iptables.service conflicts"},
		{name: "ip6tables-services", frontends: []string{"ip6tables.service"}, want: "ip6tables.service conflicts"},
		{name: "netfilter-persistent", frontends: []string{"netfilter-persistent.service"}, want: "netfilter-persistent.service conflicts"},
		{name: "both", frontends: []string{"firewalld.service", "ufw.service"}, want: "multiple active firewall frontends"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			units := validNftablesTestUnits()
			for _, unit := range test.frontends {
				state := units[unit]
				state.activeState = "active"
				units[unit] = state
			}
			err := preflightHostFirewallBackend(
				"nftables",
				firewallValidationExecutor(units, nil, nil),
				func() bool { return false },
				activeSystemd,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRejectsEnabledFrontends_SW2_FWBACKEND_008(t *testing.T) {
	for _, unit := range []string{
		"firewalld.service",
		"ufw.service",
		"iptables.service",
		"ip6tables.service",
		"netfilter-persistent.service",
	} {
		t.Run(unit, func(t *testing.T) {
			units := validNftablesTestUnits()
			state := units[unit]
			state.activeState = "inactive"
			state.unitFileState = "enabled"
			units[unit] = state
			err := preflightHostFirewallBackend(
				"nftables",
				firewallValidationExecutor(units, nil, nil),
				func() bool { return false },
				activeSystemd,
			)
			if err == nil || !strings.Contains(err.Error(), "enabled firewall frontend") ||
				!strings.Contains(err.Error(), unit) {
				t.Fatalf("preflight error = %v", err)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRejectsAmbiguousFrontendStates_SW2_FWBACKEND_009(t *testing.T) {
	tests := []struct {
		name   string
		unit   string
		mutate func(*firewallTestUnit)
		want   string
	}{
		{name: "firewalld-load-error", unit: "firewalld.service", mutate: func(state *firewallTestUnit) { state.loadState = "error" }, want: "ambiguous LoadState"},
		{name: "firewalld-activating", unit: "firewalld.service", mutate: func(state *firewallTestUnit) { state.activeState = "activating" }, want: "ambiguous ActiveState"},
		{name: "ufw-failed", unit: "ufw.service", mutate: func(state *firewallTestUnit) { state.activeState = "failed" }, want: "ambiguous ActiveState"},
		{name: "iptables-activating", unit: "iptables.service", mutate: func(state *firewallTestUnit) { state.activeState = "activating" }, want: "ambiguous ActiveState"},
		{name: "ip6tables-failed", unit: "ip6tables.service", mutate: func(state *firewallTestUnit) { state.activeState = "failed" }, want: "ambiguous ActiveState"},
		{name: "netfilter-persistent-deactivating", unit: "netfilter-persistent.service", mutate: func(state *firewallTestUnit) { state.activeState = "deactivating" }, want: "ambiguous ActiveState"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			units := validNftablesTestUnits()
			state := units[test.unit]
			test.mutate(&state)
			units[test.unit] = state
			err := preflightHostFirewallBackend(
				"nftables",
				firewallValidationExecutor(units, nil, nil),
				func() bool { return false },
				activeSystemd,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPreflightHostFirewallBackendRejectsStateChangeDuringAttestation_SW2_FWBACKEND_010(t *testing.T) {
	units := validNftablesTestUnits()
	base := firewallValidationExecutor(units, nil, nil)
	activeQueries := 0
	baseOutput := base.output
	base.output = func(name string, args ...string) ([]byte, error) {
		if len(args) == 4 && args[3] == "nftables.service" && args[1] == "--property=ActiveState" {
			activeQueries++
			if activeQueries == 2 {
				return []byte("inactive\n"), nil
			}
		}
		return baseOutput(name, args...)
	}
	err := preflightHostFirewallBackend(
		"nftables",
		base,
		func() bool { return false },
		activeSystemd,
	)
	if err == nil || !strings.Contains(err.Error(), "state changed during preflight") {
		t.Fatalf("preflight error = %v", err)
	}
}

func TestOptimizeHostFirewallKeepUsesFailSafeDefaultWithReadOnlyAttestation_SW2_FWBACKEND_011(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousLookPath := firewallCommandLookPath
	previousValidate := firewallCommandValidate
	previousOutput := firewallCommandOutput
	previousClassifier := firewallRuntimeClassifier
	previousAlpine := firewallPlatformIsAlpine
	config.GlobalConfig = nil
	firewallCommandLookPath = func(name string) (string, error) {
		if name != "systemctl" {
			return "", fmt.Errorf("unexpected executable lookup %q", name)
		}
		return "/usr/bin/systemctl", nil
	}
	firewallCommandValidate = func(string) error { return nil }
	units := validNftablesTestUnits()
	firewallCommandOutput = firewallValidationExecutor(units, nil, nil).output
	firewallRuntimeClassifier = activeSystemd
	firewallPlatformIsAlpine = func() bool { return false }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		firewallCommandLookPath = previousLookPath
		firewallCommandValidate = previousValidate
		firewallCommandOutput = previousOutput
		firewallRuntimeClassifier = previousClassifier
		firewallPlatformIsAlpine = previousAlpine
	})

	if err := OptimizeHostFirewall(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishedDefaultFirewallBackendContractIsFailClosed_SW2_FWBACKEND_012(t *testing.T) {
	parsed, err := (&config.Migrator{}).ParseFromMemory(config.DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed["SYSWARDEN_FIREWALL_BACKEND"]; got != "keep" {
		t.Fatalf("published firewall backend default = %q, want keep", got)
	}
	for _, required := range []string{
		`"keep"     = Preserve the operator-managed frontend. It performs no service transition and refuses active or enabled iptables services.`,
		`"nftables" = Validation-only explicit choice.`,
		`SYSWARDEN never transitions these services.`,
		`"iptables" = Legacy parse compatibility only. Operational firewall policy mutation paths reject this choice.`,
		`SYSWARDEN_FIREWALL_BACKEND="keep"`,
	} {
		if !strings.Contains(config.DefaultConfig, required) {
			t.Fatalf("published firewall backend contract lacks %q", required)
		}
	}
}

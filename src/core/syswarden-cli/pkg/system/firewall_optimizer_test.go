package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func TestOptimizeHostFirewallHistoricalNftablesOfflineWithoutFirewalldIsNoOp(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousLookPath := firewallCommandLookPath
	previousLstat := firewallCommandLstat
	previousClassifier := firewallRuntimeClassifier
	previousAlpine := firewallPlatformIsAlpine
	previousTransition := firewallBackendTransition
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	firewallCommandLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	firewallCommandLstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	classifierCalls := 0
	firewallRuntimeClassifier = func(bool) (serviceManagerState, error) {
		classifierCalls++
		return serviceManagerOffline, nil
	}
	firewallPlatformIsAlpine = func() bool { return false }
	transitionCalls := 0
	firewallBackendTransition = func(string) error { transitionCalls++; return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		firewallCommandLookPath = previousLookPath
		firewallCommandLstat = previousLstat
		firewallRuntimeClassifier = previousClassifier
		firewallPlatformIsAlpine = previousAlpine
		firewallBackendTransition = previousTransition
	})

	if err := OptimizeHostFirewall(); err != nil {
		t.Fatal(err)
	}
	if classifierCalls != 0 || transitionCalls != 0 {
		t.Fatalf("offline no-conflict path called classifier=%d transition=%d", classifierCalls, transitionCalls)
	}
}

func firewallTestExecutor(states map[string]*firewallUnitSnapshot, calls *[]string, failures map[string]error, lookedUp *string) firewallManagerExecutor {
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			if lookedUp != nil {
				*lookedUp = name
			}
			return "/usr/sbin/" + name, nil
		},
		output: func(_ string, args ...string) ([]byte, error) {
			property, unit := strings.TrimPrefix(args[1], "--property="), args[3]
			state := states[unit]
			if state == nil || !state.loaded {
				if property == "LoadState" {
					return []byte("not-found\n"), nil
				}
				return nil, fmt.Errorf("queried absent unit %s", unit)
			}
			switch property {
			case "LoadState":
				return []byte("loaded\n"), nil
			case "UnitFileState":
				if state.enabled {
					return []byte("enabled\n"), nil
				}
				return []byte("disabled\n"), nil
			case "ActiveState":
				if state.active {
					return []byte("active\n"), nil
				}
				return []byte("inactive\n"), nil
			}
			return nil, fmt.Errorf("unexpected property %s", property)
		},
		run: func(_ string, args ...string) error {
			call := strings.Join(args, " ")
			*calls = append(*calls, call)
			if err := failures[call]; err != nil {
				return err
			}
			unit := args[len(args)-1]
			state := states[unit]
			if state == nil {
				return fmt.Errorf("mutated absent unit %s", unit)
			}
			switch args[0] {
			case "enable":
				state.enabled = true
				state.active = len(args) == 3 || state.active
			case "disable":
				state.enabled = false
				state.active = len(args) != 3 && state.active
			case "start":
				state.active = true
			case "stop":
				state.active = false
			}
			return nil
		},
	}
}

func TestTransitionFirewallBackendPreflightsTargetBeforeMutation(t *testing.T) {
	states := map[string]*firewallUnitSnapshot{
		"firewalld.service": {name: "firewalld.service", loaded: true, enabled: true, active: true},
	}
	calls := []string{}
	err := transitionFirewallBackend("iptables", firewallTestExecutor(states, &calls, nil, nil))
	if err == nil || !strings.Contains(err.Error(), "not loaded") || len(calls) != 0 {
		t.Fatalf("preflight result=%v calls=%v", err, calls)
	}
}

func TestTransitionFirewallBackendRollsBackAndReportsRollbackFailure(t *testing.T) {
	states := map[string]*firewallUnitSnapshot{
		"firewalld.service": {name: "firewalld.service", loaded: true, enabled: true, active: true},
		"nftables.service":  {name: "nftables.service", loaded: true},
	}
	calls := []string{}
	lookedUp := ""
	failures := map[string]error{"enable --now nftables.service": errors.New("activation failed")}
	err := transitionFirewallBackend("nftables", firewallTestExecutor(states, &calls, failures, &lookedUp))
	if err == nil || !states["firewalld.service"].enabled || !states["firewalld.service"].active || states["nftables.service"].enabled {
		t.Fatalf("rollback result=%v states=%#v calls=%v", err, states, calls)
	}
	if lookedUp != "nft" {
		t.Fatalf("nftables preflight looked up %q, want nft", lookedUp)
	}

	states["firewalld.service"].enabled, states["firewalld.service"].active = true, true
	failures["enable firewalld.service"] = errors.New("rollback failed")
	err = transitionFirewallBackend("nftables", firewallTestExecutor(states, &calls, failures, nil))
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("rollback failure was not surfaced: %v", err)
	}
}

func TestTransitionFirewallBackendRejectsSuccessfulNoEffectRollback(t *testing.T) {
	states := map[string]*firewallUnitSnapshot{
		"firewalld.service": {name: "firewalld.service", loaded: true, enabled: true, active: true},
		"nftables.service":  {name: "nftables.service", loaded: true},
	}
	calls := []string{}
	executor := firewallTestExecutor(states, &calls, map[string]error{
		"enable --now nftables.service": errors.New("activation failed"),
	}, nil)
	baseRun := executor.run
	executor.run = func(name string, args ...string) error {
		if strings.Join(args, " ") == "enable firewalld.service" {
			return nil
		}
		return baseRun(name, args...)
	}
	err := transitionFirewallBackend("nftables", executor)
	if err == nil || !strings.Contains(err.Error(), "rollback attestation failed") {
		t.Fatalf("successful no-effect rollback was not rejected: %v", err)
	}
}

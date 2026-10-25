package system

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func installationPair(load, active, enabled string) installationServiceSnapshot {
	return installationServiceSnapshot{
		{name: "syswarden-firewall", load: load, active: active, enabled: enabled},
		{name: "syswarden-core", load: load, active: active, enabled: enabled},
	}
}

func TestNativeInstallationPreservesAdministratorServiceChoices(t *testing.T) {
	for _, phase := range []string{"upgrade", "fresh", "unknown", "", "FRESH"} {
		for _, load := range []string{"loaded", "not-found", "masked", "error"} {
			for _, active := range []string{"active", "inactive", "failed", "activating"} {
				for _, enabled := range []string{"enabled", "disabled", "masked", "enabled-runtime"} {
					t.Run(strings.Join([]string{phase, load, active, enabled}, "/"), func(t *testing.T) {
						state := installationPair(load, active, enabled)
						calls := 0
						plan, err := prepareNativeServiceInstallation(phase, false, func() (installationServiceSnapshot, error) {
							calls++
							return state, nil
						})
						if err != nil {
							t.Fatal(err)
						}
						allowed := (phase == "upgrade" && load == "loaded" && active == "active" && enabled == "enabled") ||
							(phase == "fresh" && load == "not-found" && active == "inactive" && enabled == "disabled")
						if plan.Deferred() == allowed {
							t.Fatalf("unexpected deferred=%t", plan.Deferred())
						}
						if phase != "fresh" && phase != "upgrade" && calls != 0 {
							t.Fatal("unknown context queried a manager")
						}
						if !allowed {
							run, mutations := serviceManagerRecorder(-1, nil)
							if err := plan.activateExisting(run); err == nil || len(*mutations) != 0 {
								t.Fatal("deferred state reached activation")
							}
						}
					})
				}
			}
		}
	}
}

func TestNativeInstallationPairCannotStartDormantDependency(t *testing.T) {
	for index := range 2 {
		for _, state := range []installationServiceState{
			{load: "loaded", active: "inactive", enabled: "enabled"},
			{load: "loaded", active: "active", enabled: "disabled"},
			{load: "masked", active: "inactive", enabled: "masked"},
			{load: "not-found", active: "inactive", enabled: "disabled"},
		} {
			pair := installationPair("loaded", "active", "enabled")
			pair[index] = state
			plan, err := prepareNativeServiceInstallation("upgrade", false, func() (installationServiceSnapshot, error) { return pair, nil })
			if err != nil || !plan.Deferred() {
				t.Fatalf("mixed pair accepted: %#v, %v", pair, err)
			}
		}
	}
}

func TestNativeInstallationRejectsObservationFailureAndDrift(t *testing.T) {
	failure := errors.New("manager unavailable")
	if _, err := prepareNativeServiceInstallation("upgrade", false, func() (installationServiceSnapshot, error) { return installationServiceSnapshot{}, failure }); !errors.Is(err, failure) {
		t.Fatalf("lost observation failure: %v", err)
	}
	for _, alpine := range []bool{false, true} {
		state := installationPair("loaded", "active", "enabled")
		plan, err := prepareNativeServiceInstallation("upgrade", alpine, func() (installationServiceSnapshot, error) { return state, nil })
		if err != nil {
			t.Fatal(err)
		}
		state[0].active = "inactive"
		run, mutations := serviceManagerRecorder(-1, nil)
		if err := plan.activateExisting(run); err == nil || len(*mutations) != 0 {
			t.Fatal("drifted pair restarted")
		}
	}
}

func TestNativeInstallationUpgradeNeverEnablesServices(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		state := installationPair("loaded", "active", "enabled")
		state[0].runlevels, state[1].runlevels = "custom", "custom"
		plan, err := prepareNativeServiceInstallation("upgrade", alpine, func() (installationServiceSnapshot, error) { return state, nil })
		if err != nil {
			t.Fatal(err)
		}
		run, calls := serviceManagerRecorder(-1, nil)
		if err := plan.activateExisting(run); err != nil {
			t.Fatal(err)
		}
		want := []string{"systemctl daemon-reload", "systemctl try-restart syswarden-core.service"}
		if alpine {
			want = []string{"rc-service --ifstarted syswarden-core restart"}
		}
		if !reflect.DeepEqual(*calls, want) {
			t.Fatalf("commands=%v", *calls)
		}
	}
}

func TestNativeInstallationRechecksAfterManagerReload(t *testing.T) {
	state := installationPair("loaded", "active", "enabled")
	plan, err := prepareNativeServiceInstallation("upgrade", false, func() (installationServiceSnapshot, error) { return state, nil })
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = plan.activateExisting(func(name string, args ...string) error {
		calls++
		state[0].enabled = "disabled"
		return nil
	})
	if err == nil || calls != 1 {
		t.Fatalf("restart followed changed enablement: %d, %v", calls, err)
	}
}

func TestNativeInstallationConditionalRestartDoesNotRepairAStoppedCore(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		state := installationPair("loaded", "active", "enabled")
		plan, err := prepareNativeServiceInstallation("upgrade", alpine, func() (installationServiceSnapshot, error) { return state, nil })
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		err = plan.activateExisting(func(name string, args ...string) error {
			calls++
			if name == "rc-service" || args[0] == "try-restart" {
				state[1].active = "inactive"
			}
			return nil
		})
		wantCalls := 2
		if alpine {
			wantCalls = 1
		}
		if err == nil || calls != wantCalls {
			t.Fatalf("conditional no-op triggered repair or success: %v, %d", err, calls)
		}
	}
}

func TestNativeInstallationManagerFailureHasNoFallback(t *testing.T) {
	failure := errors.New("manager refused action")
	state := installationPair("loaded", "active", "enabled")
	for _, alpine := range []bool{false, true} {
		plan, err := prepareNativeServiceInstallation("upgrade", alpine, func() (installationServiceSnapshot, error) { return state, nil })
		if err != nil {
			t.Fatal(err)
		}
		run, calls := serviceManagerRecorder(0, failure)
		if err := plan.activateExisting(run); !errors.Is(err, failure) || len(*calls) != 1 {
			t.Fatalf("manager failure not preserved: %v, %v", err, *calls)
		}
	}
}

func TestNativeInstallationPhaseIsNotInheritedByUpdaterChildren(t *testing.T) {
	t.Setenv(nativeInstallPhaseEnvironment, "fresh")
	for _, entry := range productionExternalCommandEnvironment() {
		if strings.HasPrefix(entry, nativeInstallPhaseEnvironment+"=") {
			t.Fatal("child inherited fresh authority")
		}
	}
}

func TestNativeInstallationPublicationPreservesEnablementBytes(t *testing.T) {
	for _, present := range []bool{false, true} {
		root := t.TempDir()
		unit := filepath.Join(root, "service")
		link := filepath.Join(root, "enablement")
		if present {
			if err := os.Symlink("administrator-target", link); err != nil {
				t.Fatal(err)
			}
		}
		err := publishInstallationServiceArtifacts(false, []serviceArtifact{
			{path: unit, content: "owned service\n", mode: 0600},
			{path: link, target: unit},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(unit); err != nil {
			t.Fatal(err)
		}
		target, err := os.Readlink(link)
		if present && (err != nil || target != "administrator-target") {
			t.Fatalf("changed enablement: %q, %v", target, err)
		}
		if !present && !os.IsNotExist(err) {
			t.Fatalf("created enablement: %v", err)
		}
	}
}

func TestNativeInstallationSystemdObservationPreservesMaskedAndMissing(t *testing.T) {
	for _, load := range []string{"masked", "not-found", "loaded", "error"} {
		executor := firewallManagerExecutor{output: func(_ string, args ...string) ([]byte, error) {
			switch args[1] {
			case "--property=LoadState":
				return []byte(load + "\n"), nil
			case "--property=ActiveState":
				return []byte("inactive\n"), nil
			case "--property=UnitFileState":
				return []byte("masked\n"), nil
			default:
				t.Fatalf("unexpected query: %v", args)
				return nil, nil
			}
		}}
		state, err := inspectInstallationSystemdServices(executor, "/inert/systemctl")
		if err != nil {
			t.Fatal(err)
		}
		plan, err := prepareNativeServiceInstallation("upgrade", false, func() (installationServiceSnapshot, error) { return state, nil })
		if err != nil || !plan.Deferred() {
			t.Fatalf("unsafe state accepted: %v, %v", state, err)
		}
	}
}

func TestNativeInstallationOpenRCObservationIncludesCustomRunlevels(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		executor := firewallManagerExecutor{output: func(name string, args ...string) ([]byte, error) {
			if name == "/inert/rc-update" {
				return []byte("syswarden-core | custom default\nsyswarden-firewall | custom\n"), nil
			}
			if args[0] == "--exists" {
				return nil, nil
			}
			if stopped && args[0] == "syswarden-firewall" {
				return nil, fakeFirewallPreflightExitError(3)
			}
			return nil, nil
		}}
		state, err := inspectInstallationOpenRCServices(executor, "/inert/rc-service", "/inert/rc-update")
		if err != nil {
			t.Fatal(err)
		}
		if state[1].runlevels != "custom default" {
			t.Fatalf("lost custom membership: %#v", state)
		}
		plan, err := prepareNativeServiceInstallation("upgrade", true, func() (installationServiceSnapshot, error) { return state, nil })
		if err != nil || plan.Deferred() != stopped {
			t.Fatalf("incorrect disposition: %v, %v", plan, err)
		}
	}
}

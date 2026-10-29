//go:build linux

package system

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestActivationHostObservationRejectsDriftBeforeApproval(t *testing.T) {
	for _, kind := range []string{"service", "interface", "scheduler", "backend", "runlevel"} {
		t.Run(kind, func(t *testing.T) {
			state := activationHostState{Schema: "test", Backend: "keep", Manager: "openrc", Services: []activationHostService{{Name: "syswarden-core", Active: "active", Runlevels: "default"}}, Interfaces: []activationHostInterface{{Name: "fixture", Addresses: []string{"192.0.2.1/24"}}}}
			observer, err := captureActivationHostWith(context.Background(), func(context.Context) (activationHostState, error) { return state, nil })
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "service":
				state.Services[0].Active = "inactive"
			case "interface":
				state.Interfaces[0].Addresses[0] = "192.0.2.2/24"
			case "scheduler":
				state.Cron.OwnedHA = true
			case "backend":
				state.Backend = "nftables"
			case "runlevel":
				state.Services[0].Runlevels = "custom"
			}
			if err := observer.Revalidate(context.Background()); err == nil {
				t.Fatal("changed host observation accepted")
			}
		})
	}
}

func TestActivationHostObservationFailureCancellationAndPrivateOutput(t *testing.T) {
	expected := errors.New("incoherent manager")
	if _, err := captureActivationHostWith(context.Background(), func(context.Context) (activationHostState, error) { return activationHostState{}, expected }); !errors.Is(err, expected) {
		t.Fatal(err)
	}
	calls := 0
	state := activationHostState{Interfaces: []activationHostInterface{{Name: "private-interface", Hardware: "private-mac", Addresses: []string{"192.0.2.1/24"}}}}
	observer, err := captureActivationHostWith(context.Background(), func(context.Context) (activationHostState, error) { calls++; return state, nil })
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("capture did not revalidate observations: %d", calls)
	}
	summary := strings.Join(observer.Summary(), " ")
	for _, secret := range []string{"192.0.2.1", "private-interface", "private-mac"} {
		if strings.Contains(summary, secret) {
			t.Fatalf("summary exposed %s", secret)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := observer.Revalidate(ctx); !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatalf("cancelled observer executed: %v / %d", err, calls)
	}
	copy := observer.Summary()
	copy[0] = "modified"
	if observer.Summary()[0] == "modified" {
		t.Fatal("mutable review escaped")
	}
}

func TestActivationSystemdObserverDoesNotUsePATHOrOpenRCCommands(t *testing.T) {
	t.Setenv("PATH", "/untrusted/administrator/wrapper")
	for name, want := range map[string]string{"systemctl": "/usr/bin/systemctl", "dpkg-query": "/usr/bin/dpkg-query", "rpm": "/usr/bin/rpm", "nft": "/usr/sbin/nft"} {
		got, err := activationSystemdExecutable(name)
		if err != nil || got != want {
			t.Fatalf("fixed lookup %s=%s: %v", name, got, err)
		}
	}
	for _, name := range []string{"rc-service", "rc-update", "crontab", "sh", "/usr/bin/systemctl", "systemctl --help"} {
		if path, err := activationSystemdExecutable(name); err == nil || path != "" {
			t.Fatalf("unreviewed executable accepted: %s", name)
		}
	}
}

func TestActivationReviewRequiresCoherentLiveManager(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		for _, state := range []serviceManagerState{serviceManagerActive, serviceManagerOffline, serviceManagerAmbiguous} {
			err := requireActivationServiceManager(alpine, func(got bool) (serviceManagerState, error) {
				if got != alpine {
					t.Fatal("incorrect target manager selected")
				}
				return state, nil
			})
			if (err == nil) != (state == serviceManagerActive) {
				t.Fatalf("alpine=%t state=%s: %v", alpine, state, err)
			}
		}
	}
	want := errors.New("untrusted PID1")
	if err := requireActivationServiceManager(true, func(bool) (serviceManagerState, error) { return serviceManagerActive, want }); !errors.Is(err, want) {
		t.Fatalf("runtime evidence error ignored: %v", err)
	}
}

func TestActivationSystemdCronPlanBindsCompleteProviderSnapshot(t *testing.T) {
	for _, kind := range []string{"package-version", "exec-start", "drop-ins"} {
		t.Run(kind, func(t *testing.T) {
			properties := map[string]string{}
			version, dropIns := "3.0pl1-200", "verified-drop-in-v1"
			base := systemdCronProviderOutput(true, false, properties)
			host := testCronProviderHost(t, false, activeCronProviderRuntime, func(path string, args ...string) ([]byte, error) {
				if filepath.Base(path) == "dpkg-query" && len(args) > 0 && args[0] == "--show" {
					return []byte(version + "\n"), nil
				}
				return base(path, args...)
			})
			host.attestDropIns = func(firewallManagerExecutor, string) (string, error) { return dropIns, nil }
			capture := func(context.Context) (activationHostState, error) {
				evidence, proof, err := activationSystemdCronProviderWith(host)
				return activationHostState{Schema: "test", Manager: "systemd", Scheduler: evidence, PlatformProofSHA256: proof}, err
			}
			observer, err := captureActivationHostWith(t.Context(), capture)
			if err != nil {
				t.Fatal(err)
			}
			before, proof, err := activationSystemdCronProviderWith(host)
			if err != nil || proof == "" {
				t.Fatal("missing complete provider proof", err)
			}
			switch kind {
			case "package-version":
				version = "3.0pl1-201"
			case "exec-start":
				properties["cron.service:ExecStart"] = "{ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f -P ; ignore_errors=no ; }"
			case "drop-ins":
				dropIns = "verified-drop-in-v2"
			}
			after, changedProof, err := activationSystemdCronProviderWith(host)
			if err != nil {
				t.Fatal("independently verified changed provider rejected unexpectedly", err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("fixture changed compact labels instead of the previously lost snapshot fields")
			}
			if proof == changedProof {
				t.Fatal("complete provider change was omitted from its proof")
			}
			if err := observer.Revalidate(t.Context()); err == nil {
				t.Fatal("changed prerequisite inherited reviewed host approval")
			}
		})
	}
}

func TestActivationSystemdCronRejectsSnapshotDriftDuringCapture(t *testing.T) {
	for _, kind := range []string{"package-version", "exec-start", "drop-ins"} {
		t.Run(kind, func(t *testing.T) {
			properties := map[string]string{}
			version, dropIns := "3.0pl1-200", "verified-drop-in-v1"
			base := systemdCronProviderOutput(true, false, properties)
			captures := 0
			host := testCronProviderHost(t, false, activeCronProviderRuntime, func(path string, args ...string) ([]byte, error) {
				if filepath.Base(path) == "systemctl" && len(args) == 4 && args[1] == "--property=LoadState" && args[3] == "cron.service" {
					captures++
					if captures == 2 {
						switch kind {
						case "package-version":
							version = "3.0pl1-201"
						case "exec-start":
							properties["cron.service:ExecStart"] = "{ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f -P ; ignore_errors=no ; }"
						case "drop-ins":
							dropIns = "verified-drop-in-v2"
						}
					}
				}
				if filepath.Base(path) == "dpkg-query" && len(args) > 0 && args[0] == "--show" {
					return []byte(version + "\n"), nil
				}
				return base(path, args...)
			})
			host.attestDropIns = func(firewallManagerExecutor, string) (string, error) { return dropIns, nil }
			if _, _, err := activationSystemdCronProviderWith(host); err == nil {
				t.Fatal("mixed provider snapshots accepted")
			}
		})
	}
}

func TestActivationSystemdCronRefusesOfflineOrChangedManager(t *testing.T) {
	host := testCronProviderHost(t, false, offlineCronProviderRuntime, func(string, ...string) ([]byte, error) {
		t.Fatal("offline provider executed a manager query")
		return nil, nil
	})
	if _, _, err := activationSystemdCronProviderWith(host); err == nil {
		t.Fatal("offline activation provider accepted")
	}
	calls := 0
	host = testCronProviderHost(t, false, func(bool) (serviceManagerState, error) {
		calls++
		if calls == 1 {
			return serviceManagerActive, nil
		}
		return serviceManagerOffline, nil
	}, systemdCronProviderOutput(true, false, nil))
	if _, _, err := activationSystemdCronProviderWith(host); err == nil {
		t.Fatal("manager transition survived provider capture")
	}
}

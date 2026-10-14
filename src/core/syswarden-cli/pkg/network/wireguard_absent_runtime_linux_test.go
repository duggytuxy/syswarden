//go:build linux

package network

import (
	"errors"
	"net"
	"strings"
	"testing"
)

const absentWireGuardSystemdFixture = "MainPID=0\nControlPID=0\nId=wg-quick@wg-syswarden.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nUnitFileState=\nJob=\n"

func TestOrphanWireGuardRuntimeFallbackIsBoundedToFailedSystemdInspection(t *testing.T) {
	missingTool := errors.New("WireGuard tools were removed")
	absenceFailure := errors.New("runtime absence is unproven")
	for _, test := range []struct {
		name         string
		alpine       bool
		state        wireGuardServiceState
		inspectErr   error
		absenceErr   error
		wantFallback bool
		wantError    bool
	}{
		{name: "verified absent systemd", inspectErr: missingTool, wantFallback: true},
		{name: "failed absence proof", inspectErr: missingTool, absenceErr: absenceFailure, wantFallback: true, wantError: true},
		{name: "no OpenRC fallback", alpine: true, inspectErr: missingTool, wantError: true},
		{name: "normal inactive runtime"},
		{name: "active service", state: wireGuardServiceState{Active: true}, wantError: true},
		{name: "remaining interface", state: wireGuardServiceState{Interface: true}, wantError: true},
		{name: "changed manager", state: wireGuardServiceState{Alpine: true}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			err := attestInactiveWireGuardOrphanRuntime(test.alpine, func() (wireGuardServiceState, error) { return test.state, test.inspectErr }, func() error { called = true; return test.absenceErr })
			if called != test.wantFallback || (err != nil) != test.wantError {
				t.Fatalf("fallback=%v error=%v", called, err)
			}
			if test.absenceErr != nil && (!errors.Is(err, missingTool) || !errors.Is(err, absenceFailure)) {
				t.Fatal("original and independent failures were not preserved")
			}
		})
	}
}

func TestOrphanWireGuardAbsenceDoesNotRequireRemovedTools(t *testing.T) {
	queries, kernelReads := 0, 0
	output := func(name string, args ...string) ([]byte, error) {
		if name != "systemctl" || strings.Join(args, " ") != "show wg-quick@wg-syswarden.service --property="+absentWireGuardSystemdProperties {
			t.Fatalf("unexpected dependency after package cleanup: %s %v", name, args)
		}
		queries++
		return []byte(absentWireGuardSystemdFixture), nil
	}
	interfaces := func() ([]net.Interface, error) {
		kernelReads++
		return []net.Interface{{Name: "lo"}, {Name: "eth0"}, {Name: "wg-administrator"}}, nil
	}
	if err := attestAbsentSystemdWireGuardRuntimeForOrphanRemoval(output, interfaces); err != nil {
		t.Fatal(err)
	}
	if queries != 2 || kernelReads != 2 {
		t.Fatal("missing runtime was not independently reattested")
	}
}

func TestOrphanWireGuardMissingToolsStillRequireExactTableAndRuntime(t *testing.T) {
	for _, remains := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent runtime", true: "remaining interface"}[remains], func(t *testing.T) {
			runner := &fakeWireGuardNFTRunner{
				tables: []fakeWireGuardNFTTable{{"inet", "operator", 2}, {"inet", "syswarden_wg", 7}},
				detail: exactWireGuardNFTJSON(),
			}
			runtimeGuard := func() error {
				return attestInactiveWireGuardOrphanRuntime(false, func() (wireGuardServiceState, error) {
					return wireGuardServiceState{}, errors.New("WireGuard tools are absent")
				}, func() error {
					return attestAbsentSystemdWireGuardRuntimeForOrphanRemoval(func(string, ...string) ([]byte, error) {
						return []byte(absentWireGuardSystemdFixture), nil
					}, func() ([]net.Interface, error) {
						if remains {
							return []net.Interface{{Name: "wg-syswarden"}}, nil
						}
						return []net.Interface{{Name: "lo"}}, nil
					})
				})
			}
			err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(runner, func() error { return nil }, runtimeGuard)
			if remains {
				if err == nil || len(runner.deleteCalls) != 0 {
					t.Fatal("remaining interface did not preserve the complete table")
				}
			} else if err != nil || len(runner.deleteCalls) != 1 || len(runner.tables) != 1 || runner.tables[0].name != "operator" {
				t.Fatalf("exact orphan retirement changed unrelated state: %v %#v", err, runner)
			}
		})
	}
}

func TestOrphanWireGuardAbsenceRejectsAmbiguousSystemdEvidence(t *testing.T) {
	cases := map[string]string{
		"loaded":          strings.Replace(absentWireGuardSystemdFixture, "LoadState=not-found", "LoadState=loaded", 1),
		"masked":          strings.Replace(absentWireGuardSystemdFixture, "LoadState=not-found", "LoadState=masked", 1),
		"active":          strings.Replace(absentWireGuardSystemdFixture, "ActiveState=inactive", "ActiveState=active", 1),
		"failed":          strings.Replace(absentWireGuardSystemdFixture, "ActiveState=inactive", "ActiveState=failed", 1),
		"starting":        strings.Replace(absentWireGuardSystemdFixture, "SubState=dead", "SubState=start", 1),
		"enabled":         strings.Replace(absentWireGuardSystemdFixture, "UnitFileState=", "UnitFileState=enabled", 1),
		"fragment":        strings.Replace(absentWireGuardSystemdFixture, "FragmentPath=", "FragmentPath=/etc/systemd/system/custom.service", 1),
		"drop-in":         strings.Replace(absentWireGuardSystemdFixture, "DropInPaths=", "DropInPaths=/etc/systemd/system/custom.conf", 1),
		"main-process":    strings.Replace(absentWireGuardSystemdFixture, "MainPID=0", "MainPID=42", 1),
		"control-process": strings.Replace(absentWireGuardSystemdFixture, "ControlPID=0", "ControlPID=42", 1),
		"job":             strings.Replace(absentWireGuardSystemdFixture, "Job=", "Job=42", 1),
		"alias":           strings.Replace(absentWireGuardSystemdFixture, "Id=wg-quick@wg-syswarden.service", "Id=custom.service", 1),
		"missing":         strings.Replace(absentWireGuardSystemdFixture, "ControlPID=0\n", "", 1),
		"duplicate":       absentWireGuardSystemdFixture + "MainPID=0\n",
		"unknown":         absentWireGuardSystemdFixture + "Unexpected=0\n",
		"truncated":       strings.TrimSuffix(absentWireGuardSystemdFixture, "\n"),
		"empty":           "",
		"oversized":       strings.Repeat("x", 4097) + "\n",
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			output := func(string, ...string) ([]byte, error) { return []byte(wire), nil }
			if err := attestAbsentSystemdWireGuardRuntimeForOrphanRemoval(output, func() ([]net.Interface, error) {
				t.Fatal("ambiguous unit evidence reached the kernel absence check")
				return nil, nil
			}); err == nil {
				t.Fatal("ambiguous systemd evidence accepted")
			}
		})
	}
}

func TestOrphanWireGuardAbsenceRejectsRuntimeRacesAndFailures(t *testing.T) {
	for _, failure := range []string{"systemd-error", "kernel-error", "interface-present", "unit-returned", "interface-returned"} {
		t.Run(failure, func(t *testing.T) {
			reads, kernelReads := 0, 0
			output := func(string, ...string) ([]byte, error) {
				reads++
				if failure == "systemd-error" {
					return []byte(absentWireGuardSystemdFixture), errors.New("manager unavailable")
				}
				if failure == "unit-returned" && reads == 2 {
					return []byte(strings.Replace(absentWireGuardSystemdFixture, "LoadState=not-found", "LoadState=loaded", 1)), nil
				}
				return []byte(absentWireGuardSystemdFixture), nil
			}
			interfaces := func() ([]net.Interface, error) {
				kernelReads++
				if failure == "kernel-error" {
					return nil, errors.New("netlink unavailable")
				}
				if failure == "interface-present" || failure == "interface-returned" && kernelReads == 2 {
					return []net.Interface{{Name: "wg-syswarden"}}, nil
				}
				return []net.Interface{{Name: "lo"}}, nil
			}
			if err := attestAbsentSystemdWireGuardRuntimeForOrphanRemoval(output, interfaces); err == nil {
				t.Fatal("failed or changing runtime evidence accepted")
			}
		})
	}
	if attestAbsentSystemdWireGuardRuntimeForOrphanRemoval(nil, net.Interfaces) == nil || attestAbsentSystemdWireGuardRuntimeForOrphanRemoval(runWireGuardServiceOutput, nil) == nil {
		t.Fatal("incomplete independent inspectors accepted")
	}
}

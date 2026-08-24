//go:build linux

package network

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func readWireGuardServiceFixture(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	file, openErr := root.Open(filepath.Base(path))
	if openErr != nil {
		_ = root.Close()
		t.Fatal(openErr)
	}
	contents, readErr := io.ReadAll(file)
	fileCloseErr := file.Close()
	rootCloseErr := root.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if fileCloseErr != nil {
		t.Fatal(fileCloseErr)
	}
	if rootCloseErr != nil {
		t.Fatal(rootCloseErr)
	}
	return contents
}

func TestEnsureExactSymlinkIsIdempotentAndFailClosed(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(directory, "wg-quick.wg-syswarden")
	target := filepath.Join(directory, "wg-quick")

	if err := ensureExactSymlink(target, link); err != nil {
		t.Fatalf("create exact symlink: %v", err)
	}
	if err := ensureExactSymlink(target, link); err != nil {
		t.Fatalf("accept existing exact symlink: %v", err)
	}
	gotTarget, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != target {
		t.Fatalf("unexpected symlink target: got %q, want %q", gotTarget, target)
	}

	wrongLink := filepath.Join(directory, "wrong-link")
	if err := os.Symlink(filepath.Join(directory, "other"), wrongLink); err != nil {
		t.Fatal(err)
	}
	if err := ensureExactSymlink(target, wrongLink); err == nil {
		t.Fatal("mismatched symlink was accepted")
	}

	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureExactSymlink(target, regular); err == nil {
		t.Fatal("regular file was accepted or replaced")
	}
	contents := readWireGuardServiceFixture(t, regular)
	if string(contents) != "do not replace" {
		t.Fatalf("regular file was modified: %q", contents)
	}
}

func TestPrepareOpenRCWireGuardServiceIsVerificationOnly_SW2_WGSTATE_001(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/init.d"), 0755); err != nil { // #nosec G301 -- fixture models the protected system OpenRC directory mode
		t.Fatal(err)
	}
	previousRoot := wireGuardFilesystemRoot
	previousUID := wireGuardExpectedOwnerUID
	previousGID := wireGuardExpectedOwnerGID
	previousAlpine := wireGuardIsAlpine
	previousDefinition := attestWireGuardServiceDefinition
	wireGuardFilesystemRoot = root
	wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID = networkTestIdentity(t)
	wireGuardIsAlpine = func() bool { return true }
	definitionCalls := 0
	attestWireGuardServiceDefinition = func() error {
		definitionCalls++
		return nil
	}
	t.Cleanup(func() {
		wireGuardFilesystemRoot = previousRoot
		wireGuardExpectedOwnerUID = previousUID
		wireGuardExpectedOwnerGID = previousGID
		wireGuardIsAlpine = previousAlpine
		attestWireGuardServiceDefinition = previousDefinition
	})
	linkPath := filepath.Join(root, strings.TrimPrefix(wireguardstate.OpenRCServiceLinkPath, "/"))
	if err := prepareConfiguredWireGuardService(); err == nil {
		t.Fatal("missing OpenRC instance link was silently created")
	}
	if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verification-only preparation mutated absent link: %v", err)
	}
	if err := os.Symlink(wireguardstate.OpenRCServiceLinkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareConfiguredWireGuardService(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(linkPath)
	if err != nil || !os.SameFile(before, after) || definitionCalls != 1 {
		t.Fatalf("exact preexisting link was changed: before=%v after=%v definitions=%d err=%v", before, after, definitionCalls, err)
	}
}

type fakeExactWireGuardService struct {
	state    wireGuardServiceState
	calls    []string
	failures map[string]error
}

func (service *fakeExactWireGuardService) run(name string, args ...string) error {
	command := strings.Join(append([]string{name}, args...), " ")
	service.calls = append(service.calls, command)
	if err := service.failures[command]; err != nil {
		return err
	}
	switch command {
	case "systemctl enable --now wg-quick@wg-syswarden.service":
		service.state.Enabled = true
		service.state.Active = true
		service.state.Interface = true
	case "systemctl enable wg-quick@wg-syswarden.service", "rc-update add wg-quick.wg-syswarden default":
		service.state.Enabled = true
	case "systemctl disable wg-quick@wg-syswarden.service", "rc-update del wg-quick.wg-syswarden default":
		service.state.Enabled = false
	case "systemctl start wg-quick@wg-syswarden.service", "rc-service wg-quick.wg-syswarden start":
		service.state.Active = true
		service.state.Interface = true
	case "systemctl stop wg-quick@wg-syswarden.service", "rc-service wg-quick.wg-syswarden stop":
		service.state.Active = false
		service.state.Interface = false
	default:
		return fmt.Errorf("unexpected service command %s", command)
	}
	return nil
}

func (service *fakeExactWireGuardService) output(name string, args ...string) ([]byte, error) {
	command := strings.Join(append([]string{name}, args...), " ")
	switch command {
	case "systemctl is-active wg-quick@wg-syswarden.service":
		if service.state.Active {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), errors.New("inactive exit status")
	case "systemctl is-enabled wg-quick@wg-syswarden.service":
		if service.state.Enabled {
			return []byte("enabled\n"), nil
		}
		return []byte("disabled\n"), errors.New("disabled exit status")
	case "rc-service wg-quick.wg-syswarden status":
		if service.state.Active {
			return []byte(" * status: started\n"), nil
		}
		return []byte(" * status: stopped\n"), errors.New("stopped exit status")
	case "rc-update show":
		if service.state.Enabled {
			return []byte("wg-quick.wg-syswarden | default\n"), nil
		}
		return []byte("sshd | default\n"), nil
	case "wg show interfaces":
		if service.state.Interface {
			return []byte("wg-syswarden\n"), nil
		}
		return []byte("\n"), nil
	default:
		return nil, fmt.Errorf("unexpected state command %s", command)
	}
}

func seamExactWireGuardHookAttestation(t *testing.T) {
	t.Helper()
	previous := wireGuardServerIdentityInspector
	previousDefinition := attestWireGuardServiceDefinition
	previousHookExecutables := wireGuardServerHookExecutableAttestor
	wireGuardServerIdentityInspector = func() (wireguardstate.ServerConfigurationIdentity, error) {
		return exactWireGuardNFTIdentity(), nil
	}
	attestWireGuardServiceDefinition = func() error { return nil }
	wireGuardServerHookExecutableAttestor = func(wireguardstate.ServerConfigurationIdentity) error { return nil }
	t.Cleanup(func() {
		wireGuardServerIdentityInspector = previous
		attestWireGuardServiceDefinition = previousDefinition
		wireGuardServerHookExecutableAttestor = previousHookExecutables
	})
}

func TestInspectWireGuardServiceStateRequiresExactManagerAndInterfaceTruth_SW2_WGSTATE_001(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		t.Run(fmt.Sprintf("alpine-%v", alpine), func(t *testing.T) {
			service := &fakeExactWireGuardService{state: wireGuardServiceState{
				Alpine: alpine, Active: true, Enabled: true, Interface: true,
			}}
			state, err := inspectWireGuardServiceState(alpine, service.output)
			if err != nil || !state.ready() || state.Alpine != alpine {
				t.Fatalf("exact service state: state=%#v err=%v", state, err)
			}
			service.state.Interface = false
			if _, err := inspectWireGuardServiceState(alpine, service.output); err == nil {
				t.Fatal("active service without exact interface was accepted")
			}
		})
	}
	service := &fakeExactWireGuardService{state: wireGuardServiceState{
		Alpine: true, Active: true, Enabled: true, Interface: true,
	}}
	spoofedStatus := func(name string, args ...string) ([]byte, error) {
		if strings.Join(append([]string{name}, args...), " ") == "rc-service wg-quick.wg-syswarden status" {
			return []byte("operator prefix * status: started\n"), nil
		}
		return service.output(name, args...)
	}
	if _, err := inspectWireGuardServiceState(true, spoofedStatus); err == nil {
		t.Fatal("OpenRC status with a noncanonical prefix was accepted")
	}
	spoofedRunlevel := func(name string, args ...string) ([]byte, error) {
		if strings.Join(append([]string{name}, args...), " ") == "rc-update show" {
			return []byte("wg-quick.wg-syswarden operator default\n"), nil
		}
		return service.output(name, args...)
	}
	if _, err := inspectWireGuardServiceState(true, spoofedRunlevel); err == nil {
		t.Fatal("OpenRC enablement with a noncanonical shape was accepted")
	}
}

func TestRestoreWireGuardServiceStatePreservesEveryInitialBoundary_SW2_WGSTATE_001(t *testing.T) {
	seamExactWireGuardHookAttestation(t)
	for _, alpine := range []bool{false, true} {
		for _, target := range []wireGuardServiceState{
			{Alpine: alpine, Active: true, Enabled: true, Interface: true},
			{Alpine: alpine, Active: true, Enabled: false, Interface: true},
			{Alpine: alpine, Active: false, Enabled: true, Interface: false},
			{Alpine: alpine, Active: false, Enabled: false, Interface: false},
		} {
			t.Run(fmt.Sprintf("alpine-%v-active-%v-enabled-%v", alpine, target.Active, target.Enabled), func(t *testing.T) {
				service := &fakeExactWireGuardService{state: wireGuardServiceState{
					Alpine: alpine, Active: true, Enabled: true, Interface: true,
				}, failures: map[string]error{}}
				if err := restoreWireGuardServiceState(target, service.run, service.output); err != nil {
					t.Fatal(err)
				}
				if service.state != target {
					t.Fatalf("restored state = %#v, want %#v", service.state, target)
				}
				if target.ready() && len(service.calls) != 0 {
					t.Fatalf("preexisting active/enabled service was mutated: %v", service.calls)
				}
			})
		}
	}
}

func TestActivateWireGuardServiceAttestsExactStateImmediatelyBeforeEveryCommand_SW2_WGSTATE_001(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		t.Run(fmt.Sprintf("alpine-%v", alpine), func(t *testing.T) {
			baseline := wireGuardServiceState{Alpine: alpine}
			service := &fakeExactWireGuardService{state: baseline, failures: map[string]error{}}
			events := make([]string, 0, 16)
			output := func(name string, args ...string) ([]byte, error) {
				events = append(events, "inspect:"+name)
				return service.output(name, args...)
			}
			definitionAttestations := 0
			attestDefinition := func() error {
				definitionAttestations++
				events = append(events, "definition")
				return nil
			}
			hookAttestations := 0
			attestHooks := func() error {
				hookAttestations++
				events = append(events, "hooks")
				return nil
			}
			run := func(name string, args ...string) error {
				if len(events) == 0 || events[len(events)-1] != "hooks" {
					t.Fatalf("service command %s was not immediately preceded by exact attestation: %v", name, events)
				}
				events = append(events, "run:"+name)
				return service.run(name, args...)
			}
			if err := activateWireGuardServiceFromExactState(
				baseline, alpine, run, output, attestDefinition, attestHooks,
			); err != nil {
				t.Fatal(err)
			}
			wantAttestations := 1
			if alpine {
				wantAttestations = 2
			}
			if definitionAttestations != wantAttestations || hookAttestations != wantAttestations || !service.state.ready() {
				t.Fatalf(
					"definition=%d hooks=%d state=%#v events=%v",
					definitionAttestations, hookAttestations, service.state, events,
				)
			}
		})
	}
}

func TestActivateWireGuardServiceDefinitionDriftPreventsManagerMutation_SW2_WGSTATE_001(t *testing.T) {
	sentinel := errors.New("service definition drift")
	for _, alpine := range []bool{false, true} {
		t.Run(fmt.Sprintf("alpine-%v", alpine), func(t *testing.T) {
			baseline := wireGuardServiceState{Alpine: alpine}
			service := &fakeExactWireGuardService{state: baseline, failures: map[string]error{}}
			runCalls := 0
			err := activateWireGuardServiceFromExactState(
				baseline,
				alpine,
				func(name string, args ...string) error {
					runCalls++
					return service.run(name, args...)
				},
				service.output,
				func() error { return sentinel },
				func() error {
					t.Fatal("configuration hooks were inspected after service-definition drift")
					return nil
				},
			)
			if err == nil || !errors.Is(err, sentinel) || runCalls != 0 || service.state != baseline {
				t.Fatalf("definition drift result: err=%v runs=%d state=%#v", err, runCalls, service.state)
			}
		})
	}
}

func TestRestoreOpenRCWireGuardServiceRunsAllCompensationsAndJoinsFailures_SW2_WGSTATE_001(t *testing.T) {
	seamExactWireGuardHookAttestation(t)
	stopFailure := errors.New("stop failed")
	disableFailure := errors.New("disable failed")
	service := &fakeExactWireGuardService{
		state: wireGuardServiceState{Alpine: true, Active: true, Enabled: true, Interface: true},
		failures: map[string]error{
			"rc-service wg-quick.wg-syswarden stop":       stopFailure,
			"rc-update del wg-quick.wg-syswarden default": disableFailure,
		},
	}
	target := wireGuardServiceState{Alpine: true}
	err := restoreWireGuardServiceState(target, service.run, service.output)
	if err == nil || !errors.Is(err, stopFailure) || !errors.Is(err, disableFailure) {
		t.Fatalf("OpenRC compensation errors were not joined: %v", err)
	}
	if !reflect.DeepEqual(service.calls, []string{
		"rc-service wg-quick.wg-syswarden stop",
		"rc-update del wg-quick.wg-syswarden default",
	}) {
		t.Fatalf("OpenRC did not attempt every compensation: %v", service.calls)
	}
}

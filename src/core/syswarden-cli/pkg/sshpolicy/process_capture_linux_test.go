//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type sshProcessFixtureLease struct {
	identity      sshProcessIdentity
	reads, closes int
	onRead        func(*sshProcessFixtureLease) error
	closeErr      error
}

func (l *sshProcessFixtureLease) observe() (sshProcessIdentity, error) {
	l.reads++
	if l.onRead != nil {
		if err := l.onRead(l); err != nil {
			return sshProcessIdentity{}, err
		}
	}
	return l.identity, nil
}

func (l *sshProcessFixtureLease) Close() error { l.closes++; return l.closeErr }

func sshProcessFixtureIdentity() sshProcessIdentity {
	return sshProcessIdentity{PID: 100, StartTicks: 1234, ExecutableSHA256: strings.Repeat("b", 64),
		Root: sshKernelIdentity{1, 2}, ControlGroupHash: digestBytes([]byte("/system.slice/ssh.service")),
		Namespaces: map[string]sshKernelIdentity{"pid": {2, 3}, "mnt": {2, 4}, "user": {2, 5}, "net": {2, 6}}}
}

func TestSSHProcessCoordinatorBindsManagerWithoutClaimingLoadedPolicy(t *testing.T) {
	units := sshManagerFixture("ssh.service", "ssh.socket", true, true, true)
	for _, scenario := range []string{"stable", "pid-change", "group-change", "invocation-change", "start-change", "executable-change", "namespace-change", "root-change", "dead", "guard-drift", "close-error", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l := &sshProcessFixtureLease{identity: sshProcessFixtureIdentity()}
			if scenario == "close-error" {
				l.closeErr = errors.New("fixture close failure")
			}
			l.onRead = func(l *sshProcessFixtureLease) error {
				if l.reads != 2 {
					return nil
				}
				switch scenario {
				case "start-change":
					l.identity.StartTicks++
				case "executable-change":
					l.identity.ExecutableSHA256 = strings.Repeat("c", 64)
				case "namespace-change":
					l.identity.Namespaces = map[string]sshKernelIdentity{"pid": {2, 3}, "mnt": {2, 4}, "user": {2, 5}, "net": {2, 7}}
				case "root-change":
					l.identity.Root.Inode++
				case "dead":
					return ErrInventoryChanged
				case "cancel":
					cancel()
				}
				return nil
			}
			samples := 0
			snapshot := func(ctx context.Context) (sshSystemdSnapshot, error) {
				samples++
				result, err := observeSSHSystemdSnapshot(ctx, strings.Repeat("a", 64), sshFixtureQuery(units), func() error { return nil })
				if samples == 2 {
					switch scenario {
					case "pid-change":
						result.units["ssh.service"]["MainPID"] = "101"
					case "group-change":
						result.units["ssh.service"]["ControlGroup"] = "/other"
					case "invocation-change":
						result.units["ssh.service"]["InvocationID"] = strings.Repeat("c", 32)
					}
				}
				return result, err
			}
			bind := func(pid int, group string) (sshProcessLease, error) {
				if pid != 100 || group != "/system.slice/ssh.service" {
					t.Fatal("wrong process selection")
				}
				return l, nil
			}
			guards := 0
			guard := func() error {
				guards++
				if scenario == "guard-drift" && guards == 3 {
					return ErrInventoryChanged
				}
				return nil
			}
			result, err := observeSSHSystemdProcess(ctx, snapshot, bind, guard)
			if l.closes != 1 {
				t.Fatal("lease was not closed exactly once", l.closes)
			}
			if scenario != "stable" {
				if err == nil || !reflect.DeepEqual(result, ProcessSummary{}) {
					t.Fatal("accepted drift or returned partial proof", result, err)
				}
				return
			}
			if err != nil || samples != 2 || l.reads != 2 || guards != 3 || !result.ProcessObserved || !result.ExecutableVerified ||
				result.ConfigurationVerified || result.ListenersVerified || result.RuntimeActivated || result.AccessVerified || result.Manager.ProcessVerified ||
				!lowerDigest.MatchString(result.IdentitySHA256) {
				t.Fatal("incorrect observation or invented stronger proof", result, err)
			}
			wire, _ := json.Marshal(result)
			if strings.Contains(string(wire), "/system.slice/") || strings.Contains(string(wire), "StartTicks") || strings.Contains(string(wire), "\"PID\"") {
				t.Fatal("summary leaked raw process observations")
			}
		})
	}
}

func TestSSHProcessCoordinatorRefusesMissingOrUnsupportedRuntime(t *testing.T) {
	for _, scenario := range []string{"absent", "inactive", "socket-only", "snapshot-error", "bind-error", "nil-lease", "cancelled", "first-read-error"} {
		t.Run(scenario, func(t *testing.T) {
			units := sshManagerFixture("ssh.service", "", true, false, false)
			switch scenario {
			case "absent":
				units = sshManagerFixture("", "", false, false, false)
			case "inactive":
				units = sshManagerFixture("ssh.service", "", false, false, false)
			case "socket-only":
				units = sshManagerFixture("ssh.service", "ssh.socket", false, true, false)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			snapshot := func(ctx context.Context) (sshSystemdSnapshot, error) {
				if scenario == "snapshot-error" {
					return sshSystemdSnapshot{}, ErrInventoryChanged
				}
				return observeSSHSystemdSnapshot(ctx, strings.Repeat("a", 64), sshFixtureQuery(units), func() error { return nil })
			}
			l := &sshProcessFixtureLease{identity: sshProcessFixtureIdentity()}
			if scenario == "first-read-error" {
				l.onRead = func(*sshProcessFixtureLease) error { return ErrInventoryChanged }
			}
			bound := false
			bind := func(int, string) (sshProcessLease, error) {
				bound = true
				if scenario == "bind-error" {
					return l, ErrInventoryChanged
				}
				if scenario == "nil-lease" {
					return nil, nil
				}
				return l, nil
			}
			got, err := observeSSHSystemdProcess(ctx, snapshot, bind, func() error { return nil })
			if err == nil || !reflect.DeepEqual(got, ProcessSummary{}) {
				t.Fatal("accepted absent or failed observation", got, err)
			}
			if bound && scenario != "nil-lease" && l.closes != 1 {
				t.Fatal("failed observation leaked its lease")
			}
		})
	}
	if result, err := observeSSHSystemdProcess(context.Background(), nil, nil, nil); err == nil || !reflect.DeepEqual(result, ProcessSummary{}) {
		t.Fatal("accepted missing dependencies")
	}
}

func TestSSHProcessCoordinatorRefusesIncompleteIdentity(t *testing.T) {
	for _, scenario := range []string{"zero-root", "zero-namespace", "wrong-namespace", "missing-namespace", "wrong-pid", "zero-start", "invalid-digest", "wrong-group"} {
		t.Run(scenario, func(t *testing.T) {
			l := &sshProcessFixtureLease{identity: sshProcessFixtureIdentity()}
			switch scenario {
			case "zero-root":
				l.identity.Root.Inode = 0
			case "zero-namespace":
				l.identity.Namespaces["net"] = sshKernelIdentity{}
			case "wrong-namespace":
				l.identity.Namespaces["unexpected"] = l.identity.Namespaces["net"]
				delete(l.identity.Namespaces, "net")
			case "missing-namespace":
				delete(l.identity.Namespaces, "mnt")
			case "wrong-pid":
				l.identity.PID++
			case "zero-start":
				l.identity.StartTicks = 0
			case "invalid-digest":
				l.identity.ExecutableSHA256 = "invalid"
			case "wrong-group":
				l.identity.ControlGroupHash = strings.Repeat("0", 64)
			}
			snapshot := func(ctx context.Context) (sshSystemdSnapshot, error) {
				return observeSSHSystemdSnapshot(ctx, strings.Repeat("a", 64),
					sshFixtureQuery(sshManagerFixture("ssh.service", "", true, false, false)), func() error { return nil })
			}
			result, err := observeSSHSystemdProcess(context.Background(), snapshot,
				func(int, string) (sshProcessLease, error) { return l, nil }, func() error { return nil })
			if err == nil || !reflect.DeepEqual(result, ProcessSummary{}) || l.closes != 1 {
				t.Fatal("incomplete identity produced proof or leaked its lease", result, err, l.closes)
			}
		})
	}
}

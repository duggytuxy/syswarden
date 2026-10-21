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

func sshStartupFixture() sshStartupCommand {
	return sshStartupCommand{path: "/usr/sbin/sshd", args: []string{"/usr/sbin/sshd", "-D", "-f", MainPath}, flags: []string{}, started: 123456789, monotonic: 123456, pid: 100}
}
func sshStartupWire(c sshStartupCommand) []byte {
	wire, _ := json.Marshal(map[string]any{"type": "a(sasasttttuii)", "data": [][]any{{c.path, c.args, c.flags, c.started, c.monotonic, c.stopped, c.stopMonotonic, c.pid, c.code, c.status}}})
	return wire
}
func sshStartupSnapshot(t *testing.T) sshSystemdSnapshot {
	t.Helper()
	s, err := observeSSHSystemdSnapshot(context.Background(), strings.Repeat("a", 64), sshFixtureQuery(sshManagerFixture("ssh.service", "", true, false, false)), func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSSHStartupTypedStaticSelection(t *testing.T) {
	for _, path := range []string{"/usr/bin/sshd", "/usr/sbin/sshd"} {
		for _, args := range [][]string{{"-D"}, {"-D", "-e"}, {"-e", "-f", MainPath, "-D"}, {"-D", "-f", MainPath}} {
			t.Run(path+strings.Join(args, "_"), func(t *testing.T) {
				c := sshStartupFixture()
				c.path = path
				c.args = append([]string{path}, args...)
				decoded, err := decodeSSHStartup(sshStartupWire(c))
				if err != nil || !reflect.DeepEqual(c, decoded) {
					t.Fatal("typed arguments changed", err)
				}
				got, err := verifySSHStartup(decoded, sshStartupSnapshot(t), path)
				if err != nil || !got.DeclarationVerified || !lowerDigest.MatchString(got.CommandSHA256) || got.ExplicitConfiguration != strings.Contains(strings.Join(args, " "), "-f") {
					t.Fatal("incorrect static declaration", got, err)
				}
				wire, _ := json.Marshal(got)
				if strings.Contains(string(wire), path) || strings.Contains(string(wire), MainPath) || strings.Contains(string(wire), "123456") {
					t.Fatal("raw startup data leaked")
				}
			})
		}
	}
}

func TestSSHStartupRefusesOverridesAndAmbiguousInvocations(t *testing.T) {
	cases := map[string]func(*sshStartupCommand, *sshSystemdSnapshot){
		"other-file": func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args[3] = "/etc/ssh/alternative.conf" },
		"override": func(c *sshStartupCommand, _ *sshSystemdSnapshot) {
			c.args = []string{c.path, "-D", "-o", "AllowTcpForwarding=yes"}
		},
		"expansion":        func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = append(c.args, "$OPTIONS") },
		"braced-expansion": func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = append(c.args, "${SSHD_OPTS}") },
		"one-argument":     func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = []string{c.path, "-D -f " + MainPath} },
		"joined-f":         func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = []string{c.path, "-D", "-f" + MainPath} },
		"duplicate":        func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = append(c.args, "-D") },
		"missing-f-value":  func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = []string{c.path, "-D", "-f"} },
		"no-foreground":    func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = []string{c.path} },
		"debug":            func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = append(c.args, "-d") },
		"family-override":  func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = append(c.args, "-4") },
		"port-override":    func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = append(c.args, "-p2222") },
		"inetd":            func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args = append(c.args, "-i") },
		"shell":            func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.path = "/bin/sh" },
		"alias":            func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.path = "/usr/bin/sshd"; c.args[0] = c.path },
		"argv-zero":        func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.args[0] = "sshd" },
		"flags":            func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.flags = []string{"ignore-failure"} },
		"different-pid":    func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.pid++ },
		"different-start":  func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.monotonic++ },
		"stopped":          func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.stopped = 1 },
		"stop-monotonic":   func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.stopMonotonic = 1 },
		"no-realtime":      func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.started = 0 },
		"exited":           func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.code = 1 },
		"exit-status":      func(c *sshStartupCommand, _ *sshSystemdSnapshot) { c.status = 1 },
		"socket":           func(_ *sshStartupCommand, s *sshSystemdSnapshot) { s.summary.SocketActive = true },
		"instance":         func(_ *sshStartupCommand, s *sshSystemdSnapshot) { s.summary.SocketInstanced = true },
		"inactive":         func(_ *sshStartupCommand, s *sshSystemdSnapshot) { s.summary.ServiceActive = false },
		"no-manager":       func(_ *sshStartupCommand, s *sshSystemdSnapshot) { s.summary.ManagerObserved = false },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, s := sshStartupFixture(), sshStartupSnapshot(t)
			change(&c, &s)
			got, err := verifySSHStartup(c, s, "/usr/sbin/sshd")
			if err == nil || got != (StartupSummary{}) {
				t.Fatal("accepted unsupported declaration", got, err)
			}
		})
	}
}

func TestSSHStartupRejectsMalformedTypedWire(t *testing.T) {
	good := string(sshStartupWire(sshStartupFixture()))
	cases := []string{"", "null", "[]", "{}", good + good, good + " x", strings.Repeat("x", maxSSHSystemdOutput+1),
		strings.Replace(good, `"type":`, `"Type":`, 1), strings.Replace(good, `"type":`, `"type":"a(sasasttttuii)","type":`, 1),
		strings.Replace(good, `"type":`, `"\u0074ype":"a(sasasttttuii)","type":`, 1), strings.Replace(good, `"type":`, `"extra":0,"type":`, 1),
		strings.Replace(good, "a(sasasttttuii)", "a(sasbttttuii)", 1), strings.Replace(good, `"data":[[`, `"data":null,"other":[[`, 1),
		strings.Replace(good, `"data":[[`, `"data":[[null,`, 1), strings.Replace(good, `"data":[[`, `"data":[[],[`, 1),
		strings.Replace(good, "123456789", "1.5", 1), strings.Replace(good, "123456789", "-1", 1), strings.Replace(good, "123456789", "18446744073709551616", 1),
		strings.Replace(good, `[]`, `null`, 1), strings.Replace(good, `"-D"`, `"-D\u0000"`, 1), strings.Replace(good, `"-D"`, `""`, 1), strings.Replace(good, `"-D"`, "\"\xff\"", 1)}
	for i, bad := range cases {
		if got, err := decodeSSHStartup([]byte(bad)); err == nil || !reflect.DeepEqual(got, sshStartupCommand{}) {
			t.Fatalf("accepted malformed wire %d", i)
		}
	}
	// Preserve a single argument containing spaces. It must not become flags.
	c := sshStartupFixture()
	c.args = []string{c.path, "-D -f " + MainPath}
	got, err := decodeSSHStartup(sshStartupWire(c))
	if err != nil || len(got.args) != 2 {
		t.Fatal("lost exact argument boundaries", err)
	}
}

func TestSSHStartupCoordinatorHoldsInvocationAndRejectsPartialProof(t *testing.T) {
	for _, scenario := range []string{"stable", "changed-command", "first-error", "second-error", "cancel", "guard-drift", "close-error", "socket", "empty-proof"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := sshStartupSnapshot(t)
			if scenario == "socket" {
				s.summary.SocketActive = true
				s.summary.Mode = "socket"
			}
			snapshot := func(context.Context) (sshSystemdSnapshot, error) { return s, nil }
			lease := &sshProcessFixtureLease{identity: sshProcessFixtureIdentity()}
			if scenario == "close-error" {
				lease.closeErr = errors.New("fixture close failure")
			}
			bound, reads, guards := false, 0, 0
			guard := func() error {
				guards++
				if scenario == "guard-drift" && reads == 2 {
					return ErrInventoryChanged
				}
				return nil
			}
			query := func(context.Context, string) ([]byte, error) {
				reads++
				c := sshStartupFixture()
				if scenario == "first-error" && reads == 1 || scenario == "second-error" && reads == 2 {
					return nil, ErrInventoryChanged
				}
				if reads == 2 && scenario == "changed-command" {
					c.args = append(c.args, "-e")
				}
				if reads == 2 && scenario == "cancel" {
					cancel()
				}
				return sshStartupWire(c), nil
			}
			startup := func(ctx context.Context, s sshSystemdSnapshot) (StartupSummary, error) {
				if scenario == "empty-proof" {
					return StartupSummary{}, nil
				}
				return observeSSHStartup(ctx, s, "/usr/sbin/sshd", query, guard)
			}
			got, err := observeSSHSystemdProcessStartup(ctx, snapshot, func(int, string) (sshProcessLease, error) { bound = true; return lease, nil }, guard, startup)
			if scenario != "stable" {
				if err == nil || !reflect.DeepEqual(got, ProcessSummary{}) {
					t.Fatal("returned partial proof", got, err)
				}
				if (scenario == "first-error" || scenario == "socket" || scenario == "empty-proof") && bound {
					t.Fatal("bound process after refused startup")
				}
			} else if err != nil || got.Startup == nil || !got.Startup.DeclarationVerified || got.ConfigurationVerified || got.RuntimeActivated || got.AccessVerified || reads != 2 || guards != 7 {
				t.Fatal("incorrect composition", got, reads, guards, err)
			}
			if bound && lease.closes != 1 {
				t.Fatal("lease not closed")
			}
		})
	}
	s := sshStartupSnapshot(t)
	for _, ctx := range []context.Context{nil, context.Background()} {
		if got, err := observeSSHStartup(ctx, s, "/usr/sbin/sshd", nil, nil); err == nil || got != (StartupSummary{}) {
			t.Fatal("accepted nil prerequisites")
		}
	}
}

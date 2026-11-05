//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strings"
	"testing"
)

func sshUnitFixture(name string, loaded, active bool) sshSystemdUnit {
	properties, _ := sshSystemdProperties(name)
	u := make(sshSystemdUnit)
	for _, key := range strings.Split(properties, ",") {
		u[key] = ""
	}
	u["Id"], u["Names"] = name, name
	u["LoadState"], u["ActiveState"], u["SubState"] = "not-found", "inactive", "dead"
	u["NeedDaemonReload"], u["ControlPID"] = "no", "0"
	if strings.HasSuffix(name, ".service") {
		u["MainPID"], u["ExecMainStartTimestampMonotonic"] = "0", "0"
	} else {
		u["Accept"] = "no"
	}
	if loaded {
		u["LoadState"], u["UnitFileState"] = "loaded", "disabled"
		u["FragmentPath"] = "/usr/lib/systemd/system/" + name
	}
	if active {
		u["ActiveState"], u["SubState"] = "active", "running"
		u["InvocationID"] = strings.Repeat("a", 32)
		if strings.HasSuffix(name, ".service") {
			u["MainPID"], u["ExecMainStartTimestampMonotonic"] = "100", "123456"
			u["ControlGroup"] = "/system.slice/" + name
		} else {
			u["SubState"] = "listening"
		}
	}
	return u
}

func sshManagerFixture(service, socket string, running, listening, aliases bool) map[string]sshSystemdUnit {
	units := make(map[string]sshSystemdUnit)
	for _, name := range []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket"} {
		units[name] = sshUnitFixture(name, false, false)
	}
	if service != "" {
		units[service] = sshUnitFixture(service, true, running)
	}
	if socket != "" {
		units[socket] = sshUnitFixture(socket, true, listening)
		units[socket]["Triggers"] = service
		units[service]["TriggeredBy"] = socket
	}
	if aliases {
		for _, name := range []string{service, socket} {
			if name == "" {
				continue
			}
			suffix := strings.Split(name, ".")[1]
			units[name]["Names"] = "ssh." + suffix + " sshd." + suffix
			units["ssh."+suffix], units["sshd."+suffix] = maps.Clone(units[name]), maps.Clone(units[name])
		}
	}
	return units
}

func sshUnitWire(u sshSystemdUnit) []byte {
	var wire strings.Builder
	for _, key := range sortedKeys(u) {
		fmt.Fprintf(&wire, "%s=%s\n", key, u[key])
	}
	return []byte(wire.String())
}

func sshFixtureQuery(units map[string]sshSystemdUnit) sshSystemdRun {
	return func(_ context.Context, name string) ([]byte, error) { return sshUnitWire(units[name]), nil }
}

func TestSSHSystemdObservationModesAndAliases(t *testing.T) {
	for _, tc := range []struct {
		name, service, socket, mode string
		running, listening, aliases bool
	}{
		{"absent", "", "", "absent", false, false, false},
		{"inactive-rhel", "sshd.service", "", "inactive", false, false, false},
		{"active-rhel", "sshd.service", "", "service", true, false, false},
		{"debian-aliases", "ssh.service", "", "service", true, false, true},
		{"socket-demand", "ssh.service", "ssh.socket", "socket", false, true, false},
		{"socket-running", "ssh.service", "ssh.socket", "socket", true, true, false},
		{"socket-aliases", "sshd.service", "sshd.socket", "socket", true, true, true},
		{"inactive-socket", "sshd.service", "sshd.socket", "service", true, false, false},
		{"both-inactive", "ssh.service", "ssh.socket", "inactive", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			units := sshManagerFixture(tc.service, tc.socket, tc.running, tc.listening, tc.aliases)
			var requests []string
			checks := 0
			query := func(_ context.Context, name string) ([]byte, error) {
				requests = append(requests, name)
				return sshUnitWire(units[name]), nil
			}
			got, err := observeSSHSystemd(context.Background(), strings.Repeat("a", 64), query, func() error { checks++; return nil })
			if err != nil || got.Mode != tc.mode || got.Service != tc.service || got.Socket != tc.socket ||
				got.ServiceActive != tc.running || got.SocketActive != tc.listening || !got.ManagerObserved ||
				got.RuntimeActivated || got.ProcessVerified || got.ListenersVerified || got.AccessVerified {
				t.Fatal("incorrect manager observation or invented runtime proof", got, err)
			}
			want := []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket", "ssh.service", "sshd.service", "ssh.socket", "sshd.socket"}
			if !reflect.DeepEqual(requests, want) || checks != 17 || !lowerDigest.MatchString(got.UnitsSHA256) {
				t.Fatal("observation omitted a unit or a transport boundary", requests, checks)
			}
		})
	}
}

func TestSSHSystemdRejectsMalformedProperties(t *testing.T) {
	valid := sshUnitFixture("ssh.service", true, true)
	for key := range valid {
		t.Run("missing-"+key, func(t *testing.T) {
			u := maps.Clone(valid)
			delete(u, key)
			if _, err := parseSSHSystemdUnit("ssh.service", sshUnitWire(u)); err == nil {
				t.Fatal("accepted missing property")
			}
		})
	}
	for key, value := range map[string]string{
		"Id": "other.service", "Names": "ssh.service ssh.service", "LoadState": "masked", "ActiveState": "reloading", "SubState": "exited",
		"MainPID": "0", "ControlPID": "200", "ExecMainStartTimestampMonotonic": "0", "NeedDaemonReload": "yes",
		"Job": "17", "InvocationID": strings.Repeat("0", 32), "FragmentPath": "relative", "UnitFileState": "",
		"TriggeredBy": "other.socket", "ControlGroup": "/", "unknown": "anything",
	} {
		t.Run(key, func(t *testing.T) {
			u := maps.Clone(valid)
			u[key] = value
			if _, err := parseSSHSystemdUnit("ssh.service", sshUnitWire(u)); err == nil {
				t.Fatal("accepted invalid property")
			}
		})
	}
	wire := string(sshUnitWire(valid))
	for _, bad := range []string{"", wire + "\n", wire + "Id=ssh.service\n", strings.TrimSuffix(wire, "\n"),
		wire + "\x00\n", wire + "\r\n", wire + "\t\n", wire + "\x7f\n", wire + "\xff\n", strings.Repeat("a", maxSSHSystemdOutput+1)} {
		if _, err := parseSSHSystemdUnit("ssh.service", []byte(bad)); err == nil {
			t.Fatal("accepted invalid manager framing")
		}
	}
	for _, pid := range []string{"1", "-1", "+100", "0100", " 100", "4294967296"} {
		u := maps.Clone(valid)
		u["MainPID"] = pid
		if _, err := parseSSHSystemdUnit("ssh.service", sshUnitWire(u)); err == nil {
			t.Fatal("accepted noncanonical PID")
		}
	}
	inactive := sshUnitFixture("ssh.service", true, false)
	inactive["ControlGroup"] = "/system.slice/ssh.service"
	if _, err := parseSSHSystemdUnit("ssh.service", sshUnitWire(inactive)); err == nil {
		t.Fatal("accepted an inactive service with a residual cgroup")
	}
	if _, err := parseSSHSystemdUnit("ssh.service;reboot", []byte(wire)); err == nil {
		t.Fatal("accepted caller-selected unit")
	}
}

func TestSSHSystemdRefusesAmbiguousTopologies(t *testing.T) {
	for _, scenario := range []string{"distinct-services", "distinct-sockets", "unresolved-alias", "alias-drift", "no-target", "wrong-target", "no-reciprocal", "wrong-reciprocal", "accept-instances", "failed", "inactive-pid", "absent-fragment", "absent-history", "absent-alias"} {
		t.Run(scenario, func(t *testing.T) {
			u := sshManagerFixture("ssh.service", "ssh.socket", true, true, false)
			switch scenario {
			case "distinct-services":
				u["sshd.service"] = sshUnitFixture("sshd.service", true, true)
			case "distinct-sockets":
				u["sshd.socket"] = sshUnitFixture("sshd.socket", true, true)
			case "unresolved-alias":
				u["ssh.service"]["Names"] = "ssh.service sshd.service"
			case "alias-drift":
				u = sshManagerFixture("ssh.service", "ssh.socket", true, true, true)
				u["sshd.service"]["MainPID"] = "101"
			case "no-target":
				u["ssh.socket"]["Triggers"] = ""
			case "wrong-target":
				u["ssh.socket"]["Triggers"] = "sshd.service"
			case "no-reciprocal":
				u["ssh.service"]["TriggeredBy"] = ""
			case "wrong-reciprocal":
				u["ssh.service"]["TriggeredBy"] = "sshd.socket"
			case "accept-instances":
				u["ssh.socket"]["Accept"] = "yes"
			case "failed":
				u["ssh.socket"]["ActiveState"] = "failed"
			case "inactive-pid":
				u["ssh.service"]["ActiveState"], u["ssh.service"]["SubState"] = "inactive", "dead"
			case "absent-fragment":
				u["sshd.service"]["FragmentPath"] = "/etc/systemd/system/sshd.service"
			case "absent-history":
				u["sshd.service"]["ExecMainStartTimestampMonotonic"] = "42"
			case "absent-alias":
				u["sshd.service"]["Names"] = "sshd.service ssh.service"
			}
			result, err := observeSSHSystemd(context.Background(), strings.Repeat("a", 64), sshFixtureQuery(u), func() error { return nil })
			if err == nil || result != (SystemdSummary{}) {
				t.Fatal("accepted ambiguous topology or returned partial success", result, err)
			}
		})
	}
}

func TestSSHSystemdObservationRechecksFailuresAndDrift(t *testing.T) {
	for _, scenario := range []string{"query-failure", "manager-before", "manager-after", "manager-final", "changed-second-pass", "cancel-before", "cancel-after"} {
		t.Run(scenario, func(t *testing.T) {
			u := sshManagerFixture("ssh.service", "", true, false, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, checks := 0, 0
			if scenario == "cancel-before" {
				cancel()
			}
			query := func(_ context.Context, name string) ([]byte, error) {
				calls++
				if scenario == "query-failure" {
					return nil, errors.New("query failed")
				}
				if scenario == "cancel-after" {
					cancel()
				}
				if scenario == "changed-second-pass" && calls == 5 {
					u["ssh.service"]["MainPID"] = "101"
				}
				return sshUnitWire(u[name]), nil
			}
			guard := func() error {
				checks++
				if (scenario == "manager-before" && checks == 1) || (scenario == "manager-after" && checks == 2) || (scenario == "manager-final" && checks == 17) {
					return ErrInventoryChanged
				}
				return nil
			}
			got, err := observeSSHSystemd(ctx, strings.Repeat("a", 64), query, guard)
			if err == nil || got != (SystemdSummary{}) {
				t.Fatal("accepted drift or failure", got, err)
			}
			if scenario == "query-failure" && checks != 2 {
				t.Fatal("failed query escaped its post-check")
			}
		})
	}
}

func TestSSHSystemdBindsObservedPropertiesAndRejectsInvalidInputs(t *testing.T) {
	u := sshManagerFixture("sshd.service", "", true, false, false)
	query, guard := sshFixtureQuery(u), func() error { return nil }
	first, err := observeSSHSystemd(context.Background(), strings.Repeat("a", 64), query, guard)
	if err != nil {
		t.Fatal(err)
	}
	u["sshd.service"]["DropInPaths"] = "/etc/systemd/system/sshd.service.d/administrator.conf"
	second, err := observeSSHSystemd(context.Background(), strings.Repeat("a", 64), query, guard)
	if err != nil || first.UnitsSHA256 == second.UnitsSHA256 {
		t.Fatal("lost configuration observation", err)
	}
	for _, tc := range []struct {
		ctx    context.Context
		digest string
		run    sshSystemdRun
		guard  func() error
	}{
		{nil, strings.Repeat("a", 64), query, guard}, {context.Background(), "bad", query, guard},
		{context.Background(), strings.Repeat("a", 64), nil, guard}, {context.Background(), strings.Repeat("a", 64), query, nil},
	} {
		if result, err := observeSSHSystemd(tc.ctx, tc.digest, tc.run, tc.guard); err == nil || result != (SystemdSummary{}) {
			t.Fatal("accepted missing prerequisite")
		}
	}
	if os.Geteuid() != 0 {
		if _, err := ObserveSystemdRuntime(); err == nil {
			t.Fatal("unprivileged public observation accepted")
		}
	}
}

func TestSSHSystemdRecordsInactiveVendorInstancedSocket(t *testing.T) {
	for _, running := range []bool{false, true} {
		units := sshManagerFixture("sshd.service", "", running, false, false)
		units["sshd.socket"] = sshUnitFixture("sshd.socket", true, false)
		units["sshd.socket"]["Accept"] = "yes"
		result, err := observeSSHSystemd(context.Background(), strings.Repeat("a", 64), sshFixtureQuery(units), func() error { return nil })
		if err != nil || !result.SocketInstanced || result.SocketActive || result.ServiceActive != running || result.RuntimeActivated {
			t.Fatal("unused vendor socket changed the observed service", err)
		}
		units["sshd.socket"]["Triggers"] = "sshd.service"
		if _, err := observeSSHSystemd(context.Background(), strings.Repeat("a", 64), sshFixtureQuery(units), func() error { return nil }); err == nil {
			t.Fatal("accepted contradictory instanced target")
		}
	}
	if _, err := classifySSHSystemd(nil, strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted incomplete map")
	}
}

func TestSSHSystemdInactiveSocketMayLackRuntimeReverseReference(t *testing.T) {
	for _, scenario := range []string{"inactive", "inactive-alias", "active", "wrong-target", "missing-target", "wrong-reverse", "changing"} {
		t.Run(scenario, func(t *testing.T) {
			units := sshManagerFixture("ssh.service", "ssh.socket", true, scenario == "active", scenario == "inactive-alias")
			units["ssh.service"]["TriggeredBy"] = ""
			if scenario == "inactive-alias" {
				units["sshd.service"]["TriggeredBy"] = ""
			}
			switch scenario {
			case "wrong-target":
				units["ssh.socket"]["Triggers"] = "sshd.service"
			case "missing-target":
				units["ssh.socket"]["Triggers"] = ""
			case "wrong-reverse":
				units["ssh.service"]["TriggeredBy"] = "sshd.socket"
			}
			calls := 0
			query := func(_ context.Context, name string) ([]byte, error) {
				calls++
				if scenario == "changing" && calls == 5 {
					units["ssh.service"]["TriggeredBy"] = "ssh.socket"
				}
				return sshUnitWire(units[name]), nil
			}
			got, err := observeSSHSystemd(context.Background(), strings.Repeat("a", 64), query, func() error { return nil })
			if scenario == "inactive" || scenario == "inactive-alias" {
				if err != nil || !got.ServiceActive || got.SocketActive || got.Mode != "service" || got.RuntimeActivated {
					t.Fatal("inactive socket blocked service observation", got, err)
				}
			} else if err == nil || got != (SystemdSummary{}) {
				t.Fatal("ambiguous socket observation accepted", got, err)
			}
		})
	}
}

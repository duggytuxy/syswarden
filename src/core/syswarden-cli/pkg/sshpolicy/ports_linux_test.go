//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

const portFixtureOutput = "port 2222\nport 22\nlistenaddress [::]:2222\nlistenaddress 192.0.2.30:2200\nallowtcpforwarding local\n"

func TestEffectivePortsPreserveDistinctPortAndListenAddressSets(t *testing.T) {
	tests := []struct {
		name, output          string
		configured, listeners []uint16
	}{
		{"default-from-parser", "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n", []uint16{22}, []uint16{22}},
		{"explicit-listen-port", "port 22\nlistenaddress 127.0.0.1:2222\n", []uint16{22}, []uint16{2222}},
		{"multiple", portFixtureOutput, []uint16{22, 2222}, []uint16{2200, 2222}},
		{"repeated", "port 2222\nport 2222\nlistenaddress 0.0.0.0:2222\nlistenaddress [::]:2222\n", []uint16{2222}, []uint16{2222}},
		{"ipv6-zone", "port 65535\nlistenaddress [fe80::1%eth0]:65535\n", []uint16{65535}, []uint16{65535}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			values, err := parseEffective([]byte(tc.output))
			if err != nil {
				t.Fatal(err)
			}
			before := strings.Join(values["port"], "\n")
			ports, listeners, err := effectivePorts(values)
			if err != nil || !reflect.DeepEqual(ports, tc.configured) || !reflect.DeepEqual(listeners, tc.listeners) {
				t.Fatalf("ports=%v listeners=%v err=%v", ports, listeners, err)
			}
			if strings.Join(values["port"], "\n") != before {
				t.Fatal("changed parser input")
			}
		})
	}
}

func TestEffectivePortsRejectAmbiguityWithoutGuessing(t *testing.T) {
	for _, output := range []string{
		"allowtcpforwarding yes\n", "port 22\n", "listenaddress 0.0.0.0:22\n",
		"port 0\nlistenaddress 0.0.0.0:22\n", "port 65536\nlistenaddress 0.0.0.0:22\n",
		"port 022\nlistenaddress 0.0.0.0:22\n", "port +22\nlistenaddress 0.0.0.0:22\n",
		"port 22 2222\nlistenaddress 0.0.0.0:22\n", "port 22\nlistenaddress *:22\n",
		"port 22\nlistenaddress private.example:22\n", "port 22\nlistenaddress [::]:0\n",
		"port 22\nlistenaddress [::]:022\n", "port 22\nlistenaddress [::]:22 rdomain private\n",
		"port 22\nlistenaddress ::22\n", "port 22\nlistenaddress 0.0.0.0:ssh\n",
		"port 22\nlistenaddress 0.0.0.0:65536\n",
		strings.Repeat("port 22\n", 257) + "listenaddress 0.0.0.0:22\n",
		"port 22\n" + strings.Repeat("listenaddress [::]:22\n", 513),
	} {
		values, err := parseEffective([]byte(output))
		if err != nil {
			t.Fatal(err)
		}
		ports, listeners, err := effectivePorts(values)
		if err == nil || ports != nil || listeners != nil {
			t.Fatal("invented a port from ambiguous output")
		}
		if strings.Contains(err.Error(), "private") {
			t.Fatal("disclosed private parser values")
		}
	}
}

func TestPortInspectionNeedsNoIntentAndNeverPublishesOrAltersConfiguration(t *testing.T) {
	f := newInventoryFixture(t, includeDropIns+"AllowTcpForwarding local\n")
	f.write(DropInPath, "# Existing administrator-managed contents are observation only.\n")
	inventory := f.open()
	var calls, checks int
	run := func(_ context.Context, image *parserImage, mode, access string) ([]byte, error) {
		calls++
		if access != "" {
			t.Fatal("port inspection invented an access context")
		}
		if mode == "syntax" {
			return nil, nil
		}
		return []byte(portFixtureOutput), nil
	}
	recheck := func() error { checks++; return inventory.Recheck() }
	result, err := inspectPorts(context.Background(), inventory.snapshot, strings.Repeat("a", 64), run, recheck)
	if err != nil || !result.ParserVerified || result.RuntimeVerified || result.HardeningApplied ||
		result.Schema != 1 || calls != 4 || checks != 9 || !reflect.DeepEqual(result.ListenPorts, []uint16{2200, 2222}) {
		t.Fatalf("invalid observation: %+v calls=%d checks=%d err=%v", result, calls, checks, err)
	}
	current, err := collectInventory(f.root, os.Geteuid())
	if err != nil || !reflect.DeepEqual(current, inventory.snapshot) {
		t.Fatal("changed source inventory")
	}
	for _, name := range []string{IntentPath, "/var/lib/syswarden"} {
		if _, err := os.Lstat(f.path(name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("created intent or state")
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"192.0.2.30", "allowtcpforwarding", "administrator", "local"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("disclosed unrelated configuration")
		}
	}
}

func TestPortInspectionFailsClosedAtEveryBoundary(t *testing.T) {
	for _, scenario := range []string{"syntax-live", "syntax-sealed", "effective-live", "effective-sealed",
		"changed-port", "changed-unrelated", "malformed", "missing-listener", "before", "after", "final", "cancel-before", "cancel-after"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			inventory := f.open()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel-before" {
				cancel()
			}
			calls, checks := 0, 0
			run := func(_ context.Context, image *parserImage, mode, _ string) ([]byte, error) {
				calls++
				if scenario == "cancel-after" {
					cancel()
				}
				phase := "live"
				if image != nil {
					phase = "sealed"
				}
				if scenario == mode+"-"+phase {
					return nil, errors.New("fixture refusal")
				}
				if mode == "syntax" {
					return nil, nil
				}
				output := portFixtureOutput
				if scenario == "changed-port" && image != nil {
					output = strings.ReplaceAll(output, "2222", "3333")
				}
				if scenario == "changed-unrelated" && image != nil {
					output += "permitrootlogin yes\n"
				}
				if scenario == "malformed" {
					output = "\x00"
				}
				if scenario == "missing-listener" {
					output = "port 22\n"
				}
				return []byte(output), nil
			}
			recheck := func() error {
				checks++
				if (scenario == "before" && checks == 1) || (scenario == "after" && checks == 2) || (scenario == "final" && checks == 9) {
					return ErrInventoryChanged
				}
				return inventory.Recheck()
			}
			result, err := inspectPorts(ctx, inventory.snapshot, strings.Repeat("a", 64), run, recheck)
			if err == nil || !reflect.DeepEqual(result, PortSummary{}) {
				t.Fatal("returned a partial or stale port observation")
			}
			if (scenario == "before" || scenario == "cancel-before") && calls != 0 {
				t.Fatal("ran parser after refusal")
			}
		})
	}
}

func TestPortInspectionRechecksProtectedIncludesOnParserFailure(t *testing.T) {
	f := newInventoryFixture(t, includeDropIns)
	inventory := f.open()
	run := func(context.Context, *parserImage, string, string) ([]byte, error) {
		f.write("/etc/ssh/sshd_config.d/50-automation.conf", "Port 3333\n")
		return nil, errors.New("fixture parser failure")
	}
	result, err := inspectPorts(context.Background(), inventory.snapshot, strings.Repeat("a", 64), run, inventory.Recheck)
	if !errors.Is(err, ErrInventoryChanged) || !reflect.DeepEqual(result, PortSummary{}) {
		t.Fatal("missed changed Include membership")
	}
}

func TestPortInspectionRejectsInvalidDependencies(t *testing.T) {
	f := newInventoryFixture(t, includeDropIns)
	inventory := f.open()
	run := func(context.Context, *parserImage, string, string) ([]byte, error) {
		t.Fatal("unexpected execution")
		return nil, nil
	}
	for _, scenario := range []string{"context", "runner", "recheck", "digest", "inventory"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, parser, check, digest, snapshot := context.Background(), sshParserRun(run), inventory.Recheck, strings.Repeat("a", 64), inventory.snapshot
			switch scenario {
			case "context":
				ctx = nil
			case "runner":
				parser = nil
			case "recheck":
				check = nil
			case "digest":
				digest = strings.Repeat("A", 64)
			case "inventory":
				snapshot = inventorySnapshot{}
			}
			result, err := inspectPorts(ctx, snapshot, digest, parser, check)
			if err == nil || !reflect.DeepEqual(result, PortSummary{}) {
				t.Fatal("accepted invalid prerequisite")
			}
		})
	}
	if os.Geteuid() != 0 {
		if result, err := InspectPorts(); err == nil || !reflect.DeepEqual(result, PortSummary{}) {
			t.Fatal("public inspection accepted a non-root caller")
		}
	}
}

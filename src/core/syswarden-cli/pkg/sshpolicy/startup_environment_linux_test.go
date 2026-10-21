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

func sshEnvironmentWire(kind string, data any) []byte {
	wire, _ := json.Marshal(map[string]any{"type": kind, "data": data})
	return wire
}

func TestSSHStartupEnvironmentFileSubset(t *testing.T) {
	for _, text := range []string{"OPTIONS=\n", " OPTIONS = \"\" \r\n", "OPTIONS=''", "# comment\n; comment\nOPTIONS=-oBad=yes\nOPTIONS=\n", "OTHER='literal $VALUE'\nOPTIONS=\n"} {
		got, err := parseSSHStartupEnvironmentFile([]byte(text))
		value, present := got["OPTIONS"]
		if err != nil || !present || value != "" {
			t.Fatal("lost explicit empty assignment", err)
		}
	}
	for _, text := range []string{"export OPTIONS=", "OPTIONS=\\\n", "OPTIONS='unterminated", "OPTIONS=\"\" # suffix", "OPTIONS='a' 'b'", "OPTIONS=a\"b\"", "OPTIONS=a\rb", "OPTIONS=\x00", "OPTIONS=\xff", "OPTIONS=\ufeff", "OPTIONS=\ufdd0", "OPTIONS=\U0001ffff", "OPTIONS=\x1b", "=", "1OPTION=", "not an assignment", strings.Repeat("x", maxSSHSystemdOutput+1)} {
		if got, err := parseSSHStartupEnvironmentFile([]byte(text)); err == nil || got != nil {
			t.Fatal("accepted ambiguous environment syntax")
		}
	}
	for _, text := range []string{"OPTIONS=\" \"", "OPTIONS='-oAllowTcpForwarding=yes'", "OPTIONS=$OTHER", "OPTIONS= # literal value"} {
		got, err := parseSSHStartupEnvironmentFile([]byte(text))
		if err != nil || got["OPTIONS"] == "" {
			t.Fatal("nonempty was erased", err)
		}
	}
}

func TestSSHStartupEnvironmentTypedBounds(t *testing.T) {
	env := sshEnvironmentWire("as", []string{"OPTIONS="})
	files := sshEnvironmentWire("a(sb)", [][]any{{"/etc/default/ssh", true}})
	pam := sshEnvironmentWire("s", "")
	if _, err := decodeSSHStartupEnvironment(env, files, pam); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		field int
		wire  string
	}{
		{0, `{"type":"as","data":null}`}, {0, `{"type":"as","data":[ null ]}`},
		{0, `{"type":"as","data":["OPTIONS"]}`}, {0, `{"type":"as","data":["1OPTIONS="]}`},
		{0, `{"type":"as","data":["OPTIONS=\u0000"]}`}, {0, `{"type":"as","data":[""]}`},
		{1, `{"type":"a(sb)","data":null}`}, {1, `{"type":"a(sb)","data":[["/etc/default/ssh", null ]]}`},
		{1, `{"type":"a(sb)","data":[["/etc/default/ssh",0]]}`}, {1, `{"type":"a(sb)","data":[["/etc/default/ssh"]]}`},
		{1, `{"type":"a(sb)","data":[["/etc/default/*",true]]}`}, {1, `{"type":"a(sb)","data":[["/etc/default/../ssh",true]]}`},
		{1, `{"type":"a(sb)","data":[["/etc/default/ssh",true],["/etc/default/ssh",false]]}`},
		{2, `{"type":"s","data": null }`}, {2, `{"type":"s","data":"sshd"}`}, {2, `{"type":"s","data":[""]}`},
	} {
		wires := [][]byte{env, files, pam}
		wires[change.field] = []byte(change.wire)
		if got, err := decodeSSHStartupEnvironment(wires[0], wires[1], wires[2]); err == nil || !reflect.DeepEqual(got, sshStartupEnvironment{}) {
			t.Fatal("accepted malformed property", change.field)
		}
	}
}

func TestSSHStartupEnvironmentStorageAndPrecedence(t *testing.T) {
	for _, scenario := range []string{"explicit-file", "unit-only", "optional-missing", "required-missing", "later-file", "symlink", "hardlink", "writable", "writable-parent", "wrong-owner", "malformed", "unknown-path"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			f.write("/etc/default/ssh", "OPTIONS=\n")
			e := sshStartupEnvironment{[]string{"OPTIONS=-oBad=yes"}, []sshEnvironmentFile{{"/etc/default/ssh", true}}}
			uid := os.Geteuid()
			switch scenario {
			case "unit-only":
				e.assignments = []string{"OPTIONS="}
				e.files = nil
			case "optional-missing", "required-missing":
				if err := os.Remove(f.path("/etc/default/ssh")); err != nil {
					t.Fatal(err)
				}
				e.files[0].optional = scenario == "optional-missing"
			case "later-file":
				f.write("/etc/sysconfig/sshd", "OPTIONS=-oBad=yes\n")
				e.files = append(e.files, sshEnvironmentFile{"/etc/sysconfig/sshd", true})
			case "symlink":
				if err := os.Rename(f.path("/etc/default/ssh"), f.path("/etc/default/saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("saved", f.path("/etc/default/ssh")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path("/etc/default/ssh"), f.path("/etc/default/saved")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := f.chmod("/etc/default/ssh", 0666); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := f.chmod("/etc/default", 0777); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			case "malformed":
				f.write("/etc/default/ssh", "OPTIONS=\\\n")
			case "unknown-path":
				e.files[0].path = "/tmp/ssh-env"
			}
			values, snapshot, err := readSSHStartupEnvironment(f.root, uid, e)
			safe := scenario == "explicit-file" || scenario == "unit-only" || scenario == "optional-missing" || scenario == "later-file"
			if !safe {
				if err == nil || values != nil || !reflect.DeepEqual(snapshot, inventorySnapshot{}) {
					t.Fatal("accepted unsafe environment file")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if scenario == "optional-missing" || scenario == "later-file" {
				want = "-oBad=yes"
			}
			if values["OPTIONS"] != want {
				t.Fatal("lost ordered assignment precedence")
			}
			if scenario == "optional-missing" {
				if st, ok := snapshot.nodes["/etc/default/ssh"]; !ok || st.exists {
					t.Fatal("lost negative lookup")
				}
			}
		})
	}
}

func TestSSHStartupOnlyExplicitEmptyStandaloneVariables(t *testing.T) {
	for _, scenario := range []string{"options", "sshd-opts", "both", "absent", "nonempty", "whitespace", "braced", "embedded", "unknown", "duplicate", "missing-proof", "changed-digest", "file-override", "no-capture"} {
		t.Run(scenario, func(t *testing.T) {
			c := sshStartupFixture()
			c.args = append(c.args, "$OPTIONS")
			e := sshEnvironmentResult{map[string]string{"OPTIONS": "", "SSHD_OPTS": ""}, strings.Repeat("a", 64)}
			switch scenario {
			case "sshd-opts":
				c.args[len(c.args)-1] = "$SSHD_OPTS"
			case "both":
				c.args = append(c.args, "$SSHD_OPTS")
			case "absent":
				delete(e.values, "OPTIONS")
			case "nonempty":
				e.values["OPTIONS"] = "-oAllowTcpForwarding=yes"
			case "whitespace":
				e.values["OPTIONS"] = " "
			case "braced":
				c.args[len(c.args)-1] = "${OPTIONS}"
			case "embedded":
				c.args[len(c.args)-1] = "-o$OPTIONS"
			case "unknown":
				c.args[len(c.args)-1] = "$CRYPTO_POLICY"
			case "duplicate":
				c.args = append(c.args, "$OPTIONS")
			case "missing-proof":
				e.digest = ""
			case "changed-digest":
				e.digest = strings.Repeat("b", 64)
			case "file-override":
				c.args[3] = "/etc/ssh/other.conf"
			}
			capture := sshEnvironmentCapture(func(context.Context, string) (sshEnvironmentResult, error) { return e, nil })
			if scenario == "no-capture" {
				capture = nil
			}
			got, err := observeSSHStartupEnvironment(context.Background(), sshStartupSnapshot(t), c.path, func(context.Context, string) ([]byte, error) { return sshStartupWire(c), nil }, func() error { return nil }, capture)
			safe := scenario == "options" || scenario == "sshd-opts" || scenario == "both" || scenario == "changed-digest"
			if !safe {
				if err == nil || got != (StartupSummary{}) {
					t.Fatal("accepted unqualified options", err)
				}
				return
			}
			if err != nil || !got.DeclarationVerified || got.EnvironmentSHA256 != e.digest {
				t.Fatal("lost bound environment", err)
			}
			static := sshStartupFixture()
			staticSummary, err := verifySSHStartup(static, sshStartupSnapshot(t), c.path)
			if err != nil || staticSummary.CommandSHA256 == got.CommandSHA256 {
				t.Fatal("lost original variable declaration")
			}
			wire, _ := json.Marshal(got)
			if strings.Contains(string(wire), "OPTIONS") || strings.Contains(string(wire), "/etc/") {
				t.Fatal("raw environment leaked")
			}
		})
	}
}

func TestSSHStartupEnvironmentCaptureDrift(t *testing.T) {
	for _, scenario := range []string{"stable", "property-change", "replacement", "appearance", "parent-mode", "cancel", "query-error", "guard-error"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			f.write("/etc/default/ssh", "OPTIONS=\n")
			if scenario == "appearance" {
				if err := os.Remove(f.path("/etc/default/ssh")); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			query := func(_ context.Context, key string) ([]byte, error) {
				calls++
				if calls == 4 {
					switch scenario {
					case "replacement":
						f.write("/etc/default/new", "OPTIONS=\n")
						if err := os.Rename(f.path("/etc/default/new"), f.path("/etc/default/ssh")); err != nil {
							t.Fatal(err)
						}
					case "appearance":
						f.write("/etc/default/ssh", "OPTIONS=\n")
					case "parent-mode":
						if err := f.chmod("/etc/default", 0777); err != nil {
							t.Fatal(err)
						}
					case "cancel":
						cancel()
					case "query-error":
						return nil, errors.New("fixture query failed")
					}
				}
				switch key {
				case "ssh.service/environment":
					v := []string{"OPTIONS="}
					if calls == 4 && scenario == "property-change" {
						v = []string{"OPTIONS=-oBad=yes"}
					}
					return sshEnvironmentWire("as", v), nil
				case "ssh.service/environment-files":
					return sshEnvironmentWire("a(sb)", [][]any{{"/etc/default/ssh", true}}), nil
				case "ssh.service/pam-name":
					return sshEnvironmentWire("s", ""), nil
				default:
					t.Fatal("unexpected query")
					return nil, ErrInventoryUnsafe
				}
			}
			guard := func() error {
				if calls >= 6 && scenario == "guard-error" {
					return ErrInventoryChanged
				}
				return nil
			}
			got, err := captureSSHStartupEnvironment(ctx, "ssh.service", f.root, os.Geteuid(), query, guard)
			if scenario == "stable" {
				if err != nil || got.values["OPTIONS"] != "" || !lowerDigest.MatchString(got.digest) || calls != 6 {
					t.Fatal("bad stable capture", err)
				}
			} else if err == nil || got.values != nil || got.digest != "" {
				t.Fatal("accepted changed environment", err)
			}
		})
	}
}

func TestSSHStartupEnvironmentTransportAndInstalledOracle(t *testing.T) {
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// A descriptor is sufficient to inspect fixed command construction; it is not executed.
	tool := &sshBusctl{file: root}
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		for _, item := range []struct{ key, property string }{{"environment", "Environment"}, {"environment-files", "EnvironmentFiles"}, {"pam-name", "PAMName"}} {
			key := unit + "/" + item.key
			command, err := tool.command(context.Background(), key)
			if err != nil || !validSSHStartupQuery(key) || command.Args[len(command.Args)-1] != item.property || command.Args[9] != "/org/freedesktop/systemd1/unit/"+strings.ReplaceAll(unit, ".", "_2e") {
				t.Fatal("invalid fixed property query", err)
			}
			if command.Path != "/proc/self/fd/3" || len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != root || len(command.Env) != 2 || command.Dir != "/" {
				t.Fatal("unbounded helper")
			}
		}
	}
	if os.Getenv("SYSWARDEN_SSH_SYSTEMD_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_SYSTEMD_ORACLE_TEST=1 for installed read-only property oracle")
	}
	pinned, err := openSSHBusctl(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.file.Close()
	var wires [][]byte
	for _, property := range []string{"environment", "environment-files", "pam-name"} {
		wire, err := pinned.run(context.Background(), "sshd.service/"+property)
		if err != nil {
			t.Fatal("installed property query failed", err)
		}
		wires = append(wires, wire)
	}
	if _, err := decodeSSHStartupEnvironment(wires[0], wires[1], wires[2]); err != nil {
		t.Fatal("installed property decoding failed", err)
	}
	if err := pinned.recheck(root, 0); err != nil {
		t.Fatal(err)
	}
}

func TestSSHStartupEnvironmentChangesInvalidateProcessSummary(t *testing.T) {
	for _, changed := range []bool{false, true} {
		snapshot := sshStartupSnapshot(t)
		lease := &sshProcessFixtureLease{identity: sshProcessFixtureIdentity()}
		calls := 0
		startup := func(ctx context.Context, s sshSystemdSnapshot) (StartupSummary, error) {
			calls++
			c := sshStartupFixture()
			c.args = append(c.args, "$OPTIONS")
			capture := func(context.Context, string) (sshEnvironmentResult, error) {
				digest := strings.Repeat("a", 64)
				if changed && calls == 2 {
					digest = strings.Repeat("b", 64)
				}
				return sshEnvironmentResult{map[string]string{"OPTIONS": ""}, digest}, nil
			}
			return observeSSHStartupEnvironment(ctx, s, c.path, func(context.Context, string) ([]byte, error) { return sshStartupWire(c), nil }, func() error { return nil }, capture)
		}
		got, err := observeSSHSystemdProcessStartup(context.Background(), func(context.Context) (sshSystemdSnapshot, error) { return snapshot, nil }, func(int, string) (sshProcessLease, error) { return lease, nil }, func() error { return nil }, startup)
		if changed {
			if err == nil || !reflect.DeepEqual(got, ProcessSummary{}) {
				t.Fatal("accepted changed source with identical effective options")
			}
		} else if err != nil || got.Startup == nil || got.Startup.EnvironmentSHA256 == "" || got.ConfigurationVerified || got.RuntimeActivated || got.AccessVerified {
			t.Fatal("incorrect environment composition", err)
		}
		if lease.closes != 1 || calls != 2 {
			t.Fatal("lost process lease boundary")
		}
	}
}

func TestSSHStartupEnvironmentResourceAndCancellationBounds(t *testing.T) {
	assignments := make([]string, 129)
	for i := range assignments {
		assignments[i] = "OPTIONS="
	}
	files := sshEnvironmentWire("a(sb)", [][]any{})
	pam := sshEnvironmentWire("s", "")
	for _, env := range [][]byte{sshEnvironmentWire("as", assignments), sshEnvironmentWire("as", []string{"OPTIONS=" + strings.Repeat("x", 4097)})} {
		if _, err := decodeSSHStartupEnvironment(env, files, pam); err == nil {
			t.Fatal("accepted excessive environment")
		}
	}
	f := newInventoryFixture(t, includeDropIns)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	query := func(context.Context, string) ([]byte, error) { called = true; return nil, nil }
	got, err := captureSSHStartupEnvironment(ctx, "ssh.service", f.root, os.Geteuid(), query, func() error { return nil })
	if err == nil || called || got.values != nil || got.digest != "" {
		t.Fatal("cancelled capture read a property")
	}
	for _, unit := range []string{"", "sshd.socket", "ssh.service/environment", "sshd.service;reboot"} {
		if _, err := captureSSHStartupEnvironment(context.Background(), unit, f.root, os.Geteuid(), query, func() error { return nil }); err == nil {
			t.Fatal("accepted unknown unit")
		}
	}
}

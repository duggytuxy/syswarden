//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSSHDefaultConfigurationTraceBindsFirstLoad(t *testing.T) {
	const correct = "debug2: load_server_config: filename /etc/ssh/sshd_config\r\n"
	for _, test := range []struct {
		name, trace string
		valid       bool
	}{
		{"main", correct, true},
		{"includes", correct + "debug2: load_server_config: filename /etc/ssh/sshd_config.d/vendor.conf\r\n", true},
		{"line-feed", strings.ReplaceAll(correct, "\r", ""), true},
		{"preamble", "debug1: sshd version OpenSSH_10.0, fixture\r\n" + correct, true},
		{"other-main-before-include", "debug2: load_server_config: filename /opt/custom/sshd_config\n" + correct, false},
		{"same-name-other-directory", strings.ReplaceAll(correct, "/etc/ssh/", "/usr/local/etc/"), false},
		{"relative", strings.ReplaceAll(correct, "/etc/ssh/", ""), false},
		{"noncanonical", strings.ReplaceAll(correct, "/etc/ssh/", "/etc/ssh/../ssh/"), false},
		{"diagnostic-substring", "debug3: arbitrary diagnostic " + correct, false},
		{"trailing-data", strings.TrimSpace(correct) + " extra\n", false},
		{"unsupported-format", strings.ReplaceAll(correct, "debug2:", "debug1:"), false},
		{"unsupported-main-before-include", "debug1: load_server_config: filename /opt/fixture/sshd_config\n" + correct, false},
		{"empty", "", false},
		{"missing", "debug1: fixture\n", false},
		{"nul", correct + "\x00", false},
		{"invalid-utf8", correct + "\xff", false},
		{"oversize", correct + strings.Repeat("x", MaxBytes), false},
		{"long-preamble", strings.Repeat("x", 2*MaxLineBytes+1) + "\n" + correct, false},
		{"long-suffix", correct + strings.Repeat("x", 2*MaxLineBytes+1) + "\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifySSHDefaultConfigurationTrace([]byte(test.trace))
			if (err == nil) != test.valid {
				t.Fatal("incorrect compiled-path decision", err)
			}
			if err != nil && strings.Contains(err.Error(), "/opt/custom") {
				t.Fatal("private trace leaked")
			}
		})
	}
}

func TestSSHConfigurationSelectionRefusesDriftAndUncertainProbe(t *testing.T) {
	for _, scenario := range []string{"default", "explicit", "nil-context", "nil-guard", "nil-run", "undeclared", "schema",
		"command-digest", "parser-digest", "empty-policy", "cancel-before", "guard-before", "cancel-in-guard",
		"probe-error", "cancel-in-probe", "guard-after", "wrong-path", "different-policy", "missing-policy",
		"malformed-policy", "wrong-debug-mode", "repeated-debug-mode", "guard-final", "cancel-final"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var parent context.Context = ctx
			startup := StartupSummary{Schema: 1, DeclarationVerified: true, CommandSHA256: strings.Repeat("a", 64)}
			digest := strings.Repeat("b", 64)
			expected := sshEffective{"port": {"2222"}, "allowtcpforwarding": {"no"}, "loglevel": {"VERBOSE"}}
			output := []byte("port 2222\nallowtcpforwarding no\nloglevel DEBUG3\n")
			trace := []byte("debug2: load_server_config: filename " + MainPath + "\n")
			calls, checks := 0, 0
			guard := func() error {
				checks++
				if scenario == "cancel-in-guard" || scenario == "cancel-final" && checks == 3 {
					cancel()
				}
				if scenario == "guard-before" || scenario == "guard-after" && checks == 2 || scenario == "guard-final" && checks == 3 {
					return ErrInventoryChanged
				}
				return nil
			}
			run := func(context.Context) ([]byte, []byte, error) {
				calls++
				if scenario == "cancel-in-probe" {
					cancel()
				}
				if scenario == "probe-error" {
					return output, trace, ErrInventoryChanged
				}
				return output, trace, nil
			}
			switch scenario {
			case "explicit":
				startup.ExplicitConfiguration = true
			case "nil-context":
				parent = nil
			case "nil-guard":
				guard = nil
			case "nil-run":
				run = nil
			case "undeclared":
				startup.DeclarationVerified = false
			case "schema":
				startup.Schema = 2
			case "command-digest":
				startup.CommandSHA256 = ""
			case "parser-digest":
				digest = ""
			case "empty-policy":
				expected = nil
			case "cancel-before":
				cancel()
			case "wrong-path":
				trace = []byte("debug2: load_server_config: filename /opt/fixture/sshd_config\n")
			case "different-policy":
				output = bytes.ReplaceAll(output, []byte("2222"), []byte("2223"))
			case "missing-policy":
				output = []byte("port 2222\nloglevel DEBUG3\n")
			case "malformed-policy":
				output = []byte("\x00")
			case "wrong-debug-mode":
				output = bytes.ReplaceAll(output, []byte("DEBUG3"), []byte("DEBUG1"))
			case "repeated-debug-mode":
				output = append(output, []byte("loglevel DEBUG3\n")...)
			}
			identity, err := bindSSHConfigurationSelection(parent, startup, digest, expected, run, guard)
			valid := scenario == "default" || scenario == "explicit"
			if (err == nil) != valid || valid && !lowerDigest.MatchString(identity) || !valid && identity != "" {
				t.Fatal("incorrect selection result", identity, err)
			}
			if scenario == "explicit" && calls != 0 || calls > 1 {
				t.Fatal("unexpected default probe")
			}
			if calls == 1 && (!bytes.Equal(output, make([]byte, len(output))) || !bytes.Equal(trace, make([]byte, len(trace)))) {
				t.Fatal("private parser buffers were not cleared")
			}
		})
	}
}

func TestSSHConfigurationSelectionIdentityBindsDeclarationParserAndPolicy(t *testing.T) {
	startup := StartupSummary{Schema: 1, DeclarationVerified: true, ExplicitConfiguration: true, CommandSHA256: strings.Repeat("a", 64)}
	digest := strings.Repeat("b", 64)
	policy := sshEffective{"port": {"2222"}}
	bind := func() string {
		t.Helper()
		identity, err := bindSSHConfigurationSelection(context.Background(), startup, digest, policy, nil, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	first := bind()
	if first != bind() {
		t.Fatal("unstable selection identity")
	}
	startup.CommandSHA256 = strings.Repeat("c", 64)
	second := bind()
	digest = strings.Repeat("d", 64)
	third := bind()
	policy["port"] = []string{"2223"}
	fourth := bind()
	seen := make(map[string]bool)
	for _, value := range []string{first, second, third, fourth} {
		if seen[value] {
			t.Fatal("selection identity did not bind inputs")
		}
		seen[value] = true
	}
}

func TestSSHDefaultConfigurationRunnerRejectsAbsentInputs(t *testing.T) {
	for _, daemon := range []*pinnedSSHD{nil, {}} {
		_, _, err := daemon.runDefaultConfiguration(context.Background())
		if !errors.Is(err, ErrInventoryUnsafe) {
			t.Fatal("invalid daemon accepted", err)
		}
	}
	if _, _, err := (&pinnedSSHD{}).runDefaultConfiguration(nil); !errors.Is(err, ErrInventoryUnsafe) { //nolint:staticcheck // Deliberately exercise the nil-context refusal.
		t.Fatal("missing context accepted", err)
	}
}

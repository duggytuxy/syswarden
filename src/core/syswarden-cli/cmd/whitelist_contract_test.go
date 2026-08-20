package cmd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"syswarden-cli/pkg/firewall"
)

func executeWhitelistCommand(t *testing.T, args []string, validate, add whitelistEntryOperation) error {
	t.Helper()
	command := newWhitelistCommand(validate, add)
	command.SilenceErrors = true
	command.SilenceUsage = true
	command.SetArgs(args)
	return command.Execute()
}

func TestWhitelistCommandOfficialPortPrevalidatesEveryEntry_SW_LIST_001(t *testing.T) {
	events := make([]string, 0)
	validate := func(address, port string) error {
		events = append(events, "validate "+address+" "+port)
		return firewall.ValidateWhitelistEntry(address, port)
	}
	add := func(address, port string) error {
		events = append(events, "add "+address+" "+port)
		return nil
	}
	err := executeWhitelistCommand(t, []string{"192.0.2.1", "2001:db8::1", "--port", "0443"}, validate, add)
	if err != nil {
		t.Fatalf("official --port form failed: %v", err)
	}
	want := []string{
		"validate 192.0.2.1 0443",
		"validate 2001:db8::1 0443",
		"add 192.0.2.1 0443",
		"add 2001:db8::1 0443",
	}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("operation order = %q, want %q", events, want)
	}
}

func TestWhitelistCommandPreservesOneFinalLegacyPort_SW_LIST_001(t *testing.T) {
	var calls []string
	operation := func(address, port string) error {
		calls = append(calls, address+"|"+port)
		return nil
	}
	if err := executeWhitelistCommand(t, []string{"192.0.2.1", "2001:db8::1", "2222"}, operation, operation); err != nil {
		t.Fatalf("legacy positional port failed: %v", err)
	}
	want := []string{
		"192.0.2.1|2222", "2001:db8::1|2222",
		"192.0.2.1|2222", "2001:db8::1|2222",
	}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("legacy operations = %q, want %q", calls, want)
	}
}

func TestWhitelistCommandRejectsAmbiguousOrInvalidPortBeforeWrites_SW_LIST_001(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "combined flag and positional", args: []string{"--port", "443", "192.0.2.1", "8443"}, wantErr: "cannot be combined"},
		{name: "multiple official flags", args: []string{"--port", "443", "--port", "8443", "192.0.2.1"}, wantErr: "multiple --port flags"},
		{name: "multiple positional ports", args: []string{"192.0.2.1", "443", "8443"}, wantErr: "multiple legacy positional ports"},
		{name: "non-final positional port", args: []string{"192.0.2.1", "443", "2001:db8::1"}, wantErr: "must be the final argument"},
		{name: "positional port without address", args: []string{"443"}, wantErr: "at least one IP address"},
		{name: "empty flag port", args: []string{"--port=", "192.0.2.1"}, wantErr: "requires a decimal port"},
		{name: "invalid flag port", args: []string{"--port", "65536", "192.0.2.1"}, wantErr: "outside 1..65535"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writes := 0
			err := executeWhitelistCommand(t, test.args, firewall.ValidateWhitelistEntry, func(string, string) error {
				writes++
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want fragment %q", err, test.wantErr)
			}
			if writes != 0 {
				t.Fatalf("invalid invocation performed %d persistent writes", writes)
			}
		})
	}
}

func TestWhitelistCommandInvalidEntryPreventsEveryWrite_SW_LIST_001(t *testing.T) {
	writes := 0
	err := executeWhitelistCommand(
		t,
		[]string{"--port", "443", "192.0.2.1", "invalid.example"},
		firewall.ValidateWhitelistEntry,
		func(string, string) error {
			writes++
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid IP address or CIDR") {
		t.Fatalf("invalid address error = %v", err)
	}
	if writes != 0 {
		t.Fatalf("mixed valid and invalid input performed %d persistent writes", writes)
	}
}

func TestWhitelistCommandPropagatesEveryEntryFailure(t *testing.T) {
	attempts := 0
	err := executeWhitelistCommand(
		t,
		[]string{"192.0.2.1", "192.0.2.2"},
		func(string, string) error { return nil },
		func(address, _ string) error {
			attempts++
			return errors.New("failure for " + address)
		},
	)
	if attempts != 2 {
		t.Fatalf("write attempts = %d, want 2", attempts)
	}
	for _, address := range []string{"192.0.2.1", "192.0.2.2"} {
		if err == nil || !strings.Contains(err.Error(), "whitelist "+address) {
			t.Fatalf("joined error %q omits %s", err, address)
		}
	}
}

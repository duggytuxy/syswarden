package cmd

import (
	"sort"
	"strings"
	"testing"
)

func TestTopLevelCommandContract(t *testing.T) {
	want := []string{
		"alerts",
		"allow-ssh",
		"audit",
		"block",
		"check",
		"config",
		"config-get",
		"ha-sync",
		"install",
		"list",
		"manual",
		"migrate-config",
		"reload",
		"revoke-ssh",
		"tui",
		"unblock",
		"uninstall",
		"unwhitelist",
		"update",
		"update-feeds",
		"web-token",
		"web-tui",
		"whitelist",
		"whitelist-infra",
	}

	var got []string
	for _, command := range rootCmd.Commands() {
		if command.Name() == "completion" || command.Name() == "help" {
			continue
		}
		got = append(got, command.Name())
	}
	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("top-level commands = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("top-level commands = %v, want %v", got, want)
		}
	}
}

func TestOperatorClaimContracts_SW_DOC_001(t *testing.T) {
	migrate, _, err := rootCmd.Find([]string{"migrate-config"})
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{
		"migrated file contents are not written",
		"output directory and modules subdirectory may be created",
	} {
		if !strings.Contains(migrate.Long, phrase) {
			t.Fatalf("migrate-config help omits %q: %s", phrase, migrate.Long)
		}
	}
	dryRun := migrate.Flags().Lookup("dry-run")
	if dryRun == nil || !strings.Contains(dryRun.Usage, "output directories may be created") {
		t.Fatalf("--dry-run usage does not disclose directory creation: %#v", dryRun)
	}

	for _, test := range []struct {
		hadError bool
		want     string
	}{
		{hadError: false, want: "[INFO] Reload sequence completed; verify the resulting service and kernel state."},
		{hadError: true, want: "[WARNING] Reload sequence completed with reported errors; review the messages above and verify the resulting system state."},
	} {
		got := reloadCompletionMessage(test.hadError)
		if got != test.want || strings.Contains(got, "[SUCCESS]") {
			t.Fatalf("reload completion for hadError=%t = %q", test.hadError, got)
		}
	}
}

func TestCriticalFlagContract(t *testing.T) {
	tests := []struct {
		command string
		flags   map[string]string
	}{
		{
			command: "migrate-config",
			flags: map[string]string{
				"source":  "",
				"output":  "",
				"dry-run": "false",
			},
		},
		{
			command: "reload",
			flags: map[string]string{
				"no-restart": "false",
			},
		},
		{
			command: "web-tui",
			// SW-WEB-001: this compatibility assertion tracks the legacy
			// all-interface bind until the opt-in transition is implemented.
			flags: map[string]string{
				"bind":  "0.0.0.0:62027",
				"token": "",
			},
		},
		{
			command: "web-token",
			flags: map[string]string{
				"rotate": "false",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.command, func(t *testing.T) {
			command, _, err := rootCmd.Find([]string{test.command})
			if err != nil {
				t.Fatalf("command %q not found: %v", test.command, err)
			}
			for name, wantDefault := range test.flags {
				flag := command.Flags().Lookup(name)
				if flag == nil {
					t.Errorf("flag --%s is missing", name)
					continue
				}
				if flag.DefValue != wantDefault {
					t.Errorf("flag --%s default = %q, want %q", name, flag.DefValue, wantDefault)
				}
			}
		})
	}
}

func TestRootPersistentConfigFlagContract(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	if flag == nil {
		t.Fatal("persistent --config flag is missing")
	}
	// SW-CFG-002: retain the legacy path during the documented migration window.
	if flag.DefValue != "/opt/syswarden/syswarden-auto.conf" {
		t.Fatalf("--config default = %q", flag.DefValue)
	}
}

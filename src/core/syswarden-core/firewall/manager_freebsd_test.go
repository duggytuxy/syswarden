//go:build freebsd

package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "syswarden-pf-manager-tests-")
	if err != nil {
		panic(err)
	}
	firewallRuntimeLockPath = filepath.Join(directory, "firewall.lock")
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

func TestPFManagerRequiresExternalExpiryCoordination_SW_FW_003(t *testing.T) {
	manager := &PFManager{health: HealthHealthy}
	if manager.BanExpiryMode() != BanExpiryExternal {
		t.Fatalf("PF expiry mode = %q, want external", manager.BanExpiryMode())
	}
	if _, ok := any(manager).(BanWithTTLManager); ok {
		t.Fatal("PF manager falsely advertises native TTL enforcement")
	}
	if _, ok := any(manager).(BanPermanentManager); !ok {
		t.Fatal("PF manager does not expose permanent-ban capability")
	}
}

func TestPFManagerRequiresEnabledEnforcement_SW_FW_003(t *testing.T) {
	manager, err := newPFManager(func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "-s" && args[1] == "info" {
			return []byte("Status: Disabled\n"), nil
		}
		return nil, fmt.Errorf("unexpected call: %v", args)
	})
	if err == nil || manager.Health() != HealthUnavailable {
		t.Fatalf("disabled PF initialized as health=%q err=%v", manager.Health(), err)
	}
}

func TestPFManagerBanAndUnbanAreIdempotentAndVerified_SW_FW_003(t *testing.T) {
	present := false
	adds := 0
	deletes := 0
	runner := func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "-s" && args[1] == "info":
			return []byte("Status: Enabled for 0 days\n"), nil
		case len(args) == 2 && args[0] == "-s" && args[1] == "Tables":
			return []byte("<banned_ips>\n"), nil
		case len(args) == 4 && args[0] == "-t" && args[1] == "banned_ips" && args[2] == "-T" && args[3] == "show":
			if present {
				return []byte("192.0.2.44\n"), nil
			}
			return nil, nil
		case len(args) == 5 && args[0] == "-t" && args[1] == "banned_ips" && args[2] == "-T" && args[4] == "192.0.2.44":
			if args[3] == "add" {
				adds++
				present = true
				return nil, nil
			}
			if args[3] == "delete" {
				deletes++
				present = false
				return nil, nil
			}
		}
		return nil, fmt.Errorf("unexpected call: %s", strings.Join(args, " "))
	}
	manager, err := newPFManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := manager.BanPermanent("192.0.2.44"); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := manager.Unban("192.0.2.44"); err != nil {
			t.Fatal(err)
		}
	}
	if adds != 1 || deletes != 1 {
		t.Fatalf("PF mutation counts add/delete = %d/%d, want 1/1", adds, deletes)
	}
}

func TestPFCommandDispatchRejectsUnexpectedOperations_SW_FW_003(t *testing.T) {
	for _, arguments := range [][]string{
		{"-f", "/tmp/untrusted.conf"},
		{"-t", "other_table", "-T", "add", "192.0.2.1"},
		{"-t", "banned_ips", "-T", "add", "192.0.2.99/24"},
		{"-t", "banned_ips", "-T", "replace", "192.0.2.1"},
	} {
		if _, err := runPFCommand(arguments...); err == nil {
			t.Fatalf("runPFCommand() accepted %#v", arguments)
		}
	}
}

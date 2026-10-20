//go:build linux

package sshpolicy

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOpenSSHPortObservationOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_ORACLE_TEST=1 for the installed OpenSSH parser oracle")
	}
	hostRoot, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer hostRoot.Close()
	daemon, err := openSSHD(hostRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.file.Close()
	directory := t.TempDir()
	key := sshOracleKey(t, directory)
	for _, tc := range []struct {
		name, main, include   string
		configured, listeners []uint16
	}{
		{"default", "", "", []uint16{22}, []uint16{22}},
		{"nonstandard-include", "", "Port 2222\n", []uint16{2222}, []uint16{2222}},
		{"multiple-ports", "Port 2222\nPort 22\n", "", []uint16{22, 2222}, []uint16{22, 2222}},
		{"listen-overrides-port", "Port 22\nListenAddress 127.0.0.1:2200\n", "", []uint16{22}, []uint16{2200}},
		{"dual-listen-overrides", "Port 2222\nListenAddress 127.0.0.1:2200\nListenAddress [::1]:2201\n", "", []uint16{2222}, []uint16{2200, 2201}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Preserve externally managed forwarding and authentication. No
			// migration intent, role choice or candidate policy is supplied.
			main := includeDropIns + "HostKey " + key + "\nUsePAM no\nAllowTcpForwarding local\nPasswordAuthentication no\n" + tc.main
			f := newInventoryFixture(t, main)
			f.write("/etc/ssh/sshd_config.d/50-automation.conf", tc.include+
				"Match User automation\n PermitTTY no\n PermitOpen 192.0.2.30:22\nMatch all\n")
			inventory := f.open()
			translated := strings.ReplaceAll(main, "/etc/ssh/", f.path("/etc/ssh/")+"/")
			baseline := filepath.Join(directory, "baseline-"+tc.name)
			if err := os.WriteFile(baseline, []byte(translated), 0600); err != nil {
				t.Fatal(err)
			}
			run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				if image == nil {
					image = &parserImage{main: baseline}
				}
				return daemon.run(ctx, image, mode, access)
			}
			recheck := func() error {
				if err := inventory.Recheck(); err != nil {
					return err
				}
				return daemon.recheck(hostRoot, 0)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result, err := inspectPorts(ctx, inventory.snapshot, daemon.digest, run, recheck)
			if err != nil || !result.ParserVerified || result.RuntimeVerified || result.HardeningApplied ||
				!reflect.DeepEqual(result.ConfiguredPorts, tc.configured) || !reflect.DeepEqual(result.ListenPorts, tc.listeners) {
				t.Fatalf("incorrect configured port observation: %+v %v", result, err)
			}
			current, err := collectInventory(f.root, os.Geteuid())
			if err != nil || !reflect.DeepEqual(current, inventory.snapshot) {
				t.Fatal("modified administrator configuration")
			}
			for _, name := range []string{IntentPath, DropInPath, "/var/lib/syswarden"} {
				if _, err := os.Lstat(f.path(name)); !os.IsNotExist(err) {
					t.Fatal("created hardening or state")
				}
			}
		})
	}
}

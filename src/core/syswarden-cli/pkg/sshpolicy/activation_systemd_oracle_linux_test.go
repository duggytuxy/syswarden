//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// This opt-in test is only for the disposable rootless systemd fixture. It
// exercises the production binder, never an installed host SSH service.
func TestSSHIsolatedSystemdActivationOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ISOLATED_SYSTEMD_ORACLE_TEST") != "1" {
		t.Skip("requires the disposable rootless systemd SSH oracle")
	}
	requireSSHIsolatedSystemdFixture(t)
	before, err := os.ReadFile(MainPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(DropInPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reserved fixture path is not absent", err)
	}
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	probe := func(allowed bool) { isolatedSSHForwardProbe(t, backend.Addr().String(), allowed) }
	probe(true)
	if err := os.WriteFile(DropInPath, []byte("# Isolated production-binder oracle.\nAllowTcpForwarding no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(DropInPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	}()
	probe(true) // Publication alone must not change the already running daemon.

	// A successful no-op send must not pass the production listener observer.
	inventory, err := OpenInventory()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	lease, err := bindSSHSystemdActivation(ctx, inventory.Recheck)
	if err != nil {
		_ = inventory.Close()
		t.Fatalf("bind negative control: %v", err)
	}
	target, ok := lease.(*sshActivationTarget)
	if !ok {
		_ = lease.Close()
		_ = inventory.Close()
		t.Fatal("unexpected production lease")
	}
	target.send = func() error { return nil }
	err = lease.request(ctx, inventory.Recheck)
	closeErr := errors.Join(lease.Close(), inventory.Close())
	if (!errors.Is(err, context.DeadlineExceeded) && (err == nil || !strings.Contains(err.Error(), "SSH listener replacement was not observed"))) || ctx.Err() != nil || closeErr != nil {
		t.Fatal("no-op dispatch accepted or cleanup failed", err, closeErr)
	}
	probe(true)

	reload := func() {
		t.Helper()
		inventory, err := OpenInventory()
		if err != nil {
			t.Fatal(err)
		}
		lease, err := bindSSHSystemdActivation(ctx, inventory.Recheck)
		if err != nil {
			_ = inventory.Close()
			t.Fatalf("bind real reload: %v", err)
		}
		requestErr := lease.request(ctx, inventory.Recheck)
		replayErr := lease.request(ctx, inventory.Recheck)
		closeErr := errors.Join(lease.Close(), inventory.Close())
		if requestErr != nil || replayErr == nil || closeErr != nil {
			t.Fatal("production reload/replay/cleanup", requestErr, replayErr, closeErr)
		}
	}
	reload()
	probe(false)
	if err := os.Remove(DropInPath); err != nil {
		t.Fatal(err)
	}
	probe(false) // Restored files do not restore the daemon's loaded policy.
	reload()
	probe(true)
	after, err := os.ReadFile(MainPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("main fixture policy changed", err)
	}
	t.Log("production systemd binder: no-op refused, real reload and restoration observed; no migration completion claimed")
}

func requireSSHIsolatedSystemdFixture(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("isolated fixture must run as remapped root")
	}
	mapping, err := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || len(fields) < 3 || fields[0] != "0" {
		t.Fatal("missing rootless user namespace")
	}
	outside, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || outside == 0 {
		t.Fatal("initial user namespace is prohibited")
	}
	init, err := os.ReadFile("/proc/1/comm")
	if err != nil || string(init) != "systemd\n" {
		t.Fatal("fixture requires real systemd PID1")
	}
	marker, err := os.ReadFile("/run/syswarden-ssh-native-oracle/ready")
	if err != nil || string(marker) != "SYSWARDEN-ISOLATED-SSH-BINDER-V1\n" {
		t.Fatal("isolated fixture marker missing")
	}
	config, err := os.ReadFile(MainPath)
	if err != nil || !bytes.HasPrefix(config, []byte("# SYSWARDEN-ISOLATED-SSH-BINDER-V1\n")) {
		t.Fatal("isolated main fixture identity missing")
	}
}

func isolatedSSHForwardProbe(t *testing.T, backend string, allowed bool) {
	t.Helper()
	key, err := os.ReadFile("/run/syswarden-ssh-native-oracle/client")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	host, _, _, _, err := ssh.ParseAuthorizedKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host), Timeout: 5 * time.Second}
	conn, err := net.DialTimeout("tcp4", "127.0.0.1:22222", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	authenticated, channels, requests, err := ssh.NewClientConn(conn, "127.0.0.1:22222", config)
	if err != nil {
		t.Fatalf("fresh pinned authentication failed: %v", err)
	}
	client := ssh.NewClient(authenticated, channels, requests)
	defer client.Close()
	forwarded, err := client.Dial("tcp", backend)
	if allowed {
		if err != nil {
			t.Fatalf("expected forwarding after fresh authentication: %v", err)
		}
		_ = forwarded.Close()
	} else {
		if forwarded != nil {
			_ = forwarded.Close()
		}
		var refusal *ssh.OpenChannelError
		if !errors.As(err, &refusal) || refusal.Reason != ssh.Prohibited {
			t.Fatal("expected explicit forwarding policy refusal", err)
		}
	}
}

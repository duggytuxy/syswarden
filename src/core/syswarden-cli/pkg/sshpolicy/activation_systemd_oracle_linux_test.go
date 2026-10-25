//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
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
	isolatedSSHDefaultConfigurationOracle(t, before)
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
	isolatedSSHPrivateMountRefusal(t, before, backend.Addr().String())
	t.Log("production systemd binder: no-op refused, real reload and restoration observed; no migration completion claimed")
}

// A changed compiled default can produce identical effective values while
// loading a different file. Patch only a copied fixture ELF's exact pathname
// literal, and run it only in parser mode inside the disposable namespace.
func isolatedSSHDefaultConfigurationOracle(t *testing.T, original []byte) {
	t.Helper()
	before, err := ObserveSystemdListeners()
	if err != nil {
		t.Fatal("observe service before parser-only default selection", err)
	}
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.file.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	output, err := daemon.run(ctx, nil, "effective", "")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := parseEffective(output)
	if err != nil {
		t.Fatal(err)
	}
	startup := StartupSummary{Schema: 1, DeclarationVerified: true, CommandSHA256: strings.Repeat("a", 64)}
	guard := func() error { return daemon.recheck(root, 0) }
	if identity, err := bindSSHConfigurationSelection(ctx, startup, daemon.digest, policy, daemon.runDefaultConfiguration, guard); err != nil || identity == "" {
		t.Fatal("installed default configuration was not bound", err)
	}
	const alternative = "/run/ssh/sshd_config"
	const private = "/run/syswarden-ssh-native-oracle/default-path"
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("/run/ssh", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alternative, original, 0600); err != nil { // #nosec G703 -- The destination is a fixed literal in the guarded disposable fixture; original is file content, never a path.
		t.Fatal(err)
	}
	// Read the already pinned original. Require exactly one same-size literal
	// so the control cannot accidentally modify instructions or ELF layout.
	originalELF := make([]byte, daemon.state.size)
	if _, err := daemon.file.ReadAt(originalELF, 0); err != nil {
		t.Fatal(err)
	}
	oldLiteral, newLiteral := []byte(MainPath+"\x00"), []byte(alternative+"\x00")
	if len(oldLiteral) != len(newLiteral) || bytes.Count(originalELF, oldLiteral) != 1 {
		t.Fatal("unsupported fixture ELF default-path literal")
	}
	modified := bytes.Replace(originalELF, oldLiteral, newLiteral, 1)
	if err := os.WriteFile(private+"/sshd", modified, 0700); err != nil { // #nosec G306 -- This private copied AMD64 test executable needs owner execute permission; it runs only in parser mode in the disposable fixture.
		t.Fatal(err)
	}
	directory, err := os.Open(private)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	file, state, digest, err := readSSHD(directory, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	changed := &pinnedSSHD{file: file, state: state, digest: digest}
	actual, trace, err := changed.runDefaultConfiguration(ctx)
	if err != nil {
		t.Fatal("modified default parser fixture failed", err)
	}
	defer clear(actual)
	defer clear(trace)
	values, err := parseEffective(actual)
	if err != nil || compareEffective(policy, values, map[string]bool{"loglevel": true}) != nil {
		t.Fatal("negative control did not retain equivalent effective values", err)
	}
	identity, err := bindSSHConfigurationSelection(ctx, startup, changed.digest, policy, changed.runDefaultConfiguration, guard)
	if err == nil || identity != "" || !strings.Contains(err.Error(), "compiled configuration path differs") {
		t.Fatal("different compiled default accepted despite identical effective values", err)
	}
	startup.ExplicitConfiguration = true
	identity, err = bindSSHConfigurationSelection(ctx, startup, changed.digest, policy, nil, guard)
	if err != nil || identity == "" {
		t.Fatal("explicit configuration incorrectly depends on compiled default", err)
	}
	after, err := ObserveSystemdListeners()
	if err != nil || before.Process.IdentitySHA256 != after.Process.IdentitySHA256 || before.SocketsSHA256 != after.SocketsSHA256 {
		t.Fatal("parser-only default selection changed the process or listeners", err)
	}
	current, err := os.ReadFile(MainPath)
	if err != nil || !bytes.Equal(original, current) {
		t.Fatal("parser-only default selection changed the active main file", err)
	}
	t.Log("compiled default selection: installed path accepted; identical policy from alternate default refused; explicit selection remains separate")
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

// An ordinary unit bind mount can keep the same root and executable while
// exposing a different main configuration. Only this disposable fixture owns
// the unit restart; product code must refuse before producing a signal lease.
func isolatedSSHPrivateMountRefusal(t *testing.T, original []byte, backend string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	const saved = "/run/syswarden-ssh-native-oracle/private-sshd_config"
	const unitDirectory = "/run/systemd/system/ssh.service.d"
	const unitOverride = unitDirectory + "/90-oracle-private-view.conf"
	private := bytes.Replace(original, []byte("Include /etc/ssh/sshd_config.d/*.conf\n"), nil, 1)
	if bytes.Equal(private, original) {
		t.Fatal("fixture include is missing")
	}
	if err := os.WriteFile(saved, private, 0600); err != nil { // #nosec G703 -- Constant destination in a guarded disposable container; synthetic configuration affects content only, never the path.
		t.Fatal(err)
	}
	if err := os.WriteFile(DropInPath, []byte("AllowTcpForwarding no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(unitDirectory, 0755); err != nil { // #nosec G301 -- Fixed disposable systemd fixture directory, matching public unit-directory permissions.
		t.Fatal(err)
	}
	if err := os.WriteFile(unitOverride, []byte("[Service]\nBindReadOnlyPaths="+saved+":"+MainPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	commands := []*exec.Cmd{
		exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload"),
		exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", "ssh.service"),
	}
	for _, command := range commands {
		command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "SYSTEMD_PAGER=cat"}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("private fixture setup failed: %v: %s", err, output)
		}
	}
	// Type=simple reports restart before sshd has created its listener. Wait
	// only for fixture readiness; authentication below remains independent.
	ready := false
	for attempt := 0; attempt < 50; attempt++ {
		dialer := net.Dialer{Timeout: 100 * time.Millisecond}
		conn, err := dialer.DialContext(ctx, "tcp4", "127.0.0.1:22222")
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		if err := pauseSSHListenerObservation(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !ready {
		t.Fatal("private fixture listener did not become ready")
	}
	isolatedSSHForwardProbe(t, backend, true)
	before, err := ObserveSystemdListeners()
	if err != nil || !before.Process.ProcessObserved {
		t.Fatal("read-only observation refused a stable private mount", err)
	}
	inventory, err := OpenInventory()
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()
	lease, err := bindSSHSystemdActivation(ctx, inventory.Recheck)
	if lease != nil {
		_ = lease.Close()
		t.Fatal("private mount obtained an activation lease")
	}
	if err == nil || !strings.Contains(err.Error(), "SSH activation requires the verifier mount namespace") {
		t.Fatal("private mount did not stop at the mount-view boundary", err)
	}
	after, err := ObserveSystemdListeners()
	if err != nil || before.Process.IdentitySHA256 != after.Process.IdentitySHA256 || before.SocketsSHA256 != after.SocketsSHA256 {
		t.Fatal("rejected private mount changed the process or listeners", err)
	}
	isolatedSSHForwardProbe(t, backend, true)
	for _, name := range []string{sshJournalDirectory, IntentPath} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("private mount refusal created product history", name, err)
		}
	}
	t.Log("private mount: observation preserved, activation refused before signaling; fixture forwarding unchanged")
}

//go:build linux

package sshpolicy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// This explicit oracle uses disposable loopback daemons and generated keys.
// It neither calls the production activation binder nor edits installed SSH.
func TestOpenSSHRuntimeAccessOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_RUNTIME_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_RUNTIME_ORACLE_TEST=1 for disposable authenticated SSH sessions")
	}
	if os.Geteuid() == 0 {
		t.Fatal("the runtime oracle requires an ordinary local test account")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []Profile{Forwarding, CIS} {
		t.Run(map[Profile]string{Forwarding: "forwarding", CIS: "cis"}[profile], func(t *testing.T) {
			f := newSSHRuntimeFixture(t, account)
			candidate, err := Prepare(profile, inventory(includeDropIns))
			if err != nil {
				t.Fatal(err)
			}
			f.write("target-policy.conf", "# Initially inactive fixture policy.\n")
			target := f.startDaemon("target", "Include "+strconv.Quote(f.path("target-policy.conf"))+"\n")
			jump := f.startDaemon("bastion", "AllowTcpForwarding local\nPermitOpen "+target.address+"\n")
			f.writeClient(target, jump)
			f.expectAccess("target", true)
			f.expectAccess("via-bastion", true)
			f.expectRejectedIdentity()
			backend := f.backend()
			f.expectForward(target, backend, true)
			oldChannel := f.holdForward(target, backend)
			oldChannel()
			bastionOriginal := f.read("bastion.conf")

			// Publication and a successful parser do not prove live enforcement.
			f.write("target-policy.conf", string(candidate.Bytes()))
			parsed := f.command("sshd", "-T", "-f", f.path("target.conf"))
			output, err := parsed.CombinedOutput()
			if err != nil {
				t.Fatalf("candidate parser: %v: %s", err, output)
			}
			if err := candidate.CheckEffective(output); err != nil {
				t.Fatal(err)
			}
			f.expectForward(target, backend, true)
			f.reload(target)
			f.expectFreshTransport(target, jump)
			oldChannel()
			f.expectForward(target, backend, false)
			f.expectAccess("target", true)
			f.expectAccess("via-bastion", true)
			if !bytes.Equal(f.read("bastion.conf"), bastionOriginal) {
				t.Fatal("target hardening changed the independent bastion")
			}

			// A listening daemon can still reject the intended identity. Restore
			// only fixture bytes and require a new authenticated connection.
			f.write("target-authorized_keys", "")
			f.expectAccess("bastion", true)
			f.expectAccess("target", false)
			f.expectAccess("via-bastion", false)
			f.write("target-authorized_keys", string(f.read("client.pub")))
			f.expectAccess("target", true)
			f.expectAccess("via-bastion", true)

			// Restoring disk policy is not runtime recovery. The old restriction
			// must remain observable until this fixture's separate reload.
			f.write("target-policy.conf", "# Restored inactive fixture policy.\n")
			f.expectForward(target, backend, false)
			f.reload(target)
			f.expectForward(target, backend, true)
			f.expectAccess("target", true)
			f.expectAccess("via-bastion", true)
		})
	}
}

type sshRuntimeFixture struct {
	t     *testing.T
	ctx   context.Context
	dir   string
	user  string
	tools map[string]string
}

type sshRuntimeDaemon struct {
	name       string
	address    string
	port       string
	pidfd      int
	generation int
}

func newSSHRuntimeFixture(t *testing.T, account *user.User) *sshRuntimeFixture {
	t.Helper()
	// StrictModes checks every authorized_keys ancestor. /tmp is unsuitable,
	// even when the immediate temporary directory is private. Use the current
	// account's home, never its existing .ssh directory or authentication keys.
	dir, err := os.MkdirTemp(account.HomeDir, ".syswarden-ssh-oracle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove private oracle directory: %v", err)
		}
	})
	if strings.ContainsAny(dir, "%\r\n") {
		t.Fatal("fixture path cannot contain SSH expansion tokens or line breaks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	f := &sshRuntimeFixture{t: t, ctx: ctx, dir: dir, user: account.Username, tools: make(map[string]string)}
	for _, name := range []string{"ssh", "sshd", "ssh-keygen"} {
		path, err := exec.LookPath(name)
		if err != nil || !filepath.IsAbs(path) {
			t.Fatalf("required installed tool %s: %v", name, err)
		}
		f.tools[name] = path
	}
	for _, name := range []string{"target-host", "bastion-host", "client", "wrong-client"} {
		output, err := f.command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f.path(name)).CombinedOutput()
		if err != nil {
			t.Fatalf("generate fixture key: %v: %s", err, output)
		}
	}
	version, err := f.command("ssh", "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed client: %s", bytes.TrimSpace(version))
	return f
}

func (f *sshRuntimeFixture) path(name string) string { return filepath.Join(f.dir, name) }

func (f *sshRuntimeFixture) read(name string) []byte {
	f.t.Helper()
	content, err := os.ReadFile(f.path(name))
	if err != nil {
		f.t.Fatal(err)
	}
	return content
}

func (f *sshRuntimeFixture) write(name, content string) {
	f.t.Helper()
	if err := os.WriteFile(f.path(name), []byte(content), 0600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *sshRuntimeFixture) command(tool string, args ...string) *exec.Cmd {
	f.t.Helper()
	path, ok := f.tools[tool]
	if !ok {
		f.t.Fatal("unknown fixture tool")
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	f.t.Cleanup(cancel)
	command := exec.CommandContext(ctx, path, args...) // #nosec G204 -- Test-only installed-tool allowlist and fixed callers; arguments select generated private fixtures, loopback hosts and hex challenges without a local shell.
	command.WaitDelay = time.Second
	command.Dir = f.dir
	command.Env = append(os.Environ(), "LC_ALL=C")
	return command
}

func (f *sshRuntimeFixture) startDaemon(name, policy string) *sshRuntimeDaemon {
	f.t.Helper()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	address := reservation.Addr().String()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := reservation.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.write(name+"-authorized_keys", string(f.read("client.pub")))
	config := fmt.Sprintf("%sListenAddress %s\nHostKey %q\nPidFile %q\nAuthorizedKeysFile %q\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nPermitRootLogin no\nStrictModes yes\nUseDNS no\nAllowAgentForwarding no\nLogLevel VERBOSE\n", policy, address, f.path(name+"-host"), f.path(name+".pid"), f.path(name+"-authorized_keys"))
	f.write(name+".conf", config)
	log, err := os.OpenFile(f.path(name+".log"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = log.Close() })
	command := exec.CommandContext(f.ctx, f.tools["sshd"], "-D", "-e", "-f", f.path(name+".conf")) // #nosec G204 -- Test-only installed daemon with a generated private configuration and loopback listener; no installed configuration or service is used.
	command.WaitDelay = time.Second
	command.Dir = f.dir
	command.Env = append(os.Environ(), "LC_ALL=C")
	command.Stdout, command.Stderr = log, log
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		f.t.Fatal(err)
	}
	// Do not reap until cleanup: the unreaped direct child prevents PID reuse.
	// This signal addresses only its disposable process group, including any
	// fixture authentication children left by a failed or cancelled client.
	f.t.Cleanup(func() {
		if err := unix.Kill(-command.Process.Pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
			f.t.Errorf("stop disposable daemon group: %v", err)
		}
		_ = command.Wait()
	})
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = unix.Close(pidfd) })
	daemon := &sshRuntimeDaemon{name: name, address: address, port: port, pidfd: pidfd, generation: 1}
	f.waitListening(daemon)
	return daemon
}

func (f *sshRuntimeFixture) waitListening(daemon *sshRuntimeDaemon) {
	f.t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		// No unauthenticated readiness connection: recent OpenSSH versions
		// penalize those connections. The subsequent nonce proves actual access.
		if bytes.Count(f.read(daemon.name+".log"), []byte("Server listening on 127.0.0.1 port "+daemon.port+".")) == daemon.generation {
			return
		}
		select {
		case <-f.ctx.Done():
			f.t.Fatal("fixture lifetime expired")
		case <-deadline.C:
			f.t.Fatalf("fixture listener did not become ready: %s", f.read(daemon.name+".log"))
		case <-tick.C:
		}
	}
}

func (f *sshRuntimeFixture) reload(daemon *sshRuntimeDaemon) {
	f.t.Helper()
	if err := unix.PidfdSendSignal(daemon.pidfd, unix.SIGHUP, nil, 0); err != nil {
		f.t.Fatal(err)
	}
	daemon.generation++
	f.waitListening(daemon)
}

func (f *sshRuntimeFixture) writeClient(target, jump *sshRuntimeDaemon) {
	f.t.Helper()
	var known strings.Builder
	for _, daemon := range []*sshRuntimeDaemon{target, jump} {
		parts := strings.Fields(string(f.read(daemon.name + "-host.pub")))
		if len(parts) < 2 {
			f.t.Fatal("invalid fixture public key")
		}
		fmt.Fprintf(&known, "[127.0.0.1]:%s %s %s\n", daemon.port, parts[0], parts[1])
	}
	f.write("known_hosts", known.String())
	f.write("client.conf", fmt.Sprintf("Host target via-bastion\n Port %s\nHost bastion\n Port %s\nHost via-bastion\n ProxyJump bastion\nHost *\n HostName 127.0.0.1\n User %q\n IdentityFile %q\n IdentityAgent none\n IdentitiesOnly yes\n BatchMode yes\n PreferredAuthentications publickey\n PasswordAuthentication no\n KbdInteractiveAuthentication no\n ControlMaster no\n ControlPath none\n ControlPersist no\n StrictHostKeyChecking yes\n UserKnownHostsFile %q\n GlobalKnownHostsFile /dev/null\n UpdateHostKeys no\n ForwardAgent no\n RequestTTY no\n ConnectionAttempts 1\n ConnectTimeout 3\n", target.port, jump.port, f.user, f.path("client"), f.path("known_hosts")))
}

func (f *sshRuntimeFixture) expectAccess(host string, allowed bool) {
	f.t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		f.t.Fatal(err)
	}
	expected := fmt.Sprintf("syswarden-oracle-%x", nonce)
	command := f.command("ssh", "-F", f.path("client.conf"), host, "printf '"+expected+"'")
	output, err := command.CombinedOutput()
	if allowed {
		if err != nil || string(output) != expected {
			f.t.Fatalf("fresh %s authentication failed: %v: %s", host, err, output)
		}
	} else if err == nil || !bytes.Contains(output, []byte("Permission denied (publickey)")) {
		f.t.Fatalf("missing key did not refuse %s authentication: %v: %s", host, err, output)
	}
}

func (f *sshRuntimeFixture) expectRejectedIdentity() {
	f.t.Helper()
	// Change the sole configured identity. Adding another -i would still allow
	// the valid key and would not establish refusal of an unauthorized client.
	original := f.read("client.conf")
	f.write("client.conf", strings.ReplaceAll(string(original), f.path("client")+"\"", f.path("wrong-client")+"\""))
	f.expectAccess("target", false)
	f.write("client.conf", string(original))
	known := f.read("known_hosts")
	f.write("known_hosts", "")
	output, err := f.command("ssh", "-F", f.path("client.conf"), "target", "true").CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("Host key verification failed")) {
		f.t.Fatalf("unpinned server identity accepted: %v: %s", err, output)
	}
	f.write("known_hosts", string(known))
}

func (f *sshRuntimeFixture) backend() string {
	f.t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	finished := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(finished)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	f.t.Cleanup(func() { _ = listener.Close(); <-finished; workers.Wait() })
	return listener.Addr().String()
}

func (f *sshRuntimeFixture) expectForward(daemon *sshRuntimeDaemon, backend string, allowed bool) {
	f.t.Helper()
	command := f.command("ssh", "-F", f.path("client.conf"), "-W", backend, daemon.name)
	command.Stdin = strings.NewReader("syswarden-fixture-backend\n")
	output, err := command.CombinedOutput()
	if allowed {
		if err != nil || string(output) != "syswarden-fixture-backend\n" {
			f.t.Fatalf("fixture forwarding unexpectedly refused: %v: %s", err, output)
		}
	} else if err == nil || !bytes.Contains(output, []byte("administratively prohibited")) {
		f.t.Fatalf("fixture forwarding restriction missing: %v: %s", err, output)
	}
}

// An already authenticated forwarding channel can survive daemon reload. Its
// continued success must never substitute for a newly authenticated probe.
func (f *sshRuntimeFixture) holdForward(daemon *sshRuntimeDaemon, backend string) func() {
	f.t.Helper()
	command := exec.CommandContext(f.ctx, f.tools["ssh"], "-F", f.path("client.conf"), "-W", backend, daemon.name) // #nosec G204 -- Test-only client uses the generated pinned-key configuration, fixed fixture host and kernel-assigned loopback endpoint; no external destination or operator key.
	command.WaitDelay = time.Second
	command.Dir = f.dir
	command.Env = append(os.Environ(), "LC_ALL=C")
	input, err := command.StdinPipe()
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = input.Close() })
	output, err := command.StdoutPipe()
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = output.Close() })
	if err := command.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	reader := bufio.NewReader(output)
	return func() {
		f.t.Helper()
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			f.t.Fatal(err)
		}
		expected := fmt.Sprintf("existing-channel-%x\n", nonce)
		if _, err := io.WriteString(input, expected); err != nil {
			f.t.Fatal(err)
		}
		received, err := reader.ReadString('\n')
		if err != nil || received != expected {
			f.t.Fatalf("existing fixture channel: %v: %q", err, received)
		}
	}
}

// Exercise the production transport primitive against installed OpenSSH after
// the fixture reload. These synthetic bindings are not a protected journal or
// controller enrollment, and cannot make the migration production-ready.
func (f *sshRuntimeFixture) expectFreshTransport(target, jump *sshRuntimeDaemon) {
	f.t.Helper()
	identity := f.read("client")
	peer := func(daemon *sshRuntimeDaemon) sshAccessPeer {
		key, _, _, _, err := ssh.ParseAuthorizedKey(f.read(daemon.name + "-host.pub"))
		if err != nil {
			f.t.Fatal(err)
		}
		return sshAccessPeer{daemon.address, f.user, key.Marshal(), identity}
	}
	port, err := strconv.ParseUint(target.port, 10, 16)
	if err != nil {
		f.t.Fatal(err)
	}
	binding := sshAccessBinding{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), "",
		accessContext{"administrator", "direct", f.user, "controller.example", "127.0.0.1", "127.0.0.1", uint16(port)}}
	guard := func() error { return nil }
	for _, route := range []string{"direct", "proxyjump"} {
		binding.Access.Route = route
		var bastion *sshAccessPeer
		if route == "proxyjump" {
			value := peer(jump)
			bastion = &value
		}
		requestRoute := sshAccessRequestRoute{Access: binding.Access, Target: accessRequestPin(f.t, peer(target))}
		credentials := sshAccessCredentials{ContextID: binding.Access.ID, Target: identity}
		if bastion != nil {
			pin := accessRequestPin(f.t, *bastion)
			requestRoute.Jump = &pin
			credentials.Jump = identity
		}
		request := sshAccessRequest{1, sshAccessRequestDomain, binding.Transaction, binding.Plan, binding.Intent, binding.Target, strings.Repeat("e", 64), []sshAccessRequestRoute{requestRoute}}
		wire, err := json.Marshal(request)
		if err != nil {
			f.t.Fatal(err)
		}
		probe := func() (sshAccessObservation, error) {
			batch, err := probeSSHActivationAccessRequest(f.ctx, wire, digestBytes(wire), []sshAccessCredentials{credentials}, guard)
			if err != nil {
				return sshAccessObservation{}, err
			}
			if !batch.RecoveryRequired || len(batch.Observations) != 1 {
				return sshAccessObservation{}, ErrInventoryUnsafe
			}
			return batch.Observations[0], nil
		}
		first, err := probe()
		if err != nil || !first.RecoveryRequired {
			f.t.Fatalf("native %s probe failed: %v", route, err)
		}
		second, err := probe()
		if err != nil || first.BindingSHA256 != second.BindingSHA256 || first.ChallengeSHA256 == second.ChallengeSHA256 || first.SessionSHA256 == second.SessionSHA256 {
			f.t.Fatalf("native %s probe reused authentication: %v", route, err)
		}
		if route == "proxyjump" && (first.JumpSessionSHA256 == "" || first.JumpSessionSHA256 == second.JumpSessionSHA256) {
			f.t.Fatal("bastion authentication was reused")
		}
	}
}

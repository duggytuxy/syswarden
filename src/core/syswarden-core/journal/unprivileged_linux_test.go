package journal

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const adversaryID = 65534

// The opt-in parent needs SETUID/SETGID only to start a distinct identity. Local
// runs use podman unshare; CI uses a disposable runner. No account is created.
// This is component isolation, not installed-package or native OS acceptance.
func TestLocalUnprivilegedBoundary(t *testing.T) {
	if os.Getenv("SYSWARDEN_REQUIRE_CROSS_UID") != "1" {
		t.Skip("dedicated cross-UID gate required; ordinary component run has no credential-changing authority")
	}
	if os.Geteuid() != 0 {
		t.Fatal("cross-UID gate requires a root identity inside its test environment")
	}
	t.Run("launch-configuration", testAuthorityLaunchProtectedFile)
	f := authorityFixture(t)
	f.config.PolicyAdministrator = nil
	a := openAuthority(t, f.config)
	dirs := []string{f.policyPath, f.custodyPath, f.files.anchorPath, f.files.journalPath}
	// Make the harness ancestors searchable so a hidden test directory cannot
	// accidentally supply the protection attributed to a product directory.
	for _, dir := range dirs {
		if err := chmodFixture(filepath.Dir(dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	work, err := os.MkdirTemp("", "swj-cross-uid-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	if err = chmodFixture(work, 0755); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(work, "attacker")
	if err = os.Mkdir(canary, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(canary, adversaryID, adversaryID); err != nil {
		t.Fatal(err)
	}

	before := adversarialSnapshot(t, dirs)
	_, checkpoint := checkpointNames(testName)
	files := []string{filepath.Join(f.policyPath, policyFileName), filepath.Join(f.custodyPath, custodyFileName), filepath.Join(f.files.anchorPath, anchorName), filepath.Join(f.files.journalPath, testName), filepath.Join(f.files.journalPath, checkpoint)}
	for i, path := range files {
		label := []string{"policy", "custody", "anchor", "segment", "checkpoint"}[i]
		for _, attack := range []string{"read", "overwrite", "append", "truncate", "unlink", "rename", "hardlink", "chmod", "chown"} {
			t.Run(label+"/"+attack, func(t *testing.T) {
				runAdversary(t, canary, attack, path, nil)
				requireAdversarialSnapshot(t, before, dirs)
			})
		}
	}
	for i, dir := range dirs {
		label := []string{"policy", "custody", "anchor", "journal"}[i]
		for _, attack := range []string{"create", "symlink", "replace-directory"} {
			t.Run(label+"/"+attack, func(t *testing.T) {
				runAdversary(t, canary, attack, dir, nil)
				requireAdversarialSnapshot(t, before, dirs)
			})
		}
	}

	socket := filepath.Join(work, "authority.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socket})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err = chmodFixture(socket, 0600); err != nil {
		t.Fatal(err)
	}
	t.Run("private-socket", func(t *testing.T) {
		runAdversary(t, canary, "private-socket", socket, nil)
	})
	// Deliberately expose only this disposable test listener, to prove that
	// product authorization still rejects a peer that can reach the dispatcher.
	if err = chmodFixture(socket, 0666); err != nil {
		t.Fatal(err)
	}
	requests := []authorityRequest{
		{Operation: "resume"}, {Operation: "commit", Segment: testName},
		{Operation: "inspect-recovery"}, {Operation: "apply-recovery", PlanSHA256: strings.Repeat("0", 64)},
		{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}},
		{Operation: "apply-policy", Change: &authorityChange{Operation: "disable"}, PlanSHA256: strings.Repeat("0", 64)},
	}
	for _, request := range requests {
		t.Run("ungranted-peer/"+request.Operation, func(t *testing.T) {
			data := authorityMessage(t, request)
			runAdversary(t, canary, "request", socket, func(cmd *exec.Cmd) {
				if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				peer, err := listener.AcceptUnix()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				if err = peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				cred, err := custodyPeer(peer)
				if err != nil || cred.Uid != adversaryID || cred.Gid != adversaryID || int(cred.Pid) != cmd.Process.Pid {
					t.Fatal("attacker did not have the required kernel identity", err)
				}
				claimed, err := io.ReadAll(io.LimitReader(peer, 64))
				if err != nil || string(claimed) != "uid=0;role=administrator" {
					t.Fatal("missing identity-spoofing probe", err)
				}
				// Claimed identity bytes are not an authorization input. Exercise
				// each canonical route against the actual accepted kernel peer.
				_ = authorityDenied(t, a, peer, data)
				if _, err = peer.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
			})
			requireAdversarialSnapshot(t, before, dirs)
		})
	}
	// Replace the test-only dispatcher with the actual bounded listener. Group
	// membership permits connecting but does not grant any authority operation.
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	endpointPath := filepath.Join(work, "endpoint")
	if err := os.Mkdir(endpointPath, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(endpointPath, 0, adversaryID); err != nil {
		t.Fatal(err)
	}
	endpoint, err := openFixtureDirectory(endpointPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	limits := testTransportLimits()
	limits.MaxPeersPerUID = 1
	limits.ReadTimeout = MaxAuthorityIOTimeout
	pin, _ := testDirectory(t)
	server := testServer(t, AuthorityServerConfig{Authority: f.config, Transport: limits, Directory: endpoint, PinDirectory: pin, GroupID: adversaryID, AcceptInterval: MinAuthorityAcceptInterval})
	done := runServer(server)
	endpointName := filepath.Join(endpointPath, AuthoritySocketName)
	var socketBefore unix.Stat_t
	if err = unix.Lstat(endpointName, &socketBefore); err != nil {
		t.Fatal(err)
	}
	for _, attack := range []string{"unlink", "rename", "hardlink", "chmod", "chown", "create", "symlink", "replace-directory"} {
		t.Run("endpoint-"+attack, func(t *testing.T) {
			target := endpointName
			if attack == "create" || attack == "symlink" || attack == "replace-directory" {
				target = endpointPath
			}
			runAdversary(t, canary, attack, target, nil)
			var after unix.Stat_t
			if err := unix.Lstat(endpointName, &after); err != nil || after != socketBefore {
				t.Fatal("endpoint changed", err)
			}
			requireAdversarialSnapshot(t, before, dirs)
		})
	}
	for _, attack := range []string{"read", "overwrite", "append", "truncate", "unlink", "rename", "hardlink", "chmod", "chown"} {
		t.Run("endpoint-owner-"+attack, func(t *testing.T) {
			name := filepath.Join(endpointPath, AuthorityEndpointRecordName)
			before := adversarialSnapshot(t, []string{name})
			runAdversary(t, canary, attack, name, nil)
			requireAdversarialSnapshot(t, before, []string{name})
		})
	}
	t.Run("endpoint-outside-group", func(t *testing.T) { runAdversary(t, canary, "outside-socket", endpointName, nil) })
	for _, request := range requests {
		t.Run("endpoint-ungranted-"+request.Operation, func(t *testing.T) {
			runAdversary(t, canary, "framed-"+request.Operation, endpointName, nil)
			requireAdversarialSnapshot(t, before, dirs)
		})
	}
	serverWait(t, server, func(st AuthorityServerStatus) bool { return st.Failed == 6 && st.Active == 0 })
	if server.Status().Accepted != 6 || server.Status().Completed != 0 {
		t.Fatal("ungranted group member accepted", server.Status())
	}
	t.Run("endpoint-uid-quota", func(t *testing.T) {
		testAuthorityPeerQuotaBoundary(t, canary, endpointName, server, f)
		requireAdversarialSnapshot(t, before, dirs)
	})
	t.Run("client-rejects-impostor", func(t *testing.T) {
		fakeDir := filepath.Join(work, "impostor-endpoint")
		if err := os.Mkdir(fakeDir, 0750); err != nil {
			t.Fatal(err)
		}
		owned, err := openFixtureDirectory(fakeDir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = owned.Close() }()
		fakeSocket := filepath.Join(canary, AuthoritySocketName)
		runAdversary(t, canary, "fake-service", fakeSocket, func(_ *exec.Cmd) {
			ready := filepath.Join(canary, "listener-ready")
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, err := os.Lstat(ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("impostor not ready")
				}
				time.Sleep(time.Millisecond)
			}
			// Deliberately deposit the attacker's already listening socket in an
			// otherwise correctly provisioned directory and repair its metadata.
			// Only the kernel listener identity still distinguishes the impostor.
			name := filepath.Join(fakeDir, AuthoritySocketName)
			if err := os.Rename(fakeSocket, name); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(name, 0, 0); err != nil {
				t.Fatal(err)
			}
			if err := chmodFixture(name, 0660); err != nil {
				t.Fatal(err)
			}
			client := testAuthorityClient(t, AuthorityClientConfig{Directory: owned, ServiceUID: 0, ServiceGID: 0, SocketGID: 0, Timeout: time.Second})
			data, err := client.Call(authorityMessage(t, authorityRequest{Operation: "resume"}))
			if data != nil || !errors.Is(err, ErrAuthorityService) || errors.Is(err, ErrAuthorityOutcomeUnknown) {
				t.Fatal("impostor received a request", err)
			}
		})
		requireAdversarialSnapshot(t, before, dirs)
	})
	t.Run("authorized-operation-after-attacks", func(t *testing.T) {
		// The same listener must still serve an authorized real peer after every
		// refused attack, rather than merely returning denials to all callers.
		client := testAuthorityClient(t, AuthorityClientConfig{Directory: endpoint, ServiceUID: 0, ServiceGID: 0, SocketGID: adversaryID, Timeout: time.Second})
		authorityAnchor(t, clientReply(t, client, authorityRequest{Operation: "resume"}), f.files.expected)
		authorityAnchor(t, clientReply(t, client, authorityRequest{Operation: "commit", Segment: testName}), f.files.next)
		stopServer(t, server, done)
		reopened := openAuthority(t, f.config)
		authorityAnchor(t, authorityReply(t, reopened, f.peer, authorityRequest{Operation: "resume"}), f.files.next)
	})
	t.Run("endpoint-uid-rate", func(t *testing.T) { testAuthorityRateBoundary(t, canary, work) })
	testAuthorityProcessBoundary(t)
}

type adversarialFileState struct {
	Mode, UID, GID uint32
	Links          uint64
	Dev, Inode     uint64
	Modified       unix.Timespec
	Changed        unix.Timespec
	Data           string
}

func adversarialSnapshot(t *testing.T, dirs []string) map[string]adversarialFileState {
	t.Helper()
	out := make(map[string]adversarialFileState)
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			var st unix.Stat_t
			if err = unix.Lstat(path, &st); err != nil {
				return err
			}
			state := adversarialFileState{Mode: st.Mode, UID: st.Uid, GID: st.Gid, Links: uint64(st.Nlink), Dev: uint64(st.Dev), Inode: st.Ino, Modified: st.Mtim, Changed: st.Ctim}
			if !entry.IsDir() {
				state.Data = string(readFile(t, path))
			}
			out[path] = state
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
func requireAdversarialSnapshot(t *testing.T, before map[string]adversarialFileState, dirs []string) {
	t.Helper()
	if !reflect.DeepEqual(before, adversarialSnapshot(t, dirs)) {
		t.Fatal("attacker changed protected bytes, metadata or directory entries")
	}
}

func runAdversary(t *testing.T, canary, attack, target string, serve func(*exec.Cmd), extraFiles ...*os.File) {
	t.Helper()
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestLocalUnprivilegedChild$", "-test.timeout=10s")
	cmd.Dir = "/"
	cmd.ExtraFiles = extraFiles
	cmd.Env = []string{"SYSWARDEN_CROSS_UID_CHILD=" + attack, "SYSWARDEN_CROSS_UID_TARGET=" + target, "SYSWARDEN_CROSS_UID_CANARY=" + canary}
	gid := uint32(adversaryID)
	if attack == "outside-socket" {
		gid--
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: adversaryID, Gid: gid, Groups: []uint32{}}}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if serve != nil {
		serve(cmd)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err, output.String())
	}
	if !strings.Contains(output.String(), "cross-UID attacker completed") {
		t.Fatal("attacker did not execute its assertions")
	}
}

func TestLocalUnprivilegedChild(t *testing.T) {
	attack := os.Getenv("SYSWARDEN_CROSS_UID_CHILD")
	if attack == "" {
		return
	}
	// no_new_privs is thread-scoped. Keep all attack syscalls on the verified
	// thread instead of relying on Go scheduler placement.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gid := adversaryID
	if attack == "outside-socket" {
		gid--
	}
	if os.Getuid() != adversaryID || os.Geteuid() != adversaryID || os.Getgid() != gid || os.Getegid() != gid {
		t.Fatal("attacker identity not dropped")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("attacker retained supplementary groups", err)
	}
	if err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	status := string(readFile(t, "/proc/thread-self/status"))
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if !strings.Contains(status, key+":\t0000000000000000\n") {
			t.Fatal("attacker retained capability", key)
		}
	}
	if !strings.Contains(status, "NoNewPrivs:\t1\n") || unix.Setuid(0) == nil {
		t.Fatal("attacker can acquire privilege")
	}
	canary, err := os.OpenRoot(os.Getenv("SYSWARDEN_CROSS_UID_CANARY"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = canary.Close() }()
	// Positive control: ordinary filesystem access must work for this identity.
	if err = canary.WriteFile("probe", []byte("attacker-controlled"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := canary.ReadFile("probe"); err != nil || string(got) != "attacker-controlled" {
		t.Fatal("positive control failed", err)
	}
	defer func() { _ = canary.Remove("probe") }()
	target := os.Getenv("SYSWARDEN_CROSS_UID_TARGET")
	if strings.HasPrefix(attack, "framed-") {
		r := authorityRequest{Operation: strings.TrimPrefix(attack, "framed-")}
		switch r.Operation {
		case "commit":
			r.Segment = testName
		case "apply-recovery":
			r.PlanSHA256 = strings.Repeat("0", 64)
		case "inspect-policy":
			r.Change = &authorityChange{Operation: "disable"}
		case "apply-policy":
			r.Change = &authorityChange{Operation: "disable"}
			r.PlanSHA256 = strings.Repeat("0", 64)
		}
		dir, err := openFixtureDirectory(filepath.Dir(target))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = dir.Close() }()
		client, err := OpenLocalAuthorityClient(AuthorityClientConfig{Directory: dir, ServiceUID: 0, ServiceGID: 0, SocketGID: adversaryID, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		body, err := client.Call(authorityMessage(t, r))
		if body != nil || !errors.Is(err, ErrAuthorityDenied) || !errors.Is(err, ErrAuthorityOutcomeUnknown) {
			t.Fatal("ungranted client obtained a result", err)
		}
		println("cross-UID attacker completed")
		return
	}
	switch attack {
	case "quota-hold", "quota-denied":
		quotaAdversary(t, target, attack)
		println("cross-UID attacker completed")
		return
	case "rate-repeat":
		rateAdversary(t, target)
		println("cross-UID attacker completed")
		return
	case "fake-service":
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: target})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		defer func() { _ = listener.Close() }()
		if err := canary.WriteFile("listener-ready", []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		peer, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = peer.Close() }()
		if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(peer, 1))
		if err != nil || len(data) != 0 {
			t.Fatal("client disclosed request to wrong service UID", err)
		}
		println("cross-UID attacker completed")
		return
	case "private-socket", "outside-socket", "request":
		var conn *net.UnixConn
		conn, err = net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: target})
		if err == nil {
			defer func() { _ = conn.Close() }()
		}

		if attack == "request" {
			if err != nil {
				t.Fatal(err)
			}
			if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = conn.Write([]byte("uid=0;role=administrator")); err != nil {
				t.Fatal(err)
			}
			if err = conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var ack [1]byte
			if _, err = io.ReadFull(conn, ack[:]); err != nil || ack[0] != 0 {
				t.Fatal("test dispatcher did not reject peer", err)
			}
			println("cross-UID attacker completed")
			return
		}
	case "read", "overwrite", "append", "truncate", "create":
		flags := map[string]int{"read": unix.O_RDONLY, "overwrite": unix.O_WRONLY, "append": unix.O_WRONLY | unix.O_APPEND, "truncate": unix.O_WRONLY | unix.O_TRUNC, "create": unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL}[attack]
		if attack == "create" {
			target = filepath.Join(target, "forged-result")
		}
		var fd int
		fd, err = unix.Open(target, flags|unix.O_CLOEXEC, 0600)
		if err == nil {
			_ = unix.Close(fd)
		}
	case "unlink":
		err = unix.Unlink(target)
	case "rename":
		err = unix.Rename(filepath.Join(os.Getenv("SYSWARDEN_CROSS_UID_CANARY"), "probe"), target)
	case "hardlink":
		err = unix.Link(target, filepath.Join(os.Getenv("SYSWARDEN_CROSS_UID_CANARY"), "alias"))
	case "chmod":
		err = unix.Chmod(target, 0666)
	case "chown":
		err = unix.Chown(target, adversaryID, adversaryID)
	case "symlink":
		err = unix.Symlink(filepath.Join(os.Getenv("SYSWARDEN_CROSS_UID_CANARY"), "probe"), filepath.Join(target, "forged-result"))
	case "replace-directory":
		err = unix.Rename(target, filepath.Join(os.Getenv("SYSWARDEN_CROSS_UID_CANARY"), "stolen"))
	default:
		t.Fatal("unknown attack")
	}
	// A nonexistent target, wrong syscall or other incidental error is not proof
	// of an access-control refusal. The parent separately attests unchanged state.
	if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
		t.Fatal("operation was not denied by access control", err)
	}
	println("cross-UID attacker completed")
}

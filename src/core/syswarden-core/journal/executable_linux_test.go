package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This separate opt-in gate runs the real product executable built by CI. Test
// provisioning and credential drop remain synthetic, not an installed launcher.
func TestAuthorityExecutableBoundary(t *testing.T) {
	if os.Getenv("SYSWARDEN_REQUIRE_AUTHORITY_EXECUTABLE") != "1" {
		t.Skip("dedicated executable gate required; explicit built binary and credential-changing authority needed")
	}
	if os.Geteuid() != 0 {
		t.Fatal("executable gate requires a root identity inside its test environment")
	}
	var binary executableImages
	if !t.Run("verified-binary", func(child *testing.T) {
		binary.authority = authorityExecutableFixture(child, t, "SYSWARDEN_AUTHORITY_EXECUTABLE")
	}) {
		return
	}
	if !t.Run("verified-bootstrap", func(child *testing.T) {
		binary.bootstrap = authorityExecutableFixture(child, t, "SYSWARDEN_AUTHORITY_BOOTSTRAP")
	}) {
		return
	}
	if !t.Run("verified-launcher", func(child *testing.T) {
		binary.launcher = authorityExecutableFixture(child, t, "SYSWARDEN_AUTHORITY_LAUNCHER")
	}) {
		return
	}
	binary.digest = os.Getenv("SYSWARDEN_AUTHORITY_EXECUTABLE_SHA256")
	policy := testCustodyPolicy()
	policy.NotBefore, policy.NotAfter = time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix()
	t.Run("executable-snapshot", testAuthorityExecutableSnapshot)
	c, next := provisionProcessFixture(t, policy)
	before := adversarialSnapshot(t, c.Paths)
	for _, kind := range []string{"missing-descriptors", "wrong-digest", "wrong-identity", "swapped-directories", "read-only-readiness", "missing-no-new-privileges", "real-root-identity", "unexpected-group", "ambient-capability", "wrong-image-digest", "unsealed-image", "missing-image", "bootstrap-root", "launcher-not-root", "launcher-wrong-launch-digest", "launcher-wrong-image-digest", "launcher-missing-image", "launcher-unsealed-image"} {
		t.Run(kind, func(t *testing.T) {
			p := executableCommand(t, binary, c, kind)
			p.start(t)
			p.exit(t, 1)
			p.noReadiness(t)
			requireAdversarialSnapshot(t, before, c.Paths)
			requireExecutableCleanup(t, c)
		})
	}
	t.Run("bootstrap-lifecycle", func(t *testing.T) {
		p := executableCommand(t, binary, c, "bootstrap-only")
		p.start(t)
		p.ready(t)
		requireExecutableIdentity(t, p.cmd.Process.Pid)
		p.signal(t, syscall.SIGTERM)
		p.exit(t, 0)
		p.noReadiness(t)
		requireExecutableCleanup(t, c)
		requireAdversarialSnapshot(t, before, c.Paths)
	})
	var p *executableProcess
	if !t.Run("start", func(child *testing.T) { p = executableCommand(t, binary, c, ""); p.start(child); p.ready(child) }) {
		return
	}
	c.ServicePID = p.cmd.Process.Pid
	t.Run("kernel-identity", func(t *testing.T) { requireExecutableIdentity(t, c.ServicePID) })
	t.Run("bootstrap-inheritance", func(t *testing.T) { requireBootstrapInheritance(t, p, binary) })
	t.Run("launcher-bounding-set", func(t *testing.T) {
		requireExecutableThreadFields(t, c.ServicePID, map[string]string{"CapBnd": "0000000000000000"})
	})
	for _, check := range []struct {
		name, mode string
		uid        uint32
	}{
		{"client-resume", "resume", processClientID},
		{"client-private-storage", "private-storage", processClientID},
		{"client-process-interference", "process-interference", processClientID},
		{"client-no-administration", "no-administration", processClientID},
		{"stranger-resume-denied", "deny-resume", processStrangerID},
	} {
		t.Run(check.name, func(t *testing.T) {
			runProcessClient(t, check.mode, c, check.uid)
			requireAdversarialSnapshot(t, before, c.Paths)
		})
	}
	c.Expected = next
	t.Run("client-commit", func(t *testing.T) { runProcessClient(t, "commit", c, processClientID) })
	after := adversarialSnapshot(t, c.Paths)
	if reflect.DeepEqual(before, after) {
		t.Fatal("authorized executable commit did not change protected state")
	}
	t.Run("client-replay-denied", func(t *testing.T) {
		runProcessClient(t, "deny-commit", c, processClientID)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	t.Run("sigterm-clean-drain", func(t *testing.T) {
		p.signal(t, syscall.SIGTERM)
		p.exit(t, 0)
		p.noReadiness(t)
		requireExecutableCleanup(t, c)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	if !t.Run("restart", func(child *testing.T) {
		p = executableCommand(t, binary, c, "")
		p.start(child)
		p.ready(child)
		requireExecutableIdentity(child, p.cmd.Process.Pid)
	}) {
		return
	}
	c.ServicePID = p.cmd.Process.Pid
	t.Run("client-resume-after-restart", func(t *testing.T) {
		runProcessClient(t, "resume", c, processClientID)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	t.Run("sigint-clean-drain", func(t *testing.T) {
		p.signal(t, syscall.SIGINT)
		p.exit(t, 0)
		p.noReadiness(t)
		requireExecutableCleanup(t, c)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	t.Run("sigkill-preserves-evidence", func(child *testing.T) {
		p = executableCommand(t, binary, c, "")
		p.start(child)
		p.ready(child)
		paths := executableEvidencePaths(c)
		retained := endpointRecoverySnapshot(child, paths)
		if len(retained) != len(paths) {
			child.Fatal("missing live endpoint evidence")
		}
		p.signal(child, syscall.SIGKILL)
		p.exit(child, -1)
		p.noReadiness(child)
		requireEndpointRecoverySnapshot(child, retained, paths)
		requireAdversarialSnapshot(child, after, c.Paths)
	})
	t.Run("stale-restart-refused", func(t *testing.T) {
		paths := executableEvidencePaths(c)
		retained := endpointRecoverySnapshot(t, paths)
		if len(retained) != len(paths) {
			t.Fatal("missing crash evidence")
		}
		p := executableCommand(t, binary, c, "")
		p.start(t)
		p.exit(t, 1)
		p.noReadiness(t)
		requireEndpointRecoverySnapshot(t, retained, paths)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
}

func authorityExecutableFixture(t, owner *testing.T, prefix string) *os.File {
	t.Helper()
	path, expected := os.Getenv(prefix), os.Getenv(prefix+"_SHA256")
	if !filepath.IsAbs(path) || !validRecoveryApproval(expected) {
		t.Fatal("explicit executable path and lowercase digest required")
	}
	source, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	f, err := source.Open(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 64<<20 {
		t.Fatal("invalid built executable", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	digest := sha256.Sum256(data)
	if err != nil || len(data) > 64<<20 || hex.EncodeToString(digest[:]) != expected {
		t.Fatal("built executable digest mismatch", err)
	}
	// Copy only the verified bytes into a root-controlled fixture. The unprivileged
	// process cannot replace its executable between verification and exec.
	dir := owner.TempDir()
	if err := chmodFixture(filepath.Dir(dir), 0755); err != nil {
		t.Fatal(err)
	}
	if err := chmodFixture(dir, 0755); err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	if err := target.WriteFile("syswarden-authority", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := target.Chmod("syswarden-authority", 0555); err != nil {
		t.Fatal(err)
	}
	sourceImage, err := target.Open("syswarden-authority")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sourceImage.Close() }()
	image, err := SnapshotAuthorityExecutable(sourceImage, expected)
	if err != nil {
		t.Fatal("failed to seal actual executable", err)
	}
	owner.Cleanup(func() { _ = image.Close() })
	// The actual exec must no longer depend on the checked pathname.
	if err := target.Rename("syswarden-authority", "retired-image"); err != nil {
		t.Fatal(err)
	}
	if err := target.WriteFile("syswarden-authority", []byte("not the verified program"), 0600); err != nil {
		t.Fatal(err)
	}
	return image
}

type executableImages struct {
	authority, bootstrap, launcher *os.File
	digest                         string
}

type executableProcess struct {
	canary         *os.File
	cmd            *exec.Cmd
	output         bytes.Buffer
	done           chan error
	reader, writer *os.File
	finished       bool
}

func executableCommand(t *testing.T, binary executableImages, c processFixtureConfig, kind string) *executableProcess {
	t.Helper()
	digest := c.LaunchDigest
	if kind == "wrong-digest" || kind == "launcher-wrong-launch-digest" {
		digest = strings.Repeat("0", 64)
	}
	if !validRecoveryApproval(digest) {
		t.Fatal("invalid fixture launch digest")
	}
	// Normal lifecycle uses the root-to-service product launcher. Bootstrap
	// rejection cases independently retain the non-root product entry point.
	// A separate test-only helper retains the four direct executable guard probes.
	p := &executableProcess{cmd: exec.Command("/proc/self/fd/8"), done: make(chan error, 1)}
	imageDigest := binary.digest
	if kind == "wrong-image-digest" || kind == "launcher-wrong-image-digest" {
		imageDigest = strings.Repeat("0", 64)
	}
	rootLaunch := kind == "" || strings.HasPrefix(kind, "launcher-")
	if rootLaunch {
		p.cmd = exec.Command("/proc/self/fd/10")
	}
	p.cmd.Args = append(p.cmd.Args, "--launch-sha256", digest, "--image-sha256", imageDigest)
	p.cmd.Env = []string{"GOMAXPROCS=2", "SYSWARDEN_INHERITANCE_CANARY=must-not-survive", "LANG=C"}
	switch kind {
	case "missing-no-new-privileges", "real-root-identity", "unexpected-group", "ambient-capability":
		p.cmd = exec.Command("/proc/self/exe", "-test.run=^TestAuthorityExecLauncherChild$")
		p.cmd.Env = []string{"GOMAXPROCS=2", "SYSWARDEN_EXEC_LAUNCH_CHILD=1", "SYSWARDEN_EXEC_LAUNCH_DIGEST=" + digest, "SYSWARDEN_EXEC_LAUNCH_MODE=" + kind}
	}
	p.cmd.Stdout, p.cmd.Stderr = &p.output, &p.output
	uid := uint32(processServiceID)
	if kind == "wrong-identity" {
		uid = processClientID
	}
	if kind == "real-root-identity" || kind == "bootstrap-root" {
		uid = 0
	}
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: processServiceID, Groups: []uint32{processClientID}}}
	if kind == "unexpected-group" {
		p.cmd.SysProcAttr.Credential.Groups = []uint32{processClientID, processStrangerID}
	}
	if kind == "ambient-capability" {
		p.cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_BIND_SERVICE}
	}
	if rootLaunch && kind != "launcher-not-root" {
		// Deliberately inherit unrelated groups and an ambient/inheritable
		// capability. The real launcher must remove them before the service runs.
		p.cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{0, processStrangerID}}
		p.cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_BIND_SERVICE}
	}
	for _, path := range []string{c.LaunchPath, c.StateDirectory, c.Endpoint} {
		root, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		file, err := root.Open(filepath.Base(path))
		if err := errors.Join(err, root.Close()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		p.cmd.ExtraFiles = append(p.cmd.ExtraFiles, file)
	}
	p.reader, p.writer = readinessPipe(t)
	var err error
	p.canary, err = os.CreateTemp(t.TempDir(), "inherited-canary")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.canary.Close() })
	p.cmd.ExtraFiles = append(p.cmd.ExtraFiles, p.writer, binary.authority, binary.bootstrap, p.canary, binary.launcher)
	switch kind {
	case "missing-descriptors":
		p.cmd.ExtraFiles = []*os.File{nil, nil, nil, nil, binary.authority, binary.bootstrap, p.canary, binary.launcher}
	case "swapped-directories":
		p.cmd.ExtraFiles[1], p.cmd.ExtraFiles[2] = p.cmd.ExtraFiles[2], p.cmd.ExtraFiles[1]
	case "read-only-readiness":
		p.cmd.ExtraFiles[3] = p.reader
	case "missing-image", "launcher-missing-image":
		p.cmd.ExtraFiles[4] = nil
	case "unsealed-image", "launcher-unsealed-image":
		fd, err := unix.MemfdCreate("unsealed-negative", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), "unsealed-negative")
		t.Cleanup(func() { _ = f.Close() })
		if _, err := f.Write([]byte("unsealed image")); err != nil {
			t.Fatal(err)
		}
		if err := f.Chmod(0555); err != nil {
			t.Fatal(err)
		}
		p.cmd.ExtraFiles[4] = f
	}
	t.Cleanup(func() {
		if p.cmd.Process != nil && !p.finished {
			_ = p.cmd.Process.Kill()
			select {
			case <-p.done:
				p.finished = true
			case <-time.After(5 * time.Second):
				t.Error("executable cleanup timeout")
			}
		}
	})
	return p
}
func (p *executableProcess) start(t *testing.T) {
	t.Helper()
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	_ = p.writer.Close()
}
func (p *executableProcess) ready(t *testing.T) {
	t.Helper()
	if err := p.reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := io.ReadFull(p.reader, data[:]); err != nil || data[0] != 'R' {
		t.Fatal("executable readiness missing", err)
	}
}
func (p *executableProcess) noReadiness(t *testing.T) {
	t.Helper()
	if err := p.reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	n, err := p.reader.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("unexpected readiness or retained writer", n, err)
	}
}
func (p *executableProcess) signal(t *testing.T, signal syscall.Signal) {
	t.Helper()
	if err := p.cmd.Process.Signal(signal); err != nil {
		t.Fatal(err)
	}
}
func (p *executableProcess) exit(t *testing.T, expected int) {
	t.Helper()
	select {
	case err := <-p.done:
		p.finished = true
		if p.cmd.ProcessState.ExitCode() != expected || (expected == 0 && err != nil) {
			t.Fatal("unexpected executable exit", err, p.output.String())
		}
		if expected == -1 {
			status, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("expected kernel SIGKILL termination")
			}
		}
		if expected == 1 {
			if p.output.String() != "Local authority startup or shutdown failed; preserve retained evidence for inspection.\n" {
				t.Fatal("unexpected failure diagnostic", p.output.String())
			}
		} else if p.output.Len() != 0 {
			t.Fatal("unexpected executable output", p.output.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("executable exit timeout")
	}
}
func requireExecutableCleanup(t *testing.T, c processFixtureConfig) {
	t.Helper()
	for _, dir := range []string{c.Endpoint, c.PinDirectory} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("owned endpoint evidence survived clean lifecycle", err)
		}
	}
}
func requireExecutableIdentity(t *testing.T, pid int) {
	t.Helper()
	requireExecutableThreadFields(t, pid, map[string]string{
		"Uid": "65533 65533 65533 65533", "Gid": "65533 65533 65533 65533", "Groups": "65534",
		"NoNewPrivs": "1", "Umask": "0077",
		"CapInh": "0000000000000000", "CapPrm": "0000000000000000", "CapEff": "0000000000000000", "CapAmb": "0000000000000000",
	})
}

func requireExecutableThreadFields(t *testing.T, pid int, expected map[string]string) {
	t.Helper()
	tasks := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(tasks)
	if err != nil || len(entries) == 0 {
		t.Fatal("missing live executable threads", err)
	}
	for _, entry := range entries {
		data := readFile(t, filepath.Join(tasks, entry.Name(), "status"))
		fields := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[key] = strings.Join(strings.Fields(value), " ")
			}
		}
		for key, want := range expected {
			if fields[key] != want {
				t.Fatalf("executable thread %s has unexpected %s", entry.Name(), key)
			}
		}
	}
	// A status read is an observed startup assertion, not a service sandbox policy.
	// The root launcher establishes an empty bounding set across exec. Native
	// MAC, seccomp and installed service policy still require separate evidence.
}

func executableEvidencePaths(c processFixtureConfig) []string {
	return []string{c.Endpoint, c.PinDirectory, filepath.Join(c.Endpoint, AuthoritySocketName), filepath.Join(c.Endpoint, AuthorityEndpointRecordName), filepath.Join(c.PinDirectory, AuthorityEndpointPinName)}
}

// This helper is linked into the test binary only. The fixed verified relative
// sealed executable descriptor and validated digest cannot select a shell or option.
func TestAuthorityExecLauncherChild(t *testing.T) {
	if os.Getenv("SYSWARDEN_EXEC_LAUNCH_CHILD") != "1" {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	digest := os.Getenv("SYSWARDEN_EXEC_LAUNCH_DIGEST")
	if !validRecoveryApproval(digest) {
		t.Fatal("invalid launch digest")
	}
	mode := os.Getenv("SYSWARDEN_EXEC_LAUNCH_MODE")
	if mode == "missing-no-new-privileges" {
		value, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
		if err != nil || value != 0 {
			t.Fatal("negative control requires an initially unsealed launcher", err)
		}
	} else if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if mode == "real-root-identity" {
		if err := unix.Setresgid(processServiceID, processServiceID, processServiceID); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setresuid(0, processServiceID, processServiceID); err != nil {
			t.Fatal(err)
		}
		r, e, s := unix.Getresuid()
		if r != 0 || e != processServiceID || s != processServiceID {
			t.Fatal("real-root negative control was not established")
		}
	}
	if mode == "ambient-capability" {
		value, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, unix.CAP_NET_BIND_SERVICE, 0, 0)
		if err != nil || value != 1 {
			t.Fatal("ambient capability negative control was not established", err)
		}
	}
	seals, err := unix.FcntlInt(7, unix.F_GET_SEALS, 0)
	if err != nil || seals&authorityImageSeals != authorityImageSeals {
		t.Fatal("unsealed executable descriptor", err)
	}
	if _, err := unix.FcntlInt(7, unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	// The kernel resolves this fixed inherited descriptor before closing it
	// on exec. The service receives only its four original startup handles.
	if err := unix.Exec("/proc/self/fd/7", []string{"syswarden-authority", "--launch-sha256", digest}, []string{"GOMAXPROCS=2"}); err != nil {
		t.Fatal(err)
	}
}

// Inspect the actual post-exec process, not a simulation of descriptor flags.
func requireBootstrapInheritance(t *testing.T, p *executableProcess, images executableImages) {
	t.Helper()
	root := filepath.Join("/proc", strconv.Itoa(p.cmd.Process.Pid))
	env := readFile(t, filepath.Join(root, "environ"))
	if string(env) != "GOMAXPROCS=2\x00" {
		t.Fatal("unexpected inherited environment")
	}
	cwd, err := os.Readlink(filepath.Join(root, "cwd"))
	if err != nil || cwd != "/" {
		t.Fatal("unexpected authority working directory", err)
	}
	var forbidden []os.FileInfo
	for _, f := range []*os.File{p.canary, images.authority, images.bootstrap, images.launcher} {
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		forbidden = append(forbidden, info)
	}
	entries, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil || len(entries) == 0 {
		t.Fatal("cannot inspect authority descriptors", err)
	}
	for _, entry := range entries {
		info, err := os.Stat(filepath.Join(root, "fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} // Runtime fds can close after listing.
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if os.SameFile(info, bad) {
				t.Fatal("unrelated inherited descriptor survived exec")
			}
		}
	}
}

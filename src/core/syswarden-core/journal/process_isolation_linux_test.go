package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	contracts "syswarden-core/contracts/v5"
)

const processServiceID = 65533
const processClientID = 65534
const processStrangerID = 65532

// This is synthetic parent-controlled test provisioning, not a deployable
// configuration loader or an authentication/approval provider.
type processFixtureConfig struct {
	Paths               []string
	Endpoint            string
	Root                CustodyPolicyTrust
	Expected            contracts.JournalCheckpointAnchor
	ServicePID          int
	ExpectStaleEndpoint bool
	RecoverEndpoint     bool
	PinDirectory        string
}

type authorityTestProcess struct {
	cmd      *exec.Cmd
	output   bytes.Buffer
	done     chan error
	stop     *os.File
	finished bool
}

func processCommand(t, owner *testing.T, mode string, c processFixtureConfig, uid, gid uint32, groups []uint32) *authorityTestProcess {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	p := &authorityTestProcess{cmd: exec.Command("/proc/self/exe", "-test.run=^TestAuthorityProcessChild$", "-test.timeout=40s"), done: make(chan error, 1)}
	p.cmd.Dir = "/"
	role := "client"
	if uid == processServiceID {
		role = "service"
	} else if uid == processStrangerID {
		role = "stranger"
	}
	p.cmd.Env = []string{"SYSWARDEN_AUTHORITY_PROCESS_CHILD=" + mode, "SYSWARDEN_AUTHORITY_PROCESS_ROLE=" + role, "GOMAXPROCS=2"}
	p.cmd.Stdin = bytes.NewReader(data)
	p.cmd.Stdout, p.cmd.Stderr = &p.output, &p.output
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	owner.Cleanup(func() {
		if p.cmd.Process != nil && !p.finished {
			_ = p.cmd.Process.Kill()
			select {
			case <-p.done:
				p.finished = true
			case <-time.After(5 * time.Second):
				owner.Error("test child failed to exit")
			}
		}
		if p.stop != nil {
			_ = p.stop.Close()
		}
	})
	return p
}
func (p *authorityTestProcess) start(t *testing.T) {
	t.Helper()
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
}
func (p *authorityTestProcess) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.done:
		p.finished = true
		if err != nil {
			t.Fatal(err, p.output.String())
		}
		if !strings.Contains(p.output.String(), "isolated authority child verified") {
			t.Fatal("child assertion marker missing", p.output.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("test child timeout")
	}
}
func startProcessService(t, owner *testing.T, c processFixtureConfig) *authorityTestProcess {
	t.Helper()
	p := processCommand(t, owner, "service", c, processServiceID, processServiceID, []uint32{processClientID})
	readyR, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readyR.Close(); _ = readyW.Close() }()
	stopR, stopW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stopR.Close() }()
	p.stop = stopW
	p.cmd.ExtraFiles = []*os.File{readyW, stopR}
	p.start(t)
	_ = readyW.Close()
	_ = stopR.Close()
	ready := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := io.ReadFull(readyR, b[:])
		if err == nil && b[0] != 'R' {
			err = errors.New("invalid readiness marker")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			p.wait(t)
			t.Fatal("service did not become ready", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service readiness timeout")
	}
	return p
}
func stopProcessService(t *testing.T, p *authorityTestProcess) {
	t.Helper()
	if _, err := p.stop.Write([]byte{'S'}); err != nil {
		t.Fatal(err)
	}
	p.wait(t)
}
func runProcessClient(t *testing.T, mode string, c processFixtureConfig, uid uint32) {
	t.Helper()
	p := processCommand(t, t, mode, c, uid, processClientID, []uint32{})
	p.start(t)
	p.wait(t)
}

func testAuthorityProcessBoundary(t *testing.T) {
	t.Helper()
	policy := testCustodyPolicy()
	policy.Grants = []CustodyLocalGrant{{UID: processClientID, Operations: []CustodyOperation{CustodyCommit, CustodyResume}}}
	policies, _, policyPath, root := policyFixture(t, policy)
	custody, _, custodyPath := localCustodyFixture(t, nil)
	f, _ := custodyFixture(t, 2)
	if err := errors.Join(policies.Close(), custody.Close()); err != nil {
		t.Fatal(err)
	}
	c := processFixtureConfig{Paths: []string{policyPath, custodyPath, f.anchorPath, f.journalPath}, Root: root.Trust, Expected: f.expected}
	for _, dir := range c.Paths {
		if err := chmodFixture(filepath.Dir(dir), 0755); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("unexpected fixture symlink")
			}
			return root.Chown(name, processServiceID, processServiceID)
		})
		if err := errors.Join(err, root.Close()); err != nil {
			t.Fatal(err)
		}
	}
	_, endpoint := testDirectory(t)
	c.Endpoint = endpoint
	if err := chmodFixture(filepath.Dir(endpoint), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(endpoint, processServiceID, processClientID); err != nil {
		t.Fatal(err)
	}
	if err := chmodFixture(endpoint, 0750); err != nil {
		t.Fatal(err)
	}
	_, c.PinDirectory = testDirectory(t)
	if err := chmodFixture(filepath.Dir(c.PinDirectory), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(c.PinDirectory, processServiceID, processServiceID); err != nil {
		t.Fatal(err)
	}
	before := adversarialSnapshot(t, c.Paths)
	var server *authorityTestProcess
	if !t.Run("process-service-start", func(child *testing.T) { server = startProcessService(child, t, c) }) {
		return
	}
	c.ServicePID = server.cmd.Process.Pid
	protectedPin := adversarialSnapshot(t, []string{c.PinDirectory})
	for _, item := range []struct {
		name, mode string
		uid        uint32
	}{
		{"process-client-resume", "resume", processClientID},
		{"process-client-private-storage", "private-storage", processClientID},
		{"process-client-process-interference", "process-interference", processClientID},
		{"process-client-no-administration", "no-administration", processClientID},
		{"process-stranger-private-storage", "private-storage", processStrangerID},
	} {
		t.Run(item.name, func(t *testing.T) {
			runProcessClient(t, item.mode, c, item.uid)
			requireAdversarialSnapshot(t, protectedPin, []string{c.PinDirectory})
			requireAdversarialSnapshot(t, before, c.Paths)
		})
	}
	for _, op := range []string{"resume", "commit", "inspect-recovery", "apply-recovery", "inspect-policy", "apply-policy"} {
		t.Run("process-stranger-"+op, func(t *testing.T) {
			runProcessClient(t, "deny-"+op, c, processStrangerID)
			requireAdversarialSnapshot(t, before, c.Paths)
		})
	}
	c.Expected = f.next
	t.Run("process-client-commit", func(t *testing.T) { runProcessClient(t, "commit", c, processClientID) })
	after := adversarialSnapshot(t, c.Paths)
	if reflect.DeepEqual(before, after) {
		t.Fatal("authorized commit did not change protected state")
	}
	t.Run("process-client-replay-refused", func(t *testing.T) {
		runProcessClient(t, "deny-commit", c, processClientID)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	t.Run("process-service-stop", func(t *testing.T) {
		stopProcessService(t, server)
		requireAdversarialSnapshot(t, after, c.Paths)
		if _, err := os.Lstat(filepath.Join(endpoint, AuthoritySocketName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned socket survived clean shutdown", err)
		}
	})
	if !t.Run("process-service-restart", func(child *testing.T) { server = startProcessService(child, t, c) }) {
		return
	}
	c.ServicePID = server.cmd.Process.Pid
	t.Run("process-client-resume-after-restart", func(t *testing.T) {
		runProcessClient(t, "resume", c, processClientID)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	t.Run("process-service-final-stop", func(t *testing.T) {
		stopProcessService(t, server)
		requireAdversarialSnapshot(t, after, c.Paths)
		if _, err := os.Lstat(filepath.Join(endpoint, AuthoritySocketName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("restarted socket survived clean shutdown", err)
		}
	})
	t.Run("process-endpoint-crash-preservation", func(t *testing.T) {
		testEndpointProcessCrash(t, c)
		c.RecoverEndpoint = true
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	t.Run("process-endpoint-recovery-denied", func(t *testing.T) {
		runProcessClient(t, "endpoint-recovery-denied", c, processClientID)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
	t.Run("process-endpoint-reviewed-restart", func(t *testing.T) {
		p := startProcessService(t, t, c)
		c.ServicePID = p.cmd.Process.Pid
		runProcessClient(t, "resume", c, processClientID)
		stopProcessService(t, p)
		requireAdversarialSnapshot(t, after, c.Paths)
	})
}

func TestAuthorityProcessChild(t *testing.T) {
	mode := os.Getenv("SYSWARDEN_AUTHORITY_PROCESS_CHILD")
	if mode == "" {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	uid, gid := processClientID, processClientID
	role := os.Getenv("SYSWARDEN_AUTHORITY_PROCESS_ROLE")
	switch role {
	case "service":
		uid, gid = processServiceID, processServiceID
	case "stranger":
		uid = processStrangerID
	case "client":
	default:
		t.Fatal("missing expected process role")
	}
	if (mode == "service") != (role == "service") {
		t.Fatal("role and operation differ")
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid {
		t.Fatal("incorrect child identity")
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if (mode == "service" && !reflect.DeepEqual(groups, []int{processClientID})) || (mode != "service" && len(groups) != 0) {
		t.Fatal("unexpected child supplementary groups")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	status := string(readFile(t, "/proc/thread-self/status"))
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if !strings.Contains(status, key+":\t0000000000000000\n") {
			t.Fatal("child retained capability", key)
		}
	}
	if !strings.Contains(status, "NoNewPrivs:\t1\n") || unix.Setuid(0) == nil {
		t.Fatal("child can acquire privilege")
	}
	canary, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = canary.Close() }()
	if err := canary.WriteFile("probe", []byte("ordinary I/O"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := canary.ReadFile("probe"); err != nil || string(data) != "ordinary I/O" {
		t.Fatal("positive control failed", err)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 32769))
	if err != nil || len(data) > 32768 {
		t.Fatal("invalid test provisioning", err)
	}
	var c processFixtureConfig
	if err := json.Unmarshal(data, &c); err != nil || len(c.Paths) != 4 {
		t.Fatal("invalid test configuration", err)
	}
	// Only the service receives the two explicit lifecycle pipes. No child receives
	// a protected storage descriptor that could bypass its pathname permissions.
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range c.Paths {
			if target == path || strings.HasPrefix(target, path+"/") {
				t.Fatal("inherited private storage descriptor")
			}
		}
	}
	if mode == "service" {
		processServiceChild(t, c)
	} else {
		processClientChild(t, c, mode)
	}
	fmt.Println("isolated authority child verified")
}
func processServiceChild(t *testing.T, c processFixtureConfig) {
	t.Helper()
	dirs := make([]*os.File, 0, 6)
	for _, path := range append(append([]string{}, c.Paths...), c.Endpoint, c.PinDirectory) {
		dir, err := openFixtureDirectory(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = dir.Close() }()
		dirs = append(dirs, dir)
	}
	config := LocalAuthorityConfig{PolicyDirectory: dirs[0], CustodyDirectory: dirs[1], AnchorDirectory: dirs[2], JournalDirectory: dirs[3], PolicyRoot: c.Root, Enrollment: testEnrollment(), Limits: testLimits(), Now: func() time.Time { return policyNow(testCustodyPolicy()) }}
	if c.RecoverEndpoint && !c.ExpectStaleEndpoint {
		// The new process reads the creator's durable private pin after exit.
		// The synthetic callback models supervisor approval, not human MFA.
		peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
		recovery := EndpointRecoveryConfig{Directory: dirs[4], GroupID: processClientID, PinDirectory: dirs[5], Peer: peer, Now: config.Now,
			Authorizer: endpointTestAuthorizer(func(r EndpointRecoveryRequest) (EndpointRecoveryDecision, error) { return endpointTestDecision(r), nil }),
		}
		plan := endpointPlan(t, recovery)
		if result, err := ApplyEndpointRecovery(recovery, plan.SHA256); err != nil || result.PlanSHA256 != plan.SHA256 {
			t.Fatal("reviewed non-root recovery failed", err)
		}
	}
	server, err := OpenLocalAuthorityServer(AuthorityServerConfig{Authority: config, Transport: testTransportLimits(), Directory: dirs[4], PinDirectory: dirs[5], GroupID: processClientID, AcceptInterval: MinAuthorityAcceptInterval})
	if c.ExpectStaleEndpoint {
		if server != nil || !errors.Is(err, ErrAuthorityEndpoint) {
			t.Fatal("fresh service did not preserve stale endpoint", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	done := runServer(server)
	ready, stop := os.NewFile(3, "test-readiness"), os.NewFile(4, "test-stop")
	defer func() { _ = ready.Close(); _ = stop.Close() }()
	if _, err := ready.Write([]byte{'R'}); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(stop, signal[:]); err != nil || signal[0] != 'S' {
		t.Fatal("invalid supervisor stop", err)
	}
	stopServer(t, server, done)
}
func processClientChild(t *testing.T, c processFixtureConfig, mode string) {
	t.Helper()
	if mode == "private-storage" {
		_, checkpoint := checkpointNames(testName)
		paths := []string{filepath.Join(c.Paths[0], policyFileName), filepath.Join(c.Paths[1], custodyFileName), filepath.Join(c.Paths[2], anchorName), filepath.Join(c.Paths[3], testName), filepath.Join(c.Paths[3], checkpoint), filepath.Join(c.PinDirectory, AuthorityEndpointPinName)}
		for _, path := range paths {
			for _, flags := range []int{unix.O_RDONLY, unix.O_WRONLY | unix.O_APPEND} {
				fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if err == nil {
					_ = unix.Close(fd)
					t.Fatal("requester opened private storage")
				}
				if !errors.Is(err, unix.EACCES) {
					t.Fatal("unexpected storage refusal", err)
				}
			}
		}
		pin := filepath.Join(c.PinDirectory, AuthorityEndpointPinName)
		for _, mutate := range []func() error{
			func() error { return os.Remove(pin) },
			func() error { return os.Rename(pin, pin+".moved") },
			func() error { return os.Link(pin, pin+".alias") },
			func() error { return os.Symlink("untrusted", filepath.Join(c.PinDirectory, "replacement")) },
			func() error { return chmodFixture(pin, 0640) },
		} {
			if err := mutate(); !errors.Is(err, unix.EACCES) {
				t.Fatal("ordinary user reached pin mutation", err)
			}
		}
		return
	}
	if mode == "process-interference" {
		if c.ServicePID <= 1 {
			t.Fatal("invalid fixture service PID")
		}
		// Signal zero checks actual permission without sending a destructive signal.
		if err := unix.Kill(c.ServicePID, 0); !errors.Is(err, unix.EPERM) {
			t.Fatal("client can signal service", err)
		}
		return
	}
	dir, err := openFixtureDirectory(c.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()

	if mode == "endpoint-recovery-denied" {
		peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
		recovery := EndpointRecoveryConfig{Directory: dir, GroupID: processClientID, ExpectedRecordSHA256: strings.Repeat("0", 64), Peer: peer,
			Now: func() time.Time { return policyNow(testCustodyPolicy()) },
			Authorizer: endpointTestAuthorizer(func(EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
				t.Fatal("ordinary user reached trusted approval")
				return EndpointRecoveryDecision{}, ErrEndpointRecoveryApproval
			}),
		}
		if _, err := PlanEndpointRecovery(recovery); !errors.Is(err, ErrAuthorityEndpoint) {
			t.Fatal("ordinary user obtained recovery plan", err)
		}
		if _, err := ApplyEndpointRecovery(recovery, strings.Repeat("0", 64)); !errors.Is(err, ErrAuthorityEndpoint) {
			t.Fatal("ordinary user applied recovery", err)
		}
		return
	}
	client, err := OpenLocalAuthorityClient(AuthorityClientConfig{Directory: dir, ServiceUID: processServiceID, ServiceGID: processServiceID, SocketGID: processClientID, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if mode == "no-administration" {
		for _, op := range []string{"inspect-policy", "apply-policy"} {
			processDenied(t, client, op)
		}
		return
	}
	if strings.HasPrefix(mode, "deny-") {
		processDenied(t, client, strings.TrimPrefix(mode, "deny-"))
		return
	}
	r := authorityRequest{Operation: mode}
	if mode == "commit" {
		r.Segment = testName
	}
	authorityAnchor(t, clientReply(t, client, r), c.Expected)
}
func processDenied(t *testing.T, client *LocalAuthorityClient, op string) {
	t.Helper()
	r := authorityRequest{Operation: op}
	switch op {
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
	data, err := client.Call(authorityMessage(t, r))
	if data != nil || !errors.Is(err, ErrAuthorityDenied) || !errors.Is(err, ErrAuthorityOutcomeUnknown) {
		t.Fatal("ungranted process obtained authority", err)
	}
}

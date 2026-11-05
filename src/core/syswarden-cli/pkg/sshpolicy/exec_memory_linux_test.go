//go:build linux

package sshpolicy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSSHExecProbeRequiresExactEmptyResult(t *testing.T) {
	for _, test := range []struct {
		n              int
		err            error
		retired, valid bool
	}{
		{0, unix.EIO, false, true}, {0, fmt.Errorf("probe: %w", unix.EIO), false, true},
		{0, io.EOF, true, true}, {0, nil, false, false}, {1, nil, false, false},
		{1, io.EOF, false, false}, {1, unix.EIO, false, false}, {-1, unix.EIO, false, false},
		{0, unix.EPERM, false, false}, {0, unix.EBADF, false, false}, {0, unix.EINTR, false, false},
		{0, unix.ESRCH, false, false}, {0, io.ErrUnexpectedEOF, false, false},
	} {
		got, err := classifySSHExecProbe(test.n, test.err)
		if (err == nil) != test.valid || got != test.retired {
			t.Fatalf("unexpected probe classification: %+v %t %v", test, got, err)
		}
	}
}

func TestSSHExecMemoryRejectsFakeProcAndClosedHandles(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(root.Name()+"/mem", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if memory, err := pinSSHExecMemory(root, os.Geteuid()); err == nil {
		_ = memory.Close()
		t.Fatal("regular file accepted as proc memory")
	}
	if err := os.Remove(root.Name() + "/mem"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/mem", root.Name()+"/mem"); err != nil {
		t.Fatal(err)
	}
	if memory, err := pinSSHExecMemory(root, os.Geteuid()); err == nil {
		_ = memory.Close()
		t.Fatal("proc memory symlink accepted")
	}
	if memory, err := pinSSHExecMemory(nil, os.Geteuid()); err == nil {
		_ = memory.Close()
		t.Fatal("missing proc accepted")
	}
	var memory *sshExecMemory
	if _, err := memory.retired(); err == nil {
		t.Fatal("nil memory accepted")
	}
	if err := memory.Close(); err != nil {
		t.Fatal(err)
	}
	var reload *sshExecReload
	if reload.beforeRequest() == nil || reload.checkAfter() == nil || reload.observe(t.Context(), func() error { return nil }) == nil {
		t.Fatal("nil generation accepted")
	}
	if err := reload.Close(); err != nil {
		t.Fatal(err)
	}
}

// The isolated child execs the same test executable only after a parent byte.
// No SSH daemon, operator state, signal, arbitrary executable or secret is used.
func TestSSHExecMemoryFixtureChild(t *testing.T) {
	stage := os.Getenv("SYSWARDEN_EXEC_MEMORY_CHILD")
	if stage == "" {
		return
	}
	if stage != "before" && stage != "after" {
		t.Fatal("invalid fixture stage")
	}
	fmt.Println(stage)
	if stage == "after" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	var gate [1]byte
	if _, err := io.ReadFull(os.Stdin, gate[:]); err != nil || gate[0] != 'x' {
		t.Fatal("missing exec instruction", err)
	}
	if err := unix.Exec("/proc/self/exe", []string{"ssh-exec-memory-fixture", "-test.run=^TestSSHExecMemoryFixtureChild$"}, []string{"SYSWARDEN_EXEC_MEMORY_CHILD=after", "GOMAXPROCS=2"}); err != nil {
		t.Fatal(err)
	}
}

func TestSSHExecMemoryNativeGenerationAndExit(t *testing.T) {
	state, digest, group := sshProcessOracleExpectation(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestSSHExecMemoryFixtureChild$")
	command.Env = []string{"SYSWARDEN_EXEC_MEMORY_CHILD=before", "GOMAXPROCS=2"}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = command.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "before\n" {
		t.Fatal("fixture did not start", err)
	}
	process, err := bindSSHProcess(command.Process.Pid, os.Geteuid(), group, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	before, err := process.observe()
	if err != nil {
		t.Fatal(err)
	}
	guard := func() error {
		current, err := process.observe()
		if err != nil || !reflect.DeepEqual(before, current) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return ctx.Err()
	}
	memory, err := pinSSHExecMemory(process.proc, process.uid)
	if err != nil {
		t.Fatal(err)
	}
	reload := &sshExecReload{before: memory, open: func() (*sshExecMemory, error) { return pinSSHExecMemory(process.proc, process.uid) }}
	defer reload.Close()
	if err := reload.beforeRequest(); err != nil {
		t.Fatal(err)
	}
	if err := reload.observe(ctx, guard); err == nil || !strings.Contains(err.Error(), "address-space replacement") {
		t.Fatal("no-op accepted", err)
	}
	if reload.after != nil {
		t.Fatal("no-op opened replacement")
	}
	if _, err := stdin.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "after\n" {
		t.Fatal("fixture did not exec", err)
	}
	if err := reload.beforeRequest(); err == nil {
		t.Fatal("exec before dispatch accepted")
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	if err := reload.observe(stopped, guard); !errors.Is(err, context.Canceled) || reload.after != nil {
		t.Fatal("canceled observation accepted", err)
	}
	refused := errors.New("fixture policy changed")
	if err := reload.observe(ctx, func() error { return refused }); !errors.Is(err, refused) || reload.after != nil {
		t.Fatal("policy refusal accepted", err)
	}
	open := reload.open
	reload.open = func() (*sshExecMemory, error) { return nil, unix.EACCES }
	if err := reload.observe(ctx, guard); !errors.Is(err, unix.EACCES) || reload.after != nil {
		t.Fatal("inaccessible replacement accepted", err)
	}
	reload.open = open
	if err := reload.observe(ctx, guard); err != nil {
		t.Fatal("same-process exec not observed", err)
	}
	if err := reload.checkAfter(); err != nil {
		t.Fatal(err)
	}
	if err := reload.observe(ctx, guard); err == nil {
		t.Fatal("duplicate observation accepted")
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
	if err := guard(); err == nil {
		t.Fatal("exit accepted as live process")
	}
	if err := reload.checkAfter(); err == nil {
		t.Fatal("exited replacement accepted")
	}
	if err := reload.Close(); err == nil {
		t.Fatal("late process exit concealed at close")
	}
	if err := reload.Close(); err != nil {
		t.Fatal("second close failed", err)
	}
}

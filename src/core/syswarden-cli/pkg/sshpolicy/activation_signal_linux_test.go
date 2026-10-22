//go:build linux

package sshpolicy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSSHReloadSignalFixtureChild(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_RELOAD_CHILD") != "yes" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGHUP)
	defer signal.Stop(signals)
	fmt.Println("ready")
	<-signals
	fmt.Println("reload-received")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// Signal only a disposable copy of this test binary, never an installed SSH
// service. This proves the syscall target and exit boundary, not SSH reload.
func TestSSHReloadSignalNativePinnedChild(t *testing.T) {
	state, digest, group := sshProcessOracleExpectation(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestSSHReloadSignalFixtureChild$")
	command.Env = []string{"SYSWARDEN_SSH_RELOAD_CHILD=yes", "GOMAXPROCS=2"}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			cancel()
			_ = command.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal("child did not start", err)
	}
	process, err := bindSSHProcess(command.Process.Pid, os.Geteuid(), group, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	if err := sendSSHProcessReload(process); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "reload-received\n" {
		t.Fatal("pinned child did not receive SIGHUP", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
	if err := sendSSHProcessReload(process); err == nil {
		t.Fatal("signalled an exited target")
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	if sendSSHProcessReload(process) == nil || sendSSHProcessReload(nil) == nil {
		t.Fatal("accepted closed or nil target")
	}
}

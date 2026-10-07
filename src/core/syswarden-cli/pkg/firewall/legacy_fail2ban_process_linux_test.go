//go:build linux

package firewall

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLegacyFail2banProcessChild(t *testing.T) {
	mode := os.Getenv("SYSWARDEN_PROCESS_BINDING_CHILD")
	if mode == "" {
		return
	}
	fmt.Println("fixture ready")
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	if mode == "exec" {
		// The child deliberately replaces its own image to test rejection.
		if err := syscall.Exec("/usr/bin/sleep", []string{"/usr/bin/sleep", "10"}, []string{"PATH=/usr/bin:/bin"}); err != nil {
			t.Fatal(err)
		}
	}
}

func fixtureLegacyFail2banProcess(t *testing.T, mode string) (syscall.Ucred, legacyFail2banProcessExpectation, *exec.Cmd, io.WriteCloser) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, executable, "-test.run=^TestLegacyFail2banProcessChild$", "-test.count=1") // #nosec G204 -- Executes only this compiled test binary as a bounded disposable child.
	command.Env = append(os.Environ(), "SYSWARDEN_PROCESS_BINDING_CHILD="+mode)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "fixture ready\n" {
		t.Fatal("fixture did not become ready", err)
	}
	pid, err := strconv.ParseInt(strconv.Itoa(command.Process.Pid), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(strconv.Itoa(os.Geteuid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(strconv.Itoa(os.Getegid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := os.OpenRoot("/proc/" + strconv.FormatInt(pid, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proc.Close() }()
	cgroup, err := readLegacyFail2banProcessFile(proc, "cgroup", 16384)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	return syscall.Ucred{Pid: int32(pid), Uid: uint32(uid), Gid: uint32(gid)}, legacyFail2banProcessExpectation{
		executable: identity, arguments: command.Args, cgroup: cgroup, paths: map[string]os.FileInfo{executable: identity},
	}, command, input
}

func TestLegacyFail2banProcessRejectsExitAndChangedImage(t *testing.T) {
	for _, mode := range []string{"exit", "exec"} {
		t.Run(mode, func(t *testing.T) {
			peer, expected, command, input := fixtureLegacyFail2banProcess(t, mode)
			binding, err := bindLegacyFail2banProcess(peer, expected)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = binding.Close() })
			if err := binding.verify(); err != nil {
				t.Fatal("stable fixture rejected", err)
			}
			if err := binding.verifyReadOnlyPeer(); err != nil {
				t.Fatal("stable read-only peer rejected", err)
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "exit" {
				if err := command.Wait(); err != nil {
					t.Fatal(err)
				}
			} else {
				deadline := time.Now().Add(3 * time.Second)
				for {
					info, err := os.Stat(fmt.Sprintf("/proc/%d/exe", peer.Pid))
					if err != nil || !os.SameFile(info, expected.executable) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("child did not replace its image")
					}
					time.Sleep(time.Millisecond)
				}
			}
			if err := binding.verify(); err == nil {
				t.Fatal("exited or replaced process accepted")
			}
			if err := binding.verifyReadOnlyPeer(); err == nil {
				t.Fatal("exited or replaced read-only peer accepted")
			}
			if err := binding.Close(); err != nil {
				t.Fatal(err)
			}
			if err := binding.verify(); err == nil {
				t.Fatal("closed binding accepted")
			}
			if err := binding.verifyReadOnlyPeer(); err == nil {
				t.Fatal("closed read-only peer binding accepted")
			}
		})
	}
}

func TestLegacyFail2banProcessVerifiesRetiredPathAbsence(t *testing.T) {
	peer, expected, _, _ := fixtureLegacyFail2banProcess(t, "exit")
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := root.WriteFile("active.conf", []byte("fixture original"), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := root.Stat("active.conf")
	if err != nil {
		t.Fatal(err)
	}
	active, backup := filepath.Join(directory, "active.conf"), filepath.Join(directory, "original")
	expected.paths[active] = original
	binding, err := bindLegacyFail2banProcess(peer, expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close() })
	if err := root.Rename("active.conf", "original"); err != nil {
		t.Fatal(err)
	}
	if err := binding.verify(); err == nil {
		t.Fatal("ordinary process verification allowed an unplanned source move")
	}
	retired, err := root.Stat("original")
	if err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]os.FileInfo)
	for path, identity := range expected.paths {
		if path != active {
			paths[path] = identity
		}
	}
	paths[backup] = retired
	check := func() error {
		binding.mu.Lock()
		defer binding.mu.Unlock()
		return binding.observePaths(false, paths, []string{active})
	}
	if err := check(); err != nil {
		t.Fatal("process could not attest the exact backup and active-path absence", err)
	}
	if err := root.Symlink("missing", "active.conf"); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("a dangling active-path symlink was treated as absence")
	}
	if err := root.Remove("active.conf"); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("active.conf", []byte("recreated configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("a recreated active configuration escaped process-view checks")
	}
}

func TestLegacyFail2banProcessRejectsUnmatchedExpectations(t *testing.T) {
	for _, kind := range []string{"pid", "uid", "gid", "arguments", "cgroup", "executable", "path-view", "missing-paths", "invalid-path", "missing-executable"} {
		t.Run(kind, func(t *testing.T) {
			peer, expected, _, _ := fixtureLegacyFail2banProcess(t, "exit")
			switch kind {
			case "pid":
				peer.Pid = -1
			case "uid":
				peer.Uid++
			case "gid":
				peer.Gid++
			case "arguments":
				expected.arguments = []string{"/usr/bin/python3", "/usr/bin/fail2ban-server"}
			case "cgroup":
				expected.cgroup = []byte("0::/wrong-service\n")
			case "executable":
				var err error
				expected.executable, err = os.Stat("/usr/bin/sleep")
				if err != nil {
					t.Fatal(err)
				}
			case "path-view":
				expected.paths = map[string]os.FileInfo{"/usr/bin/sleep": expected.executable}
			case "missing-paths":
				expected.paths = nil
			case "invalid-path":
				expected.paths = map[string]os.FileInfo{"/proc/../etc": expected.executable}
			case "missing-executable":
				expected.executable = nil
			}
			binding, err := bindLegacyFail2banProcess(peer, expected)
			if binding != nil {
				_ = binding.Close()
			}
			if err == nil {
				t.Fatal("unmatched process expectation accepted")
			}
		})
	}
}

func TestLegacyFail2banProcessRechecksTrustedPath(t *testing.T) {
	peer, expected, _, _ := fixtureLegacyFail2banProcess(t, "exit")
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("configuration", []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := root.Stat("configuration")
	if err != nil {
		t.Fatal(err)
	}
	expected.paths[filepath.Join(root.Name(), "configuration")] = identity
	binding, err := bindLegacyFail2banProcess(peer, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = binding.Close() }()
	if err := root.WriteFile("configuration", []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := binding.verifyReadOnlyPeer(); err != nil {
		t.Fatal("read-only peer unexpectedly attested configuration", err)
	}
	if err := binding.verify(); err == nil {
		t.Fatal("changed trusted path accepted")
	}
}

func TestLegacyFail2banProcessParsers(t *testing.T) {
	fields := strings.Fields("S " + strings.Repeat("0 ", 49))
	fields[19] = "12345"
	valid := "42 (comm ) with\nparentheses) " + strings.Join(fields, " ") + "\n"
	if ticks, err := legacyFail2banProcessStart([]byte(valid), 42); err != nil || ticks != 12345 {
		t.Fatal("valid proc stat rejected", err)
	}
	for _, invalid := range []string{"", "42 (x) S 0", strings.Replace(valid, "42 (", "43 (", 1), strings.Replace(valid, ") S ", ") Z ", 1), strings.Replace(valid, "12345", "-1", 1)} {
		if _, err := legacyFail2banProcessStart([]byte(invalid), 42); err == nil {
			t.Fatal("malformed or dead proc stat accepted")
		}
	}
	peer := syscall.Ucred{Pid: 42, Uid: 3, Gid: 4}
	status := "Name:\tfixture\nPid:\t42\nTgid:\t42\nTracerPid:\t0\nUid:\t3 3 3 3\nGid:\t4 4 4 4\n"
	if err := verifyLegacyFail2banProcessCredentials([]byte(status), peer); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", status + "Pid:\t42\n", strings.Replace(status, "3 3 3 3", "3 0 3 3", 1), strings.Replace(status, "TracerPid:\t0", "TracerPid:\t9", 1), strings.Replace(status, "Tgid:\t42\n", "", 1)} {
		if err := verifyLegacyFail2banProcessCredentials([]byte(invalid), peer); err == nil {
			t.Fatal("unsafe process credentials accepted")
		}
	}
}

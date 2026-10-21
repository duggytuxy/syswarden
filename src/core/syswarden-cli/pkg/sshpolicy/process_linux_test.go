//go:build linux

package sshpolicy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func sshProcStatFixture() []byte {
	fields := append([]string{"S"}, strings.Fields(strings.Repeat("0 ", 49))...)
	fields[19] = "12345"
	return []byte("123 (sshd (listener)) " + strings.Join(fields, " ") + "\n")
}

func TestSSHProcessStartRejectsMalformedOrDeadIdentity(t *testing.T) {
	valid := string(sshProcStatFixture())
	if started, err := sshProcessStart([]byte(valid), 123); err != nil || started != 12345 {
		t.Fatal(started, err)
	}
	for name, value := range map[string]string{
		"empty": "", "wrong-pid": strings.Replace(valid, "123 (", "124 (", 1),
		"leading-pid-zero": "0" + valid, "missing-end": strings.TrimSuffix(valid, "\n"),
		"dead": strings.Replace(valid, ") S ", ") Z ", 1), "traced": strings.Replace(valid, ") S ", ") t ", 1),
		"stopped": strings.Replace(valid, ") S ", ") T ", 1), "absent-start": strings.Replace(valid, "12345", "0", 1),
		"signed-start": strings.Replace(valid, "12345", "+12345", 1), "leading-start-zero": strings.Replace(valid, "12345", "012345", 1),
		"overflow": strings.Replace(valid, "12345", "18446744073709551616", 1), "missing-fields": "123 (sshd) S 0\n",
		"too-many-fields": strings.TrimSuffix(valid, "\n") + strings.Repeat(" 0", 20) + "\n", "large": strings.Repeat("x", 8193),
		"embedded-newline": strings.Replace(valid, "sshd", "ssh\nd", 1), "nul": strings.Replace(valid, "sshd", "ssh\x00d", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sshProcessStart([]byte(value), 123); err == nil {
				t.Fatal("accepted malformed process identity")
			}
		})
	}
	for _, pid := range []int{-1, 0, 1} {
		if _, err := sshProcessStart([]byte(valid), pid); err == nil {
			t.Fatal("accepted invalid PID")
		}
	}
}

func TestSSHProcessCredentialsRequireCompleteUntracedRoot(t *testing.T) {
	valid := "Name:\tsshd\nTgid:\t123\nPid:\t123\nTracerPid:\t0\nUid:\t0\t0\t0\t0\n"
	if err := verifySSHProcessCredentials([]byte(valid), 123, 0); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Tgid", "Pid", "TracerPid", "Uid"} {
		for _, mutation := range []string{"missing", "duplicate", "different"} {
			t.Run(key+"-"+mutation, func(t *testing.T) {
				lines := strings.Split(valid, "\n")
				for i, line := range lines {
					if strings.HasPrefix(line, key+":") {
						switch mutation {
						case "missing":
							lines[i] = "Ignored: value"
						case "duplicate":
							lines[i] += "\n" + line
						case "different":
							lines[i] = key + ": 1000"
						}
					}
				}
				if err := verifySSHProcessCredentials([]byte(strings.Join(lines, "\n")), 123, 0); err == nil {
					t.Fatal("accepted incomplete or changed credentials")
				}
			})
		}
	}
	for _, value := range []string{"", valid + "\x00\n", strings.TrimSuffix(valid, "\n"), strings.Repeat("x", 16385), strings.Replace(valid, "0\t0\t0\t0", "0\t1000\t0\t0", 1)} {
		if verifySSHProcessCredentials([]byte(value), 123, 0) == nil {
			t.Fatal("accepted unsafe process credentials")
		}
	}
}

func TestSSHProcessCgroupRequiresOneExactManagerHierarchy(t *testing.T) {
	const group = "/system.slice/sshd.service"
	for _, wire := range []string{"0::" + group + "\n", "2:cpu,cpuacct:/\n1:name=systemd:" + group + "\n"} {
		if err := verifySSHProcessGroup([]byte(wire), group); err != nil {
			t.Fatal(err)
		}
	}
	for _, wire := range []string{
		"", "0::" + group, "0::" + group + "/child\n", "0::/other.service\n", "0::/\n",
		"0::" + group + "\n1:name=systemd:" + group + "\n", "1:cpu:" + group + "\n",
		"1:name=systemd:" + group + "\n1:name=systemd:" + group + "\n", "0:name=systemd:" + group + "\n",
		"01:name=systemd:" + group + "\n", "1::" + group + "\n", "0::/system.slice/../sshd.service\n",
		"0::/system.slice/sshd.service\x00\n", "1:cpu,cpu:" + group + "\n", "1:,:" + group + "\n", "1:private-value!:" + group + "\n", strings.Repeat("x", 16385),
	} {
		if err := verifySSHProcessGroup([]byte(wire), group); err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatal("accepted ambiguous cgroup or reflected its contents", err)
		}
	}
	for _, group := range []string{"", "/", "relative", "/a/../b", "/a//b", "/a/", "/a b", "/a:b", "/a\\b", "/a\nb", "/a\x00b", "/" + strings.Repeat("x", 4096)} {
		if validSSHControlGroup(group) {
			t.Fatal("accepted unsafe manager cgroup")
		}
	}
}

func sshProcessOracleExpectation(t *testing.T) (inventoryStamp, string, string) {
	t.Helper()
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var group string
	for _, line := range strings.Split(strings.TrimSuffix(string(cgroup), "\n"), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && (parts[0] == "0" || containsSSHUnit(strings.Split(parts[1], ","), "name=systemd")) {
			group = parts[2]
		}
	}
	if !validSSHControlGroup(group) {
		t.Skip("native process oracle requires a non-root, unambiguous service cgroup")
	}
	return stamp(st), fmt.Sprintf("%x", h.Sum(nil)), group
}

func TestSSHProcessNativeBindingAndSubstitution(t *testing.T) {
	state, digest, group := sshProcessOracleExpectation(t)
	b, err := bindSSHProcess(os.Getpid(), os.Geteuid(), group, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	first, err := b.observe()
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.observe()
	if err != nil || !reflect.DeepEqual(first, second) || first.PID != os.Getpid() || first.StartTicks == 0 || len(first.Namespaces) != 4 {
		t.Fatal("unstable native process identity", err)
	}
	for _, scenario := range []string{"digest", "inode", "group", "uid"} {
		t.Run(scenario, func(t *testing.T) {
			s, d, g, uid := state, digest, group, os.Geteuid()
			switch scenario {
			case "digest":
				d = strings.Repeat("0", 64)
			case "inode":
				s.ino++
			case "group":
				g += "/incorrect"
			case "uid":
				uid++
				s.uid++
			}
			bad, err := bindSSHProcess(os.Getpid(), uid, g, s, d)
			if err == nil {
				_ = bad.Close()
				t.Fatal("accepted substituted process expectation")
			}
		})
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.observe(); err == nil {
		t.Fatal("closed binding remained usable")
	}
	if err := b.Close(); err != nil {
		t.Fatal("close must be idempotent", err)
	}
}

func TestSSHProcessFixtureChild(t *testing.T) {
	if os.Getenv("SYSWARDEN_PROCESS_TEST_CHILD") != "yes" {
		return
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestSSHProcessNativeExitInvalidatesPinnedLease(t *testing.T) {
	state, digest, group := sshProcessOracleExpectation(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestSSHProcessFixtureChild$")
	command.Env = []string{"SYSWARDEN_PROCESS_TEST_CHILD=yes", "GOMAXPROCS=2"}
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
			_ = command.Wait()
		}
	}()
	if ready, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatal("test child did not start", err)
	}
	b, err := bindSSHProcess(command.Process.Pid, os.Geteuid(), group, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
	if _, err := b.observe(); err == nil {
		t.Fatal("exited process still produced a valid identity")
	}
}

func TestSSHProcessRejectsNonProcfsAndUnboundedInputs(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if proc, err := openSSHProcDirectory(f, "."); err == nil {
		_ = proc.Close()
		t.Fatal("accepted a fake proc filesystem")
	}
	for _, name := range []string{"../exe", "cmdline", "environ", "ns/time", "fd/1"} {
		if link, err := openSSHProcessLink(f, name); err == nil {
			_ = link.Close()
			t.Fatal("accepted an arbitrary proc link")
		}
		if _, err := readSSHProcText(f, name); err == nil {
			t.Fatal("accepted an arbitrary proc read")
		}
	}
	for _, pid := range []int{-1, 0, 1, 1 << 31} {
		if b, err := bindSSHProcess(pid, 0, "/service", inventoryStamp{}, strings.Repeat("a", 64)); err == nil {
			_ = b.Close()
			t.Fatal("accepted invalid process", strconv.Itoa(pid))
		}
	}
	if os.Geteuid() != 0 {
		if summary, err := ObserveSystemdProcess(); err == nil || !reflect.DeepEqual(summary, ProcessSummary{}) {
			t.Fatal("unprivileged caller obtained a process observation", summary, err)
		}
	}
}

//go:build linux

package integration

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func resetJournaldExecutionFixture() string {
	wire := journaldRemovalFixtureProperties(0)
	return strings.Replace(wire, "start_time=[fixture] ; stop_time=[n/a] ; pid=100", "start_time=[n/a] ; stop_time=[n/a] ; pid=0", 1)
}

func TestJournaldRemovalAcceptsResetAccountingOnlyWithStableLiveIdentity(t *testing.T) {
	for _, name := range []string{"valid", "wrong-command-pid", "partial-reset", "stopped-command", "missing-verifier", "process-mismatch", "service-changed", "observation-error"} {
		t.Run(name, func(t *testing.T) {
			wire := resetJournaldExecutionFixture()
			switch name {
			case "wrong-command-pid":
				wire = strings.Replace(wire, " ; pid=0 ; ", " ; pid=101 ; ", 1)
			case "partial-reset":
				wire = strings.Replace(wire, "start_time=[n/a]", "start_time=[fixture]", 1)
			case "stopped-command":
				wire = strings.Replace(wire, "stop_time=[n/a]", "stop_time=[fixture]", 1)
			}
			calls, checks := 0, 0
			run := func(_ string, _ ...string) ([]byte, error) {
				calls++
				if calls == 2 {
					if name == "service-changed" {
						return []byte(strings.Replace(wire, "MainPID=100", "MainPID=101", 1)), nil
					}
					if name == "observation-error" {
						return nil, errors.New("synthetic service observation error")
					}
				}
				return []byte(wire), nil
			}
			verify := func(state journaldRemovalService) error {
				checks++
				if state.pid != 100 || state.started != 1000 || state.invocation != strings.Repeat("0", 31)+"1" {
					t.Fatal("live verifier received a different active identity")
				}
				if name == "process-mismatch" {
					return errors.New("synthetic wrong live process")
				}
				return nil
			}
			if name == "missing-verifier" {
				verify = nil
			}
			state, err := inspectJournaldRemovalServiceUsing(run, verify)
			if name == "valid" {
				if err != nil || calls != 2 || checks != 1 || state.pid != 100 {
					t.Fatal("verified reset accounting was not accepted", err, calls, checks)
				}
			} else if err == nil {
				t.Fatal("unproven process identity was accepted")
			}
		})
	}
}

func TestJournaldLiveProcessFieldsRejectIdentitySubstitution(t *testing.T) {
	const invocation = "0123456789abcdef0123456789abcdef"
	for _, name := range []string{"valid", "usrmerge-command", "extra-argument", "other-cgroup", "missing-invocation", "wrong-invocation", "duplicate-invocation", "truncated-environment", "non-root-uid", "non-root-gid", "missing-uid", "duplicate-uid"} {
		t.Run(name, func(t *testing.T) {
			fields := map[string][]byte{
				"cmdline": []byte("/usr/lib/systemd/systemd-journald\x00"),
				"cgroup":  []byte("0::/system.slice/systemd-journald.service\n"),
				"environ": []byte("PATH=/usr/bin\x00INVOCATION_ID=" + invocation + "\x00"),
				"status":  []byte("Name:\tsystemd-journal\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"),
			}
			switch name {
			case "usrmerge-command":
				fields["cmdline"] = []byte("/lib/systemd/systemd-journald\x00")
			case "extra-argument":
				fields["cmdline"] = append(fields["cmdline"], []byte("operator\x00")...)
			case "other-cgroup":
				fields["cgroup"] = []byte("0::/system.slice/operator.service\n")
			case "missing-invocation":
				fields["environ"] = []byte("PATH=/usr/bin\x00")
			case "wrong-invocation":
				fields["environ"] = []byte("INVOCATION_ID=" + strings.Repeat("f", 32) + "\x00")
			case "duplicate-invocation":
				fields["environ"] = append(fields["environ"], []byte("INVOCATION_ID="+invocation+"\x00")...)
			case "truncated-environment":
				fields["environ"] = []byte("INVOCATION_ID=" + invocation)
			case "non-root-uid":
				fields["status"] = []byte("Uid:\t0\t1000\t0\t0\nGid:\t0\t0\t0\t0\n")
			case "non-root-gid":
				fields["status"] = []byte("Uid:\t0\t0\t0\t0\nGid:\t1000\t0\t0\t0\n")
			case "missing-uid":
				fields["status"] = []byte("Gid:\t0\t0\t0\t0\n")
			case "duplicate-uid":
				fields["status"] = append(fields["status"], []byte("Uid:\t0\t0\t0\t0\n")...)
			}
			err := verifyJournaldProcessFields(fields, invocation)
			valid := name == "valid" || name == "usrmerge-command"
			if valid != (err == nil) {
				t.Fatal("unexpected live identity verdict", err)
			}
		})
	}
}

func TestJournaldProcessReaderRejectsUnsafeAndUnboundedFields(t *testing.T) {
	directory := t.TempDir()
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	for _, name := range []string{"valid", "empty", "oversized", "symlink", "directory", "missing"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			switch name {
			case "valid", "empty", "oversized":
				size := 3
				if name == "empty" {
					size = 0
				} else if name == "oversized" {
					size = maximumJournaldProcessFile + 1
				}
				if err := os.WriteFile(path, []byte(strings.Repeat("a", size)), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("valid", path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			_, err := readJournaldProcessFile(fd, name)
			if (name == "valid") != (err == nil) {
				t.Fatal("unsafe or incomplete field accepted", err)
			}
		})
	}
}

func TestJournaldLiveProcessRejectsUnrelatedExecutable(t *testing.T) {
	pid, err := strconv.ParseUint(strconv.Itoa(os.Getpid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyJournaldRemovalProcess(journaldRemovalService{pid: pid}); err == nil {
		t.Fatal("the test executable was accepted as journald")
	}
}

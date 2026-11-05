//go:build linux

package firewall

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func writeNFTOpenRCProcessFixture(t *testing.T, host nftPersistenceFilesystem, pid, comm, state string, flags, start uint64, arguments []string) {
	t.Helper()
	fields := strings.Fields(state + " " + strings.Repeat("0 ", 49))
	fields[6], fields[19] = strconv.FormatUint(flags, 10), strconv.FormatUint(start, 10)
	base := "/proc/" + pid + "/"
	writeNFTOpenRCFixture(t, host, base+"stat", pid+" ("+comm+") "+strings.Join(fields, " ")+"\n")
	content := ""
	if len(arguments) != 0 {
		content = strings.Join(arguments, "\x00") + "\x00"
	}
	writeNFTOpenRCFixture(t, host, base+"cmdline", content)
	writeNFTOpenRCFixture(t, host, base+"comm", comm+"\n")
}

func fixtureNFTOpenRCProcesses(t *testing.T) (nftPersistenceFilesystem, *os.Root) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	writeNFTOpenRCProcessFixture(t, host, "1", "init", "S", 0, 100, []string{"/sbin/init"})
	writeNFTOpenRCProcessFixture(t, host, "42", "syswarden-cli", "S", 0, 200,
		[]string{"/usr/bin/syswarden-cli", "uninstall", "--evidence", "/etc/nftables.nft", "/etc/init.d/nftables"})
	proc, err := host.root.OpenRoot("proc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Close() })
	return host, proc
}

func TestNFTOpenRCProcessesRejectActiveInvocations(t *testing.T) {
	cases := map[string]struct {
		comm string
		args []string
	}{
		"manager reload":         {"openrc-run", []string{"/sbin/openrc-run", "/etc/init.d/nftables", "reload"}},
		"renamed argv0":          {"openrc-run", []string{"masked", "/etc/init.d/nftables", "reload"}},
		"service reload":         {"rc-service", []string{"rc-service", "-D", "nftables", "reload"}},
		"shell wrapper":          {"openrc-run.sh", []string{"/bin/sh", "/usr/libexec/rc/sh/openrc-run.sh", "/etc/init.d/nftables", "reload"}},
		"busybox wrapper":        {"busybox", []string{"/bin/busybox", "sh", "/usr/libexec/rc/sh/openrc-run.sh", "/etc/init.d/nftables", "reload"}},
		"direct shell":           {"sh", []string{"sh", "/etc/init.d/nftables", "start"}},
		"shell command":          {"sh", []string{"sh", "-c", "rc-service -D nftables reload"}},
		"runlevel manager":       {"openrc", []string{"openrc", "default"}},
		"missing manager target": {"openrc-run", []string{"openrc-run"}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			host, proc := fixtureNFTOpenRCProcesses(t)
			writeNFTOpenRCProcessFixture(t, host, "43", test.comm, "S", 0, 300, test.args)
			if _, err := captureNFTOpenRCProcessesAt(host, proc); err == nil {
				t.Fatal("active or ambiguous OpenRC invocation accepted")
			}
		})
	}
}

func TestNFTOpenRCProcessesAllowUnrelatedAndNonExecutingTasks(t *testing.T) {
	host, proc := fixtureNFTOpenRCProcesses(t)
	writeNFTOpenRCProcessFixture(t, host, "43", "openrc-run", "S", 0, 300,
		[]string{"/sbin/openrc-run", "/etc/init.d/sshd", "status"})
	writeNFTOpenRCProcessFixture(t, host, "44", "kworker/0:1", "I", 0x00200000, 0, nil)
	writeNFTOpenRCProcessFixture(t, host, "45", "openrc-run", "Z", 0, 400, nil)
	proof, err := captureNFTOpenRCProcessesAt(host, proc)
	if err != nil || string(proof.content) != "init\n" || proof.identity == nil {
		t.Fatal("stable process observation failed", err)
	}
}

func TestNFTOpenRCProcessesRejectAmbiguousEvidence(t *testing.T) {
	cases := map[string]func(*testing.T, nftPersistenceFilesystem){
		"missing command line": func(t *testing.T, h nftPersistenceFilesystem) {
			if err := h.root.Remove("proc/42/cmdline"); err != nil {
				t.Fatal(err)
			}
		},
		"unterminated command line": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/proc/42/cmdline", "syswarden-cli")
		},
		"oversized command line": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/proc/42/cmdline", strings.Repeat("x", 65537))
		},
		"empty live command line": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/proc/42/cmdline", "")
		},
		"symlink command line": func(t *testing.T, h nftPersistenceFilesystem) {
			if err := h.root.Remove("proc/42/cmdline"); err != nil {
				t.Fatal(err)
			}
			if err := h.root.Symlink("stat", "proc/42/cmdline"); err != nil {
				t.Fatal(err)
			}
		},
		"symlink process": func(t *testing.T, h nftPersistenceFilesystem) {
			if err := h.root.Symlink("42", "proc/43"); err != nil {
				t.Fatal(err)
			}
		},
		"malformed stat": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/proc/42/stat", "42 (invalid) S\n")
		},
		"untrusted PID 1": func(t *testing.T, h nftPersistenceFilesystem) {
			if err := h.root.Chmod("proc/1/comm", 0666); err != nil {
				t.Fatal(err)
			}
		},
		"inconsistent PID 1": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/proc/1/comm", "openrc-init\n")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			host, proc := fixtureNFTOpenRCProcesses(t)
			change(t, host)
			if _, err := captureNFTOpenRCProcessesAt(host, proc); err == nil {
				t.Fatal("ambiguous process evidence accepted")
			}
		})
	}
}

func TestNFTOpenRCProcessesRejectRaces(t *testing.T) {
	for _, change := range []string{"arguments", "start time", "reused PID", "new PID", "disappeared file"} {
		t.Run(change, func(t *testing.T) {
			host, proc := fixtureNFTOpenRCProcesses(t)
			reads := 0
			host.afterRead = func() {
				reads++
				if reads != 2 {
					return
				}
				switch change {
				case "arguments":
					writeNFTOpenRCFixture(t, host, "/proc/42/cmdline", "/sbin/openrc-run\x00/etc/init.d/nftables\x00reload\x00")
				case "start time":
					writeNFTOpenRCProcessFixture(t, host, "42", "syswarden-cli", "S", 0, 999, []string{"/usr/bin/syswarden-cli"})
				case "reused PID":
					if err := host.root.Rename("proc/42", "proc/old"); err != nil {
						t.Fatal(err)
					}
					writeNFTOpenRCProcessFixture(t, host, "42", "syswarden-cli", "S", 0, 200, []string{"/usr/bin/syswarden-cli"})
				case "new PID":
					writeNFTOpenRCProcessFixture(t, host, "43", "openrc-run", "S", 0, 300, []string{"openrc-run", "/etc/init.d/nftables", "reload"})
				case "disappeared file":
					if err := host.root.Remove("proc/42/cmdline"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := captureNFTOpenRCProcessesAt(host, proc); err == nil {
				t.Fatal("changed process evidence accepted")
			}
		})
	}
}

func TestNFTOpenRCProcessesProductionRejectsSyntheticProc(t *testing.T) {
	host, _ := fixtureNFTOpenRCProcesses(t)
	if _, err := captureNFTOpenRCProcesses(host); err == nil {
		t.Fatal("production observation accepted a synthetic proc filesystem")
	}
	if err := host.root.Rename("proc", "synthetic-proc"); err != nil {
		t.Fatal(err)
	}
	if err := host.root.Symlink("synthetic-proc", "proc"); err != nil {
		t.Fatal(err)
	}
	if _, err := captureNFTOpenRCProcesses(host); err == nil {
		t.Fatal("production observation followed a proc symlink")
	}
}

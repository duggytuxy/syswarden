//go:build linux

package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func nativeOpenRCFixture(t *testing.T) (nativeOpenRCObserver, nativeOpenRCCoreObserver) {
	t.Helper()
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership unavailable")
	}
	host := nativeOpenRCObserver{root: root, uid: owner.Uid, gid: owner.Gid}
	for _, directory := range []string{"etc/init.d", "etc/conf.d", "etc/runlevels/custom", "etc/runlevels/default", "run/openrc/started", "run/openrc/daemons/syswarden-core", "run/openrc/options/syswarden-core"} {
		if err := os.MkdirAll(filepath.Join(host.root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	nativeOpenRCWrite(t, host, "run/openrc/daemons/syswarden-core/001", "exec=/opt/syswarden/bin/syswarden-core\nargv_0=/opt/syswarden/bin/syswarden-core\npidfile=/run/syswarden-core.pid\n", 0644)
	nativeOpenRCWrite(t, host, "run/openrc/options/syswarden-core/command", "/opt/syswarden/bin/syswarden-core", 0644)
	nativeOpenRCWrite(t, host, "run/openrc/options/syswarden-core/pidfile", "/run/syswarden-core.pid", 0644)
	nativeOpenRCWrite(t, host, "etc/rc.conf", "# Distribution configuration\nrc_cgroup_mode=\"unified\"\n", 0644)
	nativeOpenRCWrite(t, host, "run/openrc/softlevel", "default\n", 0644)
	nativeOpenRCWrite(t, host, "etc/init.d/syswarden-core", openRCCoreService, 0755)
	nativeOpenRCWrite(t, host, "etc/init.d/syswarden-firewall", openRCFirewallService, 0755)
	for _, name := range []string{"syswarden-core", "syswarden-firewall"} {
		nativeOpenRCLink(t, host, "run/openrc/started/"+name, "/etc/init.d/"+name)
		nativeOpenRCLink(t, host, "etc/runlevels/custom/"+name, "../../init.d/"+name)
	}
	nativeOpenRCLink(t, host, "etc/runlevels/default/syswarden-core", "/etc/init.d/syswarden-core")
	return host, func(*nativeOpenRCRead) (string, error) { return "42:100:/opt/syswarden/bin/syswarden-core", nil }
}

func nativeOpenRCWrite(t *testing.T, host nativeOpenRCObserver, name, content string, mode os.FileMode) {
	t.Helper()
	target := filepath.Join(host.root, name)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); err == nil {
		if err := os.Chmod(target, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(target, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, mode); err != nil {
		t.Fatal(err)
	}
}

func nativeOpenRCLink(t *testing.T, host nativeOpenRCObserver, name, target string) {
	t.Helper()
	link := filepath.Join(host.root, name)
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestNativeOpenRCObserverDoesNotResolveExecutables(t *testing.T) {
	executor := firewallManagerExecutor{
		lookPath: func(string) (string, error) { t.Fatal("observer resolved an executable"); return "", nil },
		output:   func(string, ...string) ([]byte, error) { t.Fatal("observer ran an executable"); return nil, nil },
	}
	if _, err := installationServiceInspector(executor, true); err != nil {
		t.Fatal(err)
	}
}

func TestNativeOpenRCObserverPreservesCustomRunlevelsAndStoppedChoices(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(fmt.Sprint(stopped), func(t *testing.T) {
			host, core := nativeOpenRCFixture(t)
			if stopped {
				if err := os.Remove(filepath.Join(host.root, "run/openrc/started/syswarden-firewall")); err != nil {
					t.Fatal(err)
				}
			}
			state, err := inspectNativeOpenRCServices(host, core)
			if err != nil {
				t.Fatal(err)
			}
			if state[0].runlevels != "custom" || state[1].runlevels != "custom default" {
				t.Fatalf("lost custom membership: %#v", state)
			}
			plan, err := prepareNativeServiceInstallation("upgrade", true, func() (installationServiceSnapshot, error) { return inspectNativeOpenRCServices(host, core) })
			if err != nil || plan.Deferred() != stopped {
				t.Fatalf("incorrect disposition: %v, %v", plan, err)
			}
		})
	}
}

func TestNativeOpenRCObserverNeverExecutesAdministratorService(t *testing.T) {
	host, core := nativeOpenRCFixture(t)
	marker := filepath.Join(host.root, "executed")
	script := "#!/bin/sh\nprintf executed > " + marker + "\n"
	nativeOpenRCWrite(t, host, "etc/init.d/syswarden-core", script, 0755)
	state, err := inspectNativeOpenRCServices(host, core)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareNativeServiceInstallation("upgrade", true, func() (installationServiceSnapshot, error) { return state, nil })
	if err != nil || !plan.Deferred() {
		t.Fatalf("custom service accepted: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("custom service executed")
	}
	content, err := os.ReadFile(filepath.Join(host.root, "etc/init.d/syswarden-core"))
	if err != nil || string(content) != script {
		t.Fatal("custom definition changed")
	}
}

func TestNativeOpenRCObserverRefusesUnsafeEvidenceWithoutRepair(t *testing.T) {
	cases := map[string]func(*testing.T, nativeOpenRCObserver){
		"global-transition": func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCWrite(t, h, "run/openrc/rc.starting", "", 0644)
		},
		"shutdown": func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCWrite(t, h, "run/openrc/softlevel", "shutdown\n", 0644)
		},
		"shell-config": func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCWrite(t, h, "etc/rc.conf", "status() { touch /never; }\n", 0644)
		},
		"config-substitution": func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCWrite(t, h, "etc/rc.conf", "rc_logger=\"$(touch /never)\"\n", 0644)
		},
		"service-override": func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCWrite(t, h, "etc/conf.d/syswarden-core.custom", "command=/other\n", 0644)
		},
		"scheduled": func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCLink(t, h, "run/openrc/scheduled/networking/syswarden-core", "/etc/init.d/syswarden-core")
		},
		"unsafe-mode": func(t *testing.T, h nativeOpenRCObserver) {
			if err := os.Chmod(filepath.Join(h.root, "run/openrc/started"), 0777); err != nil { // #nosec G302 -- deliberate unsafe fixture must be rejected
				t.Fatal(err)
			}
		},
		"missing-definition": func(t *testing.T, h nativeOpenRCObserver) {
			if err := os.Remove(filepath.Join(h.root, "etc/init.d/syswarden-core")); err != nil {
				t.Fatal(err)
			}
		},
		"link-definition": func(t *testing.T, h nativeOpenRCObserver) {
			if err := os.Remove(filepath.Join(h.root, "etc/init.d/syswarden-core")); err != nil {
				t.Fatal(err)
			}
			nativeOpenRCLink(t, h, "etc/init.d/syswarden-core", "/etc/init.d/other")
		},
		"fifo": func(t *testing.T, h nativeOpenRCObserver) {
			if err := os.Remove(filepath.Join(h.root, "run/openrc/softlevel")); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(h.root, "run/openrc/softlevel"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"oversize": func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCWrite(t, h, "run/openrc/softlevel", strings.Repeat("a", 65), 0644)
		},
		"runlevel-alias": func(t *testing.T, h nativeOpenRCObserver) { nativeOpenRCLink(t, h, "etc/runlevels/alias", "custom") },
	}
	for _, marker := range []string{"stopped", "starting", "stopping", "inactive", "wasinactive", "failed", "crashed", "hotplugged", "exclusive"} {
		cases[marker] = func(t *testing.T, h nativeOpenRCObserver) {
			nativeOpenRCLink(t, h, "run/openrc/"+marker+"/syswarden-core", "/etc/init.d/syswarden-core")
		}
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			host, core := nativeOpenRCFixture(t)
			change(t, host)
			if _, err := inspectNativeOpenRCServices(host, core); err == nil {
				t.Fatal("unsafe observation accepted")
			}
			if _, err := os.Lstat(filepath.Join(host.root, "run/openrc/started/syswarden-firewall")); err != nil {
				t.Fatal("unrelated state removed")
			}
		})
	}
}

func TestNativeOpenRCObserverRejectsChangedEvidence(t *testing.T) {
	for _, change := range []string{"process", "script", "membership"} {
		t.Run(change, func(t *testing.T) {
			host, _ := nativeOpenRCFixture(t)
			calls := 0
			core := func(*nativeOpenRCRead) (string, error) {
				calls++
				if calls == 1 {
					if change == "script" {
						nativeOpenRCWrite(t, host, "etc/init.d/syswarden-firewall", historicalV4104OpenRCFirewallService, 0755)
					}
					if change == "membership" {
						if err := os.Remove(filepath.Join(host.root, "etc/runlevels/custom/syswarden-core")); err != nil {
							t.Fatal(err)
						}
					}
				}
				if change == "process" {
					return fmt.Sprint(calls), nil
				}
				return "stable", nil
			}
			if _, err := inspectNativeOpenRCServices(host, core); err == nil {
				t.Fatal("changing evidence accepted")
			}
		})
	}
}

func TestNativeOpenRCObserverDoesNotCreateAbsentRuntimeDirectories(t *testing.T) {
	host, core := nativeOpenRCFixture(t)
	if _, err := inspectNativeOpenRCServices(host, core); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stopping", "starting", "scheduled", "failed", "crashed"} {
		if _, err := os.Lstat(filepath.Join(host.root, "run/openrc", name)); !os.IsNotExist(err) {
			t.Fatalf("created %s", name)
		}
	}
}

func nativeOpenRCProcStat(pid, state, start string) string {
	fields := make([]string, 50)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = state
	fields[19] = start
	return pid + " (syswarden-core) " + strings.Join(fields, " ") + "\n"
}

func TestNativeOpenRCCoreRequiresLiveStableIdentity(t *testing.T) {
	for _, kind := range []string{"live", "deleted", "missing", "zombie", "stopped", "wrong-executable", "bad-pid", "bad-stat", "symlink-pid", "pid-reuse"} {
		t.Run(kind, func(t *testing.T) {
			host, _ := nativeOpenRCFixture(t)
			nativeOpenRCWrite(t, host, "run/syswarden-core.pid", "42\n", 0644)
			nativeOpenRCWrite(t, host, "proc/42/stat", nativeOpenRCProcStat("42", "S", "100"), 0444)
			target := nativeOpenRCCorePath
			if kind == "deleted" {
				target += " (deleted)"
			}
			if kind == "wrong-executable" {
				target = "/bin/sleep"
			}
			nativeOpenRCLink(t, host, "proc/42/exe", target)
			switch kind {
			case "missing":
				if err := os.RemoveAll(filepath.Join(host.root, "proc/42")); err != nil {
					t.Fatal(err)
				}
			case "zombie":
				nativeOpenRCWrite(t, host, "proc/42/stat", nativeOpenRCProcStat("42", "Z", "100"), 0444)
			case "stopped":
				nativeOpenRCWrite(t, host, "proc/42/stat", nativeOpenRCProcStat("42", "T", "100"), 0444)
			case "bad-pid":
				nativeOpenRCWrite(t, host, "run/syswarden-core.pid", "042\n", 0644)
			case "bad-stat":
				nativeOpenRCWrite(t, host, "proc/42/stat", "not a process\n", 0444)
			case "symlink-pid":
				if err := os.Remove(filepath.Join(host.root, "run/syswarden-core.pid")); err != nil {
					t.Fatal(err)
				}
				nativeOpenRCLink(t, host, "run/syswarden-core.pid", "other.pid")
			}
			proc, err := os.OpenRoot(filepath.Join(host.root, "proc"))
			if err != nil {
				t.Fatal(err)
			}
			defer proc.Close()
			calls := 0
			core := func(r *nativeOpenRCRead) (string, error) {
				result, err := observeNativeOpenRCCoreAt(r, proc)
				calls++
				if kind == "pid-reuse" && calls == 1 {
					nativeOpenRCWrite(t, host, "proc/42/stat", nativeOpenRCProcStat("42", "S", "200"), 0444)
				}
				return result, err
			}
			_, err = inspectNativeOpenRCServices(host, core)
			if (err == nil) != (kind == "live" || kind == "deleted") {
				t.Fatalf("unexpected %s result: %v", kind, err)
			}
		})
	}
}

func TestNativeOpenRCObserverRejectsHiddenAndIgnoredEnablement(t *testing.T) {
	for _, level := range []string{".backup", "single", "custom level"} {
		t.Run(level, func(t *testing.T) {
			host, core := nativeOpenRCFixture(t)
			for _, name := range []string{"syswarden-core", "syswarden-firewall"} {
				for _, old := range []string{"custom", "default"} {
					_ = os.Remove(filepath.Join(host.root, "etc/runlevels", old, name))
				}
				nativeOpenRCLink(t, host, "etc/runlevels/"+level+"/"+name, "/etc/init.d/"+name)
			}
			if _, err := inspectNativeOpenRCServices(host, core); err == nil {
				t.Fatal("ignored runlevel authorized automatic activation")
			}
		})
	}
}

func TestNativeOpenRCObserverRefusesContradictorySavedParameters(t *testing.T) {
	for name, content := range map[string]string{
		"options/syswarden-core/command":  "/bin/other",
		"options/syswarden-core/pidfile":  "/run/other.pid",
		"options/syswarden-core/chroot":   "/other",
		"options/syswarden-core/procname": "other",
		"daemons/syswarden-core/001":      "exec=/bin/other\n",
		"daemons/syswarden-core/002":      "unexpected\n",
	} {
		t.Run(name, func(t *testing.T) {
			host, core := nativeOpenRCFixture(t)
			nativeOpenRCWrite(t, host, "run/openrc/"+name, content, 0644)
			if _, err := inspectNativeOpenRCServices(host, core); err == nil {
				t.Fatal("contradictory stop bookkeeping accepted")
			}
		})
	}
}

func TestNativeOpenRCObserverFreshAbsenceRequiresNoRetainedCore(t *testing.T) {
	for _, retained := range []string{"", "run/syswarden-core.pid", "run/openrc/options/syswarden-core/command", "run/openrc/daemons/syswarden-core/001"} {
		t.Run(retained, func(t *testing.T) {
			host, core := nativeOpenRCFixture(t)
			for _, p := range []string{"etc/init.d/syswarden-core", "etc/init.d/syswarden-firewall", "etc/runlevels/custom", "etc/runlevels/default", "run/openrc/started", "run/openrc/daemons", "run/openrc/options"} {
				if err := os.RemoveAll(filepath.Join(host.root, p)); err != nil {
					t.Fatal(err)
				}
			}
			if retained != "" {
				nativeOpenRCWrite(t, host, retained, "retained", 0644)
			}
			state, err := inspectNativeOpenRCServices(host, core)
			if retained != "" {
				if err == nil {
					t.Fatal("retained runtime accepted as fresh")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			plan, err := prepareNativeServiceInstallation("fresh", true, func() (installationServiceSnapshot, error) { return state, nil })
			if err != nil || plan.Deferred() {
				t.Fatalf("clean fresh absence refused: %v", err)
			}
		})
	}
}

func TestNativeOpenRCObserverRealProcfs(t *testing.T) {
	if os.Getenv("SYSWARDEN_NATIVE_OPENRC_PROC_TEST") != "1" {
		t.Skip("requires the disposable Linux AMD64 native observer fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native fixture requires container root")
	}
	for _, deleted := range []bool{false, true} {
		t.Run(fmt.Sprint(deleted), func(t *testing.T) {
			// The disposable container supplies an inert executable in a temporary
			// directory. This never writes to an installed product path.
			wire, err := os.ReadFile("/fixtures/inert-core")
			if err != nil {
				t.Fatal(err)
			}
			testCorePath := filepath.Join(t.TempDir(), "inert-core")
			fixture, err := os.OpenRoot(filepath.Dir(testCorePath))
			if err != nil {
				t.Fatal(err)
			}
			executable, err := fixture.OpenFile("inert-core", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := executable.Write(wire)
			closeErr := executable.Close()
			_ = fixture.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal("write inert fixture")
			}

			cmd := exec.Command(testCorePath) // #nosec G204 -- trusted inert fixture in this test's private temporary directory
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reaped := false
			defer func() {
				if !reaped {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			host, _ := nativeOpenRCFixture(t)
			nativeOpenRCWrite(t, host, "run/syswarden-core.pid", strconv.Itoa(cmd.Process.Pid)+"\n", 0644)
			if deleted {
				if err := os.Remove(testCorePath); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(10 * time.Millisecond)
			if _, err := inspectNativeOpenRCServices(host, func(r *nativeOpenRCRead) (string, error) { return observeNativeOpenRCCoreWithPath(r, testCorePath) }); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			reaped = true
			if _, err := inspectNativeOpenRCServices(host, func(r *nativeOpenRCRead) (string, error) { return observeNativeOpenRCCoreWithPath(r, testCorePath) }); err == nil {
				t.Fatal("stale started marker accepted after process death")
			}
		})
	}
}

func TestNativeOpenRCConfigAndReadBounds(t *testing.T) {
	for _, valid := range []string{"# inert\n", "rc_logger=\"yes\"\n", "rc_tty_number=12\n", "rc_env_allow=\"\"\n"} {
		if err := nativeOpenRCConfigLiteral([]byte(valid)); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{"command=/bin/sh\n", "rc_logger=yes\nrc_logger=no\n", "rc_logger=yes;id\n", "source /other\n", "rc_env_allow=PATH\n", "rc_logger=\"$(id)\"\n", "rc_logger=YES\r\n"} {
		if err := nativeOpenRCConfigLiteral([]byte(invalid)); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	for _, kind := range []string{"plugin", "inventory", "bytes", "runtime-mode"} {
		t.Run(kind, func(t *testing.T) {
			host, core := nativeOpenRCFixture(t)
			switch kind {
			case "plugin":
				nativeOpenRCWrite(t, host, "usr/lib/rc/plugins/custom.so", "inert", 0600)
			case "inventory":
				for i := 0; i <= nativeOpenRCInventoryLimit; i++ {
					nativeOpenRCWrite(t, host, fmt.Sprintf("etc/rc.conf.d/%04d.conf", i), "# inert\n", 0600)
				}
			case "bytes":
				for i := 0; i < 65; i++ {
					nativeOpenRCWrite(t, host, fmt.Sprintf("etc/rc.conf.d/%04d.conf", i), "#"+strings.Repeat("x", 65534)+"\n", 0600)
				}
			case "runtime-mode":
				if err := os.Chmod(filepath.Join(host.root, "run/openrc/started"), 0775); err != nil {
					t.Fatal(err)
				} // #nosec G302 -- OpenRC's supported root-group runtime directory mode
			}
			_, err := inspectNativeOpenRCServices(host, core)
			if (err == nil) != (kind == "runtime-mode") {
				t.Fatalf("unexpected %s result: %v", kind, err)
			}
		})
	}
}

func TestNativeOpenRCObserverRejectsOneshotDaemonState(t *testing.T) {
	for _, directory := range []string{"daemons", "options"} {
		t.Run(directory, func(t *testing.T) {
			host, core := nativeOpenRCFixture(t)
			name := "run/openrc/" + directory + "/syswarden-firewall/001"
			content := "pidfile=/run/missing.pid\n"
			nativeOpenRCWrite(t, host, name, content, 0600)
			if _, err := inspectNativeOpenRCServices(host, core); err == nil {
				t.Fatal("crashed oneshot bookkeeping accepted")
			}
			actual, err := os.ReadFile(filepath.Join(host.root, name)) // #nosec G304 -- fixed fixture suffix under this test's private root
			if err != nil || string(actual) != content {
				t.Fatal("contradictory bookkeeping changed")
			}
		})
	}
}

//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func lxcDropInFixture(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zzz-lxc-service.conf")
	writeLXCProfile(t, path, approvedLXCServiceDropInContent)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	return path, stat.Uid, stat.Gid
}

func writeLXCProfile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil { // #nosec G306 -- fixture models the exact root-owned runtime profile mode
		t.Fatal(err)
	}
}

func lxcDetectorFixture(t *testing.T, query func() ([]byte, error)) firewallManagerExecutor {
	t.Helper()
	detector := testCronProviderExecutable(t, t.TempDir(), "systemd-detect-virt")
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			if name != "systemd-detect-virt" {
				return "", errors.New("unexpected executable")
			}
			return detector, nil
		},
		validate: func(path string) error {
			if path != detector {
				return errors.New("unexpected executable path")
			}
			return nil
		},
		output: func(path string, args ...string) ([]byte, error) {
			if path != detector || strings.Join(args, " ") != "--container" {
				return nil, errors.New("unexpected detector invocation")
			}
			return query()
		},
	}
}

func TestLXCServiceDropInExactProfileAndContext(t *testing.T) {
	path, uid, gid := lxcDropInFixture(t)
	calls := 0
	executor := lxcDetectorFixture(t, func() ([]byte, error) { calls++; return []byte("lxc\n"), nil })
	evidence, err := attestLXCServiceDropInAt(executor, path, path, filepath.Dir(path), uid, gid)
	if err != nil || calls != 2 || !strings.Contains(evidence, "#lxc-reviewed-profile#") {
		t.Fatalf("evidence=%q calls=%d error=%v", evidence, calls, err)
	}
	again, err := attestLXCServiceDropInAt(executor, path, path, filepath.Dir(path), uid, gid)
	if err != nil || again != evidence {
		t.Fatalf("stable evidence=%q error=%v", again, err)
	}
}

func TestLXCServiceDropInRejectsChangedProfile(t *testing.T) {
	profiles := []string{
		approvedLXCServiceDropInContent + "ExecStart=/bin/sh\n",
		approvedLXCServiceDropInContent + "Environment=PATH=/tmp\n",
		approvedLXCServiceDropInContent + "LoadCredential=secret:/tmp/input\n",
		approvedLXCServiceDropInContent + "BindPaths=/tmp:/etc/cron.d\n",
		approvedLXCServiceDropInContent + "ProtectHome=no\n",
		approvedLXCServiceDropInContent + "User=nobody\n",
		approvedLXCServiceDropInContent + "[Unit]\nConditionPathExists=/tmp/skip\n",
		strings.ReplaceAll(approvedLXCServiceDropInContent, "\n", "\r\n"),
		strings.Replace(approvedLXCServiceDropInContent, "NoNewPrivileges=no", "NoNewPrivileges=yes", 1),
		strings.Replace(approvedLXCServiceDropInContent, "ImportCredential=\n", "", 1),
		approvedLXCServiceDropInContent + "\x00",
		strings.Repeat("X", maximumFirewallRemovalUnitSize+1),
	}
	for index, profile := range profiles {
		t.Run(string(rune('A'+index)), func(t *testing.T) {
			path, uid, gid := lxcDropInFixture(t)
			writeLXCProfile(t, path, profile)
			executor := lxcDetectorFixture(t, func() ([]byte, error) { t.Fatal("unreviewed profile reached detector"); return nil, nil })
			if _, err := attestLXCServiceDropInAt(executor, path, path, filepath.Dir(path), uid, gid); err == nil {
				t.Fatal("accepted unreviewed profile")
			}
		})
	}
}

func TestLXCServiceDropInRejectsUnsafeMetadata(t *testing.T) {
	for _, name := range []string{"writable", "executable", "symlink", "hardlink", "parent-writable", "parent-symlink", "uid", "gid", "path", "missing"} {
		t.Run(name, func(t *testing.T) {
			path, uid, gid := lxcDropInFixture(t)
			expected, root := path, filepath.Dir(path)
			switch name {
			case "writable":
				if err := os.Chmod(path, 0666); err != nil { // #nosec G302 -- isolated negative fixture must be writable to prove profile rejection
					t.Fatal(err)
				}
			case "executable":
				if err := os.Chmod(path, 0755); err != nil { // #nosec G302 -- isolated negative fixture must be executable to prove profile rejection
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "parent-writable":
				if err := os.Chmod(root, 0777); err != nil { // #nosec G302 -- temporary ancestor beneath a private test parent deliberately violates the trust contract
					t.Fatal(err)
				}
			case "parent-symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(root, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, filepath.Base(path))
				expected = path
				root = filepath.Dir(alias)
			case "uid":
				uid++
			case "gid":
				gid++
			case "path":
				expected += ".other"
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			executor := lxcDetectorFixture(t, func() ([]byte, error) { t.Fatal("unsafe metadata reached detector"); return nil, nil })
			if _, err := attestLXCServiceDropInAt(executor, path, expected, root, uid, gid); err == nil {
				t.Fatal("accepted unsafe profile metadata")
			}
		})
	}
}

func TestLXCServiceDropInRejectsContextAndReplacement(t *testing.T) {
	for _, name := range []string{"host", "docker", "ambiguous", "error", "changed-context", "changed-file", "same-bytes-replacement", "parent-change", "untrusted-detector"} {
		t.Run(name, func(t *testing.T) {
			path, uid, gid := lxcDropInFixture(t)
			calls := 0
			executor := lxcDetectorFixture(t, func() ([]byte, error) {
				calls++
				switch name {
				case "host":
					return []byte("none\n"), nil
				case "docker":
					return []byte("docker\n"), nil
				case "ambiguous":
					return []byte("lxc\nlxc\n"), nil
				case "error":
					return []byte("lxc\n"), errors.New("detector failed")
				case "changed-context":
					if calls == 2 {
						return []byte("docker\n"), nil
					}
				case "changed-file":
					writeLXCProfile(t, path, approvedLXCServiceDropInContent+"ExecStart=/bin/sh\n")
				case "same-bytes-replacement":
					writeLXCProfile(t, path+".new", approvedLXCServiceDropInContent)
					if err := os.Rename(path+".new", path); err != nil {
						t.Fatal(err)
					}
				case "parent-change":
					if err := os.Chmod(filepath.Dir(path), 0777); err != nil { // #nosec G302 -- private test subtree deliberately simulates an ancestor permission change during attestation
						t.Fatal(err)
					}
				}
				return []byte("lxc\n"), nil
			})
			if name == "untrusted-detector" {
				executor.validate = func(string) error { return errors.New("unsafe detector") }
			}
			if _, err := attestLXCServiceDropInAt(executor, path, path, filepath.Dir(path), uid, gid); err == nil {
				t.Fatal("accepted ambiguous or changed evidence")
			}
		})
	}
}

func TestLXCServiceDropInComposition(t *testing.T) {
	for _, name := range []string{"runtime-only", "package-and-runtime", "reverse-order", "two-packages-and-runtime", "three-without-runtime", "duplicate", "unknown", "empty-element", "too-many", "package-failure", "runtime-failure"} {
		t.Run(name, func(t *testing.T) {
			paths := approvedLXCServiceDropInPath
			switch name {
			case "package-and-runtime", "package-failure", "runtime-failure":
				paths = systemdCoreSocketCapabilityDropInPath + " " + paths
			case "reverse-order":
				paths += " " + systemdCoreSocketCapabilityDropInPath
			case "two-packages-and-runtime":
				paths += " " + systemdCoreSocketCapabilityDropInPath + " " + systemdFirewallWireGuardOrderingDropInPath
			case "three-without-runtime":
				paths = approvedSystemdServiceDropInPath + " " + systemdCoreSocketCapabilityDropInPath + " " + systemdFirewallWireGuardOrderingDropInPath
			case "duplicate":
				paths += " " + paths
			case "unknown":
				paths += " /etc/systemd/system/custom.conf"
			case "empty-element":
				paths += " "
			case "too-many":
				paths += " " + paths + " " + paths + " " + paths
			}
			pkg := func(_ firewallManagerExecutor, p string) (string, error) {
				if name == "package-failure" {
					return "", errors.New("package mismatch")
				}
				if p != systemdCoreSocketCapabilityDropInPath && p != systemdFirewallWireGuardOrderingDropInPath {
					t.Fatal("unexpected package path")
				}
				return "package#verified", nil
			}
			lxc := func(_ firewallManagerExecutor, p string) (string, error) {
				if name == "runtime-failure" {
					return "", errors.New("runtime mismatch")
				}
				if p != approvedLXCServiceDropInPath {
					t.Fatal("unexpected runtime path")
				}
				return "runtime#verified", nil
			}
			evidence, err := attestSystemdServiceDropInsWithAttestors(firewallManagerExecutor{}, paths, pkg, lxc)
			valid := name == "runtime-only" || name == "package-and-runtime" || name == "reverse-order" || name == "two-packages-and-runtime"
			if (err == nil) != valid {
				t.Fatalf("evidence=%q error=%v", evidence, err)
			}
		})
	}
}

func TestLXCProfileCronCapturePreservesProviderChecks(t *testing.T) {
	for _, name := range []string{"valid", "inactive", "disabled", "executable", "stale-manager", "package", "replacement-between-captures"} {
		t.Run(name, func(t *testing.T) {
			path, uid, gid := lxcDropInFixture(t)
			override := map[string]string{"cron.service:DropInPaths": approvedLXCServiceDropInPath, "cron.service:NeedDaemonReload": "no"}
			switch name {
			case "inactive":
				override["cron.service:ActiveState"] = "inactive"
			case "disabled":
				override["cron.service:UnitFileState"] = "disabled"
			case "executable":
				override["cron.service:ExecStart"] = "{ path=/bin/sh ; argv[]=/bin/sh ; ignore_errors=no ; }"
			case "stale-manager":
				override["cron.service:NeedDaemonReload"] = "yes"
			}
			output := systemdCronProviderOutput(true, false, override)
			host := testCronProviderHost(t, false, activeCronProviderRuntime, func(p string, args ...string) ([]byte, error) {
				if name == "package" && filepath.Base(p) == "dpkg-query" {
					return nil, errors.New("package mismatch")
				}
				return output(p, args...)
			})
			calls := 0
			host.attestDropIns = func(_ firewallManagerExecutor, value string) (string, error) {
				calls++
				if name == "replacement-between-captures" && calls == 2 {
					writeLXCProfile(t, path+".new", approvedLXCServiceDropInContent)
					if err := os.Rename(path+".new", path); err != nil {
						t.Fatal(err)
					}
				}
				detector := lxcDetectorFixture(t, func() ([]byte, error) { return []byte("lxc\n"), nil })
				return attestSystemdServiceDropInsWithAttestors(detector, value, attestNormalSystemdPackageDropIn,
					func(e firewallManagerExecutor, _ string) (string, error) {
						return attestLXCServiceDropInAt(e, path, path, filepath.Dir(path), uid, gid)
					})
			}
			_, err := host.attest()
			if (err == nil) != (name == "valid") {
				t.Fatalf("provider result=%v", err)
			}
		})
	}
}

func TestLXCProfileAcceptsAttributedRPMCrond(t *testing.T) {
	path, uid, gid := lxcDropInFixture(t)
	host := testCronProviderHost(t, false, activeCronProviderRuntime, func(p string, args ...string) ([]byte, error) {
		if filepath.Base(p) == "rpm" && len(args) == 5 && args[0] == "--query" && args[1] == "--file" && args[3] == "--queryformat" && args[4] == "%{NAME}\\t%{EVR}\\n" {
			return []byte("cronie\t1.7.2-1.el10\n"), nil
		}
		if filepath.Base(p) != "systemctl" || len(args) != 4 {
			return nil, errors.New("unexpected query")
		}
		property := strings.TrimPrefix(args[1], "--property=")
		if args[3] == "cron.service" && property == "LoadState" {
			return []byte("not-found\n"), nil
		}
		if args[3] != "crond.service" {
			return nil, errors.New("unexpected service")
		}
		values := map[string]string{
			"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled",
			"FragmentPath": "/usr/lib/systemd/system/crond.service",
			"DropInPaths":  approvedLXCServiceDropInPath, "NeedDaemonReload": "no",
			"ExecStart": "{ path=/usr/sbin/crond ; argv[]=/usr/sbin/crond -n ; ignore_errors=no ; }",
		}
		value, ok := values[property]
		if !ok {
			return nil, errors.New("unexpected property")
		}
		return []byte(value + "\n"), nil
	})
	detector := lxcDetectorFixture(t, func() ([]byte, error) { return []byte("lxc\n"), nil })
	host.attestDropIns = func(_ firewallManagerExecutor, value string) (string, error) {
		return attestSystemdServiceDropInsWithAttestors(detector, value, attestNormalSystemdPackageDropIn,
			func(e firewallManagerExecutor, _ string) (string, error) {
				return attestLXCServiceDropInAt(e, path, path, filepath.Dir(path), uid, gid)
			})
	}
	evidence, err := host.attest()
	if err != nil || evidence.Unit != "crond.service" || strings.Join(evidence.Packages, ",") != "cronie" {
		t.Fatalf("RPM Cronie evidence=%#v error=%v", evidence, err)
	}
}

func TestLXCProfileRemovalPreservesSharedRuntimeFile(t *testing.T) {
	for _, name := range []string{"valid", "stale-manager", "changed-profile"} {
		t.Run(name, func(t *testing.T) {
			path, uid, gid := lxcDropInFixture(t)
			before, err := readFirewallRemovalFileWithOwner(path, 0644, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			manager := &fakeFirewallRemovalManager{states: defaultSystemdFirewallRemovalStates()}
			for _, state := range manager.states {
				if state.loaded {
					state.dropInPathsOverride = approvedLXCServiceDropInPath
				}
			}
			host := newFirewallRemovalTestHost(t, manager, true)
			host.executor.output = func(p string, args ...string) ([]byte, error) {
				if len(args) == 4 && args[0] == "show" && args[1] == "--property=NeedDaemonReload" {
					if name == "stale-manager" {
						return []byte("yes\n"), nil
					}
					return []byte("no\n"), nil
				}
				return manager.output(p, args...)
			}
			detector := lxcDetectorFixture(t, func() ([]byte, error) { return []byte("lxc\n"), nil })
			host.attestSystemdDropIns = func(_ firewallManagerExecutor, value string) (string, error) {
				return attestSystemdServiceDropInsWithAttestors(detector, value, attestExactSystemdRemovalDropIn,
					func(e firewallManagerExecutor, _ string) (string, error) {
						return attestLXCServiceDropInAt(e, path, path, filepath.Dir(path), uid, gid)
					})
			}
			if name == "changed-profile" {
				writeLXCProfile(t, path, approvedLXCServiceDropInContent+"ExecStop=/bin/sh\n")
			}
			err = host.prepare()
			if name != "valid" {
				if err == nil || len(manager.mutationCalls()) != 0 {
					t.Fatalf("unsafe removal error=%v mutations=%v", err, manager.mutationCalls())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := host.reattest(); err != nil {
				t.Fatal(err)
			}
			after, err := readFirewallRemovalFileWithOwner(path, 0644, uid, gid)
			if err != nil || !sameFirewallRemovalFileIdentity(before.identity, after.identity) || string(after.content) != string(before.content) {
				t.Fatal("removal changed shared LXC profile")
			}
		})
	}
}

func TestLXCProfileLegacyWebTUIRequiresCurrentManager(t *testing.T) {
	for _, current := range []string{"no", "yes", "", "unknown"} {
		t.Run("reload-"+current, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, false)
			fixture.seedExact(t)
			original := readRetirementCommandOutput
			readRetirementCommandOutput = func(name string, args ...string) (string, error) {
				if len(args) == 4 && args[2] == "--property=DropInPaths" {
					return approvedLXCServiceDropInPath, nil
				}
				if len(args) == 4 && args[2] == "--property=NeedDaemonReload" {
					return current, nil
				}
				return original(name, args...)
			}
			path, uid, gid := lxcDropInFixture(t)
			detector := lxcDetectorFixture(t, func() ([]byte, error) { return []byte("lxc\n"), nil })
			legacySystemdDropInAttestor = func(_ firewallManagerExecutor, value string) (string, error) {
				return attestSystemdServiceDropInsWithAttestors(detector, value, attestNormalSystemdPackageDropIn,
					func(e firewallManagerExecutor, _ string) (string, error) {
						return attestLXCServiceDropInAt(e, path, path, filepath.Dir(path), uid, gid)
					})
			}
			err := attestLegacyServiceManagerRuntime(false)
			if (err == nil) != (current == "no") {
				t.Fatalf("legacy manager result=%v", err)
			}
			if len(fixture.calls) != 0 {
				t.Fatal("inspection mutated service manager")
			}
		})
	}
}

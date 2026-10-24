package system

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBaseDependenciesKeepPlatformPrerequisitesWithoutOptionalPackages(t *testing.T) {
	for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum", "/sbin/apk", "/usr/sbin/apk"} {
		t.Run(manager, func(t *testing.T) {
			var calls [][]string
			err := installBaseDependenciesWith(context.Background(), func(name string) (string, error) {
				if name == filepath.Base(manager) {
					return manager, nil
				}
				return "", exec.ErrNotFound
			}, func(string) error { return nil }, func(_ context.Context, path string, refresh bool) error {
				args, err := baseDependencyArguments(path, refresh)
				if err != nil {
					return err
				}
				calls = append(calls, append([]string{path}, args...))
				return nil
			})
			if err != nil || len(calls) == 0 {
				t.Fatalf("base plan failed: calls=%v err=%v", calls, err)
			}
			install := calls[len(calls)-1]
			for _, required := range []string{"nftables", "curl", "wget", "jq"} {
				if !slices.Contains(install, required) {
					t.Errorf("missing base prerequisite %s: %v", required, install)
				}
			}
			for _, denied := range []string{"wireguard-tools", "wg", "qrencode", "libqrencode-tools", "rsyslog", "rsyslog-uxsock", "wazuh-agent", "checkpolicy", "policycoreutils-python-utils", "unattended-upgrades", "dnf-automatic", "epel-release", "autoremove", "remove", "del", "--allow-untrusted", "--nogpgcheck", "--allowerasing"} {
				for _, call := range calls {
					if slices.Contains(call, denied) {
						t.Errorf("implicit optional, destructive or untrusted operation %s: %v", denied, call)
					}
				}
			}
			if filepath.Base(manager) == "apk" {
				for _, required := range []string{"cronie", "cronie-openrc", "openrc", "procps-ng", "shadow"} {
					if !slices.Contains(install, required) {
						t.Errorf("missing Alpine lifecycle prerequisite %s", required)
					}
				}
			}
			if filepath.Base(manager) == "apt-get" {
				if len(calls) != 2 || strings.Join(calls[0], " ") != manager+" update" || !slices.Contains(install, "--no-remove") || !slices.Contains(install, "--no-install-recommends") {
					t.Fatalf("APT ordering/preservation guard changed: %v", calls)
				}
			} else if len(calls) != 1 {
				t.Fatalf("unexpected transaction count: %v", calls)
			}
		})
	}
}

func TestBaseDependenciesFailBeforeMutationForUnsafeManagers(t *testing.T) {
	denied := errors.New("manager not trusted")
	for _, test := range []struct {
		name        string
		path        string
		lookupErr   error
		validateErr error
	}{
		{name: "PATH shadow", path: "/tmp/apt-get"},
		{name: "relative PATH", path: "apt-get"},
		{name: "noncanonical path", path: "/usr/bin/../bin/apt-get"},
		{name: "wrong manager", path: "/sbin/apk"},
		{name: "lookup permission denied", lookupErr: os.ErrPermission},
		{name: "untrusted binary", path: "/usr/bin/apt-get", validateErr: denied},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookups := 0
			err := installBaseDependenciesWith(context.Background(), func(string) (string, error) {
				lookups++
				return test.path, test.lookupErr
			}, func(string) error { return test.validateErr }, func(context.Context, string, bool) error {
				t.Fatal("unsafe manager reached an installation/refresh command")
				return nil
			})
			if err == nil || lookups != 1 {
				t.Fatalf("unsafe manager accepted or silently bypassed: %v, lookups=%d", err, lookups)
			}
		})
	}
}

func TestBaseDependenciesStopAfterMetadataFailureOrManagerDrift(t *testing.T) {
	for _, failure := range []string{"metadata", "drift", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			denied := errors.New("refused fixture operation")
			validated, refreshed := 0, 0
			err := installBaseDependenciesWith(ctx, func(string) (string, error) {
				return "/usr/bin/apt-get", nil
			}, func(string) error {
				validated++
				if failure == "drift" && validated == 2 {
					return denied
				}
				return nil
			}, func(_ context.Context, _ string, refresh bool) error {
				if !refresh {
					t.Fatal("installation ran after metadata failure, drift or cancellation")
				}
				refreshed++
				if failure == "metadata" {
					return denied
				}
				if failure == "cancel" {
					cancel()
				}
				return nil
			})
			want := denied
			if failure == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || refreshed != 1 {
				t.Fatalf("failed boundary: %v, refreshes=%d", err, refreshed)
			}
		})
	}
}

func TestBaseDependenciesPropagateInstallationFailureAndRejectNoManager(t *testing.T) {
	denied := errors.New("native transaction failed")
	calls := 0
	err := installBaseDependenciesWith(context.Background(), func(name string) (string, error) {
		if name == "apk" {
			return "/sbin/apk", nil
		}
		return "", exec.ErrNotFound
	}, func(string) error { return nil }, func(context.Context, string, bool) error {
		calls++
		return denied
	})
	if !errors.Is(err, denied) || calls != 1 {
		t.Fatalf("failed native transaction was retried/hidden: %v, calls=%d", err, calls)
	}
	err = installBaseDependenciesWith(context.Background(), func(string) (string, error) {
		return "", exec.ErrNotFound
	}, func(string) error { t.Fatal("validated missing manager"); return nil }, func(context.Context, string, bool) error {
		t.Fatal("executed missing manager")
		return nil
	})
	if err == nil {
		t.Fatal("no manager reported success")
	}
}

func TestNativeInstallNeverEntersManualDependencyResolver(t *testing.T) {
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	t.Setenv(offlineQualificationEnvironment, "")
	t.Setenv("PATH", t.TempDir())
	if err := InstallDependencies(); err != nil {
		t.Fatalf("native install attempted manual dependency resolution: %v", err)
	}
}

func TestBaseDependencyCommandBoundaryRejectsUntrustedOperations(t *testing.T) {
	for _, manager := range []string{"apt-get", "/tmp/apk", "/usr/bin/../bin/apt-get", "/usr/bin/apt-get;true"} {
		if err := runBaseDependencyCommand(context.Background(), manager, false); err == nil {
			t.Fatalf("untrusted manager accepted: %s", manager)
		}
	}
	for _, manager := range []string{"/usr/bin/dnf", "/usr/bin/yum", "/sbin/apk", "/usr/sbin/apk"} {
		if err := runBaseDependencyCommand(context.Background(), manager, true); err == nil {
			t.Fatalf("unsupported refresh accepted: %s", manager)
		}
	}
}

func TestBaseDependencyEnvironmentCannotRedirectOrWeakenNativeDatabase(t *testing.T) {
	for _, key := range []string{"APT_CONFIG", "DPKG_ROOT", "DNF_VAR_INSTALLROOT", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "BASH_ENV", "ENV", "SYSWARDEN_PKG_INSTALL", offlineQualificationEnvironment} {
		t.Setenv(key, "untrusted-value")
	}
	t.Setenv("PATH", "/tmp/foreign-bin")
	t.Setenv("LANG", "untrusted-locale")
	t.Setenv("HTTPS_PROXY", "https://proxy.example.invalid:8443")
	for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum", "/sbin/apk", "/usr/sbin/apk"} {
		command, err := baseDependencyCommand(manager, false)
		if err != nil {
			t.Fatal(err)
		}
		if command.Path != manager || command.Dir != "/" {
			t.Fatal("redirected native command", command.Path, command.Dir)
		}
		for _, entry := range command.Env {
			if strings.Contains(entry, "untrusted") || strings.Contains(entry, "foreign-bin") {
				t.Fatal("unsafe inherited environment", entry)
			}
		}
		if !slices.Contains(command.Env, "HTTPS_PROXY=https://proxy.example.invalid:8443") || !slices.Contains(command.Env, "DEBIAN_FRONTEND=noninteractive") {
			t.Fatal("lost explicit transport or fixed environment")
		}
	}
}

func TestBaseDependencyCancellationDoesNotStartNativeManager(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// These fixed absolute paths must never be executed by this cancelled call.
	for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum", "/sbin/apk", "/usr/sbin/apk"} {
		if err := runBaseDependencyCommand(ctx, manager, false); !errors.Is(err, context.Canceled) {
			t.Fatal(manager, err)
		}
	}
	if err := runBaseDependencyCommand(nil, "/usr/bin/apt-get", false); err == nil { //nolint:staticcheck // SA1012: Deliberate invalid input verifies rejection before a native package manager can start.
		t.Fatal("nil context accepted")
	}
}

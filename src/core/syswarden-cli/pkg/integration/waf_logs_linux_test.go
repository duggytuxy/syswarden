//go:build linux

package integration

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateSELinuxPolicyWorkspaceUsesPrivateUniqueDirectory(t *testing.T) {
	parent := t.TempDir()
	var workspace string
	err := withPrivateSELinuxPolicyWorkspace(parent, func(privateWorkspace string) error {
		workspace = privateWorkspace
		tePath := filepath.Join(workspace, "syswarden_rsyslog.te")
		modulePath := filepath.Join(workspace, "syswarden_rsyslog.mod")
		packagePath := filepath.Join(workspace, "syswarden_rsyslog.pp")
		for _, path := range []string{tePath, modulePath, packagePath} {
			relative, err := filepath.Rel(parent, path)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				t.Fatalf("policy path escaped private parent: %q", path)
			}
			if filepath.Dir(path) != workspace {
				t.Fatalf("policy artifacts do not share one workspace: %q", path)
			}
		}
		info, err := os.Stat(tePath)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("SELinux source mode = %v, want regular 0600", info.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withPrivateSELinuxPolicyWorkspace() error = %v", err)
	}
	if workspace == "" || !strings.HasPrefix(filepath.Base(workspace), "syswarden-rsyslog-") {
		t.Fatalf("unexpected private workspace %q", workspace)
	}
	if _, err := os.Stat(workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private workspace was not removed: %v", err)
	}
}

func TestPrivateSELinuxPolicyWorkspaceCleansUpAfterFailure(t *testing.T) {
	parent := t.TempDir()
	sentinel := errors.New("synthetic policy failure")
	err := withPrivateSELinuxPolicyWorkspace(parent, func(workspace string) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("workspace error = %v, want sentinel", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed policy action left temporary artifacts: %#v", entries)
	}
}

func TestRestartManagedServiceUsesOpenRCNodepsRestartForRsyslog_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return true },
		func(name string, args ...string) error {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/sbin/rc-service --ifnotstarted rsyslog start",
		"/sbin/rc-service rsyslog status",
		"/sbin/rc-service --nodeps rsyslog restart",
		"/sbin/rc-service rsyslog status",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceKeepsOpenRCRestartForOtherServices_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsing(
		"wazuh-agent",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return true },
		func(name string, args ...string) error {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	if got, want := strings.Join(calls, "\n"), "/sbin/rc-service wazuh-agent restart"; got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceKeepsSystemdRestartForRsyslog_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) error {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	if got, want := strings.Join(calls, "\n"), "systemctl restart rsyslog"; got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceDefersOfflineWithoutCommand_SW_PKG_001(t *testing.T) {
	called := false
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "OFFLINE", nil },
		func() bool { return true },
		func(string, ...string) error {
			called = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	if called {
		t.Fatal("offline service-manager state executed a runtime command")
	}
}

func TestRestartManagedServiceFailsClosedOnUnknownStateAndRunnerError_SW_PKG_001(t *testing.T) {
	t.Run("unknown state", func(t *testing.T) {
		called := false
		err := restartManagedServiceUsing(
			"rsyslog",
			func() (string, error) { return "UNKNOWN", nil },
			func() bool { return true },
			func(string, ...string) error {
				called = true
				return nil
			},
		)
		if err == nil || !strings.Contains(err.Error(), "refusing unrecognized service-manager runtime state") {
			t.Fatalf("unknown-state error = %v", err)
		}
		if called {
			t.Fatal("unknown service-manager state executed a runtime command")
		}
	})

	for _, test := range []struct {
		name          string
		failCall      int
		wantCalls     int
		wantErrorText string
	}{
		{
			name:          "configuration validation failure",
			failCall:      1,
			wantCalls:     1,
			wantErrorText: "validate rsyslog configuration before OpenRC restart",
		},
		{
			name:          "conditional start failure",
			failCall:      2,
			wantCalls:     2,
			wantErrorText: "conditionally start OpenRC service rsyslog with dependencies",
		},
		{
			name:          "pre-restart active-state failure",
			failCall:      3,
			wantCalls:     3,
			wantErrorText: "attest active OpenRC service rsyslog before dependency-bypassing restart",
		},
		{
			name:          "nodeps restart failure",
			failCall:      4,
			wantCalls:     4,
			wantErrorText: "restart OpenRC service rsyslog without dependency traversal",
		},
		{
			name:          "post-restart attestation failure",
			failCall:      5,
			wantCalls:     5,
			wantErrorText: "attest restarted OpenRC service rsyslog",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sentinel := errors.New("synthetic service-manager failure")
			calls := 0
			err := restartManagedServiceUsing(
				"rsyslog",
				func() (string, error) { return "ACTIVE", nil },
				func() bool { return true },
				func(string, ...string) error {
					calls++
					if calls == test.failCall {
						return sentinel
					}
					return nil
				},
			)
			if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), test.wantErrorText) {
				t.Fatalf("OpenRC activation error = %v", err)
			}
			if calls != test.wantCalls {
				t.Fatalf("runtime commands after failure = %d, want %d", calls, test.wantCalls)
			}
		})
	}
}

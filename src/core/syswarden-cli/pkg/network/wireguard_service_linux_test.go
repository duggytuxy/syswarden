//go:build linux

package network

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func readWireGuardServiceFixture(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	file, openErr := root.Open(filepath.Base(path))
	if openErr != nil {
		_ = root.Close()
		t.Fatal(openErr)
	}
	contents, readErr := io.ReadAll(file)
	fileCloseErr := file.Close()
	rootCloseErr := root.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if fileCloseErr != nil {
		t.Fatal(fileCloseErr)
	}
	if rootCloseErr != nil {
		t.Fatal(rootCloseErr)
	}
	return contents
}

func chmodWireGuardServiceFixture(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod(filepath.Base(path), mode); err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

func wireGuardServiceRecorder(failAt int, failure error) (wireGuardServiceRunner, *[]string) {
	calls := make([]string, 0, 2)
	run := func(name string, args ...string) error {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		if len(calls)-1 == failAt {
			return failure
		}
		return nil
	}
	return run, &calls
}

func TestEnsureExactSymlinkIsIdempotentAndFailClosed(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(directory, "wg-quick.wg-syswarden")
	target := filepath.Join(directory, "wg-quick")

	if err := ensureExactSymlink(target, link); err != nil {
		t.Fatalf("create exact symlink: %v", err)
	}
	if err := ensureExactSymlink(target, link); err != nil {
		t.Fatalf("accept existing exact symlink: %v", err)
	}
	gotTarget, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != target {
		t.Fatalf("unexpected symlink target: got %q, want %q", gotTarget, target)
	}

	wrongLink := filepath.Join(directory, "wrong-link")
	if err := os.Symlink(filepath.Join(directory, "other"), wrongLink); err != nil {
		t.Fatal(err)
	}
	if err := ensureExactSymlink(target, wrongLink); err == nil {
		t.Fatal("mismatched symlink was accepted")
	}

	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureExactSymlink(target, regular); err == nil {
		t.Fatal("regular file was accepted or replaced")
	}
	contents := readWireGuardServiceFixture(t, regular)
	if string(contents) != "do not replace" {
		t.Fatalf("regular file was modified: %q", contents)
	}
}

func wireGuardConfigurationOwnerUID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("configuration ownership is unavailable")
	}
	return stat.Uid
}

func TestReuseExistingWireGuardConfigurationRetriesActivationWithoutRegeneratingKeys(t *testing.T) {
	directory := t.TempDir()
	server := filepath.Join(directory, "wg-syswarden.conf")
	client := filepath.Join(directory, "admin-pc.conf")
	if err := os.WriteFile(server, []byte("server-private-key-material"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(client, []byte("client-private-key-material"), 0600); err != nil {
		t.Fatal(err)
	}
	expectedUID := wireGuardConfigurationOwnerUID(t, server)
	failure := errors.New("injected first activation failure")
	activationCalls := 0
	activate := func() error {
		activationCalls++
		if activationCalls == 1 {
			return failure
		}
		return nil
	}

	reused, err := reuseExistingWireGuardConfiguration(server, client, expectedUID, activate)
	if reused || !errors.Is(err, failure) {
		t.Fatalf("first activation must fail closed: reused=%v err=%v", reused, err)
	}
	reused, err = reuseExistingWireGuardConfiguration(server, client, expectedUID, activate)
	if err != nil || !reused {
		t.Fatalf("retry must reactivate existing complete configuration: reused=%v err=%v", reused, err)
	}
	if activationCalls != 2 {
		t.Fatalf("activation called %d times, want 2", activationCalls)
	}
	for path, want := range map[string]string{
		server: "server-private-key-material",
		client: "client-private-key-material",
	} {
		got := readWireGuardServiceFixture(t, path)
		if string(got) != want {
			t.Fatalf("configuration %s changed during activation retry: %q", path, got)
		}
	}
}

func TestReuseExistingWireGuardConfigurationAcceptsHistoricalServerOnlyState(t *testing.T) {
	directory := t.TempDir()
	server := filepath.Join(directory, "wg-syswarden.conf")
	client := filepath.Join(directory, "admin-pc.conf")
	if err := os.WriteFile(server, []byte("server-private-key-material"), 0600); err != nil {
		t.Fatal(err)
	}
	activationCalls := 0
	reused, err := reuseExistingWireGuardConfiguration(
		server,
		client,
		wireGuardConfigurationOwnerUID(t, server),
		func() error { activationCalls++; return nil },
	)
	if err != nil || !reused {
		t.Fatalf("historical server-only configuration was not reused: reused=%v err=%v", reused, err)
	}
	if activationCalls != 1 {
		t.Fatalf("activation called %d times, want 1", activationCalls)
	}
}

func TestReuseExistingWireGuardConfigurationRejectsPartialOrUnsafeState(t *testing.T) {
	newFixture := func(t *testing.T) (string, string, uint32) {
		t.Helper()
		directory := t.TempDir()
		server := filepath.Join(directory, "wg-syswarden.conf")
		client := filepath.Join(directory, "admin-pc.conf")
		if err := os.WriteFile(server, []byte("server"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(client, []byte("client"), 0600); err != nil {
			t.Fatal(err)
		}
		return server, client, wireGuardConfigurationOwnerUID(t, server)
	}

	tests := []struct {
		name   string
		mutate func(*testing.T, string, string, uint32) uint32
	}{
		{
			name: "client only",
			mutate: func(t *testing.T, server, _ string, uid uint32) uint32 {
				if err := os.Remove(server); err != nil {
					t.Fatal(err)
				}
				return uid
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, server, _ string, uid uint32) uint32 {
				if err := os.Remove(server); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("elsewhere", server); err != nil {
					t.Fatal(err)
				}
				return uid
			},
		},
		{
			name: "permissive mode",
			mutate: func(t *testing.T, server, _ string, uid uint32) uint32 {
				chmodWireGuardServiceFixture(t, server, 0640)
				return uid
			},
		},
		{
			name: "unexpected owner",
			mutate: func(_ *testing.T, _ string, _ string, uid uint32) uint32 {
				return uid ^ 1
			},
		},
		{
			name: "hard link",
			mutate: func(t *testing.T, server, _ string, uid uint32) uint32 {
				if err := os.Link(server, server+".backup"); err != nil {
					t.Fatal(err)
				}
				return uid
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client, expectedUID := newFixture(t)
			expectedUID = test.mutate(t, server, client, expectedUID)
			activationCalls := 0
			reused, err := reuseExistingWireGuardConfiguration(server, client, expectedUID, func() error {
				activationCalls++
				return nil
			})
			if err == nil || reused {
				t.Fatalf("unsafe or partial state was accepted: reused=%v err=%v", reused, err)
			}
			if activationCalls != 0 {
				t.Fatalf("activation called %d times for rejected state", activationCalls)
			}
		})
	}
}

func TestActivateOpenRCWireGuardServicePropagatesEveryFailure(t *testing.T) {
	failure := errors.New("injected service-manager failure")
	allCalls := []string{
		"rc-update add wg-quick.wg-syswarden default",
		"rc-service wg-quick.wg-syswarden start",
	}

	t.Run("link", func(t *testing.T) {
		run, calls := wireGuardServiceRecorder(-1, nil)
		err := activateWireGuardService(true, func() error { return failure }, run)
		if !errors.Is(err, failure) || !strings.Contains(err.Error(), "prepare OpenRC WireGuard service") {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(*calls) != 0 {
			t.Fatalf("service manager was called after link failure: %v", *calls)
		}
	})

	for failAt, operation := range []string{"enable OpenRC WireGuard service", "start OpenRC WireGuard service"} {
		t.Run(fmt.Sprintf("step-%d", failAt+1), func(t *testing.T) {
			linkCalls := 0
			run, calls := wireGuardServiceRecorder(failAt, failure)
			err := activateWireGuardService(true, func() error { linkCalls++; return nil }, run)
			if !errors.Is(err, failure) || !strings.Contains(err.Error(), operation) {
				t.Fatalf("unexpected error: %v", err)
			}
			if linkCalls != 1 {
				t.Fatalf("link preparation called %d times, want 1", linkCalls)
			}
			if !reflect.DeepEqual(*calls, allCalls[:failAt+1]) {
				t.Fatalf("unexpected calls: got %v, want %v", *calls, allCalls[:failAt+1])
			}
		})
	}
}

func TestActivateWireGuardServiceSuccessPreservesManagerSelection(t *testing.T) {
	tests := []struct {
		name      string
		alpine    bool
		wantLink  int
		wantCalls []string
	}{
		{
			name:     "OpenRC",
			alpine:   true,
			wantLink: 1,
			wantCalls: []string{
				"rc-update add wg-quick.wg-syswarden default",
				"rc-service wg-quick.wg-syswarden start",
			},
		},
		{
			name:     "systemd",
			alpine:   false,
			wantLink: 0,
			wantCalls: []string{
				"systemctl daemon-reload",
				"systemctl enable --now wg-quick@wg-syswarden",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linkCalls := 0
			run, calls := wireGuardServiceRecorder(-1, nil)
			err := activateWireGuardService(test.alpine, func() error { linkCalls++; return nil }, run)
			if err != nil {
				t.Fatal(err)
			}
			if linkCalls != test.wantLink {
				t.Fatalf("link preparation called %d times, want %d", linkCalls, test.wantLink)
			}
			if !reflect.DeepEqual(*calls, test.wantCalls) {
				t.Fatalf("unexpected calls: got %v, want %v", *calls, test.wantCalls)
			}
		})
	}
}

func TestActivateSystemdWireGuardServicePropagatesEveryFailure(t *testing.T) {
	failure := errors.New("injected service-manager failure")
	allCalls := []string{
		"systemctl daemon-reload",
		"systemctl enable --now wg-quick@wg-syswarden",
	}
	for failAt, operation := range []string{"reload systemd", "enable and start systemd WireGuard service"} {
		t.Run(fmt.Sprintf("step-%d", failAt+1), func(t *testing.T) {
			run, calls := wireGuardServiceRecorder(failAt, failure)
			err := activateWireGuardService(false, func() error {
				t.Fatal("systemd path attempted OpenRC link preparation")
				return nil
			}, run)
			if !errors.Is(err, failure) || !strings.Contains(err.Error(), operation) {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(*calls, allCalls[:failAt+1]) {
				t.Fatalf("unexpected calls: got %v, want %v", *calls, allCalls[:failAt+1])
			}
		})
	}
}

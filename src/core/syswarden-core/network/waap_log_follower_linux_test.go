//go:build linux

package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSecureWAAPLogFollowerRejectsDiscoverySwapAndSpecialFiles_SW_CFG_002(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	logPath := filepath.Join(root, "access.log")
	secretPath := filepath.Join(root, "secret.log")
	if err := os.WriteFile(logPath, []byte("safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("must-not-be-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, rejected := resolveWAAPLogFiles([]string{logPath})
	if len(resolved) != 1 || len(rejected) != 0 {
		t.Fatalf("initial resolution = %#v, rejected=%v", resolved, rejected)
	}
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretPath, logPath); err != nil {
		t.Fatal(err)
	}
	if _, err := newSecureWAAPLogFollower(logPath, false); err == nil {
		t.Fatal("follower accepted a symlink swapped in after discovery")
	}

	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(logPath, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := newSecureWAAPLogFollower(logPath, false); err == nil {
		t.Fatal("follower accepted a FIFO")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO rejection blocked for %s", elapsed)
	}
}

func TestSecureWAAPLogFollowerRejectsSymlinkedParent_SW_CFG_002(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	linkedDir := filepath.Join(root, "linked")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "access.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Fatal(err)
	}
	if _, err := newSecureWAAPLogFollower(filepath.Join(linkedDir, "access.log"), false); err == nil {
		t.Fatal("follower accepted a symlinked parent directory")
	}
}

func TestSecureWAAPLogFollowerFollowsRegularRotation_SW_CFG_002(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	logPath := filepath.Join(root, "access.log")
	if err := os.WriteFile(logPath, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := newSecureWAAPLogFollower(logPath, true)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = 5 * time.Millisecond
	defer func() {
		if err := follower.Close(); err != nil {
			t.Error(err)
		}
	}()

	appendWAAPTestLine(t, logPath, "before-rotation\n")
	if got := nextWAAPTestLine(t, follower); got != "before-rotation" {
		t.Fatalf("line before rotation = %q", got)
	}

	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("after-rotation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := nextWAAPTestLine(t, follower); got != "after-rotation" {
		t.Fatalf("line after rotation = %q", got)
	}
}

func TestSecureWAAPLogFollowerPinsParentDirectory_SW_CFG_002(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	movedDir := filepath.Join(root, "logs-old")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := newSecureWAAPLogFollower(logPath, true)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = 5 * time.Millisecond
	defer func() {
		if err := follower.Close(); err != nil {
			t.Error(err)
		}
	}()

	if err := os.Rename(logDir, movedDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret.log")
	if err := os.WriteFile(secret, []byte("unsafe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, logPath); err != nil {
		t.Fatal(err)
	}
	appendWAAPTestLine(t, filepath.Join(movedDir, "access.log"), "pinned-directory\n")

	if got := nextWAAPTestLine(t, follower); got != "pinned-directory" {
		t.Fatalf("line from pinned directory = %q", got)
	}
}

func TestSecureWAAPLogFollowerFailsClosedOnUnsafeRotation_SW_CFG_002(t *testing.T) {
	t.Parallel()

	for _, replacement := range []string{"symlink", "fifo"} {
		replacement := replacement
		t.Run(replacement, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			logPath := filepath.Join(root, "access.log")
			if err := os.WriteFile(logPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			follower, err := newSecureWAAPLogFollower(logPath, true)
			if err != nil {
				t.Fatal(err)
			}
			follower.pollInterval = 5 * time.Millisecond
			defer func() {
				if err := follower.Close(); err != nil {
					t.Error(err)
				}
			}()

			if err := os.Remove(logPath); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "symlink":
				secret := filepath.Join(root, "secret.log")
				if err := os.WriteFile(secret, []byte("unsafe\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(secret, logPath); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(logPath, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := follower.Next(ctx); err == nil || !strings.Contains(err.Error(), "non-regular") {
				t.Fatalf("unsafe rotation error = %v", err)
			}
		})
	}
}

func TestSecureWAAPLogFollowerHandlesCopyTruncate_SW_CFG_002(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	logPath := filepath.Join(root, "access.log")
	if err := os.WriteFile(logPath, []byte("existing-long-entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := newSecureWAAPLogFollower(logPath, true)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = 5 * time.Millisecond
	defer func() {
		if err := follower.Close(); err != nil {
			t.Error(err)
		}
	}()

	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	result := make(chan string, 1)
	errs := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		line, nextErr := follower.Next(ctx)
		if nextErr != nil {
			errs <- nextErr
			return
		}
		result <- line
	}()
	time.Sleep(30 * time.Millisecond)
	appendWAAPTestLine(t, logPath, "after-truncate\n")

	select {
	case line := <-result:
		if line != "after-truncate" {
			t.Fatalf("line after copytruncate = %q", line)
		}
	case err := <-errs:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestSecureWAAPLogFollowerCancellationUnblocksRead_SW_CFG_002(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := newSecureWAAPLogFollower(logPath, true)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = 5 * time.Millisecond
	defer func() {
		if err := follower.Close(); err != nil {
			t.Error(err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, nextErr := follower.Next(ctx)
		done <- nextErr
	}()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Next after cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled follower goroutine did not exit")
	}
}

func TestSecureWAAPLogFollowerBoundsUnterminatedLines_SW_CFG_002(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(logPath, []byte(strings.Repeat("x", maxWAAPLogLineBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := newSecureWAAPLogFollower(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := follower.Close(); err != nil {
			t.Error(err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := follower.Next(ctx); err == nil || !strings.Contains(err.Error(), "line larger") {
		t.Fatalf("oversized line error = %v", err)
	}
}

func TestWAAPEngineContextShutdownJoinsFollowers_SW_CFG_002(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waap := &WAAPEngine{config: WAAPConfig{Logs: []string{logPath}}}
	ctx, cancel := context.WithCancel(context.Background())
	waap.StartContext(ctx)
	cancel()

	done := make(chan struct{})
	go func() {
		waap.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WAAP follower goroutine did not join after context cancellation")
	}
}

func appendWAAPTestLine(t *testing.T, path, line string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(line); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func nextWAAPTestLine(t *testing.T, follower *secureWAAPLogFollower) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	line, err := follower.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

//go:build linux

package system

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAPKTerminalDatabaseLockRequiresOriginalNativeObject(t *testing.T) {
	for _, kind := range []string{"valid", "busy", "missing", "symlink", "mode", "replacement", "parent-link", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			host := t.TempDir()
			directory := filepath.Join(host, "lib/apk/db")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "lock")
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			proposal, err := captureAPKDatabaseLock(t.Context(), host)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			switch kind {
			case "busy":
				held, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- fixed lock basename under this test temporary native database directory
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
				if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("lock.original", path); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- private temporary lock deliberately has unsafe readable metadata to verify refusal
					t.Fatal(err)
				}
			case "replacement":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				if err := os.Rename(directory, directory+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("db.original", directory); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			lock, err := openAPKDatabaseLock(ctx, host, proposal, true)
			if kind != "valid" {
				if err == nil {
					_ = lock.Close()
					t.Fatal("changed or busy native lock accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := lock.Revalidate(ctx); err != nil {
				t.Fatal(err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAPKTerminalOriginalReopenDoesNotAdoptReplacedSource(t *testing.T) {
	for _, kind := range []string{"replaced-source", "retained-bytes", "receipt", "missing", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			host, path, proposal, digest := originalRuntimeFixture(t, true)
			retained, err := retainAPKOriginalPayloadAt(t.Context(), host, path, proposal, digest)
			if err != nil {
				t.Fatal(err)
			}
			if err := retained.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(host, "opt/syswarden/bin/syswarden-core"), []byte("new inert candidate\n"), 0750); err != nil { // #nosec G306 -- fixed temporary core fixture models an inert executable candidate
				t.Fatal(err)
			}
			ctx := t.Context()
			switch kind {
			case "retained-bytes":
				err = os.WriteFile(filepath.Join(path, "original-runtime/bin/syswarden-core"), []byte("changed evidence\n"), 0750) // #nosec G306 -- fixed temporary retained-core evidence is deliberately corrupted
			case "receipt":
				err = os.WriteFile(filepath.Join(path, "original-runtime.json"), []byte("{}\n"), 0600)
			case "missing":
				err = os.Remove(filepath.Join(path, "original-runtime/bin/syswarden-core"))
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := reopenAPKOriginalPayloadAt(ctx, host, path, proposal, digest)
			if kind != "replaced-source" {
				if err == nil {
					_ = reopened.Close()
					t.Fatal("damaged original evidence accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.RevalidateRetained(ctx); err != nil {
				t.Fatal(err)
			}
			if err := reopened.RevalidateSource(ctx); err == nil {
				t.Fatal("new source adopted as original")
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAPKTerminalGateRetirementPreservesSubstitutionAndInterruption(t *testing.T) {
	for _, kind := range []string{"valid", "substitution", "rename-failure", "cancel", "resume"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			journalPath := t.TempDir()
			directory, err := openExistingPinnedServiceDirectory(path)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.close()
			journal, err := openExistingPinnedServiceDirectory(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			defer journal.close()
			body := []byte("#!/bin/sh\nexit 1\n")
			if err := os.WriteFile(filepath.Join(path, "gate"), body, 0755); err != nil { // #nosec G306 -- private temporary gate fixture models required executable0755 metadata
				t.Fatal(err)
			}
			expected, err := readAPKNativeHook(directory.root, "gate")
			if err != nil {
				t.Fatal(err)
			}
			rename := serviceArtifactRename(unix.Renameat2)
			ctx := t.Context()
			switch kind {
			case "substitution":
				rename = func(a int, b string, c int, d string, flags uint) error {
					if b == "gate" {
						if err := os.Rename(filepath.Join(path, "gate"), filepath.Join(path, "original-gate")); err != nil {
							return err
						}
						if err := os.WriteFile(filepath.Join(path, "gate"), []byte("administrator replacement\n"), 0755); err != nil { // #nosec G306 -- private temporary administrator replacement deliberately models executable0755 hook metadata
							return err
						}
					}
					return unix.Renameat2(a, b, c, d, flags)
				}
			case "rename-failure":
				rename = func(int, string, int, string, uint) error { return syscall.EIO }
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = retireAPKTerminalGate(ctx, directory, journal, "gate", expected, 0755, "terminal-retire-gate.json", rename)
			if kind == "valid" || kind == "resume" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(path, "gate")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("owned gate remains", err)
				}
				if kind == "resume" {
					if err := retireAPKTerminalGate(ctx, directory, journal, "gate", expected, 0755, "terminal-retire-gate.json", unix.Renameat2); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if err == nil {
					t.Fatal("unsafe retirement accepted")
				}
				got, readErr := os.ReadFile(filepath.Join(path, "gate")) // #nosec G304 -- fixed gate basename in this test private temporary directory
				if readErr != nil {
					t.Fatal("named object lost", readErr)
				}
				if kind == "substitution" && string(got) != "administrator replacement\n" {
					t.Fatal("administrator replacement deleted")
				}
			}
		})
	}
}

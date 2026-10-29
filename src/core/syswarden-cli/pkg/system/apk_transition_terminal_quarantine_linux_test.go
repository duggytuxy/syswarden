//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// This models an actual crash boundary: the real rename succeeds, then the
// retirement call stops before unlink. No owning failure writer is invoked.
func apkTerminalGateCrashFixture(t *testing.T) (*apkExecutionTestFixture, func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error), apkTerminalGateRetirement) {
	t.Helper()
	return apkTerminalGateCrashFixtureWithSetup(t, nil)
}

func apkTerminalGateCrashFixtureWithSetup(t *testing.T, setup func(*authenticatedAPKCandidate, *apkTransitionServices)) (*apkExecutionTestFixture, func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error), apkTerminalGateRetirement) {
	t.Helper()
	f, factory := apkTerminalCompleteFixtureWithSetup(t, setup)
	authority, err := inspectAPKTerminalFixture(t.Context(), f, factory)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	intent, err := authority.retirementBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAPKTerminalExact(authority.directory, "terminal-finalizing.json", intent); err != nil {
		t.Fatal(err)
	}
	if err := publishAPKExecutionLauncherLineage(t.Context(), authority); err != nil {
		t.Fatal(err)
	}
	if err := writeAPKTerminalExact(authority.directory, "terminal-retirement-intent.json", intent); err != nil {
		t.Fatal(err)
	}
	dispatcher, err := openExistingPinnedServiceDirectory(f.services.root)
	if err != nil {
		t.Fatal(err)
	}
	err = errors.Join(retireAPKTerminalGate(t.Context(), dispatcher, authority.directory, "active-hook", authority.handoff.Active, 0700, "terminal-retire-dispatcher.json", unix.Renameat2), closeAPKExecutionDirectory(dispatcher))
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := openExistingPinnedServiceDirectory(filepath.Join(f.services.hostRoot, apkTransitionGateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("synthetic crash immediately after gate rename")
	rename := func(oldFD int, oldName string, newFD int, newName string, flags uint) error {
		if err := unix.Renameat2(oldFD, oldName, newFD, newName, flags); err != nil {
			return err
		}
		return interrupted
	}
	err = retireAPKTerminalGate(t.Context(), hooks, authority.directory, apkTransitionGateName, authority.handoff.Hook, 0755, "terminal-retire-gate.json", rename)
	err = errors.Join(err, closeAPKExecutionDirectory(hooks))
	if !errors.Is(err, interrupted) {
		t.Fatal("real rename interruption was not reached", err)
	}
	raw, err := readAPKTransitionBytes(authority.directory, "terminal-retire-gate.json", 16384)
	var record apkTerminalGateRetirement
	if err != nil || decodeAPKTransitionJSON(raw, &record) != nil {
		t.Fatal("retirement evidence unavailable", err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	return f, factory, record
}

func TestAPKTerminalRecordedGateQuarantineReconstruction(t *testing.T) {
	f, factory, record := apkTerminalGateCrashFixture(t)
	path := filepath.Join(f.services.hostRoot, apkTransitionGateDirectory, record.Quarantine)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	var preserved = map[string][]byte{}
	for _, name := range []string{"original-runtime.json", "original-runtime/bin/syswarden-cli", "original-runtime/bin/syswarden-core", "original-runtime/bin/syswarden-tui", "original-runtime/signatures.json", "native-result.json", "resources-closed.json"} {
		raw, err := os.ReadFile(filepath.Join(f.review.Directory, name)) // #nosec G304 -- fixed inert evidence names under the temporary execution directory
		if err != nil {
			t.Fatal(err)
		}
		preserved[name] = raw
	}
	if _, err := captureAPKNativeHooks(t.Context(), f.services.hostRoot); err == nil {
		t.Fatal("ordinary pretransaction capture accepted recovery quarantine")
	}
	authority, err := inspectAPKTerminalFixture(t.Context(), f, factory)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("read-only terminal inspection mutated quarantine", err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	if err := finalizeAPKTransitionWith(t.Context(), f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{apkTransitionGateName, record.Quarantine} {
		if _, err := os.Lstat(filepath.Join(f.services.hostRoot, apkTransitionGateDirectory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("recorded gate was not completely retired", err)
		}
	}
	h, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), f.services.hostRoot)
	if err != nil {
		t.Fatal("closed recovered terminal lineage refused", err)
	}
	if err := h.close(); err != nil {
		t.Fatal(err)
	}
	for name, want := range preserved {
		got, err := os.ReadFile(filepath.Join(f.review.Directory, name)) // #nosec G304 -- fixed inert evidence names captured above
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("recovery rewrote original outcome evidence", name, err)
		}
	}
	if f.calls != 1 {
		t.Fatal("terminal recovery replayed native execution")
	}
}

func TestAPKTerminalRecordedGateQuarantineRefusesAmbiguity(t *testing.T) {
	for _, kind := range []string{"missing-finalizing", "wrong-finalizing", "missing-retirement", "missing-gate-intent", "wrong-parent-intent", "wrong-quarantine-name", "inode", "symlink", "hardlink", "mode", "bytes", "named-conflict", "extra-hook", "parent-replaced", "unresolved", "pending-closed", "busy-database", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f, factory, record := apkTerminalGateCrashFixture(t)
			directory := filepath.Join(f.services.hostRoot, apkTransitionGateDirectory)
			path := filepath.Join(directory, record.Quarantine)
			ctx := t.Context()
			write := func(name string, raw []byte, mode os.FileMode) {
				if err := os.WriteFile(name, raw, mode); err != nil { // #nosec G306 G703 -- callers select fixed temporary corruption fixtures only
					t.Fatal(err)
				}
			}
			switch kind {
			case "missing-finalizing":
				if err := os.Remove(filepath.Join(f.review.Directory, "terminal-finalizing.json")); err != nil {
					t.Fatal(err)
				}
			case "wrong-finalizing":
				write(filepath.Join(f.review.Directory, "terminal-finalizing.json"), []byte("{}\n"), 0600)
			case "missing-retirement":
				if err := os.Remove(filepath.Join(f.review.Directory, "terminal-retirement-intent.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-gate-intent":
				if err := os.Remove(filepath.Join(f.review.Directory, "terminal-retire-gate.json")); err != nil {
					t.Fatal(err)
				}
			case "wrong-parent-intent", "wrong-quarantine-name":
				if kind == "wrong-parent-intent" {
					record.Parent.Inode = 0
				} else {
					record.Quarantine = ".syswarden-apk-retired-x"
				}
				raw, err := apkExecutionJSON(record)
				if err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(f.review.Directory, "terminal-retire-gate.json"), raw, 0600)
			case "inode", "symlink":
				raw, err := os.ReadFile(path) // #nosec G304 -- exact recorded gate path under the temporary fixture host
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, filepath.Join(f.services.hostRoot, "held-gate")); err != nil {
					t.Fatal(err)
				}
				if kind == "inode" {
					write(path, raw, 0755)
				} else if err := os.Symlink("/dev/null", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(f.services.hostRoot, "linked-gate")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0700); err != nil { // #nosec G302 -- deliberately wrong temporary executable metadata
					t.Fatal(err)
				}
			case "bytes":
				write(path, []byte("administrator replacement\n"), 0755)
			case "named-conflict":
				write(filepath.Join(directory, apkTransitionGateName), record.Original.Content, 0755)
			case "extra-hook":
				write(filepath.Join(directory, ".unrelated-hook"), []byte("administrator hook\n"), 0755)
			case "parent-replaced":
				held := filepath.Join(f.services.hostRoot, "held-hooks")
				if err := os.Rename(directory, held); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(directory, 0755); err != nil { // #nosec G301 -- deliberate replacement of a temporary public hook directory
					t.Fatal(err)
				}
				for _, name := range []string{record.Quarantine, "syswarden-recovery"} {
					raw, err := os.ReadFile(filepath.Join(held, name)) // #nosec G304 -- fixed two names in the held temporary hook directory
					if err != nil {
						t.Fatal(err)
					}
					write(filepath.Join(directory, name), raw, 0755)
				}
			case "unresolved":
				write(filepath.Join(f.review.Directory, "terminal-unresolved.json"), []byte("{}\n"), 0600)
			case "pending-closed":
				write(filepath.Join(f.review.Directory, "terminal-closed.pending"), []byte("interrupted metadata\n"), 0600)
			case "busy-database":
				file, err := os.OpenFile(filepath.Join(f.services.hostRoot, "lib/apk/db/lock"), os.O_RDWR, 0) // #nosec G304 -- fixed lock in the temporary native database fixture
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			authority, err := inspectAPKTerminalFixture(ctx, f, factory)
			if authority != nil {
				_ = authority.Close()
			}
			if err == nil {
				t.Fatal("ambiguous recovery state was accepted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("refusal discarded recorded quarantine", err)
			}
			if _, err := os.Lstat(filepath.Join(f.review.Directory, "terminal-closed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal published completion", err)
			}
			if f.calls != 1 {
				t.Fatal("refusal replayed native execution")
			}
		})
	}
}

func TestAPKTerminalRecordedGateQuarantineLateFailurePreservesDebt(t *testing.T) {
	for _, kind := range []string{"substitution-after-observation", "cancel-after-observation", "close-error", "closure-sync-error"} {
		t.Run(kind, func(t *testing.T) {
			f, _, record := apkTerminalGateCrashFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			path := filepath.Join(f.services.hostRoot, apkTransitionGateDirectory, record.Quarantine)
			calls := 0
			factory := func(_ context.Context, prepared *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
				boundary := &apkExecutionTestBoundary{digest: prepared.plan.EffectPlanSHA256}
				if kind == "close-error" {
					boundary.closeErr = syscall.EIO
				}
				boundary.after = func(check context.Context) error {
					calls++
					if calls == 2 {
						if kind == "cancel-after-observation" {
							cancel()
						}
						if kind == "substitution-after-observation" {
							if err := os.Rename(path, filepath.Join(f.services.hostRoot, "held-observed-gate")); err != nil {
								return err
							}
							if err := os.WriteFile(path, []byte("administrator replacement\n"), 0755); err != nil { // #nosec G306 G703 -- fixed temporary quarantine replacement verifies preservation
								return err
							}
						}
					}
					return check.Err()
				}
				return boundary, nil
			}
			publisher := publishAPKTerminalClosure
			if kind == "closure-sync-error" {
				publisher = func(ctx context.Context, path string, identity apkTransitionIdentity, intent, closed []byte) error {
					return publishAPKTerminalClosureUsing(ctx, path, identity, intent, closed, func(*pinnedServiceDirectory) error { return syscall.ENOSPC })
				}
			}
			err := finalizeAPKTransitionUsing(ctx, f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory, writeAPKTransitionBytes, publisher)
			var failure *APKTransitionExecutionError
			if !errors.As(err, &failure) || !failure.Unresolved {
				t.Fatal("recovery failure was hidden", err)
			}
			if kind == "substitution-after-observation" {
				raw, err := os.ReadFile(path) // #nosec G304 -- fixed temporary quarantine whose replacement must be preserved
				if err != nil || string(raw) != "administrator replacement\n" {
					t.Fatal("replacement was discarded", err)
				}
			}
			h, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), f.services.hostRoot)
			if h != nil {
				_ = h.close()
			}
			if err == nil {
				t.Fatal("failed recovery allowed launcher removal")
			}
			if f.calls != 1 {
				t.Fatal("recovery failure replayed native execution")
			}
		})
	}
}

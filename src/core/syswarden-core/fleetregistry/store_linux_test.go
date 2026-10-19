package fleetregistry

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

func provisionFixture(t testing.TB) (string, *os.File, []byte, contracts.NodeRegistryContinuityContext) {
	t.Helper()
	s, x := snapshotFixture(t)
	data := encodeFixture(t, s, x)
	dir := t.TempDir()
	if err := chmodFixture(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SnapshotFileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openFixtureDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return dir, f, data, x
}

func TestStoreReadOnlyLeaseAndOwnedDescriptors(t *testing.T) {
	dir, input, original, x := provisionFixture(t)
	s, err := OpenSnapshotStore(input, x)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	flags, err := unix.FcntlInt(s.file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("file is not read-only", err)
	}
	for _, fd := range []uintptr{s.file.Fd(), s.directory.Fd()} {
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("descriptor leaks across exec", err)
		}
	}
	if other, err := OpenSnapshotStore(input, x); !errors.Is(err, ErrLocked) || other != nil {
		t.Fatal("second lease", err)
	}
	if err := unix.Flock(int(input.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenSnapshotStore(input, x); !errors.Is(err, ErrLocked) || other != nil {
		t.Fatal("input descriptor released owned lease", err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		got, err := s.Read(x)
		if err != nil || got.Checkpoint.Snapshot != got.Registry.Reference() {
			t.Fatal("owned read", err)
		}
		got.Generation.AuthorityID = "caller-mutation"
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("idempotent close", err)
	}
	got, err := s.Read(x)
	assertNoSnapshot(t, got, err)
	if !errors.Is(err, ErrClosed) {
		t.Fatal("closed read", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(SnapshotFileName)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("read/close changed bytes", err)
	}
	f, err := openFixtureDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	reopened, err := OpenSnapshotStore(f, x)
	if err != nil {
		t.Fatal("lease not released", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsUnsafeEntries(t *testing.T) {
	for _, scenario := range []string{"missing", "symlink", "hardlink", "fifo", "directory", "mode", "setuid", "oversize", "empty", "world-directory", "wrong-pin", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			dir, input, original, expected := provisionFixture(t)
			name := filepath.Join(dir, SnapshotFileName)
			var err error
			switch scenario {
			case "missing":
				err = os.Remove(name)
			case "symlink":
				target := filepath.Join(dir, "target")
				if err = os.Rename(name, target); err == nil {
					err = os.Symlink(target, name)
				}
			case "hardlink":
				err = os.Link(name, filepath.Join(dir, "second"))
			case "fifo":
				if err = os.Remove(name); err == nil {
					err = unix.Mkfifo(name, 0600)
				}
			case "directory":
				if err = os.Remove(name); err == nil {
					err = os.Mkdir(name, 0700)
				}
			case "mode":
				err = chmodFixture(name, 0644)
			case "setuid":
				err = chmodFixture(name, 0600|os.ModeSetuid)
			case "oversize":
				err = os.Truncate(name, int64(MaxSnapshotBytes+1))
			case "empty":
				err = os.Truncate(name, 0)
			case "world-directory":
				err = chmodFixture(dir, 0755)
			case "wrong-pin":
				expected.Checkpoint.Ref = "other"
			case "truncated":
				err = os.WriteFile(name, original[:len(original)-1], 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(name)
			if scenario != "missing" && err != nil {
				t.Fatal(err)
			}
			store, err := OpenSnapshotStore(input, expected)
			if err == nil || store != nil {
				t.Fatal("unsafe entry opened", err)
			}
			after, _ := os.Lstat(name)
			if before != nil && (after == nil || before.Mode() != after.Mode() || before.Size() != after.Size()) {
				t.Fatal("failed open repaired or removed state")
			}
		})
	}
}

func TestStoreMetadataOwnerAndType(t *testing.T) {
	var metadata unix.Stat_t
	if err := unix.Stat(t.TempDir(), &metadata); err != nil {
		t.Fatal(err)
	}
	uid := metadata.Uid
	file := unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0600, Nlink: 1, Size: 1}
	dir := unix.Stat_t{Uid: uid, Mode: unix.S_IFDIR | 0700, Nlink: 1}
	if !privateFile(file) || !privateDirectory(dir) {
		t.Fatal("valid service UID metadata rejected")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Uid++ },
		func(s *unix.Stat_t) { s.Mode |= 0020 },
		func(s *unix.Stat_t) { s.Mode |= unix.S_ISGID },
		func(s *unix.Stat_t) { s.Nlink = 0 },
	} {
		f, d := file, dir
		mutate(&f)
		mutate(&d)
		if privateFile(f) || privateDirectory(d) {
			t.Fatal("unsafe owner, mode or unlink accepted")
		}
	}
	file.Nlink = 2
	if privateFile(file) {
		t.Fatal("multiple file links")
	}
}

func TestStoreChangedHandleStaysPoisoned(t *testing.T) {
	for _, scenario := range []string{"content", "replace", "symlink", "chmod", "directory-mode", "sibling", "unlink", "hardlink", "expected"} {
		t.Run(scenario, func(t *testing.T) {
			dir, input, original, x := provisionFixture(t)
			s, err := OpenSnapshotStore(input, x)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			name := filepath.Join(dir, SnapshotFileName)
			badExpected := x
			switch scenario {
			case "content":
				changed := bytes.Clone(original)
				changed[len(changed)-2] ^= 1
				err = os.WriteFile(name, changed, 0600)
			case "replace", "symlink":
				target := filepath.Join(dir, "old")
				if err = os.Rename(name, target); err == nil {
					if scenario == "replace" {
						err = os.WriteFile(name, original, 0600)
					} else {
						err = os.Symlink(target, name)
					}
				}
			case "chmod":
				err = chmodFixture(name, 0644)
			case "directory-mode":
				err = chmodFixture(dir, 0755)
			case "sibling":
				err = os.WriteFile(filepath.Join(dir, "unexpected"), []byte("unrelated"), 0600)
			case "unlink":
				err = os.Remove(name)
			case "hardlink":
				err = os.Link(name, filepath.Join(dir, "second"))
			case "expected":
				badExpected.Checkpoint.Ref = "new-current"
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Read(badExpected)
			assertNoSnapshot(t, got, err)
			if !s.poisoned {
				t.Fatal("failure did not poison handle")
			}
			got, err = s.Read(x)
			assertNoSnapshot(t, got, err)
			if !errors.Is(err, ErrChanged) {
				t.Fatal("fallback to previously accepted state", err)
			}
		})
	}
}

type interceptedRead struct {
	snapshotFile
	after func()
	short bool
	err   error
}

func (f interceptedRead) ReadAt(data []byte, off int64) (int, error) {
	n, err := f.snapshotFile.ReadAt(data, off)
	if f.after != nil {
		f.after()
	}
	if f.short {
		return n - 1, nil
	}
	if f.err != nil {
		return 0, f.err
	}
	return n, err
}

func TestStoreReattestsAfterReadAndKeepsFailures(t *testing.T) {
	for _, scenario := range []string{"read-error", "short-read", "same-bytes-rewrite", "replacement", "mode-change"} {
		t.Run(scenario, func(t *testing.T) {
			dir, input, data, x := provisionFixture(t)
			s, err := OpenSnapshotStore(input, x)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			f := interceptedRead{snapshotFile: s.file}
			name := filepath.Join(dir, SnapshotFileName)
			switch scenario {
			case "read-error":
				f.err = io.ErrUnexpectedEOF
			case "short-read":
				f.short = true
			case "same-bytes-rewrite":
				f.after = func() {
					if err := os.WriteFile(name, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "replacement":
				f.after = func() {
					if err := os.Rename(name, filepath.Join(dir, "saved")); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(name, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "mode-change":
				f.after = func() {
					if err := chmodFixture(name, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			s.file = f
			got, err := s.Read(x)
			assertNoSnapshot(t, got, err)
			if !s.poisoned {
				t.Fatal("failed post-read observation accepted")
			}
		})
	}
}

func TestStoreConcurrentReadCloseAndZero(t *testing.T) {
	_, input, _, x := provisionFixture(t)
	s, err := OpenSnapshotStore(input, x)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				got, err := s.Read(x)
				if err != nil {
					if !errors.Is(err, ErrClosed) || got.Registry.Reference() != (contracts.RateReference{}) {
						t.Error("concurrent result", err)
					}
				} else if got.Checkpoint.Snapshot != got.Registry.Reference() {
					t.Error("mixed snapshot")
				}
			}
		}()
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for _, zero := range []*Store{nil, {}} {
		got, err := zero.Read(x)
		assertNoSnapshot(t, got, err)
		if err := zero.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := OpenSnapshotStore(nil, x); err == nil || got != nil {
		t.Fatal("nil directory")
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := OpenSnapshotStore(input, x); err == nil || got != nil {
		t.Fatal("closed directory")
	}
}

// Scope negative-mode fixtures to their disposable parent, including deliberately
// unsafe modes used to verify rejection. No production path is used.
func chmodFixture(path string, mode os.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.Chmod(filepath.Base(path), mode)
}

func openFixtureDirectory(path string) (*os.File, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.Open(".")
}

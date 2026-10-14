package journal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuthorityLaunchSnapshotCreationPolicy(t *testing.T) {
	for _, denial := range []error{nil, unix.EINVAL, unix.ENOSYS, unix.EPERM, unix.EACCES, unix.ENOMEM} {
		calls := 0
		fd, err := newAuthorityLaunchSnapshot(func(name string, flags int) (int, error) {
			calls++
			if name != "syswarden-authority-launch" || flags != unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_NOEXEC_SEAL {
				t.Fatal("weakened creation policy")
			}
			if denial != nil {
				return -1, denial
			}
			return 42, nil
		})
		if calls != 1 || !errors.Is(err, denial) || (denial == nil && fd != 42) || (denial != nil && fd != -1) {
			t.Fatal("creation retried or denial bypassed", fd, err)
		}
	}
	if validAuthorityLaunchLinks(-1, 0) || validAuthorityLaunchLinks(-1, 2) {
		t.Fatal("unproven anonymous or multiple-link source accepted")
	}
}

// Root operations run only inside the opt-in disposable process fixture.
func testAuthorityLaunchSnapshot(t *testing.T, data []byte) {
	for _, kind := range []string{"valid-sealed", "source-replaced", "source-modified", "source-unlinked", "nil", "closed", "writable-fd", "path-fd", "wrong-digest", "malformed-digest", "malformed-record"} {
		t.Run(kind, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			contents := data
			if kind == "malformed-record" {
				contents = []byte("{}")
			}
			if err := root.WriteFile("launch", contents, 0400); err != nil {
				t.Fatal(err)
			}
			flags := os.O_RDONLY
			if kind == "writable-fd" {
				flags = os.O_RDWR
			}
			if kind == "path-fd" {
				flags = unix.O_PATH
			}
			source, err := root.OpenFile("launch", flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = source.Close() }()
			input := source
			if kind == "nil" {
				input = nil
			}
			if kind == "closed" {
				_ = source.Close()
			}
			digest := recoveryDigest(contents)
			if kind == "wrong-digest" {
				digest = strings.Repeat("0", 64)
			}
			if kind == "malformed-digest" {
				digest = "bad"
			}
			valid := kind == "valid-sealed" || strings.HasPrefix(kind, "source-")
			if valid {
				if _, err := source.Seek(7, io.SeekStart); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := SnapshotAuthorityLaunch(input, digest)
			if !valid {
				if snapshot != nil {
					_ = snapshot.Close()
					t.Fatal("rejected snapshot exposed a handle")
				}
				if !errors.Is(err, ErrAuthorityLaunch) {
					t.Fatal("unsafe source accepted", err)
				}
				return
			}
			if err != nil || snapshot == nil {
				t.Fatal("valid launch refused", err)
			}
			defer func() { _ = snapshot.Close() }()
			if offset, err := source.Seek(0, io.SeekCurrent); err != nil || offset != 7 {
				t.Fatal("source offset changed", err)
			}
			original, err := root.ReadFile("launch")
			if err != nil || !bytes.Equal(original, data) {
				t.Fatal("snapshot modified source", err)
			}
			switch kind {
			case "source-replaced":
				if err := root.Rename("launch", "retired"); err != nil {
					t.Fatal(err)
				}
				if err := root.WriteFile("launch", []byte("replacement"), 0400); err != nil {
					t.Fatal(err)
				}
			case "source-modified":
				if err := root.WriteFile("launch", []byte("modified"), 0400); err != nil {
					t.Fatal(err)
				}
			case "source-unlinked":
				if err := root.Remove("launch"); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadAuthorityLaunch(source, digest); err == nil {
					t.Fatal("unsealed unlinked source accepted")
				}
			}
			assertSealedAuthorityLaunch(t, snapshot, data)
		})
	}
	for _, kind := range []string{"unsealed", "missing-write", "missing-grow", "missing-shrink", "missing-seal", "missing-exec", "anonymous-mode", "anonymous-owner", "anonymous-group", "anonymous-writable"} {
		t.Run(kind, func(t *testing.T) {
			seals := authorityLaunchSeals
			switch kind {
			case "unsealed":
				seals = 0
			case "missing-write":
				seals &^= unix.F_SEAL_WRITE
			case "missing-grow":
				seals &^= unix.F_SEAL_GROW
			case "missing-shrink":
				seals &^= unix.F_SEAL_SHRINK
			case "missing-seal":
				seals &^= unix.F_SEAL_SEAL
			case "missing-exec":
				seals &^= unix.F_SEAL_EXEC
			}
			f := authorityLaunchMemfdFixture(t, data, seals, kind == "anonymous-writable")
			switch kind {
			case "anonymous-mode":
				if err := f.Chmod(0600); err != nil {
					t.Fatal(err)
				}
			case "anonymous-owner":
				if err := f.Chown(1, 0); err != nil {
					t.Fatal(err)
				}
			case "anonymous-group":
				if err := f.Chown(0, 1); err != nil {
					t.Fatal(err)
				}
			}
			c, err := LoadAuthorityLaunch(f, recoveryDigest(data))
			if !errors.Is(err, ErrAuthorityLaunch) || !reflect.DeepEqual(c, AuthorityLaunch{}) {
				t.Fatal("unsafe anonymous record admitted", err)
			}
		})
	}
}

func authorityLaunchMemfdFixture(t *testing.T, data []byte, seals int, writable bool) *os.File {
	t.Helper()
	flags := unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING | unix.MFD_EXEC
	if seals&unix.F_SEAL_EXEC != 0 {
		flags = unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING | unix.MFD_NOEXEC_SEAL
	}
	fd, err := unix.MemfdCreate("launch-negative-fixture", flags)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "launch-negative-fixture")
	t.Cleanup(func() { _ = f.Close() })
	if n, err := f.Write(data); err != nil || n != len(data) {
		t.Fatal("incomplete fixture", err)
	}
	if err := f.Chmod(0400); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	if writable {
		return f
	}
	readerFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(readerFD), "launch-negative-reader")
	t.Cleanup(func() { _ = reader.Close() })
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return reader
}

func assertSealedAuthorityLaunch(t *testing.T, f *os.File, want []byte) {
	t.Helper()
	fd := int(f.Fd())
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Nlink != 0 || st.Mode != unix.S_IFREG|0400 || st.Uid != 0 || st.Gid != 0 {
		t.Fatal("invalid snapshot metadata")
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("snapshot descriptor writable", err)
	}
	flags, err = unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("snapshot inheritable", err)
	}
	if !validAuthorityLaunchLinks(fd, 0) {
		t.Fatal("snapshot not fully sealed")
	}
	if offset, err := f.Seek(0, io.SeekCurrent); err != nil || offset != 0 {
		t.Fatal("snapshot offset changed", err)
	}
	got := make([]byte, len(want))
	if _, err := f.ReadAt(got, 0); err != nil || !bytes.Equal(got, want) {
		t.Fatal("snapshot bytes changed", err)
	}
	if _, err := LoadAuthorityLaunch(f, recoveryDigest(want)); err != nil {
		t.Fatal("valid snapshot rejected", err)
	}
	if _, err := LoadAuthorityLaunch(f, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong snapshot digest accepted")
	}
	// Exercise seals through a separately writable descriptor, so read-only
	// access mode cannot mask a missing data seal. Root exists only in the fixture.
	writeFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(writeFD) }()
	if _, err := unix.Pwrite(writeFD, []byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatal("snapshot data writable", err)
	}
	for _, size := range []int64{0, int64(len(want) + 1)} {
		if err := unix.Ftruncate(writeFD, size); !errors.Is(err, unix.EPERM) {
			t.Fatal("snapshot resizable", err)
		}
	}
	if _, err := unix.FcntlInt(uintptr(writeFD), unix.F_ADD_SEALS, unix.F_SEAL_FUTURE_WRITE); !errors.Is(err, unix.EPERM) {
		t.Fatal("snapshot seal policy mutable", err)
	}
	if err := unix.Fchmod(writeFD, 0500); !errors.Is(err, unix.EPERM) {
		t.Fatal("snapshot executable-mode change accepted", err)
	}
	mapped, err := unix.Mmap(writeFD, 0, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err == nil {
		_ = unix.Munmap(mapped)
		t.Fatal("shared writable mapping accepted")
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatal("unexpected mapping error", err)
	}
}

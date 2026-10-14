package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuthorityImageStream(t *testing.T) {
	data := bytes.Repeat([]byte("bounded executable bytes"), 6000)
	var output []byte
	read := bytes.NewReader(data).ReadAt
	got, err := streamAuthorityImage(int64(len(data)), read, func(b []byte, offset int64) (int, error) {
		if offset != int64(len(output)) || len(b) > 64<<10 {
			t.Fatal("unbounded or discontinuous copy")
		}
		output = append(output, b...)
		return len(b), nil
	})
	if err != nil || got != recoveryDigest(data) || !bytes.Equal(output, data) {
		t.Fatal("incorrect bounded copy", err)
	}
	for _, size := range []int64{-1, 0, MaxAuthorityExecutableBytes + 1} {
		if got, err := streamAuthorityImage(size, read, nil); got != "" || !errors.Is(err, ErrAuthorityExecutable) {
			t.Fatal("invalid size accepted")
		}
	}
	if got, err := streamAuthorityImage(1, nil, nil); got != "" || err == nil {
		t.Fatal("nil reader accepted")
	}
	for _, kind := range []string{"short-read", "read-error", "short-write", "write-error"} {
		t.Run(kind, func(t *testing.T) {
			r := func(b []byte, o int64) (int, error) {
				if o > 0 && kind == "short-read" {
					return len(b) - 1, nil
				}
				if o > 0 && kind == "read-error" {
					return 0, unix.EIO
				}
				return read(b, o)
			}
			w := func(b []byte, o int64) (int, error) {
				if o > 0 && kind == "short-write" {
					return len(b) - 1, nil
				}
				if o > 0 && kind == "write-error" {
					return 0, unix.EIO
				}
				return len(b), nil
			}
			if got, err := streamAuthorityImage(int64(len(data)), r, w); got != "" || !errors.Is(err, ErrAuthorityExecutable) {
				t.Fatal("partial copy accepted")
			}
		})
	}
}

func TestAuthorityImageCreationPolicy(t *testing.T) {
	for _, first := range []error{nil, unix.EINVAL, unix.EACCES, unix.EPERM, unix.ENOSYS, unix.ENOMEM} {
		calls := 0
		fd, err := newAuthorityImage(func(name string, flags int) (int, error) {
			calls++
			want := unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING
			if calls == 1 {
				want |= unix.MFD_EXEC
			}
			if name != "syswarden-authority-image" || flags != want {
				t.Fatal("incorrect anonymous image creation")
			}
			if calls == 1 && first != nil {
				return -1, first
			}
			return 99, nil
		})
		if first == nil || first == unix.EINVAL {
			if fd != 99 || err != nil {
				t.Fatal("supported creation rejected")
			}
		} else if !errors.Is(err, first) || fd != -1 {
			t.Fatal("policy denial bypassed")
		}
		want := 1
		if first == unix.EINVAL {
			want = 2
		}
		if calls != want {
			t.Fatal("unexpected retry")
		}
	}
	calls := 0
	if _, err := newAuthorityImage(func(string, int) (int, error) { calls++; return -1, unix.EINVAL }); err == nil || calls != 2 {
		t.Fatal("legacy failure retried or ignored")
	}
}

// Part of the mandatory real-executable gate, with root only in its isolated fixture.
func testAuthorityExecutableSnapshot(t *testing.T) {
	data := bytes.Repeat([]byte("synthetic executable bytes"), 3000)
	digest := recoveryDigest(data)
	for _, kind := range []string{"valid-sealed", "source-replaced", "source-modified", "nil", "closed", "writable-fd", "path-fd", "wrong-owner", "wrong-group", "mode", "special-mode", "hardlink", "acl", "file-capability", "directory", "fifo", "empty", "oversized", "wrong-digest", "uppercase-digest", "malformed-digest"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "image")
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			contents := data
			if kind == "empty" {
				contents = nil
			}
			if err := root.WriteFile("image", contents, 0600); err != nil {
				t.Fatal(err)
			}
			if err := root.Chmod("image", 0555); err != nil {
				t.Fatal(err)
			}
			flags := os.O_RDONLY
			name := "image"
			switch kind {
			case "writable-fd":
				flags = os.O_RDWR
			case "path-fd":
				flags = unix.O_PATH
			case "wrong-owner":
				err = os.Chown(path, 1, 0)
			case "wrong-group":
				err = os.Chown(path, 0, 1)
			case "mode":
				err = root.Chmod("image", 0755)
			case "special-mode":
				err = root.Chmod("image", 0555|os.ModeSetuid)
			case "hardlink":
				err = os.Link(path, filepath.Join(dir, "alias"))
			case "acl":
				authorityTestACL(t, path, "system.posix_acl_access")
				err = root.Chmod("image", 0555)
			case "file-capability":
				capability := make([]byte, 20)
				binary.LittleEndian.PutUint32(capability, 0x02000001)
				binary.LittleEndian.PutUint32(capability[4:], 1<<unix.CAP_NET_BIND_SERVICE)
				err = unix.Setxattr(path, "security.capability", capability, 0)
			case "directory":
				name = "."
			case "fifo":
				name = "pipe"
				err = unix.Mkfifo(filepath.Join(dir, name), 0555)
				flags |= unix.O_NONBLOCK
			case "oversized":
				err = os.Truncate(path, MaxAuthorityExecutableBytes+1)
			}
			if err != nil {
				t.Fatal("fixture prerequisite failed", err)
			}
			f, err := root.OpenFile(name, flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			input := f
			if kind == "nil" {
				input = nil
			}
			if kind == "closed" {
				_ = f.Close()
			}
			expected := digest
			if kind == "wrong-digest" {
				expected = strings.Repeat("0", 64)
			}
			if kind == "uppercase-digest" {
				expected = strings.ToUpper(digest)
			}
			if kind == "malformed-digest" {
				expected = strings.Repeat("z", 64)
			}
			var before map[string]adversarialFileState
			if kind != "oversized" {
				before = layoutSnapshot(t, dir)
			}
			if kind == "valid-sealed" || kind == "source-replaced" || kind == "source-modified" {
				if _, err := f.Seek(7, io.SeekStart); err != nil {
					t.Fatal(err)
				}
			}
			image, err := SnapshotAuthorityExecutable(input, expected)
			if kind == "valid-sealed" || kind == "source-replaced" || kind == "source-modified" {
				if err != nil || image == nil {
					t.Fatal("protected executable rejected", err)
				}
				defer func() { _ = image.Close() }()
				if position, err := f.Seek(0, io.SeekCurrent); err != nil || position != 7 {
					t.Fatal("source offset changed", err)
				}
				if !reflect.DeepEqual(before, layoutSnapshot(t, dir)) {
					t.Fatal("snapshot changed source")
				}
				if kind == "source-replaced" {
					if err := root.Rename("image", "old"); err != nil {
						t.Fatal(err)
					}
					if err := root.WriteFile("image", []byte("replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "source-modified" {
					if err := root.WriteFile("image", []byte("modified"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				assertSealedAuthorityImage(t, image, data)
			} else {
				if image != nil {
					_ = image.Close()
					t.Fatal("failed snapshot exposed a handle")
				}
				if !errors.Is(err, ErrAuthorityExecutable) {
					t.Fatal("unsafe executable accepted", err)
				}
				if kind != "oversized" && !reflect.DeepEqual(before, layoutSnapshot(t, dir)) {
					t.Fatal("rejection changed source")
				}
			}
		})
	}
}

func assertSealedAuthorityImage(t *testing.T, f *os.File, want []byte) {
	t.Helper()
	fd := int(f.Fd())
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || seals&authorityImageSeals != authorityImageSeals {
		t.Fatal("missing kernel seals", err)
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("image can leak through exec", err)
	}
	if _, err := unix.Pwrite(fd, []byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatal("sealed image writable", err)
	}
	for _, size := range []int64{0, int64(len(want) + 1)} {
		if err := unix.Ftruncate(fd, size); !errors.Is(err, unix.EPERM) {
			t.Fatal("sealed image resizable", err)
		}
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_FUTURE_WRITE); !errors.Is(err, unix.EPERM) {
		t.Fatal("seal policy mutable", err)
	}
	mapped, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err == nil {
		_ = unix.Munmap(mapped)
		t.Fatal("shared writable mapping admitted")
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatal("unexpected mapping failure", err)
	}
	got, err := io.ReadAll(io.LimitReader(f, MaxAuthorityExecutableBytes+1))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("sealed output differs", err)
	}
}

func TestAuthorityImageStatBounds(t *testing.T) {
	good := unix.Stat_t{Mode: unix.S_IFREG | 0555, Uid: 0, Gid: 0, Nlink: 1, Size: 1}
	if !validAuthorityExecutableStat(good) {
		t.Fatal("valid metadata rejected")
	}
	maximum := good
	maximum.Size = MaxAuthorityExecutableBytes
	if !validAuthorityExecutableStat(maximum) {
		t.Fatal("exact size bound rejected")
	}
	for _, size := range []int64{-1, 0, MaxAuthorityExecutableBytes + 1} {
		bad := good
		bad.Size = size
		if validAuthorityExecutableStat(bad) {
			t.Fatal("size outside bounds accepted")
		}
	}
	for _, mode := range []uint32{unix.S_IFREG | 0755, unix.S_IFREG | 04755, unix.S_IFREG | 0550, unix.S_IFDIR | 0555} {
		bad := good
		bad.Mode = mode
		if validAuthorityExecutableStat(bad) {
			t.Fatal("unsafe mode accepted")
		}
	}
	for _, which := range []string{"uid", "gid", "unlinked", "hardlink"} {
		bad := good
		switch which {
		case "uid":
			bad.Uid = 1
		case "gid":
			bad.Gid = 1
		case "unlinked":
			bad.Nlink = 0
		case "hardlink":
			bad.Nlink = 2
		}
		if validAuthorityExecutableStat(bad) {
			t.Fatal("unsafe identity or link count accepted")
		}
	}
}

func TestAuthorityImageMountPolicy(t *testing.T) {
	for _, kind := range []string{"executable", "noexec", "inspection-error"} {
		calls := 0
		allowed := authorityImageMountAllowsExec(17, func(fd int, st *unix.Statfs_t) error {
			calls++
			if fd != 17 {
				t.Fatal("wrong source mount inspected")
			}
			st.Flags = unix.MS_RDONLY | unix.MS_NOSUID
			if kind == "noexec" {
				st.Flags |= unix.MS_NOEXEC
			}
			if kind == "inspection-error" {
				return unix.EIO
			}
			return nil
		})
		if calls != 1 || allowed != (kind == "executable") {
			t.Fatal("source mount policy ignored", kind)
		}
	}
}

package journal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuthorityInputResolution(t *testing.T) {
	for _, approved := range []string{"launch.json", "syswarden-authority", authorityLauncherInputName} {
		for _, denial := range []error{nil, unix.ENOSYS, unix.EINVAL, unix.EPERM, unix.EXDEV, unix.ELOOP, unix.EAGAIN} {
			calls := 0
			fd, err := openAuthorityInputFD(42, approved, func(dir int, name string, how *unix.OpenHow) (int, error) {
				calls++
				if dir != 42 || name != approved || how.Mode != 0 ||
					how.Flags != unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY ||
					how.Resolve != unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_XDEV {
					t.Fatal("weakened input resolution")
				}
				if denial != nil {
					return -1, denial
				}
				return 43, nil
			})
			if calls != 1 || !errors.Is(err, denial) || (denial == nil && fd != 43) || (denial != nil && fd != -1) {
				t.Fatal("unexpected retry or fallback", fd, err)
			}
		}
	}
	for _, name := range []string{"", ".", "..", "../launch.json", "/launch.json", "sub/launch.json", "other", "../syswarden-authority-launch", "/syswarden-authority-launch", "syswarden-authority-launch.old"} {
		if _, err := openAuthorityInputFD(42, name, func(int, string, *unix.OpenHow) (int, error) {
			t.Fatal("unapproved name opened")
			return -1, nil
		}); err == nil {
			t.Fatal("unapproved name accepted")
		}
	}
	if _, err := openAuthorityInputFD(42, "launch.json", nil); err == nil {
		t.Fatal("nil opener accepted")
	}
	if a, b, err := OpenAuthorityLaunchInputs(nil, strings.Repeat("0", 64), strings.Repeat("0", 64)); a != nil || b != nil || err == nil {
		t.Fatal("nil directory accepted")
	}
}

func testAuthorityLaunchInputs(t *testing.T, launchBytes []byte) {
	data := testAuthorityELF(runtime.GOARCH, false)
	for _, kind := range []string{"valid-held", "nil", "closed", "path-fd", "parent-file", "parent-mode", "parent-owner", "parent-group", "parent-acl", "parent-default-acl", "launch-symlink", "image-symlink", "launch-hardlink", "image-hardlink", "launch-fifo", "image-fifo", "launch-missing", "image-missing", "launch-malformed", "launch-mode", "image-mode", "image-invalid-elf", "wrong-launch-digest", "wrong-image-digest", "malformed-digest", "entry-replacement"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			launchPath, imagePath := filepath.Join(dir, "launch.json"), filepath.Join(dir, "syswarden-authority")
			if err := chmodFixture(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(launchPath, launchBytes, 0400); err != nil {
				t.Fatal(err)
			}
			contents := data
			if kind == "image-invalid-elf" {
				contents = []byte("#!/bin/sh\nexit 0\n")
			}
			if err := os.WriteFile(imagePath, contents, 0600); err != nil {
				t.Fatal(err)
			}
			if err := chmodFixture(imagePath, 0555); err != nil {
				t.Fatal(err)
			}
			ld, id := recoveryDigest(launchBytes), recoveryDigest(contents)
			var err error
			switch kind {
			case "parent-mode":
				err = chmodFixture(dir, 0755)
			case "parent-owner":
				err = os.Chown(dir, 1, 0)
			case "parent-group":
				err = os.Chown(dir, 0, 1)
			case "parent-acl":
				authorityTestACL(t, dir, "system.posix_acl_access")
				err = chmodFixture(dir, 0700)
			case "parent-default-acl":
				authorityTestACL(t, dir, "system.posix_acl_default")
			case "launch-symlink", "image-symlink":
				path := launchPath
				if kind == "image-symlink" {
					path = imagePath
				}
				if err = os.Rename(path, path+".original"); err == nil {
					err = os.Symlink(filepath.Base(path)+".original", path)
				}
			case "launch-hardlink":
				err = os.Link(launchPath, filepath.Join(dir, "alias"))
			case "image-hardlink":
				err = os.Link(imagePath, filepath.Join(dir, "alias"))
			case "launch-fifo", "image-fifo":
				path := launchPath
				if kind == "image-fifo" {
					path = imagePath
				}
				if err = os.Remove(path); err == nil {
					err = unix.Mkfifo(path, 0400)
				}
			case "launch-missing":
				err = os.Remove(launchPath)
			case "image-missing":
				err = os.Remove(imagePath)
			case "launch-malformed":
				err = os.WriteFile(launchPath, []byte("{}"), 0400)
				ld = recoveryDigest([]byte("{}"))
			case "launch-mode":
				err = chmodFixture(launchPath, 0600)
			case "image-mode":
				err = chmodFixture(imagePath, 0755)
			case "wrong-launch-digest":
				ld = strings.Repeat("0", 64)
			case "wrong-image-digest":
				id = strings.Repeat("0", 64)
			case "malformed-digest":
				ld = "bad"
			}
			if err != nil {
				t.Fatal("fixture prerequisite", err)
			}
			flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
			path := dir
			if kind == "path-fd" {
				flags |= unix.O_PATH
			}
			if kind == "parent-file" {
				path = launchPath
				flags = unix.O_RDONLY | unix.O_CLOEXEC
			}
			fd, err := unix.Open(path, flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			directory := os.NewFile(uintptr(fd), "test-input-directory")
			defer func() { _ = directory.Close() }()
			input := directory
			if kind == "closed" {
				_ = directory.Close()
			}
			if kind == "nil" {
				input = nil
			}
			launch, image, err := OpenAuthorityLaunchInputs(input, ld, id)
			if kind != "valid-held" && kind != "entry-replacement" {
				if launch != nil || image != nil || !errors.Is(err, ErrAuthorityLaunchInputs) {
					if launch != nil {
						_ = launch.Close()
					}
					if image != nil {
						_ = image.Close()
					}
					t.Fatal("unsafe inputs admitted", err)
				}
				requireNoAuthorityInputHandles(t, dir, directory.Fd())
				return
			}
			if err != nil || launch == nil || image == nil {
				t.Fatal("valid inputs refused", err)
			}
			defer func() { _ = launch.Close(); _ = image.Close() }()
			for _, f := range []*os.File{launch, image} {
				flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
				if err != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("inheritable input", err)
				}
				off, err := f.Seek(0, io.SeekCurrent)
				if err != nil || off != 0 {
					t.Fatal("changed offset", err)
				}
			}
			// Keep an independent disk handle to test the entry binding itself.
			source, _, err := openAuthorityInput(int(directory.Fd()), "launch.json", false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = source.Close() }()
			assertSealedAuthorityLaunch(t, launch, launchBytes)
			var stamp unix.Stat_t
			if err := unix.Fstat(int(source.Fd()), &stamp); err != nil {
				t.Fatal(err)
			}
			if !authorityInputStillBound(int(directory.Fd()), "launch.json", source, stamp) {
				t.Fatal("fresh input unbound")
			}
			// Replace both names and unlink the original launch inode.
			if err := os.Rename(launchPath, launchPath+".retired"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(launchPath, []byte("replacement"), 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(imagePath, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if authorityInputStillBound(int(directory.Fd()), "launch.json", source, stamp) {
				t.Fatal("replaced entry accepted")
			}
			if err := os.Remove(launchPath + ".retired"); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAuthorityLaunch(launch, ld); err != nil {
				t.Fatal("held launch changed", err)
			}
			if _, err := InspectAuthorityExecutableImage(image, id); err != nil {
				t.Fatal("sealed image changed", err)
			}
			if _, _, err := OpenAuthorityLaunchInputs(directory, ld, id); err == nil {
				t.Fatal("replaced source accepted")
			}
		})
	}
}

func requireNoAuthorityInputHandles(t *testing.T, dir string, callerFD uintptr) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == strconv.FormatUint(uint64(callerFD), 10) {
			continue
		}
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(target, dir+"/") {
			t.Fatal("failed acquisition leaked a source descriptor")
		}
	}
}

func prepareActualAuthorityInputs(t, owner *testing.T, binary *executableImages, c processFixtureConfig) {
	t.Helper()
	directory := owner.TempDir()
	if err := chmodFixture(directory, 0700); err != nil {
		t.Fatal(err)
	}
	launchBytes := readFile(t, c.LaunchPath)
	if err := os.WriteFile(filepath.Join(directory, "launch.json"), launchBytes, 0400); err != nil {
		t.Fatal(err)
	}
	st, err := binary.authority.Stat()
	if err != nil || st.Size() <= 0 || st.Size() > MaxAuthorityExecutableBytes {
		t.Fatal("invalid verified image size", err)
	}
	data := make([]byte, int(st.Size()))
	if _, err := binary.authority.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("syswarden-authority", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod("syswarden-authority", 0555); err != nil {
		t.Fatal(err)
	}
	dir, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	launch, image, err := OpenAuthorityLaunchInputs(dir, c.LaunchDigest, binary.digest)
	if err != nil {
		t.Fatal(err)
	}
	owner.Cleanup(func() { _ = launch.Close(); _ = image.Close() })
	binary.launch, binary.authority = launch, image
	// The real launcher must use the returned descriptors, never reopen names.
	if err := os.Rename(filepath.Join(directory, "launch.json"), filepath.Join(directory, "retired-launch")); err != nil {
		t.Fatal(err)
	}
	if err := root.Remove("retired-launch"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"launch.json", "syswarden-authority"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("not approved"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := readFile(t, c.LaunchPath); !bytes.Equal(got, launchBytes) {
		t.Fatal("original launch modified")
	}
}

package journal

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func endpointFixture(t *testing.T) (*os.File, string, uint32) {
	t.Helper()
	dir, path := testDirectory(t)
	if err := dir.Chmod(0750); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	return dir, path, st.Gid
}
func testEndpoint(t *testing.T, dir *os.File, group uint32) *authoritySocket {
	t.Helper()
	s, err := openAuthoritySocket(dir, group, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func TestAuthorityEndpointDescriptorOwnership(t *testing.T) {
	dir, path, gid := endpointFixture(t)
	before := countTransportFileReferences(t, dir)
	s := testEndpoint(t, dir, gid)
	if countTransportFileReferences(t, dir) != before+1 {
		t.Fatal("directory descriptor ownership not independent")
	}
	if err := s.Attest(); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(path, AuthoritySocketName), &st); err != nil || st.Mode != unix.S_IFSOCK|0660 || st.Gid != gid {
		t.Fatal("wrong endpoint permissions", err)
	}
	if other, err := openAuthoritySocket(dir, gid, 1); other != nil || !errors.Is(err, ErrLocked) {
		t.Fatal("duplicate owner admitted", err)
	}
	// The directory descriptor, not its original pathname or borrowed lifetime,
	// anchors subsequent checks and exact cleanup.
	renamed := path + "-renamed"
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(renamed) })
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(path, AuthoritySocketName)
	if err := os.WriteFile(replacement, []byte("administrator"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Attest(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Attest(), ErrClosed) {
		t.Fatal("closed endpoint attested")
	}
	if _, err := os.Lstat(filepath.Join(renamed, AuthoritySocketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket retained", err)
	}
	if string(readFile(t, replacement)) != "administrator" {
		t.Fatal("replacement directory touched")
	}
}
func TestAuthorityEndpointStartupRefusals(t *testing.T) {
	for _, kind := range []string{"nil", "closed", "file", "private", "writable", "others", "setgid", "group", "excess-group", "zero-backlog", "excess-backlog"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			backlog := 2
			switch kind {
			case "nil":
				dir = nil
			case "closed":
				_ = dir.Close()
			case "file":
				root, err := os.OpenRoot(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = root.Close() }()
				file, err := root.Create("ordinary")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = file.Close() }()
				dir = file
			case "private":
				if err := dir.Chmod(0700); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := dir.Chmod(0770); err != nil {
					t.Fatal(err)
				}
			case "others":
				if err := dir.Chmod(0755); err != nil {
					t.Fatal(err)
				}
			case "setgid":
				if err := dir.Chmod(0750 | os.ModeSetgid); err != nil {
					t.Fatal(err)
				}
			case "group":
				gid ^= 1
			case "excess-group":
				gid = math.MaxUint32
			case "zero-backlog":
				backlog = 0
			case "excess-backlog":
				backlog = MaxAuthorityPeers + 1
			}
			s, err := openAuthoritySocket(dir, gid, backlog)
			if err == nil || s != nil {
				t.Fatal("unsafe endpoint accepted", err)
			}
			if _, err := os.Lstat(filepath.Join(path, AuthoritySocketName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created endpoint", err)
			}
		})
	}
}
func TestAuthorityEndpointPreservesExistingEntries(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "directory", "socket"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			name := filepath.Join(path, AuthoritySocketName)
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(name, []byte("retained"), 0600)
			case "symlink":
				err = os.Symlink("absent", name)
			case "directory":
				err = os.Mkdir(name, 0700)
			case "socket":
				var l *net.UnixListener
				l, err = net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: name})
				if err == nil {
					l.SetUnlinkOnClose(false)
					err = l.Close()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var before, after unix.Stat_t
			if err = unix.Lstat(name, &before); err != nil {
				t.Fatal(err)
			}
			refs := countTransportFileReferences(t, dir)
			s, err := openAuthoritySocket(dir, gid, 1)
			if err == nil || s != nil {
				t.Fatal("existing entry replaced")
			}
			if err = unix.Lstat(name, &after); err != nil || before != after {
				t.Fatal("existing entry changed", err)
			}
			if countTransportFileReferences(t, dir) != refs {
				t.Fatal("failed startup leaked directory lock")
			}
		})
	}
}
func TestAuthorityEndpointRetainsChangedArtifacts(t *testing.T) {
	for _, kind := range []string{"mode", "directory-mode", "replacement", "symlink", "missing", "extra-link"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			s := testEndpoint(t, dir, gid)
			name := filepath.Join(path, AuthoritySocketName)
			var err error
			switch kind {
			case "mode":
				err = chmodFixture(name, 0600)
			case "directory-mode":
				err = dir.Chmod(0770)
			case "replacement", "symlink":
				err = os.Rename(name, name+".saved")
				if err == nil {
					if kind == "replacement" {
						err = os.WriteFile(name, []byte("retained"), 0600)
					} else {
						err = os.Symlink("absent", name)
					}
				}
			case "missing":
				err = os.Remove(name)
			case "extra-link":
				err = os.Link(name, name+".alias")
			}
			if err != nil {
				t.Fatal(err)
			}
			var before, after unix.Stat_t
			previousErr := unix.Lstat(name, &before)
			if !errors.Is(s.Attest(), ErrAuthorityEndpoint) {
				t.Fatal("changed artifact attested")
			}
			if !errors.Is(s.Close(), ErrAuthorityEndpoint) {
				t.Fatal("changed artifact not reported")
			}
			if !errors.Is(s.Close(), ErrAuthorityEndpoint) {
				t.Fatal("cleanup failure lost")
			}
			err = unix.Lstat(name, &after)
			if (previousErr == nil) != (err == nil) || before != after {
				t.Fatal("changed entry removed or altered", err)
			}
		})
	}
}

// Use real POSIX ACL bytes to exercise hidden named access and inherited ACLs.
// The containing disposable directory remains under the test's private root.
func authorityTestACL(t *testing.T, path, name string) {
	t.Helper()
	raw := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(raw, 2)
	entries := []struct {
		tag, permission uint16
		id              uint32
	}{{1, 7, math.MaxUint32}, {2, 4, 65534}, {4, 5, math.MaxUint32}, {16, 5, math.MaxUint32}, {32, 0, math.MaxUint32}}
	for i, e := range entries {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(raw[off:], e.tag)
		binary.LittleEndian.PutUint16(raw[off+2:], e.permission)
		binary.LittleEndian.PutUint32(raw[off+4:], e.id)
	}
	if err := unix.Setxattr(path, name, raw, 0); err != nil {
		t.Fatal("test filesystem must support POSIX ACL verification", err)
	}
}
func TestAuthorityEndpointRejectsACLs(t *testing.T) {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		t.Run(name, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			authorityTestACL(t, path, name)
			s, err := openAuthoritySocket(dir, gid, 1)
			if err == nil || s != nil {
				t.Fatal("ACL admitted")
			}
		})
	}
	t.Run("changed-socket", func(t *testing.T) {
		dir, path, gid := endpointFixture(t)
		s := testEndpoint(t, dir, gid)
		name := filepath.Join(path, AuthoritySocketName)
		authorityTestACL(t, name, "system.posix_acl_access")
		if !errors.Is(s.Attest(), ErrAuthorityEndpoint) || !errors.Is(s.Close(), ErrAuthorityEndpoint) {
			t.Fatal("modified socket ACL accepted")
		}
		if _, err := os.Lstat(name); err != nil {
			t.Fatal("modified socket removed", err)
		}
	})
}

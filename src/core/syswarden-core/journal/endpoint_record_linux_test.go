package journal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAuthorityEndpointRecordBindingAndCleanLifecycle(t *testing.T) {
	dir, path, gid := endpointFixture(t)
	var previous string
	for range 2 {
		s := testEndpoint(t, dir, gid)
		name := filepath.Join(path, AuthorityEndpointRecordName)
		data := readFile(t, name)
		var r endpointOwnershipRecord
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		nonce, err := hex.DecodeString(r.Nonce)
		if err != nil || len(nonce) != 32 || r.Nonce == previous || bytes.Equal(nonce, make([]byte, 32)) {
			t.Fatal("missing per-creation entropy", err)
		}
		previous = r.Nonce
		canonical, err := json.Marshal(r)
		if err != nil || !bytes.Equal(data, canonical) || len(data) > maxEndpointRecordBytes {
			t.Fatal("noncanonical or oversized ownership record", err)
		}
		if r.Schema != "syswarden.authority-endpoint-owner.v1" || r.DirectoryIno != strconv.FormatUint(s.dirStamp.Ino, 10) || r.SocketIno != strconv.FormatUint(s.entry.Ino, 10) || r.SocketUID != strconv.FormatUint(uint64(s.entry.Uid), 10) || r.ChangedSec != strconv.FormatInt(int64(s.entry.Ctim.Sec), 10) || r.ChangedNSec != strconv.FormatInt(int64(s.entry.Ctim.Nsec), 10) {
			t.Fatal("record is not bound to the created endpoint")
		}
		var st unix.Stat_t
		if err := unix.Lstat(name, &st); err != nil || !privateFile(st) {
			t.Fatal("record is not private", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		for _, entry := range []string{AuthoritySocketName, AuthorityEndpointRecordName} {
			if _, err := os.Lstat(filepath.Join(path, entry)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("clean shutdown retained owned entry", entry, err)
			}
		}
	}
}

func TestAuthorityEndpointRecordCollisionsNeverAdopted(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			name := filepath.Join(path, AuthorityEndpointRecordName)
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(name, []byte("retained administrator data"), 0600)
			case "symlink":
				err = os.Symlink("absent", name)
			case "directory":
				err = os.Mkdir(name, 0700)
			case "fifo":
				err = unix.Mkfifo(name, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var before, after unix.Stat_t
			if err := unix.Lstat(name, &before); err != nil {
				t.Fatal(err)
			}
			if s, err := openAuthoritySocket(dir, gid, 1); s != nil || !errors.Is(err, ErrAuthorityEndpoint) {
				t.Fatal("existing ownership entry adopted", err)
			}
			if err := unix.Lstat(name, &after); err != nil || before != after {
				t.Fatal("existing ownership entry modified", err)
			}
			if _, err := os.Lstat(filepath.Join(path, AuthoritySocketName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("socket created beside stale ownership evidence", err)
			}
		})
	}
}

func TestAuthorityEndpointRecordChangesPreserveBothEntries(t *testing.T) {
	for _, kind := range []string{"bytes", "truncate", "append", "mode", "hardlink", "replace", "symlink", "missing", "acl"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			s := testEndpoint(t, dir, gid)
			name := filepath.Join(path, AuthorityEndpointRecordName)
			var err error
			switch kind {
			case "bytes":
				data := readFile(t, name)
				data[len(data)-1] ^= 1
				err = os.WriteFile(name, data, 0600)
			case "truncate":
				err = os.Truncate(name, 1)
			case "append":
				data := append(readFile(t, name), 'x')
				err = os.WriteFile(name, data, 0600)
			case "mode":
				err = chmodFixture(name, 0640)
			case "hardlink":
				err = os.Link(name, name+".alias")
			case "replace", "symlink":
				err = os.Rename(name, name+".saved")
				if err == nil && kind == "replace" {
					err = os.WriteFile(name, s.record, 0600)
				} else if err == nil {
					err = os.Symlink(name+".saved", name)
				}
			case "missing":
				err = os.Remove(name)
			case "acl":
				authorityTestACL(t, name, "system.posix_acl_access")
			}
			if err != nil {
				t.Fatal(err)
			}
			var before, after unix.Stat_t
			previous := unix.Lstat(name, &before)
			if !errors.Is(s.Attest(), ErrAuthorityEndpoint) || !errors.Is(s.Close(), ErrAuthorityEndpoint) || !errors.Is(s.Close(), ErrAuthorityEndpoint) {
				t.Fatal("changed evidence accepted or cleanup failure lost")
			}
			if err := unix.Lstat(name, &after); (err == nil) != (previous == nil) || before != after {
				t.Fatal("changed receipt removed or modified", err)
			}
			if _, err := os.Lstat(filepath.Join(path, AuthoritySocketName)); err != nil {
				t.Fatal("socket removed despite changed receipt", err)
			}
		})
	}
}

func TestAuthorityEndpointRecordUncertainStorageNeverListens(t *testing.T) {
	for _, kind := range []string{"zero", "short", "full-error", "file-sync", "directory-sync", "readback", "changed-after-sync"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			var expected []byte
			writer := func(s *authoritySocket) error {
				if err := s.openEndpointRecord(); err != nil {
					return err
				}
				file := s.recordFile
				fault := &faultFile{segmentFile: file}
				s.recordFile = fault
				expected = bytes.Clone(s.record)
				syncDir := s.directory.Sync
				switch kind {
				case "zero":
					fault.write = func([]byte) (int, error) { return 0, unix.ENOSPC }
					expected = nil
				case "short":
					fault.write = func(b []byte) (int, error) { return file.Write(b[:7]) }
					expected = expected[:7]
				case "full-error":
					fault.write = func(b []byte) (int, error) { n, err := file.Write(b); return n, errors.Join(err, unix.EIO) }
				case "file-sync":
					fault.sync = func() error { return unix.EIO }
				case "directory-sync":
					syncDir = func() error { return unix.EIO }
				case "readback":
					fault.read = func([]byte, int64) (int, error) { return 0, unix.EIO }
				case "changed-after-sync":
					syncDir = func() error { return chmodFixture(filepath.Join(path, AuthorityEndpointRecordName), 0640) }
				}
				return s.syncEndpointRecord(syncDir)
			}
			refs := countTransportFileReferences(t, dir)
			if s, err := openAuthoritySocketWithRecord(dir, gid, 1, writer); s != nil || !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("uncertain record yielded a listener", err)
			}
			if countTransportFileReferences(t, dir) != refs {
				t.Fatal("uncertain startup leaked directory lock")
			}
			if got := readFile(t, filepath.Join(path, AuthorityEndpointRecordName)); !bytes.Equal(got, expected) {
				t.Fatal("uncertain record bytes removed or rewritten")
			}
			peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: filepath.Join(path, AuthoritySocketName)})
			if peer != nil {
				_ = peer.Close()
			}
			if !errors.Is(err, unix.ECONNREFUSED) {
				t.Fatal("uncertain startup listened or removed the socket", err)
			}
			if next, err := openAuthoritySocket(dir, gid, 1); next != nil || !errors.Is(err, ErrAuthorityEndpoint) {
				t.Fatal("retry adopted uncertain ownership", err)
			}
		})
	}
}

func TestAuthorityEndpointRecordRetainedAfterSocketRemoval(t *testing.T) {
	dir, path, gid := endpointFixture(t)
	s := testEndpoint(t, dir, gid)
	file := s.recordFile
	reads := 0
	s.recordFile = &faultFile{segmentFile: file, read: func(b []byte, off int64) (int, error) {
		reads++
		if reads == 2 {
			return 0, unix.EIO
		}
		return file.ReadAt(b, off)
	}}
	for range 2 {
		if !errors.Is(s.Close(), ErrAuthorityEndpoint) {
			t.Fatal("partial cleanup was reported as complete")
		}
	}
	if _, err := os.Lstat(filepath.Join(path, AuthoritySocketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected socket removal before receipt readback failure", err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(path, AuthorityEndpointRecordName)), s.record) {
		t.Fatal("cleanup removed uncertain remaining evidence")
	}
	if next, err := openAuthoritySocket(dir, gid, 1); next != nil || !errors.Is(err, ErrAuthorityEndpoint) {
		t.Fatal("receipt without socket was silently adopted", err)
	}
}

func testEndpointProcessCrash(t *testing.T, c processFixtureConfig) {
	t.Helper()
	p := startProcessService(t, t, c)
	name := filepath.Join(c.Endpoint, AuthorityEndpointRecordName)
	before := adversarialSnapshot(t, []string{name})
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		p.finished = true
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("expected killed test child", err)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("test service did not exit through deliberate SIGKILL")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test service did not exit")
	}
	requireAdversarialSnapshot(t, before, []string{name})
	c.ExpectStaleEndpoint = true
	refused := processCommand(t, t, "service", c, processServiceID, processServiceID, []uint32{processClientID})
	refused.start(t)
	refused.wait(t)
	requireAdversarialSnapshot(t, before, []string{name})
	if _, err := os.Lstat(filepath.Join(c.Endpoint, AuthoritySocketName)); err != nil {
		t.Fatal("fresh process deleted interrupted endpoint", err)
	}
}

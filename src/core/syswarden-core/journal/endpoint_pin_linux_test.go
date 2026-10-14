package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func pinnedRecoveryFixture(t *testing.T) (EndpointRecoveryConfig, AuthorityServerConfig, string, *LocalAuthorityServer) {
	t.Helper()
	_, c, path := serverFixture(t)
	s := testServer(t, c)
	peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
	return EndpointRecoveryConfig{Directory: c.Directory, PinDirectory: c.PinDirectory, GroupID: c.GroupID, Peer: peer,
		Now:        func() time.Time { return policyNow(testCustodyPolicy()) },
		Authorizer: endpointTestAuthorizer(func(r EndpointRecoveryRequest) (EndpointRecoveryDecision, error) { return endpointTestDecision(r), nil }),
	}, c, filepath.Dir(path), s
}

func abandonPinnedServer(t *testing.T, s *LocalAuthorityServer) {
	t.Helper()
	s.socket.preserve = true
	if err := s.Close(); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("fixture did not preserve complete endpoint", err)
	}
}

func TestEndpointPinCreatorRecoveryAndRotation(t *testing.T) {
	r, c, endpoint, s := pinnedRecoveryFixture(t)
	pinName := filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName)
	first := readFile(t, pinName)
	var doc endpointPinDocument
	if err := json.Unmarshal(first, &doc); err != nil || !bytes.Equal(doc.Record, s.socket.record) || doc.RecordSHA256 != recoveryDigest(s.socket.record) {
		t.Fatal("pin does not bind creator's receipt", err)
	}
	if _, err := readEndpointPin(c.PinDirectory); !errors.Is(err, ErrLocked) {
		t.Fatal("live pin lease not exclusive", err)
	}
	abandonPinnedServer(t, s)
	plan := endpointPlan(t, r)
	var review endpointRecoveryDocument
	if err := json.Unmarshal(plan.Document, &review); err != nil || review.Pin == nil || review.Pin.SHA256 != recoveryDigest(first) {
		t.Fatal("review omitted pin custody", err)
	}
	if result, err := ApplyEndpointRecovery(r, plan.SHA256); err != nil || result.PlanSHA256 != plan.SHA256 {
		t.Fatal("durable pin recovery failed", err)
	}
	for _, path := range []string{pinName, filepath.Join(endpoint, AuthoritySocketName), filepath.Join(endpoint, AuthorityEndpointRecordName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("retired artifact remains", err)
		}
	}
	next := testServer(t, c)
	if bytes.Equal(first, readFile(t, pinName)) {
		t.Fatal("restart reused old pin")
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(pinName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("clean shutdown retained pin", err)
	}
}

func TestEndpointPinInvalidStartup(t *testing.T) {
	for _, kind := range []string{"missing-directory", "endpoint-alias", "policy-alias", "custody-alias", "anchor-alias", "journal-alias", "directory-mode", "directory-acl", "file", "directory", "fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			_, c, path := serverFixture(t)
			name := filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName)
			var err error
			switch kind {
			case "missing-directory":
				c.PinDirectory = nil
			case "endpoint-alias":
				c.PinDirectory = c.Directory
			case "policy-alias":
				c.PinDirectory = c.Authority.PolicyDirectory
			case "custody-alias":
				c.PinDirectory = c.Authority.CustodyDirectory
			case "anchor-alias":
				c.PinDirectory = c.Authority.AnchorDirectory
			case "journal-alias":
				c.PinDirectory = c.Authority.JournalDirectory
			case "directory-mode":
				err = chmodFixture(c.PinDirectory.Name(), 0750)
			case "directory-acl":
				authorityTestACL(t, c.PinDirectory.Name(), "system.posix_acl_access")
			case "file":
				err = os.WriteFile(name, []byte("preserve unrelated data"), 0600)
			case "directory":
				err = os.Mkdir(name, 0700)
			case "fifo":
				err = unix.Mkfifo(name, 0600)
			case "symlink":
				err = os.Symlink("absent", name)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := endpointRecoverySnapshot(t, []string{name})
			if s, err := OpenLocalAuthorityServer(c); s != nil || err == nil {
				t.Fatal("unsafe pin provisioning accepted")
			}
			requireEndpointRecoverySnapshot(t, before, []string{name})
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("socket created with unsafe pin provisioning", err)
			}
		})
	}
}

func TestEndpointPinChangedEvidencePreserved(t *testing.T) {
	for _, kind := range []string{"bytes", "empty", "oversized", "whitespace", "unknown", "duplicate", "directory-binding", "mode", "acl", "hardlink", "symlink", "replacement", "missing", "directory-mode", "directory-acl"} {
		t.Run(kind, func(t *testing.T) {
			r, c, endpoint, s := pinnedRecoveryFixture(t)
			name := filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName)
			var err error
			data := readFile(t, name)
			switch kind {
			case "bytes":
				data[len(data)-2] ^= 1
				err = os.WriteFile(name, data, 0600)
			case "empty":
				err = os.Truncate(name, 0)
			case "oversized":
				err = os.WriteFile(name, bytes.Repeat([]byte{'x'}, maxEndpointPinBytes+1), 0600)
			case "whitespace":
				err = os.WriteFile(name, append(data, ' '), 0600)
			case "unknown":
				err = os.WriteFile(name, append([]byte(`{"extra":1,`), data[1:]...), 0600)
			case "duplicate":
				err = os.WriteFile(name, append([]byte(`{"schema":"syswarden.authority-endpoint-pin.v1",`), data[1:]...), 0600)
			case "directory-binding":
				var doc endpointPinDocument
				if err = json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				doc.DirectoryIno = "0"
				data, err = json.Marshal(doc)
				if err == nil {
					err = os.WriteFile(name, data, 0600)
				}
			case "mode":
				err = chmodFixture(name, 0640)
			case "acl":
				authorityTestACL(t, name, "system.posix_acl_access")
			case "hardlink":
				err = os.Link(name, name+".alias")
			case "symlink", "replacement":
				err = os.Rename(name, name+".saved")
				if err == nil && kind == "symlink" {
					err = os.Symlink(name+".saved", name)
				} else if err == nil {
					err = os.WriteFile(name, data, 0600)
				}
			case "missing":
				err = os.Remove(name)
			case "directory-mode":
				err = chmodFixture(c.PinDirectory.Name(), 0750)
			case "directory-acl":
				authorityTestACL(t, c.PinDirectory.Name(), "system.posix_acl_access")
			}
			if err != nil {
				t.Fatal(err)
			}
			paths := []string{name, filepath.Join(endpoint, AuthoritySocketName), filepath.Join(endpoint, AuthorityEndpointRecordName)}
			before := endpointRecoverySnapshot(t, paths)
			if !errors.Is(s.socket.Attest(), ErrAuthorityEndpoint) || !errors.Is(s.Close(), ErrAuthorityEndpoint) {
				t.Fatal("changed pin did not stop creator cleanup")
			}
			requireEndpointRecoverySnapshot(t, before, paths)
			// An identical replacement is only distinguishable by an already
			// retained review/live inode. Offline trusted storage is the boundary.
			if kind != "replacement" {
				if _, err := PlanEndpointRecovery(r); err == nil {
					t.Fatal("invalid persisted pin accepted")
				}
				requireEndpointRecoverySnapshot(t, before, paths)
			}
		})
	}
}

func TestEndpointPinRecoveryReviewAndTrustSources(t *testing.T) {
	r, c, endpoint, s := pinnedRecoveryFixture(t)
	abandonPinnedServer(t, s)
	plan := endpointPlan(t, r)
	both := r
	both.ExpectedRecordSHA256 = recoveryDigest(s.socket.record)
	if _, err := PlanEndpointRecovery(both); !errors.Is(err, ErrEndpointRecoveryApproval) {
		t.Fatal("ambiguous trust sources accepted", err)
	}
	name := filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName)
	data := readFile(t, name)
	if err := os.Rename(name, name+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	paths := []string{name, filepath.Join(endpoint, AuthoritySocketName), filepath.Join(endpoint, AuthorityEndpointRecordName)}
	before := endpointRecoverySnapshot(t, paths)
	if result, err := ApplyEndpointRecovery(r, plan.SHA256); err == nil || result != (EndpointRecoveryResult{}) {
		t.Fatal("review survived replacement pin inode")
	}
	requireEndpointRecoverySnapshot(t, before, paths)
	fresh := endpointPlan(t, r)
	if fresh.SHA256 == plan.SHA256 {
		t.Fatal("pin metadata not bound to review")
	}
	r.Authorizer = endpointTestAuthorizer(func(request EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
		if err := os.WriteFile(name, append(data, ' '), 0600); err != nil {
			t.Fatal(err)
		}
		return endpointTestDecision(request), nil
	})
	if _, err := ApplyEndpointRecovery(r, fresh.SHA256); !errors.Is(err, ErrAuthorityEndpoint) {
		t.Fatal("provider pin mutation accepted", err)
	}
	if _, err := os.Lstat(filepath.Join(endpoint, AuthoritySocketName)); err != nil {
		t.Fatal("socket lost before pin recheck", err)
	}
}

func TestEndpointPinUncertainCreationNeverListens(t *testing.T) {
	for _, kind := range []string{"zero", "short", "full-error", "file-sync", "directory-sync", "readback"} {
		t.Run(kind, func(t *testing.T) {
			dir, endpoint, gid := endpointFixture(t)
			pinDir, pinPath := testDirectory(t)
			p, err := openEndpointPinDirectory(pinDir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = p.close() }()
			var expected []byte
			writer := func(s *authoritySocket) error {
				if err := s.createEndpointRecord(); err != nil {
					return err
				}
				s.preserve = true
				if err := p.open(s.record); err != nil {
					return err
				}
				file := p.file
				fault := &faultFile{segmentFile: file}
				p.file = fault
				syncDir := p.directory.Sync
				expected = bytes.Clone(p.data)
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
				}
				return p.write(syncDir)
			}
			if s, err := openAuthoritySocketWithRecord(dir, gid, 1, writer); s != nil || !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("uncertain pin creation succeeded", err)
			}
			if !bytes.Equal(expected, readFile(t, filepath.Join(pinPath, AuthorityEndpointPinName))) {
				t.Fatal("uncertain pin bytes changed")
			}
			for _, name := range []string{AuthoritySocketName, AuthorityEndpointRecordName} {
				if _, err := os.Lstat(filepath.Join(endpoint, name)); err != nil {
					t.Fatal("endpoint evidence lost", err)
				}
			}
			if peer, err := net.DialTimeout("unix", filepath.Join(endpoint, AuthoritySocketName), time.Second); err == nil {
				_ = peer.Close()
				t.Fatal("uncertain pin began listening")
			}
		})
	}
}

func TestEndpointPinUncertainRetirement(t *testing.T) {
	for _, kind := range []string{"endpoint-sync", "pin-unlink", "pin-sync", "changed-after-endpoint-sync", "expired-after-endpoint-sync"} {
		t.Run(kind, func(t *testing.T) {
			r, c, endpoint, s := pinnedRecoveryFixture(t)
			abandonPinnedServer(t, s)
			plan := endpointPlan(t, r)
			pinName := filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName)
			before := readFile(t, pinName)
			ops := endpointRecoveryOps{unlink: unix.Unlinkat, sync: (*os.File).Sync}
			if kind == "pin-unlink" {
				ops.unlink = func(fd int, name string, flags int) error {
					if name == AuthorityEndpointPinName {
						return unix.EIO
					}
					return unix.Unlinkat(fd, name, flags)
				}
			}
			syncs := 0
			now := policyNow(testCustodyPolicy())
			r.Now = func() time.Time { return now }
			ops.sync = func(dir *os.File) error {
				syncs++
				if kind == "endpoint-sync" && syncs == 1 || kind == "pin-sync" && syncs == 2 {
					return unix.EIO
				}
				if kind == "changed-after-endpoint-sync" && syncs == 1 {
					return os.WriteFile(pinName, append(before, ' '), 0600)
				}
				if kind == "expired-after-endpoint-sync" && syncs == 1 {
					now = now.Add(time.Hour)
				}
				return dir.Sync()
			}
			if result, err := applyEndpointRecovery(r, plan.SHA256, ops); !errors.Is(err, ErrCommitUncertain) || result != (EndpointRecoveryResult{}) {
				t.Fatal("uncertain cleanup accepted", err)
			}
			for _, name := range []string{AuthoritySocketName, AuthorityEndpointRecordName} {
				if _, err := os.Lstat(filepath.Join(endpoint, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unexpected endpoint remainder", err)
				}
			}
			if kind == "pin-sync" {
				if _, err := os.Lstat(pinName); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("pin unlink not attempted", err)
				}
			} else if _, err := os.Lstat(pinName); err != nil {
				t.Fatal("pin removed after failed endpoint cleanup", err)
			}
			if _, err := PlanEndpointRecovery(r); err == nil {
				t.Fatal("partial cleanup automatically adopted")
			}
			if kind != "pin-sync" {
				if next, err := OpenLocalAuthorityServer(c); next != nil || err == nil {
					t.Fatal("remaining pin automatically replaced")
				}
			}
		})
	}
}

func TestEndpointPinRefusesForeignReceipt(t *testing.T) {
	r, c, _, s := pinnedRecoveryFixture(t)
	abandonPinnedServer(t, s)
	other, _, _, another := pinnedRecoveryFixture(t)
	abandonPinnedServer(t, another)
	p, err := readEndpointPin(c.PinDirectory)
	if err != nil {
		t.Fatal(err)
	}
	data, err := encodeEndpointPin(p.dirStamp, another.socket.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEndpointRecovery(r); !errors.Is(err, ErrAuthorityEndpoint) {
		t.Fatal("foreign endpoint receipt accepted", err)
	}
	other.ExpectedRecordSHA256 = strings.Repeat("0", 64)
	if _, err := PlanEndpointRecovery(other); !errors.Is(err, ErrEndpointRecoveryApproval) {
		t.Fatal("second trust source accepted", err)
	}
}

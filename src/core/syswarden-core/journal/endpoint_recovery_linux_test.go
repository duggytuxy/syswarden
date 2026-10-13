package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type endpointTestAuthorizer func(EndpointRecoveryRequest) (EndpointRecoveryDecision, error)

func (f endpointTestAuthorizer) AuthorizeEndpointRecovery(r EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
	return f(r)
}

// Synthetic supervisor approval only, never an installed identity/audit provider.
func endpointTestDecision(r EndpointRecoveryRequest) EndpointRecoveryDecision {
	now := policyNow(testCustodyPolicy()).Unix()
	return EndpointRecoveryDecision{Mode: r.Mode, PlanSHA256: r.Plan.SHA256, DecisionSHA256: recoveryDigest([]byte("synthetic endpoint review " + r.Mode + r.Plan.SHA256)), UID: r.UID, NotBefore: now - 1, NotAfter: now + 60}
}

func endpointRecoveryFixture(t *testing.T) (EndpointRecoveryConfig, string, *authoritySocket) {
	t.Helper()
	dir, path, gid := endpointFixture(t)
	s := testEndpoint(t, dir, gid)
	peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
	c := EndpointRecoveryConfig{Directory: dir, GroupID: gid, ExpectedRecordSHA256: recoveryDigest(s.record), Peer: peer,
		Now:        func() time.Time { return policyNow(testCustodyPolicy()) },
		Authorizer: endpointTestAuthorizer(func(r EndpointRecoveryRequest) (EndpointRecoveryDecision, error) { return endpointTestDecision(r), nil }),
	}
	return c, path, s
}

func abandonEndpoint(t *testing.T, s *authoritySocket) {
	t.Helper()
	s.preserve = true
	if err := s.Close(); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("fixture failed to retain endpoint", err)
	}
}

func endpointPlan(t *testing.T, c EndpointRecoveryConfig) EndpointRecoveryPlan {
	t.Helper()
	p, err := PlanEndpointRecovery(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func endpointRecoverySnapshot(t *testing.T, paths []string) map[string]adversarialFileState {
	t.Helper()
	out := make(map[string]adversarialFileState)
	for _, path := range paths {
		var st unix.Stat_t
		err := unix.Lstat(path, &st)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		state := adversarialFileState{Mode: st.Mode, UID: st.Uid, GID: st.Gid, Links: uint64(st.Nlink), Dev: uint64(st.Dev), Inode: st.Ino, Modified: st.Mtim, Changed: st.Ctim}
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			state.Data = string(readFile(t, path))
		}
		out[path] = state
	}
	return out
}
func requireEndpointRecoverySnapshot(t *testing.T, before map[string]adversarialFileState, paths []string) {
	t.Helper()
	if !reflect.DeepEqual(before, endpointRecoverySnapshot(t, paths)) {
		t.Fatal("recovery changed protected endpoint evidence")
	}
}

func TestEndpointRecoveryReviewedLifecycle(t *testing.T) {
	c, path, s := endpointRecoveryFixture(t)
	abandonEndpoint(t, s)
	unchanged := filepath.Join(path, "administrator-note")
	if err := os.WriteFile(unchanged, []byte("preserve unrelated content"), 0600); err != nil {
		t.Fatal(err)
	}
	before := endpointRecoverySnapshot(t, []string{path, filepath.Join(path, AuthoritySocketName), filepath.Join(path, AuthorityEndpointRecordName), unchanged})
	plan := endpointPlan(t, c)
	var doc endpointRecoveryDocument
	if err := json.Unmarshal(plan.Document, &doc); err != nil || doc.RecordSHA256 != c.ExpectedRecordSHA256 || !bytes.Equal(doc.Record, s.record) || plan.SHA256 != recoveryDigest(append([]byte(endpointRecoveryDomain), plan.Document...)) {
		t.Fatal("incomplete review plan", err)
	}
	requireEndpointRecoverySnapshot(t, before, []string{path, filepath.Join(path, AuthoritySocketName), filepath.Join(path, AuthorityEndpointRecordName), unchanged})
	if result, err := ApplyEndpointRecovery(c, strings.Repeat("0", 64)); err == nil || result != (EndpointRecoveryResult{}) {
		t.Fatal("wrong approval accepted", err)
	}
	c.Authorizer = endpointTestAuthorizer(func(r EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
		if r.Mode != "apply" || r.Plan.SHA256 != plan.SHA256 || !bytes.Equal(r.Plan.Document, plan.Document) || r.PID <= 0 {
			t.Fatal("authorization not bound to review and kernel peer")
		}
		// Provider ownership of its copy must not corrupt the internal plan.
		r.Plan.Document[0] ^= 1
		return endpointTestDecision(r), nil
	})
	result, err := ApplyEndpointRecovery(c, plan.SHA256)
	if err != nil || result.PlanSHA256 != plan.SHA256 || !validRecoveryApproval(result.DecisionSHA256) {
		t.Fatal("reviewed recovery failed", err)
	}
	for _, name := range []string{AuthoritySocketName, AuthorityEndpointRecordName} {
		if err := endpointAbsent(int(c.Directory.Fd()), name); err != nil {
			t.Fatal(err)
		}
	}
	if string(readFile(t, unchanged)) != "preserve unrelated content" {
		t.Fatal("unrelated entry changed")
	}
	if result, err = ApplyEndpointRecovery(c, plan.SHA256); err == nil || result != (EndpointRecoveryResult{}) {
		t.Fatal("replayed review accepted", err)
	}
	next := testEndpoint(t, c.Directory, c.GroupID)
	if bytes.Equal(s.record, next.record) {
		t.Fatal("fresh endpoint reused old receipt")
	}
}

func TestEndpointRecoveryRefusesLiveAndLockedEndpoints(t *testing.T) {
	c, path, s := endpointRecoveryFixture(t)
	paths := []string{filepath.Join(path, AuthoritySocketName), filepath.Join(path, AuthorityEndpointRecordName)}
	before := endpointRecoverySnapshot(t, paths)
	if _, err := PlanEndpointRecovery(c); !errors.Is(err, ErrLocked) {
		t.Fatal("live directory lock ignored", err)
	}
	// Deliberately remove cooperative locking in this synthetic adversarial fixture.
	if err := unix.Flock(int(s.directory.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEndpointRecovery(c); !errors.Is(err, ErrAuthorityEndpoint) {
		t.Fatal("live listener adopted without lock", err)
	}
	requireEndpointRecoverySnapshot(t, before, paths)
}

func TestEndpointRecoveryInvalidProvisioning(t *testing.T) {
	for _, kind := range []string{"no-pin", "wrong-pin", "uppercase-pin", "no-authorizer", "denied", "no-peer", "closed-peer", "no-clock", "zero-clock", "future-clock", "no-directory", "closed-directory", "wrong-group"} {
		t.Run(kind, func(t *testing.T) {
			c, path, s := endpointRecoveryFixture(t)
			abandonEndpoint(t, s)
			paths := []string{filepath.Join(path, AuthoritySocketName), filepath.Join(path, AuthorityEndpointRecordName)}
			before := endpointRecoverySnapshot(t, paths)
			switch kind {
			case "no-pin":
				c.ExpectedRecordSHA256 = ""
			case "wrong-pin":
				c.ExpectedRecordSHA256 = strings.Repeat("0", 64)
			case "uppercase-pin":
				c.ExpectedRecordSHA256 = strings.ToUpper(c.ExpectedRecordSHA256)
			case "no-authorizer":
				c.Authorizer = nil
			case "denied":
				c.Authorizer = endpointTestAuthorizer(func(EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
					return EndpointRecoveryDecision{}, errors.New("synthetic unavailable audit")
				})
			case "no-peer":
				c.Peer = nil
			case "closed-peer":
				if err := c.Peer.Close(); err != nil {
					t.Fatal(err)
				}
			case "no-clock":
				c.Now = nil
			case "zero-clock":
				c.Now = func() time.Time { return time.Time{} }
			case "future-clock":
				c.Now = func() time.Time { return time.Unix(maxPolicyTime+1, 0) }
			case "no-directory":
				c.Directory = nil
			case "closed-directory":
				if err := c.Directory.Close(); err != nil {
					t.Fatal(err)
				}
			case "wrong-group":
				c.GroupID = ^uint32(0)
			}
			if p, err := PlanEndpointRecovery(c); err == nil || p.SHA256 != "" || p.Document != nil {
				t.Fatal("invalid provisioning disclosed a plan", err)
			}
			requireEndpointRecoverySnapshot(t, before, paths)
		})
	}
}

func TestEndpointRecoveryRefusesMalformedAndUnboundReceipts(t *testing.T) {
	for _, kind := range []string{"empty", "oversized", "invalid-json", "unknown-field", "duplicate-field", "whitespace", "nonce", "socket-inode", "directory-inode", "socket-time", "symlink", "fifo", "directory", "hardlink", "public-mode", "missing", "socket-missing", "socket-file", "socket-mode", "directory-mode", "record-acl", "directory-acl"} {
		t.Run(kind, func(t *testing.T) {
			c, path, s := endpointRecoveryFixture(t)
			abandonEndpoint(t, s)
			name, socket := filepath.Join(path, AuthorityEndpointRecordName), filepath.Join(path, AuthoritySocketName)
			data := bytes.Clone(s.record)
			var r endpointOwnershipRecord
			if err := json.Unmarshal(data, &r); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "empty":
				data = nil
			case "oversized":
				data = bytes.Repeat([]byte{'x'}, maxEndpointRecordBytes+1)
			case "invalid-json":
				data = []byte("invalid")
			case "unknown-field":
				data = append(data[:len(data)-1], []byte(",\"extra\":true}")...)
			case "duplicate-field":
				data = append(data[:len(data)-1], []byte(",\"schema\":\"syswarden.authority-endpoint-owner.v1\"}")...)
			case "whitespace":
				data = append(data, '\n')
			case "nonce":
				r.Nonce = "x"
			case "socket-inode":
				r.SocketIno = "0"
			case "directory-inode":
				r.DirectoryIno = "0"
			case "socket-time":
				r.ChangedSec = "0"
			case "symlink", "fifo", "directory":
				if err = os.Remove(name); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "symlink":
					err = os.Symlink("absent", name)
				case "fifo":
					err = unix.Mkfifo(name, 0600)
				case "directory":
					err = os.Mkdir(name, 0700)
				}
			case "hardlink":
				err = os.Link(name, name+"-extra")
			case "public-mode":
				// Deliberately unsafe permissions within the rooted test fixture.
				err = chmodFixture(name, 0640)
			case "missing":
				err = os.Remove(name)
			case "socket-missing":
				err = os.Remove(socket)
			case "socket-file":
				if err = os.Remove(socket); err == nil {
					err = os.WriteFile(socket, []byte("administrator"), 0600)
				}
			case "socket-mode":
				err = os.Chmod(socket, 0600)
			case "directory-mode":
				err = c.Directory.Chmod(0770)
			case "record-acl":
				authorityTestACL(t, name, "system.posix_acl_access")
			case "directory-acl":
				authorityTestACL(t, path, "system.posix_acl_default")
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(kind, "inode") || kind == "nonce" || kind == "socket-time" {
				data, err = json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(data, s.record) {
				if err := os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
				// Even a pin for malformed bytes cannot make them safe or canonical.
				c.ExpectedRecordSHA256 = recoveryDigest(data)
			}
			paths := []string{path, name, socket, name + "-extra"}
			before := endpointRecoverySnapshot(t, paths)
			if p, err := PlanEndpointRecovery(c); err == nil || p.SHA256 != "" {
				t.Fatal("ambiguous endpoint admitted", err)
			}
			requireEndpointRecoverySnapshot(t, before, paths)
		})
	}
}

func TestEndpointRecoveryIndependentApplyApproval(t *testing.T) {
	for _, kind := range []string{"inspect-only", "wrong-plan", "wrong-uid", "no-audit", "expired", "future", "unbounded", "reverse-window", "callback-error", "backward-clock", "peer-closed", "changed-receipt", "changed-directory", "replaced-socket"} {
		t.Run(kind, func(t *testing.T) {
			c, path, s := endpointRecoveryFixture(t)
			abandonEndpoint(t, s)
			plan := endpointPlan(t, c)
			clock := c.Now()
			c.Now = func() time.Time { return clock }
			c.Authorizer = endpointTestAuthorizer(func(r EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
				d := endpointTestDecision(r)
				switch kind {
				case "inspect-only":
					d.Mode = "inspect"
				case "wrong-plan":
					d.PlanSHA256 = strings.Repeat("0", 64)
				case "wrong-uid":
					d.UID++
				case "no-audit":
					d.DecisionSHA256 = ""
				case "expired":
					d.NotAfter = d.NotBefore + 1
				case "future":
					d.NotBefore += 10
				case "unbounded":
					d.NotAfter = d.NotBefore + MaxPolicyApprovalSeconds + 1
				case "reverse-window":
					d.NotAfter = d.NotBefore
				case "callback-error":
					return d, errors.New("synthetic audit failure")
				case "backward-clock":
					clock = clock.Add(-time.Second)
				case "peer-closed":
					if err := c.Peer.Close(); err != nil {
						t.Fatal(err)
					}
				case "changed-receipt":
					if err := os.WriteFile(filepath.Join(path, AuthorityEndpointRecordName), []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
				case "changed-directory":
					if err := os.WriteFile(filepath.Join(path, "new-entry"), []byte("administrator"), 0600); err != nil {
						t.Fatal(err)
					}
				case "replaced-socket":
					if err := os.Rename(filepath.Join(path, AuthoritySocketName), filepath.Join(path, "retained-socket")); err != nil {
						t.Fatal(err)
					}
				}
				return d, nil
			})
			if result, err := ApplyEndpointRecovery(c, plan.SHA256); err == nil || result != (EndpointRecoveryResult{}) {
				t.Fatal("invalid apply authorization accepted", err)
			}
			if _, err := os.Lstat(filepath.Join(path, AuthorityEndpointRecordName)); err != nil {
				t.Fatal("receipt removed on denial", err)
			}
		})
	}
}

func TestEndpointRecoveryUncertainRemoval(t *testing.T) {
	for _, phase := range []string{"socket-unlink", "receipt-unlink", "directory-sync", "expired-after-socket", "expired-during-sync", "changed-after-socket", "changed-during-sync"} {
		t.Run(phase, func(t *testing.T) {
			c, path, s := endpointRecoveryFixture(t)
			abandonEndpoint(t, s)
			clock := c.Now()
			c.Now = func() time.Time { return clock }
			plan := endpointPlan(t, c)
			syncs := 0
			ops := endpointRecoveryOps{
				unlink: func(fd int, name string, flags int) error {
					if (phase == "socket-unlink" && name == AuthoritySocketName) || (phase == "receipt-unlink" && name == AuthorityEndpointRecordName) {
						return unix.EIO
					}
					if err := unix.Unlinkat(fd, name, flags); err != nil {
						return err
					}
					if name == AuthoritySocketName {
						if phase == "expired-after-socket" {
							clock = clock.Add(time.Minute)
						}
						if phase == "changed-after-socket" {
							return os.WriteFile(filepath.Join(path, AuthorityEndpointRecordName), []byte("changed"), 0600)
						}
					}
					return nil
				},
				sync: func(dir *os.File) error {
					syncs++
					if phase == "directory-sync" {
						return unix.EIO
					}
					if phase == "expired-during-sync" {
						clock = clock.Add(time.Minute)
					}
					if phase == "changed-during-sync" {
						if err := dir.Chmod(0770); err != nil {
							return err
						}
					}
					return dir.Sync()
				},
			}
			if result, err := applyEndpointRecovery(c, plan.SHA256, ops); !errors.Is(err, ErrCommitUncertain) || result != (EndpointRecoveryResult{}) || syncs != 1 {
				t.Fatal("uncertain removal reported success or was retried", phase, err, syncs)
			}
			if phase != "directory-sync" && phase != "expired-during-sync" && phase != "changed-during-sync" {
				if _, err := os.Lstat(filepath.Join(path, AuthorityEndpointRecordName)); err != nil {
					t.Fatal("remaining evidence lost", err)
				}
			}
		})
	}
}

func TestEndpointRecoveryChangedReviewAndDescriptorIsolation(t *testing.T) {
	c, path, s := endpointRecoveryFixture(t)
	abandonEndpoint(t, s)
	old := endpointPlan(t, c)
	// Renaming changes directory metadata and invalidates the prior exact review.
	moved := path + "-moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(path, AuthoritySocketName)
	if err := os.WriteFile(note, []byte("unrelated replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyEndpointRecovery(c, old.SHA256); !errors.Is(err, ErrEndpointRecoveryApproval) {
		t.Fatal("stale directory review accepted", err)
	}
	plan := endpointPlan(t, c)
	if plan.SHA256 == old.SHA256 {
		t.Fatal("changed directory metadata omitted")
	}
	c.Authorizer = endpointTestAuthorizer(func(r EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
		if other, err := openAuthoritySocket(c.Directory, c.GroupID, 1); other != nil || !errors.Is(err, ErrLocked) {
			t.Fatal("recovery lease did not exclude startup", err)
		}
		if err := c.Directory.Close(); err != nil {
			t.Fatal(err)
		}
		return endpointTestDecision(r), nil
	})
	if _, err := ApplyEndpointRecovery(c, plan.SHA256); err != nil {
		t.Fatal("borrowed descriptor closure redirected recovery", err)
	}
	if string(readFile(t, note)) != "unrelated replacement" {
		t.Fatal("replacement directory changed")
	}
	for _, entry := range []string{AuthoritySocketName, AuthorityEndpointRecordName} {
		if _, err := os.Lstat(filepath.Join(moved, entry)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned pair not retired", err)
		}
	}
}

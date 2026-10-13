package journal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

func clientConfig(t *testing.T, dir *os.File, group uint32) AuthorityClientConfig {
	t.Helper()
	peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
	cred, err := custodyPeer(peer)
	if err != nil {
		t.Fatal(err)
	}
	return AuthorityClientConfig{Directory: dir, ServiceUID: cred.Uid, ServiceGID: cred.Gid, SocketGID: group, Timeout: time.Second}
}
func testAuthorityClient(t *testing.T, c AuthorityClientConfig) *LocalAuthorityClient {
	t.Helper()
	client, err := OpenLocalAuthorityClient(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
func clientReply(t *testing.T, c *LocalAuthorityClient, r authorityRequest) authorityResponse {
	t.Helper()
	data, err := c.Call(authorityMessage(t, r))
	if err != nil {
		t.Fatal(err)
	}
	var out authorityResponse
	if json.Unmarshal(data, &out) != nil {
		t.Fatal("invalid reply")
	}
	return out
}
func TestAuthorityClientActualServerLifecycle(t *testing.T) {
	f, c, _ := serverFixture(t)
	s := testServer(t, c)
	done := runServer(s)
	client := testAuthorityClient(t, clientConfig(t, c.Directory, c.GroupID))
	authorityAnchor(t, clientReply(t, client, authorityRequest{Operation: "resume"}), f.files.expected)
	authorityAnchor(t, clientReply(t, client, authorityRequest{Operation: "commit", Segment: testName}), f.files.next)
	authorityAnchor(t, clientReply(t, client, authorityRequest{Operation: "resume"}), f.files.next)
	next := f.policy
	next.Revision++
	change := authorityInstall(t, next)
	installPlan := clientReply(t, client, authorityRequest{Operation: "inspect-policy", Change: change})
	f.administrator.approved = installPlan.PlanSHA256
	installed := clientReply(t, client, authorityRequest{Operation: "apply-policy", Change: change, PlanSHA256: installPlan.PlanSHA256})
	if installed.Policy == nil || installed.Policy.Revision != "8" || !installed.Policy.Enabled {
		t.Fatal("policy install result missing")
	}
	plan := clientReply(t, client, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
	// Setting this synthetic independent registry is test approval, not authority
	// conveyed by possession of the returned plan digest.
	f.administrator.approved = plan.PlanSHA256
	out := clientReply(t, client, authorityRequest{Operation: "apply-policy", Change: &authorityChange{Operation: "disable"}, PlanSHA256: plan.PlanSHA256})
	if out.Policy == nil || out.Policy.Enabled {
		t.Fatal("approved disable missing")
	}
	data, err := client.Call(authorityMessage(t, authorityRequest{Operation: "resume"}))
	if data != nil || !errors.Is(err, ErrAuthorityDenied) || !errors.Is(err, ErrAuthorityOutcomeUnknown) {
		t.Fatal("denial classified as no-write", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	stopServer(t, s, done)
}
func TestAuthorityClientPinningAndBorrowedDescriptor(t *testing.T) {
	f, c, path := serverFixture(t)
	s := testServer(t, c)
	done := runServer(s)
	client := testAuthorityClient(t, clientConfig(t, c.Directory, c.GroupID))
	root := filepath.Dir(path)
	renamed := root + "-retained"
	if err := os.Rename(root, renamed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(renamed) })
	if err := os.Mkdir(root, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Directory.Close(); err != nil {
		t.Fatal(err)
	}
	authorityAnchor(t, clientReply(t, client, authorityRequest{Operation: "resume"}), f.files.expected)
	stopServer(t, s, done)
	data, err := client.Call(authorityMessage(t, authorityRequest{Operation: "resume"}))
	if data != nil || !errors.Is(err, ErrAuthorityService) || errors.Is(err, ErrAuthorityOutcomeUnknown) {
		t.Fatal("stale endpoint not rejected before send", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, path)) != "replacement" {
		t.Fatal("client touched replacement")
	}
}
func TestAuthorityClientRejectsMetadataAndInvalidStartup(t *testing.T) {
	for _, kind := range []string{"nil", "closed", "file", "private-directory", "write-directory", "directory-acl", "socket-acl", "socket-mode", "socket-link", "symlink", "wrong-uid", "wrong-group", "large-uid", "large-gid", "large-socket-group", "zero-timeout", "large-timeout"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			_ = testEndpoint(t, dir, gid)
			c := clientConfig(t, dir, gid)
			name := filepath.Join(path, AuthoritySocketName)
			switch kind {
			case "nil":
				c.Directory = nil
			case "closed":
				_ = c.Directory.Close()
			case "file":
				r, err := os.OpenRoot(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = r.Close() }()
				file, err := r.Create("ordinary")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = file.Close() }()
				c.Directory = file
			case "private-directory":
				if err := dir.Chmod(0700); err != nil {
					t.Fatal(err)
				}
			case "write-directory":
				if err := dir.Chmod(0770); err != nil {
					t.Fatal(err)
				}
			case "directory-acl":
				authorityTestACL(t, path, "system.posix_acl_default")
			case "socket-acl":
				authorityTestACL(t, name, "system.posix_acl_access")
			case "socket-mode":
				if err := chmodFixture(name, 0666); err != nil {
					t.Fatal(err)
				}
			case "socket-link":
				if err := os.Link(name, name+".alias"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(name, name+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(name+".original", name); err != nil {
					t.Fatal(err)
				}
			case "wrong-uid":
				c.ServiceUID ^= 1
			case "wrong-group":
				c.SocketGID ^= 1
			case "large-uid":
				c.ServiceUID = math.MaxUint32
			case "large-gid":
				c.ServiceGID = math.MaxUint32
			case "large-socket-group":
				c.SocketGID = math.MaxUint32
			case "zero-timeout":
				c.Timeout = 0
			case "large-timeout":
				c.Timeout = MaxAuthorityIOTimeout + 1
			}
			client, err := OpenLocalAuthorityClient(c)
			if err == nil || client != nil {
				t.Fatal("invalid startup accepted", err)
			}
		})
	}
}
func TestAuthorityClientRefusesChangedEndpointAndMalformedRequest(t *testing.T) {
	for _, kind := range []string{"directory-mode", "socket-mode", "socket-replaced", "socket-acl", "bad-request"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, gid := endpointFixture(t)
			endpoint := testEndpoint(t, dir, gid)
			client := testAuthorityClient(t, clientConfig(t, dir, gid))
			name := filepath.Join(path, AuthoritySocketName)
			req := authorityMessage(t, authorityRequest{Operation: "resume"})
			switch kind {
			case "directory-mode":
				if err := dir.Chmod(0770); err != nil {
					t.Fatal(err)
				}
			case "socket-mode":
				if err := chmodFixture(name, 0600); err != nil {
					t.Fatal(err)
				}
			case "socket-replaced":
				if err := os.Rename(name, name+".old"); err != nil {
					t.Fatal(err)
				}
				l, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: name})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = l.Close() }()
				if err := chmodFixture(name, 0660); err != nil {
					t.Fatal(err)
				}
			case "socket-acl":
				authorityTestACL(t, name, "system.posix_acl_access")
			case "bad-request":
				req = []byte(`{"uid":0}`)
			}
			data, err := client.Call(req)
			if err == nil || data != nil || errors.Is(err, ErrAuthorityOutcomeUnknown) {
				t.Fatal("preflight transmitted request", err)
			}
			if err := endpoint.listener.SetDeadline(time.Now().Add(15 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if peer, err := endpoint.listener.AcceptUnix(); err == nil {
				_ = peer.Close()
				t.Fatal("invalid input connected")
			}
		})
	}
}
func fakeAuthorityExchange(t *testing.T, timeout time.Duration, serve func(*net.UnixConn)) (*LocalAuthorityClient, <-chan error) {
	t.Helper()
	dir, _, gid := endpointFixture(t)
	endpoint := testEndpoint(t, dir, gid)
	config := clientConfig(t, dir, gid)
	config.Timeout = timeout
	client := testAuthorityClient(t, config)
	done := make(chan error, 1)
	go func() {
		peer, err := endpoint.listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = peer.Close() }()
		if err = peer.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
			done <- err
			return
		}
		if _, err = readAuthorityFrame(peer); err != nil {
			done <- err
			return
		}
		serve(peer)
		done <- nil
	}()
	return client, done
}
func validClientResponse(t testing.TB) []byte {
	t.Helper()
	data, err := encodeAnchor(testEnrollment().Initial)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(authorityResponse{Schema: AuthorityResponseSchema, ID: "request.fixture.1", Operation: "resume", Anchor: data})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestAuthorityClientRejectsBrokenReplyFraming(t *testing.T) {
	good := validClientResponse(t)
	size := len(good)
	if size > MaxAuthorityResponseBytes {
		t.Fatal("invalid response fixture size")
		return
	}
	frame := make([]byte, 4+size)
	binary.BigEndian.PutUint32(frame, uint32(size))
	copy(frame[4:], good)
	for _, kind := range []string{"no-header", "partial-header", "partial-body", "oversized", "zero", "trailing", "pipelined", "no-eof", "ancillary-header", "ancillary-body", "ancillary-tail"} {
		t.Run(kind, func(t *testing.T) {
			var sentFD *os.File
			if strings.HasPrefix(kind, "ancillary") {
				sentFD, _ = testDirectory(t)
			}
			refs := 0
			if sentFD != nil {
				refs = countTransportFileReferences(t, sentFD)
			}
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			client, done := fakeAuthorityExchange(t, 80*time.Millisecond, func(peer *net.UnixConn) {
				payload := bytes.Clone(frame)
				switch kind {
				case "no-header":
					return
				case "partial-header":
					payload = frame[:3]
				case "partial-body":
					payload = frame[:len(frame)-1]
				case "oversized":
					payload = []byte{255, 255, 255, 255}
				case "zero":
					payload = make([]byte, 4)
				case "trailing":
					payload = append(payload, 'x')
				case "pipelined":
					payload = append(payload, frame...)
				case "no-eof":
					_, _ = peer.Write(payload)
					<-release
					return
				case "ancillary-header", "ancillary-body", "ancillary-tail":
					offset := 0
					if kind == "ancillary-body" {
						offset = 4
					}
					if kind == "ancillary-tail" {
						offset = len(frame)
					}
					if offset > 0 {
						_, _ = peer.Write(payload[:offset])
					}
					payload = payload[offset:]
					if len(payload) == 0 {
						payload = []byte{'x'}
					}
					_, _, _ = peer.WriteMsgUnix(payload, unix.UnixRights(int(sentFD.Fd())), nil)
					return
				}
				_, _ = peer.Write(payload)
			})
			data, err := client.Call(authorityMessage(t, authorityRequest{Operation: "resume"}))
			if data != nil || !errors.Is(err, ErrAuthorityOutcomeUnknown) {
				t.Fatal("bad reply escaped or outcome treated certain", err)
			}
			if kind == "zero" && !errors.Is(err, ErrAuthorityDenied) {
				t.Fatal("denial not identified", err)
			}
			once.Do(func() { close(release) })
			if err := transportResult(t, done); err != nil {
				t.Fatal(err)
			}
			if sentFD != nil && countTransportFileReferences(t, sentFD) != refs {
				t.Fatal("response descriptors leaked")
			}
		})
	}
}
func TestAuthorityClientBusyCloseAndUncertainCommit(t *testing.T) {
	f, c, _ := serverFixture(t)
	s := testServer(t, c)
	plan := authorityReply(t, s.transport.authority, f.peer, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
	f.administrator.approved = plan.PlanSHA256
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		close(entered)
		<-release
		return nil
	}
	done := runServer(s)
	client := testAuthorityClient(t, clientConfig(t, c.Directory, c.GroupID))
	result := make(chan error, 1)
	go func() {
		data, err := client.Call(authorityMessage(t, authorityRequest{Operation: "apply-policy", Change: &authorityChange{Operation: "disable"}, PlanSHA256: plan.PlanSHA256}))
		if data != nil {
			result <- errors.New("close exposed bytes")
			return
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("write not entered")
	}
	if data, err := client.Call(authorityMessage(t, authorityRequest{Operation: "resume"})); data != nil || !errors.Is(err, ErrAuthorityClientBusy) {
		t.Fatal("queued concurrent call", err)
	}
	if err := client.Close(); !errors.Is(err, ErrAuthorityClientBusy) {
		t.Fatal("active close not reported", err)
	}
	if err := transportResult(t, result); !errors.Is(err, ErrAuthorityOutcomeUnknown) {
		t.Fatal("lost mutation reply treated certain", err)
	}
	once.Do(func() { close(release) })
	serverWait(t, s, func(st AuthorityServerStatus) bool { return st.Active == 0 })
	if st := s.Status(); st.Accepted != 1 {
		t.Fatal("client retried mutation", st)
	}
	stopServer(t, s, done)
	b, err := OpenLocalCustodyPolicy(f.config.PolicyDirectory, f.root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if policyCurrent(t, b).Trust.Enabled {
		t.Fatal("client close undid committed operation")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := client.Call(nil); data != nil || !errors.Is(err, ErrClosed) {
		t.Fatal("closed client reused", err)
	}
}
func TestAuthorityClientWrongProcessIdentitySendsNothing(t *testing.T) {
	dir, _, gid := endpointFixture(t)
	endpoint := testEndpoint(t, dir, gid)
	cfg := clientConfig(t, dir, gid)
	cfg.ServiceGID ^= 1
	client := testAuthorityClient(t, cfg)
	data, err := client.Call(authorityMessage(t, authorityRequest{Operation: "resume"}))
	if data != nil || !errors.Is(err, ErrAuthorityService) || errors.Is(err, ErrAuthorityOutcomeUnknown) {
		t.Fatal("impostor process accepted", err)
	}
	peer, err := endpoint.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if data, err := io.ReadAll(peer); err != nil || len(data) != 0 {
		t.Fatal("request sent before peer identity check", err)
	}
}
func TestAuthorityClientEmptyLifecycle(t *testing.T) {
	var missing *LocalAuthorityClient
	for _, c := range []*LocalAuthorityClient{missing, {}} {
		if c.Close() != nil {
			t.Fatal("empty close failed")
		}
		if data, err := c.Call(nil); data != nil || !errors.Is(err, ErrClosed) {
			t.Fatal("empty client active", err)
		}
	}
}
func TestAuthorityClientReplyCanonicalBinding(t *testing.T) {
	good := validClientResponse(t)
	request := authorityRequest{Operation: "resume", ID: "request.fixture.1"}
	cases := map[string][]byte{"valid": good, "whitespace": append([]byte{' '}, good...), "unknown-field": append(bytes.Clone(good[:len(good)-1]), []byte(`,"uid":0}`)...), "duplicate-id": append(bytes.Clone(good[:len(good)-1]), []byte(`,"id":"request.fixture.1"}`)...), "bad-json": []byte(`{"`), "oversize": bytes.Repeat([]byte{'x'}, MaxAuthorityResponseBytes+1)}
	for _, kind := range []string{"schema", "id", "operation", "anchor", "unexpected-plan", "unexpected-policy"} {
		var r authorityResponse
		if err := json.Unmarshal(good, &r); err != nil {
			t.Fatal(err)
		}
		switch kind {
		case "schema":
			r.Schema = "future"
		case "id":
			r.ID = "other"
		case "operation":
			r.Operation = "commit"
		case "anchor":
			r.Anchor = json.RawMessage(`{}`)
		case "unexpected-plan":
			r.Plan = json.RawMessage(`{}`)
		case "unexpected-policy":
			r.Policy = &authorityPolicyResult{}
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		cases[kind] = b
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(data)
			err := validateAuthorityReply(data, request)
			if (err == nil) != (name == "valid") {
				t.Fatal("reply acceptance mismatch", err)
			}
			if !reflect.DeepEqual(before, data) {
				t.Fatal("reply parser mutated data")
			}
		})
	}
}

func TestAuthorityClientReviewedRecovery(t *testing.T) {
	f, c, _ := serverFixture(t)
	f.files = interruptedAnchor(t, 2, false, false)
	c.Authority.AnchorDirectory, c.Authority.JournalDirectory = f.files.anchor, f.files.journal
	auth := &testRecoveryAuthorizer{decision: strings.Repeat("d", 64)}
	c.Authority.RecoveryAuthorizer = auth
	b, err := OpenLocalCustody(c.Authority.CustodyDirectory, testEnrollment(), nil)
	if err != nil {
		t.Fatal(err)
	}
	segment, err := OpenPublishedSegment(f.files.journal, testName, contracts.JournalCheckpointContext{Anchor: f.files.expected, Authority: f.files.authority}, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := publicationIntent(segment, contracts.JournalCheckpointContext{Anchor: f.files.expected, Authority: f.files.authority})
	if err = errors.Join(err, segment.Close()); err != nil {
		t.Fatal(err)
	}
	lease := localLease(t, b)
	if err = errors.Join(lease.Prepare(intent), lease.Close(), b.Close()); err != nil {
		t.Fatal(err)
	}
	server := testServer(t, c)
	done := runServer(server)
	client := testAuthorityClient(t, clientConfig(t, c.Directory, c.GroupID))
	plan := clientReply(t, client, authorityRequest{Operation: "inspect-recovery"})
	request := authorityRequest{Operation: "inspect-recovery", ID: "request.fixture.1"}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAuthorityReply(encoded, request); err != nil {
		t.Fatal(err)
	}
	planMutations(t, request, encoded)
	authorityAnchor(t, clientReply(t, client, authorityRequest{Operation: "apply-recovery", PlanSHA256: plan.PlanSHA256}), f.files.next)
	if auth.calls != 1 || auth.request.PlanSHA256 != plan.PlanSHA256 {
		t.Fatal("independent recovery approval omitted")
	}
	stopServer(t, server, done)
}
func planMutations(t *testing.T, request authorityRequest, body []byte) {
	t.Helper()
	for _, kind := range []string{"wrong-digest", "missing-plan", "extra-anchor", "unknown-field", "different-schema", "different-operation"} {
		t.Run(kind, func(t *testing.T) {
			var r authorityResponse
			if err := json.Unmarshal(body, &r); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "wrong-digest":
				r.PlanSHA256 = strings.Repeat("0", 64)
			case "missing-plan":
				r.Plan = nil
			case "extra-anchor":
				r.Anchor = json.RawMessage(`{}`)
			case "unknown-field":
				r.Plan = append(bytes.Clone(r.Plan[:len(r.Plan)-1]), []byte(`,"administrator":true}`)...)
			case "different-schema":
				r.Plan = bytes.Replace(r.Plan, []byte(`"schema":"syswarden.`), []byte(`"schema":"foreign.`), 1)
			case "different-operation":
				r.Plan = bytes.Replace(r.Plan, []byte(`"operation":`), []byte(`"unexpected_operation":`), 1)
			}
			// Recompute the digest for malformed plans: a digest cannot make a wrong
			// vocabulary or schema acceptable. It is not independent authorization.
			if kind != "wrong-digest" {
				domain := anchorRecoveryDomain
				if request.Operation == "inspect-policy" {
					domain = policyChangeDomain
				}
				r.PlanSHA256 = recoveryDigest(append([]byte(domain), r.Plan...))
			}
			changed, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if validateAuthorityReply(changed, request) == nil {
				t.Fatal("malformed inspection accepted")
			}
		})
	}
}
func TestAuthorityClientPolicyReplyBinding(t *testing.T) {
	f := authorityFixture(t)
	a := openAuthority(t, f.config)
	request := authorityRequest{Operation: "inspect-policy", ID: "request.fixture.1", Change: &authorityChange{Operation: "disable"}}
	result := authorityReply(t, a, f.peer, request)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if validateAuthorityReply(encoded, request) != nil {
		t.Fatal("actual plan rejected")
	}
	planMutations(t, request, encoded)
	request.Operation = "apply-policy"
	for _, kind := range []string{"valid", "leading-zero", "zero", "overflow", "enabled", "bad-digest", "extra-plan"} {
		t.Run(kind, func(t *testing.T) {
			r := authorityResponse{Schema: AuthorityResponseSchema, ID: request.ID, Operation: request.Operation, Policy: &authorityPolicyResult{Enabled: false, Revision: "7", SHA256: strings.Repeat("a", 64)}}
			switch kind {
			case "leading-zero":
				r.Policy.Revision = "07"
			case "zero":
				r.Policy.Revision = "0"
			case "overflow":
				r.Policy.Revision = "18446744073709551616"
			case "enabled":
				r.Policy.Enabled = true
			case "bad-digest":
				r.Policy.SHA256 = "x"
			case "extra-plan":
				r.Plan = json.RawMessage(`{}`)
			}
			body, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if (validateAuthorityReply(body, request) == nil) != (kind == "valid") {
				t.Fatal("policy reply accepted wrong shape")
			}
		})
	}
}
func FuzzAuthorityResponse(f *testing.F) {
	f.Add(validClientResponse(f))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":"unknown"}`))
	request := authorityRequest{Operation: "resume", ID: "request.fixture.1"}
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		if validateAuthorityReply(data, request) == nil {
			if len(data) > MaxAuthorityResponseBytes {
				t.Fatal("response bound bypass")
			}
			var r authorityResponse
			if json.Unmarshal(data, &r) != nil {
				t.Fatal("accepted invalid JSON")
			}
			encoded, err := json.Marshal(r)
			if err != nil || !bytes.Equal(encoded, data) || r.ID != request.ID || r.Operation != request.Operation {
				t.Fatal("response binding bypass")
			}
			if _, err := decodeAnchor(r.Anchor); err != nil {
				t.Fatal("invalid anchor accepted")
			}
		}
		if !bytes.Equal(before, data) {
			t.Fatal("decoder changed input")
		}
	})
}

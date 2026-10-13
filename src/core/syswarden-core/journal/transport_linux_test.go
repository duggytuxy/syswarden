package journal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testTransportLimits() AuthorityTransportLimits {
	return AuthorityTransportLimits{MaxPeers: 2, MaxPeersPerUID: 2, ReadTimeout: time.Second, WriteTimeout: time.Second}
}
func transportFixture(t *testing.T) (authorityFixtureState, *LocalAuthorityTransport) {
	t.Helper()
	f := authorityFixture(t)
	tr, err := OpenLocalAuthorityTransport(f.config, testTransportLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return f, tr
}
func transportFrame(body []byte) []byte {
	size := len(body)
	if size > MaxAuthorityRequestBytes {
		panic("oversized synthetic request")
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(size))
	copy(out[4:], body)
	return out
}
func transportRun(t *testing.T, tr *LocalAuthorityTransport) (*net.UnixConn, *net.UnixConn, <-chan error) {
	t.Helper()
	server, client := custodySocketPair(t, unix.SOCK_STREAM)
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- tr.ServePeer(server) }()
	return server, client, done
}
func transportResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("transport did not finish")
		return nil
	}
}
func transportSend(t *testing.T, client *net.UnixConn, wire []byte) {
	t.Helper()
	if len(wire) > 0 {
		if n, err := client.Write(wire); err != nil || n != len(wire) {
			t.Fatal("send", n, err)
		}
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}
func transportRead(t *testing.T, client *net.UnixConn) []byte {
	t.Helper()
	data, err := io.ReadAll(io.LimitReader(client, MaxAuthorityResponseBytes+5))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 4 || len(data) > MaxAuthorityResponseBytes+4 {
		t.Fatal("invalid response length", len(data))
	}
	n := binary.BigEndian.Uint32(data[:4])
	if int(n) != len(data)-4 {
		t.Fatal("incomplete or trailing response")
	}
	return data[4:]
}

// A bounded denial can be followed by reset when rejected unread bytes remain.
// Neither partial delivery nor reset is a success response or authorizes a retry.
func transportDenial(t *testing.T, client *net.UnixConn) {
	t.Helper()
	data, err := io.ReadAll(io.LimitReader(client, 5))
	if err != nil && !errors.Is(err, unix.ECONNRESET) {
		t.Fatal(err)
	}
	if len(data) > 4 || !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("denial exposed non-generic bytes")
	}
}
func transportWaitPhase(t *testing.T, tr *LocalAuthorityTransport, peer *net.UnixConn, want authorityPeerPhase) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tr.mu.Lock()
		got, ok := tr.peers[peer]
		tr.mu.Unlock()
		if ok && got.phase == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("transport phase not reached")
}

func TestAuthorityTransportResumeCommitAcrossFreshConnections(t *testing.T) {
	f, tr := transportFixture(t)
	for index, operation := range []string{"resume", "commit", "resume"} {
		r := authorityRequest{Operation: operation}
		if operation == "commit" {
			r.Segment = testName
		}
		_, client, done := transportRun(t, tr)
		transportSend(t, client, transportFrame(authorityMessage(t, r)))
		body := transportRead(t, client)
		if err := transportResult(t, done); err != nil {
			t.Fatal(err)
		}
		var reply authorityResponse
		if json.Unmarshal(body, &reply) != nil || reply.Operation != operation {
			t.Fatal("invalid private response")
		}
		want := f.files.next
		if index == 0 {
			want = f.files.expected
		}
		if len(tr.peers) != 0 {
			t.Fatal("connection retained")
		}
		authorityAnchor(t, reply, want)
	}
}

func TestAuthorityTransportHeaderBodyFragmentationAndTruncation(t *testing.T) {
	f, tr := transportFixture(t)
	wire := transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"}))
	before := f.bytes(t)
	for cut := 0; cut <= len(wire); cut++ {
		t.Run("truncated-"+strconv.Itoa(cut), func(t *testing.T) {
			_, client, done := transportRun(t, tr)
			transportSend(t, client, wire[:cut])
			out := transportRead(t, client)
			err := transportResult(t, done)
			if cut == len(wire) {
				if err != nil || len(out) == 0 {
					t.Fatal("complete frame refused", err)
				}
			} else {
				if err == nil || len(out) != 0 {
					t.Fatal("partial request dispatched", err)
				}
			}
		})
	}
	for _, chunk := range []int{1, 2, 3, 4, 7, 16, 64} {
		t.Run("chunks-"+strconv.Itoa(chunk), func(t *testing.T) {
			_, client, done := transportRun(t, tr)
			for offset := 0; offset < len(wire); offset += chunk {
				end := min(offset+chunk, len(wire))
				if _, err := client.Write(wire[offset:end]); err != nil {
					t.Fatal(err)
				}
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if len(transportRead(t, client)) == 0 {
				t.Fatal("fragmented frame denied")
			}
			if err := transportResult(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
	if !reflect.DeepEqual(before, f.bytes(t)) {
		t.Fatal("framing tests wrote state")
	}
}

func TestAuthorityTransportDenialsHaveNoPrivateWireDetails(t *testing.T) {
	for _, kind := range []string{"zero", "oversize", "maximum-integer", "trailing", "pipeline", "malformed", "unknown-field", "nil-admin", "stale-plan"} {
		t.Run(kind, func(t *testing.T) {
			f, tr := transportFixture(t)
			wire := transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"}))
			switch kind {
			case "zero":
				wire = make([]byte, 4)
			case "oversize":
				wire = make([]byte, 4)
				binary.BigEndian.PutUint32(wire, MaxAuthorityRequestBytes+1)
			case "maximum-integer":
				wire = []byte{255, 255, 255, 255}
			case "trailing":
				wire = append(wire, 'x')
			case "pipeline":
				wire = append(wire, wire...)
			case "malformed":
				wire = transportFrame([]byte("{"))
			case "unknown-field":
				wire = transportFrame([]byte(strings.Replace(string(wire[4:]), `"operation":"resume"`, `"operation":"resume","path":"/private/synthetic"`, 1)))
			case "nil-admin":
				tr.authority.administrator = nil
				wire = transportFrame(authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}))
			case "stale-plan":
				wire = transportFrame(authorityMessage(t, authorityRequest{Operation: "apply-policy", Change: &authorityChange{Operation: "disable"}, PlanSHA256: strings.Repeat("a", 64)}))
			}
			before := f.bytes(t)
			_, client, done := transportRun(t, tr)
			transportSend(t, client, wire)
			transportDenial(t, client)
			if err := transportResult(t, done); err == nil {
				t.Fatal("failed operation accepted")
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("denial mutated state")
			}
		})
	}
}

func TestAuthorityTransportTimeoutDoesNotDispatchWithoutHalfClose(t *testing.T) {
	for _, kind := range []string{"empty", "header", "body", "no-half-close", "trickle"} {
		t.Run(kind, func(t *testing.T) {
			f := authorityFixture(t)
			limits := testTransportLimits()
			limits.ReadTimeout = 40 * time.Millisecond
			tr, err := OpenLocalAuthorityTransport(f.config, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tr.Close() }()
			wire := transportFrame(authorityMessage(t, authorityRequest{Operation: "commit", Segment: testName}))
			_, client, done := transportRun(t, tr)
			before := f.bytes(t)
			switch kind {
			case "header":
				_, err = client.Write(wire[:2])
			case "body":
				_, err = client.Write(wire[:8])
			case "no-half-close":
				_, err = client.Write(wire)
			case "trickle":
				// Header requests the largest bounded body, then one byte per interval.
				h := make([]byte, 4)
				binary.BigEndian.PutUint32(h, MaxAuthorityRequestBytes)
				_, err = client.Write(h)
			}
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if kind == "trickle" {
				for range 8 {
					time.Sleep(10 * time.Millisecond)
					if _, e := client.Write([]byte("x")); e != nil {
						break
					}
				}
			}
			transportDenial(t, client)
			if err = transportResult(t, done); err == nil || time.Since(started) > 2*time.Second {
				t.Fatal("absolute read deadline absent", err)
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("timeout dispatched mutation")
			}
		})
	}
}

func TestAuthorityTransportCapacityDuplicateAndCloseReaders(t *testing.T) {
	_, tr := transportFixture(t)
	server1, client1, done1 := transportRun(t, tr)
	server2, client2, done2 := transportRun(t, tr)
	transportWaitPhase(t, tr, server1, authorityPeerReading)
	transportWaitPhase(t, tr, server2, authorityPeerReading)
	if err := tr.ServePeer(server1); !errors.Is(err, ErrAuthorityTransportBusy) {
		t.Fatal("duplicate admitted", err)
	}
	if _, err := custodyPeer(server1); err != nil {
		t.Fatal("duplicate closed active peer", err)
	}
	server3, client3 := custodySocketPair(t, unix.SOCK_STREAM)
	if err := tr.ServePeer(server3); !errors.Is(err, ErrAuthorityTransportBusy) {
		t.Fatal("capacity bypass", err)
	}
	if _, err := custodyPeer(server3); err == nil {
		t.Fatal("excess connection retained")
	}
	if err := tr.Close(); !errors.Is(err, ErrAuthorityTransportBusy) {
		t.Fatal("active close not reported", err)
	}
	if transportResult(t, done1) == nil || transportResult(t, done2) == nil {
		t.Fatal("closed reading connection succeeded")
	}
	for _, c := range []*net.UnixConn{client1, client2, client3} {
		var b [1]byte
		if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal("closed transport exposed response", n, err)
		}
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if len(tr.peers) != 0 {
		t.Fatal("registry leaked peers")
	}
	server, _ := custodySocketPair(t, unix.SOCK_STREAM)
	if err := tr.ServePeer(server); !errors.Is(err, ErrClosed) {
		t.Fatal("closing transport admitted", err)
	}
}

func TestAuthorityTransportDrainsMutationAndSuppressesLostReply(t *testing.T) {
	f, tr := transportFixture(t)
	tr.limits.MaxPeersPerUID = 1
	plan := authorityReply(t, tr.authority, f.peer, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
	f.administrator.approved = plan.PlanSHA256
	entered, release := make(chan struct{}), make(chan struct{})
	f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		close(entered)
		<-release
		return nil
	}
	server, client, done := transportRun(t, tr)
	transportSend(t, client, transportFrame(authorityMessage(t, authorityRequest{Operation: "apply-policy", Change: &authorityChange{Operation: "disable"}, PlanSHA256: plan.PlanSHA256})))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("apply did not enter")
	}
	if transportUIDCount(tr, hostTestUID(t)) != 1 {
		t.Fatal("executing operation lost its UID slot")
	}
	other, _ := custodySocketPair(t, unix.SOCK_STREAM)
	if err := tr.ServePeer(other); !errors.Is(err, ErrAuthorityTransportBusy) {
		t.Fatal("executing operation did not consume UID quota", err)
	}
	if err := tr.Close(); !errors.Is(err, ErrAuthorityTransportBusy) {
		t.Fatal(err)
	}
	if _, err := custodyPeer(server); err != nil {
		t.Fatal("executing peer closed before credential recheck", err)
	}
	if transportUIDCount(tr, hostTestUID(t)) != 1 {
		t.Fatal("draining operation released its quota before completion")
	}
	close(release)
	if err := transportResult(t, done); !errors.Is(err, ErrClosed) {
		t.Fatal("lost reply not reported", err)
	}
	if transportUIDCount(tr, hostTestUID(t)) != 0 {
		t.Fatal("drained operation retained its UID quota")
	}
	data, err := io.ReadAll(client)
	if err != nil || len(data) != 0 {
		t.Fatal("drain exposed a response", err)
	}
	b, err := OpenLocalCustodyPolicy(f.config.PolicyDirectory, f.root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if policyCurrent(t, b).Trust.Enabled {
		t.Fatal("drain rolled back admitted approved mutation")
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityTransportBusyAuthorityUsesGenericDenial(t *testing.T) {
	f, tr := transportFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		close(entered)
		<-release
		return nil
	}
	_, client1, done1 := transportRun(t, tr)
	transportSend(t, client1, transportFrame(authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("inspection did not enter")
	}
	_, client2, done2 := transportRun(t, tr)
	transportSend(t, client2, transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"})))
	if len(transportRead(t, client2)) != 0 || !errors.Is(transportResult(t, done2), ErrAuthorityBusy) {
		t.Fatal("busy request queued or exposed details")
	}
	close(release)
	if len(transportRead(t, client1)) == 0 || transportResult(t, done1) != nil {
		t.Fatal("admitted inspection failed")
	}
}

func countTransportFileReferences(t *testing.T, file *os.File) int {
	t.Helper()
	var expected unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &expected); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		var st unix.Stat_t
		if unix.Stat(filepath.Join("/proc/self/fd", entry.Name()), &st) == nil && st.Dev == expected.Dev && st.Ino == expected.Ino {
			count++
		}
	}
	return count
}
func TestAuthorityTransportRejectsAncillaryDescriptorsWithoutLeaks(t *testing.T) {
	for _, where := range []string{"header", "body", "tail"} {
		t.Run(where, func(t *testing.T) {
			f, tr := transportFixture(t)
			file, err := os.CreateTemp(t.TempDir(), "synthetic-rights-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			beforeRefs := countTransportFileReferences(t, file)
			before := f.bytes(t)
			wire := transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"}))
			_, client, done := transportRun(t, tr)
			offset := 0
			if where == "body" {
				offset = 4
			}
			if where == "tail" {
				offset = len(wire)
			}
			if offset > 0 {
				if _, err = client.Write(wire[:offset]); err != nil {
					t.Fatal(err)
				}
			}
			// Multiple rights exceed a zero-byte control buffer on every receive.
			payload := []byte("x")
			if offset < len(wire) {
				payload = wire[offset:]
			}
			_, _, err = client.WriteMsgUnix(payload, unix.UnixRights(int(file.Fd()), int(file.Fd()), int(file.Fd())), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			transportDenial(t, client)
			if transportResult(t, done) == nil {
				t.Fatal("ancillary input accepted")
			}
			if countTransportFileReferences(t, file) != beforeRefs {
				t.Fatal("received descriptors leaked")
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("ancillary request wrote state")
			}
		})
	}
}

func TestAuthorityTransportWriteTimeoutAndReplyBounds(t *testing.T) {
	peer, client := custodySocketPair(t, unix.SOCK_STREAM)
	raw, err := peer.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 1024) }); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	started := time.Now()
	err = writeAuthorityFrame(peer, bytes.Repeat([]byte("x"), MaxAuthorityResponseBytes), 40*time.Millisecond)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || time.Since(started) > 2*time.Second {
		t.Fatal("writer unbounded", err)
	}
	if err = peer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(client)
	if err != nil || len(data) < 4 || len(data) >= 4+MaxAuthorityResponseBytes {
		t.Fatal("expected partial response", err)
	}
	if binary.BigEndian.Uint32(data[:4]) != MaxAuthorityResponseBytes {
		t.Fatal("reply length changed after failure")
	}
	peer2, client2 := custodySocketPair(t, unix.SOCK_STREAM)
	if !errors.Is(writeAuthorityFrame(peer2, make([]byte, MaxAuthorityResponseBytes+1), time.Second), ErrAuthorityFrame) {
		t.Fatal("oversize reply accepted")
	}
	if err = peer2.Close(); err != nil {
		t.Fatal(err)
	}
	data, err = io.ReadAll(client2)
	if err != nil || len(data) != 0 {
		t.Fatal("oversize reply wrote header", err)
	}
}

func TestAuthorityTransportInvalidConfigurationAndPeer(t *testing.T) {
	for _, kind := range []string{"zero-peers", "excess-peers", "zero-uid-peers", "negative-uid-peers", "excess-uid-peers", "zero-read", "negative-write", "excess-read", "excess-write", "missing-authority"} {
		t.Run(kind, func(t *testing.T) {
			f := authorityFixture(t)
			l := testTransportLimits()
			c := f.config
			switch kind {
			case "zero-peers":
				l.MaxPeers = 0
			case "excess-peers":
				l.MaxPeers = MaxAuthorityPeers + 1
			case "zero-uid-peers":
				l.MaxPeersPerUID = 0
			case "negative-uid-peers":
				l.MaxPeersPerUID = -1
			case "excess-uid-peers":
				l.MaxPeersPerUID = l.MaxPeers + 1
			case "zero-read":
				l.ReadTimeout = 0
			case "negative-write":
				l.WriteTimeout = -1
			case "excess-read":
				l.ReadTimeout = MaxAuthorityIOTimeout + 1
			case "excess-write":
				l.WriteTimeout = MaxAuthorityIOTimeout + 1
			case "missing-authority":
				c = LocalAuthorityConfig{}
			}
			tr, err := OpenLocalAuthorityTransport(c, l)
			if err == nil || tr != nil {
				t.Fatal("invalid startup accepted", err)
			}
		})
	}
	_, tr := transportFixture(t)
	if tr.ServePeer(nil) == nil {
		t.Fatal("nil peer accepted")
	}
	peer, _ := custodySocketPair(t, unix.SOCK_DGRAM)
	if tr.ServePeer(peer) == nil {
		t.Fatal("datagram accepted")
	}
	if _, err := custodyPeer(peer); err == nil {
		t.Fatal("invalid socket retained")
	}
	var missing *LocalAuthorityTransport
	peer, _ = custodySocketPair(t, unix.SOCK_STREAM)
	if !errors.Is(missing.ServePeer(peer), ErrClosed) {
		t.Fatal("nil transport accepted")
	}
	if err := missing.Close(); err != nil {
		t.Fatal(err)
	}
	var zero LocalAuthorityTransport
	if !errors.Is(zero.ServePeer(nil), ErrClosed) {
		t.Fatal("zero transport accepted")
	}
	if err := zero.Close(); err != nil {
		t.Fatal(err)
	}
}

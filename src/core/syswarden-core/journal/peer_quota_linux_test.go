package journal

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func transportUIDCount(tr *LocalAuthorityTransport, uid uint32) int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	count := 0
	for _, slot := range tr.peers {
		if slot.uid == uid {
			count++
		}
	}
	return count
}

func TestAuthorityTransportUIDQuotaBeforeReadingAndAfterRelease(t *testing.T) {
	for _, ending := range []string{"disconnect", "timeout", "malformed", "success"} {
		t.Run(ending, func(t *testing.T) {
			f := authorityFixture(t)
			limits := testTransportLimits()
			limits.MaxPeersPerUID = 1
			if ending == "timeout" {
				limits.ReadTimeout = 200 * time.Millisecond
			}
			tr, err := OpenLocalAuthorityTransport(f.config, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tr.Close() }()
			before := f.bytes(t)
			peer, client, done := transportRun(t, tr)
			transportWaitPhase(t, tr, peer, authorityPeerReading)
			if err := tr.ServePeer(peer); !errors.Is(err, ErrAuthorityTransportBusy) {
				t.Fatal("duplicate bypassed quota", err)
			}
			if _, err := custodyPeer(peer); err != nil {
				t.Fatal("duplicate closed admitted connection", err)
			}
			other, wire := custodySocketPair(t, unix.SOCK_STREAM)
			// No bytes are sent: quota rejection must precede framing/deadlines.
			if err := tr.ServePeer(other); !errors.Is(err, ErrAuthorityTransportBusy) {
				t.Fatal("same UID obtained a second slot", err)
			}
			if _, err := custodyPeer(other); err == nil {
				t.Fatal("quota rejection retained the connection")
			}
			if data, err := io.ReadAll(wire); err != nil || len(data) != 0 {
				t.Fatal("quota refusal disclosed data", err)
			}
			switch ending {
			case "disconnect":
				_ = client.Close()
			case "timeout":
				transportDenial(t, client)
			case "malformed":
				transportSend(t, client, transportFrame([]byte("invalid")))
				transportDenial(t, client)
			case "success":
				transportSend(t, client, transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"})))
				if len(transportRead(t, client)) == 0 {
					t.Fatal("admitted request refused")
				}
			}
			if err := transportResult(t, done); (err == nil) != (ending == "success") {
				t.Fatal("unexpected admitted request result", err)
			}
			if transportUIDCount(tr, hostTestUID(t)) != 0 {
				t.Fatal("completed connection retained its UID slot")
			}
			_, next, result := transportRun(t, tr)
			transportSend(t, next, transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"})))
			if len(transportRead(t, next)) == 0 || transportResult(t, result) != nil {
				t.Fatal("released slot was not reusable")
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("quota or resume changed protected state")
			}
		})
	}
}

func TestAuthorityTransportUIDQuotaConcurrentRegistration(t *testing.T) {
	f := authorityFixture(t)
	limits := testTransportLimits()
	limits.MaxPeers, limits.MaxPeersPerUID = MaxAuthorityPeers, 2
	tr, err := OpenLocalAuthorityTransport(f.config, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Close() }()
	start := make(chan struct{})
	type outcome struct {
		peer *net.UnixConn
		err  error
	}
	results := make(chan outcome, 16)
	for range cap(results) {
		peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
		go func() {
			<-start
			_, err := tr.register(peer)
			results <- outcome{peer, err}
		}()
	}
	close(start)
	admitted := 0
	for range cap(results) {
		r := <-results
		if r.err == nil {
			admitted++
		} else {
			if !errors.Is(r.err, ErrAuthorityTransportBusy) {
				t.Fatal("unexpected registration result", r.err)
			}
			_ = r.peer.Close()
		}
	}
	if admitted != 2 || transportUIDCount(tr, hostTestUID(t)) != 2 {
		t.Fatal("concurrent registrations exceeded explicit UID ceiling", admitted)
	}
	for peer := range tr.peers {
		if err := tr.release(peer); err != nil {
			t.Fatal(err)
		}
	}
}

// The real listener has two workers and a one-peer UID ceiling. An ungranted
// child holds one incomplete connection, then a separate process with the same
// UID is refused before sending bytes. A different authorized UID still resumes.
// The extra test pipe contains only a stop byte, never a protected descriptor.
func testAuthorityPeerQuotaBoundary(t *testing.T, canary, endpoint string, server *LocalAuthorityServer, f authorityFixtureState) {
	t.Helper()
	stopR, stopW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stopR.Close(); _ = stopW.Close() }()
	runAdversary(t, canary, "quota-hold", endpoint, func(_ *exec.Cmd) {
		serverWait(t, server, func(st AuthorityServerStatus) bool {
			return st.Active == 1 && transportUIDCount(server.transport, adversaryID) == 1
		})
		runAdversary(t, canary, "quota-denied", endpoint, nil)
		authorityAnchor(t, serverRequest(t, endpoint, authorityRequest{Operation: "resume"}), f.files.expected)
		if transportUIDCount(server.transport, adversaryID) != 1 {
			t.Fatal("slow peer disappeared before independent UID was served")
		}
		if _, err := stopW.Write([]byte{'S'}); err != nil {
			t.Fatal(err)
		}
	}, stopR)
	serverWait(t, server, func(st AuthorityServerStatus) bool { return st.Active == 0 })
	if transportUIDCount(server.transport, adversaryID) != 0 {
		t.Fatal("disconnected UID retained quota state")
	}
}

func quotaAdversary(t *testing.T, target, mode string) {
	t.Helper()
	// This probe accepts only a Unix pathname; it cannot select a TCP destination.
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: target})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if mode == "quota-hold" {
		stop := os.NewFile(3, "quota-stop")
		defer func() { _ = stop.Close() }()
		var b [1]byte
		if _, err := io.ReadFull(stop, b[:]); err != nil || b[0] != 'S' {
			t.Fatal("missing test stop", err)
		}
	} else {
		var b [1]byte
		if n, err := peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal("excess UID peer was not closed before framing", n, err)
		}
	}
}

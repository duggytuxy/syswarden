package journal

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAuthorityRateLimitsRejectBeforeOpeningState(t *testing.T) {
	f := authorityFixture(t)
	before := f.bytes(t)
	for _, tc := range []struct {
		name   string
		change func(*AuthorityTransportLimits)
	}{
		{"zero-budget", func(l *AuthorityTransportLimits) { l.RequestsPerUID = 0 }},
		{"negative-budget", func(l *AuthorityTransportLimits) { l.RequestsPerUID = -1 }},
		{"large-budget", func(l *AuthorityTransportLimits) { l.RequestsPerUID = MaxAuthorityRequestsPerWindow + 1 }},
		{"zero-table", func(l *AuthorityTransportLimits) { l.MaxRateUIDs = 0 }},
		{"negative-table", func(l *AuthorityTransportLimits) { l.MaxRateUIDs = -1 }},
		{"large-table", func(l *AuthorityTransportLimits) { l.MaxRateUIDs = MaxAuthorityRateUIDs + 1 }},
		{"zero-window", func(l *AuthorityTransportLimits) { l.RateWindow = 0 }},
		{"negative-window", func(l *AuthorityTransportLimits) { l.RateWindow = -1 }},
		{"short-window", func(l *AuthorityTransportLimits) { l.RateWindow = MinAuthorityRateWindow - 1 }},
		{"long-window", func(l *AuthorityTransportLimits) { l.RateWindow = MaxAuthorityRateWindow + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testTransportLimits()
			tc.change(&l)
			tr, err := OpenLocalAuthorityTransport(f.config, l)
			if tr != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatal("invalid rate limits admitted", err)
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("invalid rate limits changed state")
			}
		})
	}
	tr, err := OpenLocalAuthorityTransport(f.config, testTransportLimits())
	if err != nil {
		t.Fatal("invalid construction retained state locks", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityRateConsumptionSurvivesPeerRelease(t *testing.T) {
	for _, ending := range []string{"success", "malformed", "disconnect", "timeout"} {
		t.Run(ending, func(t *testing.T) {
			f := authorityFixture(t)
			l := testTransportLimits()
			l.RequestsPerUID, l.MaxRateUIDs, l.RateWindow = 1, 1, MaxAuthorityRateWindow
			if ending == "timeout" {
				l.ReadTimeout = 40 * time.Millisecond
			}
			tr, err := OpenLocalAuthorityTransport(f.config, l)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tr.Close() }()
			now := time.Now()
			tr.rateNow = func() time.Time { return now }
			before := f.bytes(t)
			peer, client, done := transportRun(t, tr)
			transportWaitPhase(t, tr, peer, authorityPeerReading)
			switch ending {
			case "success":
				transportSend(t, client, transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"})))
				if len(transportRead(t, client)) == 0 {
					t.Fatal("valid first request refused")
				}
			case "malformed":
				transportSend(t, client, transportFrame([]byte("invalid")))
				transportDenial(t, client)
			case "disconnect":
				_ = client.Close()
			case "timeout":
				transportDenial(t, client)
			}
			if err := transportResult(t, done); (err == nil) != (ending == "success") {
				t.Fatal("unexpected first result", err)
			}
			if len(tr.peers) != 0 || tr.rate[0].used != 1 {
				t.Fatal("release refunded admission budget")
			}
			other, wire := custodySocketPair(t, unix.SOCK_STREAM)
			// No bytes are sent. Rate refusal must close before framing begins.
			if err := tr.ServePeer(other); !errors.Is(err, ErrAuthorityRateLimit) {
				t.Fatal("released peer bypassed rate", err)
			}
			if data, err := io.ReadAll(wire); err != nil || len(data) != 0 {
				t.Fatal("rate refusal exposed bytes", err)
			}
			if len(tr.peers) != 0 || tr.rate[0].used != 1 {
				t.Fatal("refusal allocated a peer or changed the quota")
			}
			now = now.Add(l.RateWindow)
			_, next, result := transportRun(t, tr)
			transportSend(t, next, transportFrame(authorityMessage(t, authorityRequest{Operation: "resume"})))
			if len(transportRead(t, next)) == 0 || transportResult(t, result) != nil {
				t.Fatal("expired window blocked authorized resume")
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("rate control or resume changed durable state")
			}
		})
	}
}

func TestAuthorityRateRegistryPreservesUnexpiredUIDs(t *testing.T) {
	l := testTransportLimits()
	l.RequestsPerUID, l.MaxRateUIDs = 2, 2
	now := time.Now()
	start := now
	tr := &LocalAuthorityTransport{limits: l, rate: make([]authorityRateWindow, l.MaxRateUIDs), rateNow: func() time.Time { return now }}
	if !tr.admitRate(1) || !tr.admitRate(2) || !tr.admitRate(1) || tr.admitRate(1) {
		t.Fatal("UID windows not independent")
	}
	before := append([]authorityRateWindow(nil), tr.rate...)
	for uid := uint32(3); uid < 1000; uid++ {
		if tr.admitRate(uid) {
			t.Fatal("full table admitted a new UID")
		}
	}
	if !reflect.DeepEqual(before, tr.rate) || len(tr.rate) != 2 || cap(tr.rate) != 2 {
		t.Fatal("full registry evicted or allocated history")
	}
	now = start.Add(l.RateWindow - time.Nanosecond)
	if !tr.admitRate(2) || tr.admitRate(3) {
		t.Fatal("unexpired registry was reused")
	}
	now = start.Add(l.RateWindow)
	if !tr.admitRate(3) || !tr.admitRate(1) || !tr.admitRate(3) || tr.admitRate(3) {
		t.Fatal("expired entry reuse has wrong budget")
	}
	if len(tr.rate) != 2 || cap(tr.rate) != 2 {
		t.Fatal("expired registry grew")
	}
}

func TestAuthorityRateClockAndFixedWindowBoundary(t *testing.T) {
	l := testTransportLimits()
	l.RequestsPerUID, l.MaxRateUIDs = 2, 1
	now := time.Now()
	start := now
	tr := &LocalAuthorityTransport{limits: l, rate: make([]authorityRateWindow, 1), rateNow: func() time.Time { return now }}
	if !tr.admitRate(0) {
		t.Fatal("kernel UID zero was treated as empty")
	}
	before := tr.rate[0]
	for _, invalid := range []time.Time{{}, start.Add(-time.Nanosecond)} {
		now = invalid
		if tr.admitRate(0) || tr.rate[0] != before || tr.rateLast != start {
			t.Fatal("invalid clock reset quota")
		}
	}
	now = start.Add(l.RateWindow - time.Nanosecond)
	if !tr.admitRate(0) || tr.admitRate(0) {
		t.Fatal("old window budget exceeded")
	}
	now = start.Add(l.RateWindow)
	for attempt, want := range []bool{true, true, false} {
		if got := tr.admitRate(0); got != want {
			t.Fatal("fixed boundary does not enforce fresh budget", attempt, got)
		}
	}
}

func TestAuthorityRateConcurrentRegistration(t *testing.T) {
	f := authorityFixture(t)
	l := testTransportLimits()
	l.MaxPeers, l.MaxPeersPerUID, l.RequestsPerUID, l.RateWindow = MaxAuthorityPeers, MaxAuthorityPeers, 3, MaxAuthorityRateWindow
	tr, err := OpenLocalAuthorityTransport(f.config, l)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Close() }()
	start := make(chan struct{})
	type result struct {
		peer *net.UnixConn
		err  error
	}
	results := make(chan result, 16)
	for range cap(results) {
		peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
		go func() { <-start; _, err := tr.register(peer); results <- result{peer, err} }()
	}
	close(start)
	admitted := 0
	for range cap(results) {
		r := <-results
		if r.err == nil {
			admitted++
		} else {
			if !errors.Is(r.err, ErrAuthorityRateLimit) {
				t.Fatal("unexpected refusal", r.err)
			}
			_ = r.peer.Close()
		}
	}
	if admitted != 3 || len(tr.peers) != 3 || tr.rate[0].used != 3 {
		t.Fatal("concurrent admissions exceeded rate", admitted)
	}
	for peer := range tr.peers {
		if err := tr.release(peer); err != nil {
			t.Fatal(err)
		}
	}
	peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
	if err := tr.ServePeer(peer); !errors.Is(err, ErrAuthorityRateLimit) {
		t.Fatal("release erased historical budget", err)
	}
}

func testAuthorityRateBoundary(t *testing.T, canary, work string) {
	t.Helper()
	f := authorityFixture(t)
	before := f.bytes(t)
	path := filepath.Join(work, "rate-endpoint")
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, adversaryID); err != nil {
		t.Fatal(err)
	}
	dir, err := openFixtureDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	pin, _ := testDirectory(t)
	l := testTransportLimits()
	l.RequestsPerUID, l.MaxRateUIDs, l.RateWindow = 1, 2, MaxAuthorityRateWindow
	s := testServer(t, AuthorityServerConfig{Authority: f.config, Transport: l, Directory: dir, PinDirectory: pin, GroupID: adversaryID, AcceptInterval: MinAuthorityAcceptInterval})
	done := runServer(s)
	endpoint := filepath.Join(path, AuthoritySocketName)
	runAdversary(t, canary, "rate-repeat", endpoint, nil)
	serverWait(t, s, func(st AuthorityServerStatus) bool { return st.Failed == 2 && st.Active == 0 })
	// A separate authorized kernel UID still has a fresh independent window.
	authorityAnchor(t, serverRequest(t, endpoint, authorityRequest{Operation: "resume"}), f.files.expected)
	if !reflect.DeepEqual(before, f.bytes(t)) {
		t.Fatal("rate probe or authorized resume changed protected bytes")
	}
	stopServer(t, s, done)
}

func rateAdversary(t *testing.T, endpoint string) {
	t.Helper()
	for attempt := 0; attempt < 2; attempt++ {
		peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: endpoint})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			// First establish admission, framing and a generic denial. This
			// consumes a rate unit without any authority or valid claimed UID.
			transportSend(t, peer, transportFrame([]byte("invalid")))
			data, err := io.ReadAll(io.LimitReader(peer, 5))
			if err != nil || !bytes.Equal(data, make([]byte, 4)) {
				t.Fatal("first rate probe was not admitted", err)
			}
		} else {
			// The live-peer limit is two, so it cannot explain this refusal.
			// No frame or EOF is sent; rate rejection must close the connection.
			var b [1]byte
			if n, err := peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatal("reconnection bypassed per-UID rate", n, err)
			}
		}
	}
}

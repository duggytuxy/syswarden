package journal

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaxAuthorityPeers     = 8
	MaxAuthorityIOTimeout = 5 * time.Second
)

var (
	ErrAuthorityFrame         = errors.New("invalid bounded local authority frame")
	ErrAuthorityTransportBusy = errors.New("local authority transport capacity exhausted")
)

// AuthorityTransportLimits is trusted startup input, never a request field.
// MaxPeersPerUID must be explicit, from 1 through MaxPeers. Choose a smaller
// value than MaxPeers to leave concurrency for another UID. This field is a live-peer
// ceiling, not a request-rate limit, operation grant or availability guarantee.
// Both timeouts are absolute per I/O phase and are not extended by partial reads.
// They do not interrupt the authority's trusted callback or durable disk work.
// RequestsPerUID, RateWindow and MaxRateUIDs explicitly bound admission frequency
// and the historical UID registry. They never grant an authority operation.
type AuthorityTransportLimits struct {
	MaxPeers, MaxPeersPerUID    int
	ReadTimeout, WriteTimeout   time.Duration
	RequestsPerUID, MaxRateUIDs int
	RateWindow                  time.Duration
}

// authorityPeerSlot retains only live kernel-observed identities. Admission
// history is bounded separately; neither registry uses client-supplied identity.
type authorityPeerSlot struct {
	phase authorityPeerPhase
	uid   uint32
}

type authorityPeerPhase uint8

const (
	authorityPeerReading authorityPeerPhase = iota
	authorityPeerExecuting
	authorityPeerWriting
)

// LocalAuthorityTransport owns one fixed authority and the accepted peers passed
// to ServePeer. It creates no listener, goroutine or unbounded admission queue.
// A trusted supervisor must bound its own accepts/callers, secure the socket and
// provision OS isolation. No production service activates this component yet.
type LocalAuthorityTransport struct {
	mu        sync.Mutex
	closing   bool
	peers     map[*net.UnixConn]authorityPeerSlot
	authority *LocalAuthority
	limits    AuthorityTransportLimits
	rate      []authorityRateWindow
	rateNow   func() time.Time
	rateLast  time.Time
}

func OpenLocalAuthorityTransport(c LocalAuthorityConfig, limits AuthorityTransportLimits) (*LocalAuthorityTransport, error) {
	if limits.MaxPeers < 1 || limits.MaxPeers > MaxAuthorityPeers || limits.MaxPeersPerUID < 1 || limits.MaxPeersPerUID > limits.MaxPeers || limits.ReadTimeout <= 0 || limits.ReadTimeout > MaxAuthorityIOTimeout || limits.WriteTimeout <= 0 || limits.WriteTimeout > MaxAuthorityIOTimeout || !validAuthorityRateLimits(limits) {
		return nil, ErrInvalidOptions
	}
	authority, err := OpenLocalAuthority(c)
	if err != nil {
		return nil, err
	}
	return &LocalAuthorityTransport{authority: authority, limits: limits, peers: make(map[*net.UnixConn]authorityPeerSlot, limits.MaxPeers), rate: make([]authorityRateWindow, limits.MaxRateUIDs), rateNow: time.Now}, nil
}

// register distinguishes a duplicate object, whose ownership was already
// transferred by another caller, from a fresh peer that must be closed on denial.
func (t *LocalAuthorityTransport) register(peer *net.UnixConn) (bool, error) {
	if t == nil {
		return false, ErrClosed
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.peers[peer]; exists {
		return true, ErrAuthorityTransportBusy
	}
	if t.closing || t.authority == nil || t.peers == nil {
		return false, ErrClosed
	}
	if peer == nil {
		return false, ErrCustodyAdmission
	}
	if len(t.peers) >= t.limits.MaxPeers {
		return false, ErrAuthorityTransportBusy
	}
	// SO_PEERCRED is read before any frame read or body allocation. Registration and
	// counting share the lock, so concurrent sockets cannot race past a UID cap.
	cred, err := custodyPeer(peer)
	if err != nil {
		return false, err
	}
	count := 0
	for _, slot := range t.peers {
		if slot.uid == cred.Uid {
			count++
		}
	}
	if count >= t.limits.MaxPeersPerUID {
		return false, ErrAuthorityTransportBusy
	}
	if !t.admitRate(cred.Uid) {
		return false, ErrAuthorityRateLimit
	}
	t.peers[peer] = authorityPeerSlot{phase: authorityPeerReading, uid: cred.Uid}
	return false, nil
}
func (t *LocalAuthorityTransport) phase(peer *net.UnixConn, next authorityPeerPhase) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing {
		return ErrClosed
	}
	slot, exists := t.peers[peer]
	if !exists {
		return ErrClosed
	}
	slot.phase = next
	t.peers[peer] = slot
	return nil
}
func closeAuthorityPeer(peer *net.UnixConn) error {
	if peer == nil {
		return nil
	}
	err := peer.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
func (t *LocalAuthorityTransport) release(peer *net.UnixConn) error {
	err := closeAuthorityPeer(peer)
	t.mu.Lock()
	delete(t.peers, peer)
	t.mu.Unlock()
	return err
}

// Close stops admission and closes reading/writing peers. An executing authority
// operation retains its peer for final credential checks and drains naturally;
// its response is then suppressed and the peer closed. No mutation is rolled back.
// ErrAuthorityTransportBusy means accepted calls have not yet returned. Call again
// after their completion. There is no hard deadline for trusted callbacks/disk I/O.
func (t *LocalAuthorityTransport) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	t.closing = true
	peers := make([]*net.UnixConn, 0, len(t.peers))
	active := len(t.peers) > 0
	for peer, slot := range t.peers {
		if slot.phase != authorityPeerExecuting {
			peers = append(peers, peer)
		}
	}
	authority := t.authority
	t.mu.Unlock()
	var err error
	for _, peer := range peers {
		err = errors.Join(err, closeAuthorityPeer(peer))
	}
	if authority != nil {
		err = errors.Join(err, authority.Close())
	}
	if active {
		err = errors.Join(err, ErrAuthorityTransportBusy)
	}
	return err
}

// ServePeer takes exclusive ownership of one connected Unix stream socket. Never
// use, duplicate or close it concurrently in the caller. A repeated pointer is
// rejected without closing the existing active call's peer. Every other return
// closes the passed peer, including capacity rejection and invalid input.
//
// One connection carries one four-byte big-endian length, one canonical request,
// then a required client write-half-close. Trailing bytes/pipelining fail before
// dispatch. Success replies use the same length framing; denial is a zero length
// with no body when delivery succeeds. Closing unread invalid input may reset the
// stream. Over-capacity/closing peers are closed without a reply. Error text,
// paths and authorization details are never serialized. Lost replies can follow
// durable mutations, so callers must inspect/resume rather than automatically retry.
func (t *LocalAuthorityTransport) ServePeer(peer *net.UnixConn) (err error) {
	duplicate, err := t.register(peer)
	if err != nil {
		if !duplicate {
			err = errors.Join(err, closeAuthorityPeer(peer))
		}
		return err
	}
	defer func() { err = errors.Join(err, t.release(peer)) }()
	if err = peer.SetReadDeadline(time.Now().Add(t.limits.ReadTimeout)); err != nil {
		return err
	}
	request, operationErr := readAuthorityFrame(peer)
	var response []byte
	if operationErr == nil {
		if err = t.phase(peer, authorityPeerExecuting); err != nil {
			return err
		}
		response, operationErr = t.authority.Execute(peer, request)
	}
	if err = t.phase(peer, authorityPeerWriting); err != nil {
		return errors.Join(operationErr, err)
	}
	if operationErr != nil {
		response = nil
	}
	return errors.Join(operationErr, writeAuthorityFrame(peer, response, t.limits.WriteTimeout))
}

// No ancillary buffer is offered. Linux discards received SCM_RIGHTS descriptors
// instead of installing them, and reports MSG_CTRUNC; all truncation is rejected.
// Keep every read on recvmsg, including the header, body and final EOF check.
func readAuthorityBytes(peer *net.UnixConn, buffer []byte) (int, error) {
	n, oob, flags, _, err := peer.ReadMsgUnix(buffer, nil)
	if oob != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return 0, ErrAuthorityFrame
	}
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
func readAuthorityFull(peer *net.UnixConn, buffer []byte) error {
	for len(buffer) > 0 {
		n, err := readAuthorityBytes(peer, buffer)
		if err != nil {
			return errors.Join(ErrAuthorityFrame, err)
		}
		buffer = buffer[n:]
	}
	return nil
}
func readAuthorityFrame(peer *net.UnixConn) ([]byte, error) {
	var header [4]byte
	if err := readAuthorityFull(peer, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxAuthorityRequestBytes {
		return nil, ErrAuthorityFrame
	}
	body := make([]byte, int(size))
	if err := readAuthorityFull(peer, body); err != nil {
		return nil, err
	}
	var tail [1]byte
	n, err := readAuthorityBytes(peer, tail[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.Join(ErrAuthorityFrame, err)
	}
	return body, nil
}
func writeAuthorityFrame(peer *net.UnixConn, body []byte, timeout time.Duration) error {
	size := len(body)
	if size > MaxAuthorityResponseBytes {
		return ErrAuthorityFrame
	}
	if err := peer.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(size))
	for _, part := range [][]byte{header[:], body} {
		if len(part) == 0 {
			continue
		}
		n, err := peer.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

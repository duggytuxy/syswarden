package journal

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrAuthorityClientBusy     = errors.New("local authority client is active or closing")
	ErrAuthorityService        = errors.New("local authority service identity or endpoint rejected")
	ErrAuthorityDenied         = errors.New("local authority returned a generic denial")
	ErrAuthorityOutcomeUnknown = errors.New("authority request may have executed; inspect state before further mutation")
)

// AuthorityClientConfig comes from trusted local provisioning, never a server
// reply or request. ServiceGID is the process identity at listen time; SocketGID
// is the independently selected endpoint access group. Neither supplies a grant.
type AuthorityClientConfig struct {
	Directory                         *os.File
	ServiceUID, ServiceGID, SocketGID uint32
	Timeout                           time.Duration
}

// LocalAuthorityClient owns a pinned endpoint directory and one nonqueued call.
// It uses no trust-on-first-use identity, reconnect, background worker or retry.
// Do not copy it. Construction does not connect or activate a production service.
type LocalAuthorityClient struct {
	mu              sync.Mutex
	directory       *os.File
	dirStamp, entry unix.Stat_t
	path            string
	uid, gid, group uint32
	timeout         time.Duration
	active, closing bool
	peer            *net.UnixConn
	cancel          context.CancelFunc
	closeErr        error
}

func OpenLocalAuthorityClient(config AuthorityClientConfig) (*LocalAuthorityClient, error) {
	if config.Directory == nil || config.ServiceUID > math.MaxInt32 || config.ServiceGID > math.MaxInt32 || config.SocketGID > math.MaxInt32 || config.Timeout <= 0 || config.Timeout > MaxAuthorityIOTimeout {
		return nil, ErrInvalidOptions
	}
	raw, err := config.Directory.SyscallConn()
	if err != nil {
		return nil, errors.Join(ErrAuthorityService, err)
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil || openErr != nil {
		return nil, errors.Join(ErrAuthorityService, err, openErr)
	}
	c := &LocalAuthorityClient{directory: os.NewFile(uintptr(fd), "authority-client-directory"), uid: config.ServiceUID, gid: config.ServiceGID, group: config.SocketGID, timeout: config.Timeout, path: "/proc/self/fd/" + strconv.Itoa(fd) + "/" + AuthoritySocketName}
	c.dirStamp, c.entry, err = c.inspect()
	if err != nil {
		return nil, errors.Join(err, c.Close())
	}
	return c, nil
}
func (c *LocalAuthorityClient) inspect() (unix.Stat_t, unix.Stat_t, error) {
	var dir, entry unix.Stat_t
	fd := int(c.directory.Fd())
	err := unix.Fstat(fd, &dir)
	if err != nil || dir.Mode != unix.S_IFDIR|0750 || dir.Uid != c.uid || dir.Gid != c.group || dir.Nlink == 0 {
		return dir, entry, errors.Join(ErrAuthorityService, err)
	}
	if err = noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) }); err != nil {
		return dir, entry, errors.Join(ErrAuthorityService, err)
	}
	err = unix.Fstatat(fd, AuthoritySocketName, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || entry.Mode != unix.S_IFSOCK|0660 || entry.Uid != c.uid || entry.Gid != c.group || entry.Nlink != 1 {
		return dir, entry, errors.Join(ErrAuthorityService, err)
	}
	err = noAuthorityACL(func(name string) (int, error) { return unix.Lgetxattr(c.path, name, nil) })
	if err != nil {
		return dir, entry, errors.Join(ErrAuthorityService, err)
	}
	return dir, entry, nil
}
func (c *LocalAuthorityClient) attest() error {
	dir, entry, err := c.inspect()
	if err != nil || dir.Dev != c.dirStamp.Dev || dir.Ino != c.dirStamp.Ino || entry.Dev != c.entry.Dev || entry.Ino != c.entry.Ino || entry.Ctim != c.entry.Ctim || entry.Mtim != c.entry.Mtim {
		return errors.Join(ErrAuthorityService, err)
	}
	return nil
}
func (c *LocalAuthorityClient) begin() (context.Context, error) {
	if c == nil {
		return nil, ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.directory == nil {
		return nil, ErrClosed
	}
	if c.active {
		return nil, ErrAuthorityClientBusy
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	c.active, c.cancel = true, cancel
	return ctx, nil
}
func (c *LocalAuthorityClient) setPeer(peer *net.UnixConn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return ErrClosed
	}
	c.peer = peer
	return nil
}
func (c *LocalAuthorityClient) closeDirectory() error {
	if c.directory != nil {
		c.closeErr = errors.Join(c.closeErr, c.directory.Close())
		c.directory = nil
	}
	return c.closeErr
}
func (c *LocalAuthorityClient) finish() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cancel()
	c.cancel = nil
	c.peer = nil
	c.active = false
	if c.closing {
		return errors.Join(ErrClosed, c.closeDirectory())
	}
	return nil
}

// Close cancels dialing or active I/O without waiting for a remote durable write.
// An active call returns no successful result after close. Busy means that call
// still owns the directory until its deferred cleanup. No socket entry is removed.
func (c *LocalAuthorityClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closing = true
	if c.cancel != nil {
		c.cancel()
	}
	if c.active {
		return errors.Join(ErrAuthorityClientBusy, closeAuthorityPeer(c.peer))
	}
	return c.closeDirectory()
}

// Call sends exactly one canonical request on a fresh connection to the pinned
// endpoint. The expected kernel service UID/GID is checked before any send.
// The deadline covers dial, write, response and EOF. All failures return no bytes;
// errors after starting transmission also carry ErrAuthorityOutcomeUnknown,
// including a generic denial. Such an error must never trigger automatic replay.
func (c *LocalAuthorityClient) Call(data []byte) (response []byte, err error) {
	ctx, err := c.begin()
	if err != nil {
		return nil, err
	}
	sent := false
	defer func() {
		err = errors.Join(err, c.finish())
		if err != nil {
			response = nil
			if sent {
				err = errors.Join(ErrAuthorityOutcomeUnknown, err)
			}
		}
	}()
	request, err := decodeAuthorityRequest(data)
	if err != nil {
		return nil, err
	}
	// The caller must not race mutations of data with this copy. Owned bytes are
	// used for both validation and transmission after entry into the single slot.
	data, err = encodeClientRequest(request)
	if err != nil {
		return nil, err
	}
	if err = c.attest(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return nil, err
	}
	peer, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.Join(ErrAuthorityService, conn.Close())
	}
	defer func() { err = errors.Join(err, closeAuthorityPeer(peer)) }()
	if err = c.setPeer(peer); err != nil {
		return nil, err
	}
	if err = peer.SetDeadline(deadline); err != nil {
		return nil, err
	}
	cred, err := custodyPeer(peer)
	if err != nil || cred.Uid != c.uid || cred.Gid != c.gid {
		return nil, errors.Join(ErrAuthorityService, err)
	}
	if err = c.attest(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	size := len(data)
	if size == 0 || size > MaxAuthorityRequestBytes {
		return nil, ErrAuthorityRequest
	}
	sent = true
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(size))
	for _, part := range [][]byte{header[:], data} {
		n, writeErr := peer.Write(part)
		if writeErr != nil {
			return nil, writeErr
		}
		if n != len(part) {
			return nil, io.ErrShortWrite
		}
	}
	if err = peer.CloseWrite(); err != nil {
		return nil, err
	}
	response, err = readAuthorityReply(peer)
	if err != nil {
		return nil, err
	}
	if err = c.attest(); err != nil {
		return nil, err
	}
	if err = validateAuthorityReply(response, request); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return response, nil
}
func readAuthorityReply(peer *net.UnixConn) ([]byte, error) {
	var header [4]byte
	if err := readAuthorityFull(peer, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxAuthorityResponseBytes {
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
	if size == 0 {
		return nil, ErrAuthorityDenied
	}
	return body, nil
}

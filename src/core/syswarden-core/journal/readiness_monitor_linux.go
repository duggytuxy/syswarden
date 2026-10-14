package journal

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const MaxAuthorityReadinessWait = 30 * time.Second
const authorityReadinessInterval = 25 * time.Millisecond

// AuthorityReadinessChannel owns one unnamed pipe for one launch attempt. The
// caller serializes its methods, never copies it, and closes it after use. Only
// context cancellation may run concurrently with Wait. No goroutine is started.
type AuthorityReadinessChannel struct {
	reader, writer *os.File
	waited         bool
	writerError    error
}

// NewAuthorityReadinessChannel creates exactly two nonblocking, close-on-exec
// handles. There is no named file, blocking fallback or process launch. The
// caller owns the channel and must Close it even if process creation fails.
func NewAuthorityReadinessChannel() (*AuthorityReadinessChannel, error) {
	return newAuthorityReadinessChannel(unix.Pipe2)
}

func newAuthorityReadinessChannel(pipe func([]int, int) error) (*AuthorityReadinessChannel, error) {
	if pipe == nil {
		return nil, ErrAuthorityReadiness
	}
	var fds [2]int
	if err := pipe(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return nil, errors.Join(ErrAuthorityReadiness, err)
	}
	return &AuthorityReadinessChannel{
		reader: os.NewFile(uintptr(fds[0]), "authority-ready-reader"),
		writer: os.NewFile(uintptr(fds[1]), "authority-ready-writer"),
	}, nil
}

// Writer borrows the write end for the child's readiness descriptor. Do not
// write, change flags or close this borrowed handle. After Start returns, call
// CloseWriter; the child must be its sole remaining recipient. Wait also closes
// this local writer. The pointer becomes unusable after either close operation.
func (c *AuthorityReadinessChannel) Writer() *os.File {
	if c == nil || c.waited {
		return nil
	}
	return c.writer
}

// CloseWriter releases only the supervisor's write end. It does not close any
// copy inherited by a child. Repeated calls keep the same result; an earlier close failure remains fatal.
func (c *AuthorityReadinessChannel) CloseWriter() error {
	if c == nil {
		return nil
	}
	if c.writer == nil {
		return c.writerError
	}
	writer := c.writer
	c.writer = nil
	c.writerError = writer.Close()
	return c.writerError
}

// Close attempts both owned closes, including after a failure. It never stops a
// child or touches persistent evidence. Call it only after Wait has returned.
func (c *AuthorityReadinessChannel) Close() error {
	if c == nil {
		return nil
	}
	err := c.CloseWriter()
	reader := c.reader
	c.reader = nil
	c.waited = true
	if reader != nil {
		err = errors.Join(err, reader.Close())
	}
	return err
}

// Wait consumes this launch attempt exactly once. It accepts one ASCII R, with
// no other byte present in that read. EOF, malformed data and uncertain I/O fail.
// Cancellation and the 30-second ceiling bound waiting, not process shutdown.
// The caller retains the reader until Close, must observe child exit separately,
// and must never infer current health or an operation grant from a ready result.
func (c *AuthorityReadinessChannel) Wait(ctx context.Context) error {
	if c == nil || c.reader == nil || c.waited {
		return ErrAuthorityReadiness
	}
	c.waited = true
	if err := c.CloseWriter(); err != nil {
		return errors.Join(ErrAuthorityReadiness, err)
	}
	if ctx == nil {
		return ErrInvalidOptions
	}
	bounded, cancel := context.WithTimeout(ctx, MaxAuthorityReadinessWait)
	defer cancel()
	return receiveAuthorityReadiness(bounded, func(b []byte) (int, error) {
		return readAuthorityReadiness(c.reader, b)
	})
}

// Hold the Go descriptor lifetime during every metadata check and raw read.
// Never make a caller-supplied blocking descriptor nonblocking as a repair.
func readAuthorityReadiness(file *os.File, b []byte) (int, error) {
	if file == nil {
		return 0, ErrAuthorityReadiness
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, errors.Join(ErrAuthorityReadiness, err)
	}
	n := 0
	var operation error
	err = raw.Control(func(fd uintptr) {
		flags, e := unix.FcntlInt(fd, unix.F_GETFL, 0)
		var st unix.Stat_t
		if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_NONBLOCK == 0 || flags&unix.O_PATH != 0 || unix.Fstat(int(fd), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
			operation = ErrAuthorityReadiness
			return
		}
		descriptor, e := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if e != nil || descriptor&unix.FD_CLOEXEC == 0 {
			operation = ErrAuthorityReadiness
			return
		}
		n, operation = unix.Read(int(fd), b)
	})
	return n, errors.Join(err, operation)
}

func receiveAuthorityReadiness(ctx context.Context, read func([]byte) (int, error)) error {
	if ctx == nil || read == nil {
		return ErrInvalidOptions
	}
	// A fixed two-byte buffer detects an already queued overlong notification.
	// Later bytes and process liveness require independent supervision.
	var b [2]byte
	timer := time.NewTimer(authorityReadinessInterval)
	timer.Stop()
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := read(b[:])
		if canceled := ctx.Err(); canceled != nil {
			return canceled
		}
		if err == nil {
			if n == 1 && b[0] == 'R' {
				return nil
			}
			return ErrAuthorityReadiness
		}
		if n > 0 || (!errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR)) {
			return errors.Join(ErrAuthorityReadiness, err)
		}
		// Pace both empty reads and interrupted syscalls, without spinning or
		// a cancellation watcher that could outlive this wait.
		timer.Reset(authorityReadinessInterval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

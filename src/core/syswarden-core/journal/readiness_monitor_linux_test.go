package journal

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAuthorityReadinessMonitor(t *testing.T) { testAuthorityReadinessMonitor(t) }

func testAuthorityReadinessMonitor(t *testing.T) {
	for _, kind := range []string{"ready", "ready-then-eof", "eof", "wrong-byte", "extra-byte", "canceled", "deadline", "nil-context", "nil-channel", "zero-channel", "closed-channel", "closed-reader", "blocking-reader", "writer-as-reader", "regular-reader", "unsealed-reader", "second-wait", "close-failure", "earlier-close-failure", "cancel-during-wait"} {
		t.Run(kind, func(t *testing.T) {
			c, err := NewAuthorityReadinessChannel()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			peer := duplicateReadinessWriter(t, c.Writer())
			defer func() { _ = peer.Close() }()
			target := c
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var want error = ErrAuthorityReadiness
			switch kind {
			case "ready", "ready-then-eof", "second-wait":
				if _, err := peer.Write([]byte{'R'}); err != nil {
					t.Fatal(err)
				}
				if kind == "ready-then-eof" {
					_ = peer.Close()
				}
				want = nil
			case "eof":
				_ = peer.Close()
			case "wrong-byte":
				_, err = peer.Write([]byte{'X'})
			case "extra-byte":
				_, err = peer.Write([]byte("RR"))
			case "canceled":
				_, err = peer.Write([]byte{'R'})
				cancel()
				want = context.Canceled
			case "deadline":
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
				defer cancel()
				want = context.DeadlineExceeded
			case "nil-context":
				ctx = nil
				want = ErrInvalidOptions
			case "nil-channel":
				target = nil
			case "zero-channel":
				target = &AuthorityReadinessChannel{}
			case "closed-channel":
				err = c.Close()
			case "closed-reader":
				err = c.reader.Close()
			case "blocking-reader":
				err = unix.SetNonblock(int(c.reader.Fd()), false)
			case "unsealed-reader":
				var raw syscall.RawConn
				raw, err = c.reader.SyscallConn()
				if err == nil {
					err = raw.Control(func(fd uintptr) {
						_, e := unix.FcntlInt(fd, unix.F_SETFD, 0)
						if e != nil {
							t.Error(e)
						}
					})
				}
			case "writer-as-reader":
				_ = c.reader.Close()
				c.reader = duplicateReadinessWriter(t, peer)
			case "regular-reader":
				_ = c.reader.Close()
				c.reader, err = os.CreateTemp(t.TempDir(), "not-a-pipe")
			case "close-failure":
				err = c.writer.Close()
			case "earlier-close-failure":
				err = c.writer.Close()
				if c.CloseWriter() == nil {
					t.Fatal("lost prior close failure")
				}
			case "cancel-during-wait":
				// Cancel from another goroutine without touching channel state.
				finished := make(chan struct{})
				go func() { time.Sleep(time.Millisecond); cancel(); close(finished) }()
				defer func() { <-finished }()
				want = context.Canceled
			}
			if err != nil {
				t.Fatal(err)
			}
			err = target.Wait(ctx)
			if want == nil && err != nil || want != nil && !errors.Is(err, want) {
				t.Fatalf("wait = %v, want %v", err, want)
			}
			if kind == "second-wait" {
				if !errors.Is(c.Wait(context.Background()), ErrAuthorityReadiness) {
					t.Fatal("reused launch attempt")
				}
			}
			if target != nil && target.Writer() != nil {
				t.Fatal("writer survived wait")
			}
		})
	}
}

func duplicateReadinessWriter(t *testing.T, file *os.File) *os.File {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	var operation error
	err = raw.Control(func(source uintptr) { fd, operation = unix.FcntlInt(source, unix.F_DUPFD_CLOEXEC, 0) })
	if err != nil || operation != nil {
		t.Fatal(err, operation)
	}
	return os.NewFile(uintptr(fd), "readiness-child-copy")
}

func TestAuthorityReadinessChannelOwnership(t *testing.T) {
	c, err := NewAuthorityReadinessChannel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var metadata [2]unix.Stat_t
	for i, file := range []*os.File{c.reader, c.Writer()} {
		raw, err := file.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		if err = raw.Control(func(fd uintptr) {
			flags, e := unix.FcntlInt(fd, unix.F_GETFL, 0)
			seal, se := unix.FcntlInt(fd, unix.F_GETFD, 0)
			if e != nil || se != nil || flags&unix.O_NONBLOCK == 0 || flags&unix.O_ACCMODE != i || seal&unix.FD_CLOEXEC == 0 || unix.Fstat(int(fd), &metadata[i]) != nil || metadata[i].Mode&unix.S_IFMT != unix.S_IFIFO {
				t.Error("unsafe pipe metadata")
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	if metadata[0].Dev != metadata[1].Dev || metadata[0].Ino != metadata[1].Ino {
		t.Fatal("unrelated endpoints")
	}
	reader, writer := c.reader, c.Writer()
	// Even an independently closed writer must not prevent reader release.
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if c.Close() == nil {
		t.Fatal("lost writer close failure")
	}
	if _, err := reader.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("reader survived failed close", err)
	}
	if !errors.Is(c.Close(), os.ErrClosed) || c.Writer() != nil {
		t.Fatal("close not idempotent")
	}
	var absent *AuthorityReadinessChannel
	if absent.Close() != nil || absent.CloseWriter() != nil || absent.Writer() != nil {
		t.Fatal("nil channel not harmless")
	}
}

func TestAuthorityReadinessPipeFailure(t *testing.T) {
	for _, failure := range []error{unix.ENOSYS, unix.EPERM, unix.EINVAL, unix.EMFILE} {
		calls := 0
		c, err := newAuthorityReadinessChannel(func(_ []int, flags int) error {
			calls++
			if flags != unix.O_NONBLOCK|unix.O_CLOEXEC {
				t.Error("weaker creation flags")
			}
			return failure
		})
		if c != nil || calls != 1 || !errors.Is(err, failure) || !errors.Is(err, ErrAuthorityReadiness) {
			t.Fatal("creation fallback or hidden failure", err)
		}
	}
	if c, err := newAuthorityReadinessChannel(nil); c != nil || !errors.Is(err, ErrAuthorityReadiness) {
		t.Fatal("nil pipe operation")
	}
}

func TestAuthorityReadinessReceiveFailuresAndPacing(t *testing.T) {
	for _, kind := range []string{"eof", "partial-error", "fatal", "interrupted", "empty", "cancel-on-read"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			started := time.Now()
			err := receiveAuthorityReadiness(ctx, func(b []byte) (int, error) {
				calls++
				if len(b) != 2 {
					t.Fatal("unbounded read")
				}
				b[0] = 'R'
				if calls > 1 {
					return 1, nil
				}
				switch kind {
				case "eof":
					return 0, nil
				case "partial-error":
					return 1, unix.EINTR
				case "fatal":
					return 0, unix.EIO
				case "interrupted":
					return -1, unix.EINTR
				case "empty":
					return -1, unix.EAGAIN
				case "cancel-on-read":
					cancel()
					return 1, nil
				}
				panic("unknown test")
			})
			if kind == "empty" || kind == "interrupted" {
				if err != nil || calls != 2 || time.Since(started) < authorityReadinessInterval {
					t.Fatal("retry was not bounded and paced", err)
				}
			} else if kind == "cancel-on-read" {
				if !errors.Is(err, context.Canceled) || calls != 1 {
					t.Fatal("cancellation lost", err)
				}
			} else if !errors.Is(err, ErrAuthorityReadiness) || calls != 1 {
				t.Fatal("failed I/O accepted or retried", err)
			}
		})
	}
	if !errors.Is(receiveAuthorityReadiness(context.Background(), nil), ErrInvalidOptions) {
		t.Fatal("nil read operation accepted")
	}
}

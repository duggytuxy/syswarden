package journal

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var ErrAuthorityReadiness = errors.New("invalid local authority readiness channel")

// AuthorityProcessConfig contains explicitly inherited startup descriptors and
// independent trusted providers. The caller retains and closes all descriptors.
// Readiness is a nonblocking write-only pipe/FIFO; it receives one byte 'R' only
// after protected startup. It is not a health verdict or an operation grant.
type AuthorityProcessConfig struct {
	Launch, State, Endpoint, Readiness *os.File
	LaunchSHA256                       string
	Now                                func() time.Time
	Recovery                           CustodyRecoveryAuthorizer
	Administrator                      PolicyAdministrationAuthorizer
}

// RunAuthorityProcess starts one authority and drains it on context cancellation.
// It creates no accounts, directories or trust. Cancellation before startup does
// not mutate storage or emit readiness. Cancellation after startup stops new
// admission and waits for approved writes; no hard shutdown deadline is promised.
// Failure never retries, repairs or removes uncertain evidence. A successful
// return means full local drain and cleanup, not native or release acceptance.
func RunAuthorityProcess(ctx context.Context, c AuthorityProcessConfig) error {
	if ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authorityReadiness(c.Readiness, false); err != nil {
		return err
	}
	s, err := OpenAuthorityFromLaunch(c.Launch, c.LaunchSHA256, c.State, c.Endpoint, c.Now, c.Recovery, c.Administrator)
	if err != nil {
		return err
	}
	err = s.serveContext(ctx, func() error { return authorityReadiness(c.Readiness, true) })
	return errors.Join(err, s.Close())
}

// Validate again at notification. Use a raw nonblocking write rather than the
// os.File poller, so a full or disconnected pipe cannot delay service startup.
// SyscallConn holds the descriptor alive; its flags and ownership are not changed.
func authorityReadiness(file *os.File, notify bool) error {
	if file == nil {
		return ErrAuthorityReadiness
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return ErrAuthorityReadiness
	}
	var failure error
	err = raw.Control(func(fd uintptr) {
		flags, e := unix.FcntlInt(fd, unix.F_GETFL, 0)
		var st unix.Stat_t
		if e != nil || flags&unix.O_ACCMODE != unix.O_WRONLY || flags&unix.O_NONBLOCK == 0 || unix.Fstat(int(fd), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
			failure = ErrAuthorityReadiness
			return
		}
		if notify {
			n, e := unix.Write(int(fd), []byte{'R'})
			if e != nil || n != 1 {
				failure = errors.Join(ErrAuthorityReadiness, e)
			}
		}
	})
	return errors.Join(err, failure)
}

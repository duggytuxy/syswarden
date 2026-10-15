package journal

import (
	"context"
	"errors"
	"os"
)

var ErrAuthorityChildLifecycle = errors.New("authority child lifecycle did not complete successfully")

// AuthorityChildOutcome separates startup, requested termination, observed exit
// and handle cleanup. Readiness is not ongoing health. Closed means handle
// cleanup succeeded, not that retained private evidence is safe to remove.
// A nil State means the caller MUST retain the child and observe/reap it later.
type AuthorityChildOutcome struct {
	Ready, StopRequested, Closed bool
	State                        *os.ProcessState
}

// SuperviseAuthorityChild observes one already owned child until cancellation
// requests graceful termination or a failure occurs. It does not create, restart,
// force-kill or recover a child. Every admitted call is single-use, including
// after failure. The caller exclusively owns lifecycle operations during this
// call and MUST retain child on return until its exit is observed and it closes.
//
// Healthy observation can continue indefinitely. Shutdown uses one fresh bounded
// observation window, independent of the canceled run context. Its timeout leaves
// the child owned and unclosed; it does not establish drain or authorize SIGKILL.
// No goroutine is left behind and no error is replaced by successful cleanup.
func SuperviseAuthorityChild(ctx context.Context, child *AuthorityChild) (AuthorityChildOutcome, error) {
	if ctx == nil || child == nil {
		return AuthorityChildOutcome{}, ErrAuthorityChildLifecycle
	}
	child.mu.Lock()
	if child.lifecycleUsed || child.closed || child.state != nil || child.process == nil {
		child.mu.Unlock()
		return AuthorityChildOutcome{}, ErrAuthorityChildLifecycle
	}
	child.lifecycleUsed = true
	startErr := child.startErr
	child.mu.Unlock()
	out, err := superviseAuthorityChild(ctx, child)
	return out, errors.Join(err, startErr)
}

// The private interface permits deterministic observation-failure tests. The
// public API accepts only the actual owned child, not a client-selected provider.
type authorityChildLifecycle interface {
	AwaitReady(context.Context) error
	RequestStop() error
	Wait(context.Context) (*os.ProcessState, error)
	Close() error
}

func superviseAuthorityChild(ctx context.Context, child authorityChildLifecycle) (out AuthorityChildOutcome, result error) {
	finish := func() (AuthorityChildOutcome, error) {
		if out.State != nil {
			err := child.Close()
			out.Closed = err == nil
			result = errors.Join(result, err)
		}
		if result != nil || !out.Ready || !out.StopRequested || out.State == nil || !out.State.Success() || !out.Closed {
			result = errors.Join(ErrAuthorityChildLifecycle, result)
		}
		return out, result
	}
	result = child.AwaitReady(ctx)
	out.Ready = result == nil
	if out.Ready {
		for ctx.Err() == nil {
			var err error
			out.State, err = child.Wait(ctx)
			if out.State != nil {
				// Any exit observed before our stop request is unexpected, even zero.
				result = errors.Join(ErrAuthorityChildLifecycle, err)
				return finish()
			}
			if err == context.DeadlineExceeded && ctx.Err() == nil {
				// Only the exact bounded observation timeout can be repeated.
				// Joined storage/kernel errors must never disappear in a retry.
				continue
			}
			if err == nil || ctx.Err() == nil || err != ctx.Err() {
				result = errors.Join(ErrAuthorityChildLifecycle, err)
			}
			break
		}
	}
	stopErr := child.RequestStop()
	out.StopRequested = stopErr == nil
	result = errors.Join(result, stopErr)
	drain, cancel := context.WithTimeout(context.Background(), MaxAuthorityChildObservation)
	defer cancel()
	var waitErr error
	out.State, waitErr = child.Wait(drain)
	result = errors.Join(result, waitErr)
	return finish()
}

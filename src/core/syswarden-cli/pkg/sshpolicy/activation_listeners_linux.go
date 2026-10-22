//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"
)

// A listener replacement observation is not a policy-consumption receipt or a
// successful login. It only rejects the old socket generation after dispatch.
// The reader holds the original process lease and closes socket duplicates
// inside each read, never across a signal, delay or manager query.
type sshListenerReload struct {
	expected  []netip.AddrPort
	namespace uint64
	before    []sshListenerSocket
	read      func(context.Context) ([]sshListenerSocket, error)
}

func prepareSSHListenerReload(ctx context.Context, expected []netip.AddrPort, namespace uint64,
	read func(context.Context) ([]sshListenerSocket, error)) (*sshListenerReload, error) {
	if ctx == nil || read == nil {
		return nil, ErrInventoryUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := read(ctx)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(matchSSHEndpoints(expected, before, namespace), ctx.Err()); err != nil {
		return nil, err
	}
	l := &sshListenerReload{expected: slices.Clone(expected), namespace: namespace, before: slices.Clone(before), read: read}
	if _, err := l.replaced(l.before); err != nil {
		return nil, err
	}
	if err := l.check(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *sshListenerReload) check(ctx context.Context) error {
	if l == nil || ctx == nil || l.read == nil {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), matchSSHEndpoints(l.expected, l.before, l.namespace)); err != nil {
		return err
	}
	current, err := l.read(ctx)
	if err != nil || !slices.Equal(l.before, current) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return ctx.Err()
}

// Kernel socket cookies, scoped to the verified network namespace, identify
// generations. FD numbers and recycled inode numbers alone do not. Reused
// cookies with altered object metadata are ambiguous and never pending.
func (l *sshListenerReload) replaced(current []sshListenerSocket) (bool, error) {
	if len(current) == 0 {
		return false, nil
	}
	if err := matchSSHEndpoints(l.expected, current, l.namespace); err != nil {
		return false, err
	}
	old := make(map[uint64]sshListenerSocket)
	for _, socket := range l.before {
		socket.FD = 0
		if prior, exists := old[socket.Cookie]; exists && prior != socket {
			return false, ErrInventoryChanged
		}
		old[socket.Cookie] = socket
	}
	retained := false
	seen := make(map[uint64]sshListenerSocket)
	for _, socket := range current {
		socket.FD = 0
		if prior, exists := seen[socket.Cookie]; exists && prior != socket {
			return false, ErrInventoryChanged
		}
		seen[socket.Cookie] = socket
		if prior, exists := old[socket.Cookie]; exists {
			if prior != socket {
				return false, ErrInventoryChanged
			}
			retained = true
		}
	}
	return !retained, nil
}

func pauseSSHListenerObservation(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func (l *sshListenerReload) wait(ctx context.Context, guard func() error,
	pause func(context.Context) error) error {
	if l == nil || ctx == nil || guard == nil || pause == nil || l.read == nil {
		return ErrInventoryUnsafe
	}
	if err := matchSSHEndpoints(l.expected, l.before, l.namespace); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var candidate []sshListenerSocket
	// Bound both elapsed time and samples. Never replay a request to obtain a
	// better observation. An unreadable/ambiguous sample fails immediately.
	for range 150 {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return err
		}
		current, err := l.read(ctx)
		if err := errors.Join(err, ctx.Err(), guard()); err != nil {
			return err
		}
		replaced, err := l.replaced(current)
		if err != nil {
			return err
		}
		if replaced {
			if slices.Equal(candidate, current) {
				return errors.Join(ctx.Err(), guard())
			}
			candidate = slices.Clone(current)
		} else {
			candidate = nil
		}
		if err := pause(ctx); err != nil {
			return err
		}
	}
	return errors.New("SSH listener replacement was not observed within the bounded window; runtime recovery remains required")
}

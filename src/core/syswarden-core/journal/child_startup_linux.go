package journal

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var ErrAuthorityChildStartup = errors.New("invalid protected authority child startup")

// AuthorityChildInputs supplies independently trusted parent handles, a trusted
// read/write null device and three approved digests. All handles remain borrowed.
// The caller serializes handoff against their modification and closure. This is
// not a pathname locator, provisioning record or authorization to deploy.
type AuthorityChildInputs struct {
	Inputs, StateParent, EndpointParent, Null *os.File
	LaunchSHA256, ImageSHA256, LauncherSHA256 string
}

// StartAuthorityChildFromInputs composes complete protected acquisition and exact
// child creation, releasing temporary acquired inputs after handoff. Success is
// creation, not readiness. Always retain a non-nil child even alongside an error:
// post-creation cleanup failure must not discard its process or exit evidence.
// This leaves parent identity, limits, borrowed handles and source files intact.
// It does not discover trust, provision resources, retry, wait or send a signal.
func StartAuthorityChildFromInputs(c AuthorityChildInputs) (*AuthorityChild, error) {
	if c.Inputs == nil || c.StateParent == nil || c.EndpointParent == nil || c.Null == nil || !validRecoveryApproval(c.LaunchSHA256) || !validRecoveryApproval(c.ImageSHA256) || !validRecoveryApproval(c.LauncherSHA256) {
		return nil, ErrAuthorityChildStartup
	}
	u, e, s := unix.Getresuid()
	g, eg, sg := unix.Getresgid()
	if u != 0 || e != 0 || s != 0 || g != 0 || eg != 0 || sg != 0 {
		return nil, ErrAuthorityChildStartup
	}
	return startAuthorityChildFromInputs(c, func() (*AuthoritySupervisorBundle, error) {
		return OpenAuthoritySupervisorBundle(c.Inputs, c.StateParent, c.EndpointParent, c.LaunchSHA256, c.ImageSHA256, c.LauncherSHA256)
	}, StartAuthorityChild)
}

// The private seams exercise partial acquisition and post-start failures without
// adding configurable acquisition, process factories or bypasses to the API.
func startAuthorityChildFromInputs(c AuthorityChildInputs, acquire func() (*AuthoritySupervisorBundle, error), start func(AuthorityChildConfig) (*AuthorityChild, error)) (child *AuthorityChild, result error) {
	if acquire == nil || start == nil {
		return nil, ErrAuthorityChildStartup
	}
	bundle, err := acquire()
	defer func() {
		result = errors.Join(result, bundle.Close())
		if result != nil {
			result = errors.Join(ErrAuthorityChildStartup, result)
		}
		if child != nil {
			// The child has not escaped to the caller yet. Keep this composition's
			// uncertainty visible in readiness, every subsequent wait and final close.
			child.startErr = errors.Join(child.startErr, result)
		}
	}()
	if err != nil || bundle == nil {
		return nil, errors.Join(ErrAuthorityChildStartup, err)
	}
	child, result = start(AuthorityChildConfig{Bundle: bundle.Bundle, Launcher: bundle.Launcher, Null: c.Null, LaunchSHA256: c.LaunchSHA256, ImageSHA256: c.ImageSHA256, LauncherSHA256: c.LauncherSHA256})
	if child == nil && result == nil {
		result = ErrAuthorityChildStartup
	}
	return child, result
}

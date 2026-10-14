package journal

import (
	"errors"
	"os"
)

const authorityLauncherInputName = "syswarden-authority-launch"

var ErrAuthoritySupervisorBundle = errors.New("invalid protected authority supervisor bundle")

// AuthoritySupervisorBundle owns the complete launch bundle and a separately
// approved, immutable launcher image. It owns no parent input, null device or
// child process. Serialize use and Close; do not copy or replace its fields.
type AuthoritySupervisorBundle struct {
	Bundle   *AuthorityLaunchBundle
	Launcher *os.File
}

// OpenAuthoritySupervisorBundle acquires all five held resources for a root
// child launcher from independently trusted parents and three approved digests.
// The input parent contains launch.json, syswarden-authority and the fixed
// syswarden-authority-launch name. Existing ancestry, namespace, metadata,
// constrained-resolution and snapshot contracts remain mandatory. It discovers
// no trust, approves no dynamic dependencies and starts no process. The caller
// retains and serializes the parents; a failure returns no partial bundle.
func OpenAuthoritySupervisorBundle(inputs, stateParent, endpointParent *os.File, launchDigest, imageDigest, launcherDigest string) (*AuthoritySupervisorBundle, error) {
	if inputs == nil || stateParent == nil || endpointParent == nil || !validRecoveryApproval(launchDigest) || !validRecoveryApproval(imageDigest) || !validRecoveryApproval(launcherDigest) {
		return nil, ErrAuthoritySupervisorBundle
	}
	raw, err := inputs.SyscallConn()
	if err != nil {
		return nil, errors.Join(ErrAuthoritySupervisorBundle, err)
	}
	var bundle *AuthoritySupervisorBundle
	var operation error
	err = raw.Control(func(fd uintptr) {
		bundle, operation = openAuthoritySupervisorBundle(int(fd), launcherDigest, func() (*AuthorityLaunchBundle, error) {
			return OpenAuthorityLaunchBundle(inputs, stateParent, endpointParent, launchDigest, imageDigest)
		})
	})
	if err != nil || operation != nil || bundle == nil {
		return nil, errors.Join(ErrAuthoritySupervisorBundle, err, operation, bundle.Close())
	}
	return bundle, nil
}

func openAuthoritySupervisorBundle(directory int, launcherDigest string, acquire func() (*AuthorityLaunchBundle, error)) (result *AuthoritySupervisorBundle, err error) {
	if acquire == nil || !validRecoveryApproval(launcherDigest) {
		return nil, ErrAuthoritySupervisorBundle
	}
	before, err := attestAuthorityInputDirectory(directory)
	if err != nil {
		return nil, err
	}
	source, stamp, err := openAuthorityInput(directory, authorityLauncherInputName, true)
	if err != nil {
		return nil, err
	}
	owned := &AuthoritySupervisorBundle{}
	// Retain every cleanup failure. No partial acquisition escapes, even when
	// the final source close fails after otherwise successful preparation.
	defer func() {
		err = errors.Join(err, source.Close())
		if err != nil {
			err = errors.Join(ErrAuthoritySupervisorBundle, err, owned.Close())
			result = nil
		}
	}()
	owned.Launcher, err = SnapshotAuthorityExecutable(source, launcherDigest)
	if err != nil {
		return nil, err
	}
	if _, err = InspectAuthorityExecutableImage(owned.Launcher, launcherDigest); err != nil {
		return nil, err
	}
	owned.Bundle, err = acquire()
	if err != nil || owned.Bundle == nil {
		return nil, errors.Join(ErrAuthoritySupervisorBundle, err)
	}
	after, err := attestAuthorityInputDirectory(directory)
	if err != nil || !sameStamp(before, after) || !authorityInputStillBound(directory, authorityLauncherInputName, source, stamp) {
		return nil, errors.Join(ErrAuthoritySupervisorBundle, err)
	}
	return owned, nil
}

// Close consumes both fields and attempts every close, including after one
// handle failed. Nil or repeated closure is harmless. It does not stop a child,
// delete source files, release a service lease, or retire runtime evidence.
func (b *AuthoritySupervisorBundle) Close() error {
	if b == nil {
		return nil
	}
	bundle, launcher := b.Bundle, b.Launcher
	b.Bundle, b.Launcher = nil, nil
	result := bundle.Close()
	if launcher != nil {
		result = errors.Join(result, launcher.Close())
	}
	return result
}

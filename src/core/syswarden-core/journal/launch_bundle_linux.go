package journal

import (
	"errors"
	"os"
)

var ErrAuthorityLaunchBundle = errors.New("invalid protected authority launch bundle")

// AuthorityLaunchBundle owns four independent CLOEXEC descriptors. Launch and
// Image are immutable snapshots; State and Endpoint retain existing directories.
// The owner must serialize use and Close, must not copy the bundle or replace its
// fields, and must not close it until descriptor handoff has completed.
// This contains no readiness channel, process, approval or active storage lease.
type AuthorityLaunchBundle struct {
	Launch, Image, State, Endpoint *os.File
}

// OpenAuthorityLaunchBundle acquires every protected startup resource or returns
// no bundle. Caller-owned parent descriptors remain open on both success and
// failure. The independently approved launch and image digests and trusted parent
// provenance are required by the underlying acquisition contracts. A runtime
// failure closes both snapshots and all acquired children without changing files.
// Success does not approve deployment or replace the service's startup checks.
func OpenAuthorityLaunchBundle(inputs, stateParent, endpointParent *os.File, launchDigest, imageDigest string) (*AuthorityLaunchBundle, error) {
	if inputs == nil || stateParent == nil || endpointParent == nil {
		return nil, ErrAuthorityLaunchBundle
	}
	launch, image, err := OpenAuthorityLaunchInputs(inputs, launchDigest, imageDigest)
	if err != nil {
		return nil, ErrAuthorityLaunchBundle
	}
	bundle := &AuthorityLaunchBundle{Launch: launch, Image: image}
	bundle.State, bundle.Endpoint, err = OpenAuthorityRuntimeDirectories(stateParent, endpointParent, launch, launchDigest)
	if err != nil {
		_ = bundle.Close()
		return nil, ErrAuthorityLaunchBundle
	}
	return bundle, nil
}

// Close releases every owned handle even if one close fails. The bundle is
// consumed before closing, so repeated or nil-receiver closure is harmless.
// It never removes an endpoint, retires evidence or shuts down a running process.
func (b *AuthorityLaunchBundle) Close() error {
	if b == nil {
		return nil
	}
	files := [4]*os.File{b.Launch, b.Image, b.State, b.Endpoint}
	b.Launch, b.Image, b.State, b.Endpoint = nil, nil, nil, nil
	var result error
	for _, f := range files {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	return result
}

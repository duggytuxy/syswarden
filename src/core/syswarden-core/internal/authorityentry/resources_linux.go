package authorityentry

import (
	"errors"
	"syscall"
)

const authorityDescriptorLimit uint64 = 256

var errAuthorityResources = errors.New("invalid authority process resource limits")

// Resource limits are process-wide, unlike thread-local capability flags. Both
// ceilings are irreversible without external privilege. Use the Go syscall
// wrapper so its saved pre-runtime file limit cannot be restored on later exec.
// This is a dedicated executable policy, never an embedding-library operation.
func confineAuthorityResources() error {
	return setAuthorityResourceLimits(syscall.Getrlimit, syscall.Setrlimit)
}

func setAuthorityResourceLimits(get func(int, *syscall.Rlimit) error, set func(int, *syscall.Rlimit) error) error {
	if get == nil || set == nil {
		return errAuthorityResources
	}
	profiles := [2]struct {
		resource int
		limit    uint64
	}{
		{syscall.RLIMIT_CORE, 0}, {syscall.RLIMIT_NOFILE, authorityDescriptorLimit},
	}
	// Read every current budget before changing any of them. Never raise an
	// observed limit or repair insufficient provisioning. The caller exits on
	// every failure, including partial application or an uncertain readback.
	for _, profile := range profiles {
		var current syscall.Rlimit
		if err := get(profile.resource, &current); err != nil {
			return err
		}
		if current.Cur > current.Max || current.Cur < profile.limit || current.Max < profile.limit {
			return errAuthorityResources
		}
	}
	for _, profile := range profiles {
		expected := syscall.Rlimit{Cur: profile.limit, Max: profile.limit}
		if err := set(profile.resource, &expected); err != nil {
			return err
		}
		var actual syscall.Rlimit
		if err := get(profile.resource, &actual); err != nil {
			return err
		}
		if actual != expected {
			return errAuthorityResources
		}
	}
	return nil
}

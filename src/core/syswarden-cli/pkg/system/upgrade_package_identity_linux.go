//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// nativeUpdateIdentity binds artifact selection to the registered product and
// native database authority. It does not authorize a change of package identity.
type nativeUpdateIdentity struct {
	name, manager, state string
}

func (identity nativeUpdateIdentity) validate() error {
	if identity.name == baseNativePackageName {
		return fmt.Errorf("syswarden-base updates are unavailable pending coordinated native signature and lifecycle qualification; refusing compatibility-package substitution")
	}
	if identity.name != compatibilityNativePackageName {
		return fmt.Errorf("standard updater requires the registered compatibility package identity")
	}
	if identity.state != "installed" {
		return fmt.Errorf("native SysWarden package requires repair before an update")
	}
	switch identity.manager {
	case "dpkg-query", "rpm", "apk":
		return nil
	default:
		return fmt.Errorf("standard updater package authority is unsupported")
	}
}

// The v5 inventory represents both identities, but production base transactions
// remain closed pending native signature and lifecycle qualification.
// Base installations must not select a compatibility artifact or retain for it.
func preflightStandardNativeUpdate(ctx context.Context) (nativeUpdateIdentity, error) {
	executor := hostFirewallExecutor()
	executor.output = func(path string, arguments ...string) ([]byte, error) {
		if !allowedNativeProductRegistrationQuery(path, arguments) {
			return nil, fmt.Errorf("unapproved native update identity query")
		}
		output, err := runQualificationCommandOutput(ctx, path, arguments...)
		var exit *qualificationCommandExitError
		if errors.As(err, &exit) {
			// Preserve both native streams for exact, typed absence recognition.
			return append(output, exit.stderr...), err
		}
		return output, err
	}
	return preflightStandardNativeUpdateWith(ctx, executor, uninstallAuthorityPathExists)
}

func preflightStandardNativeUpdateWith(ctx context.Context, executor firewallManagerExecutor, exists func(string) (bool, error)) (nativeUpdateIdentity, error) {
	if ctx == nil {
		return nativeUpdateIdentity{}, fmt.Errorf("native update identity context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nativeUpdateIdentity{}, err
	}
	registrations, err := inspectNativeProductRegistrations(executor, exists)
	if err != nil {
		return nativeUpdateIdentity{}, fmt.Errorf("cannot establish native update package identity: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nativeUpdateIdentity{}, err
	}
	if len(registrations) != 1 {
		return nativeUpdateIdentity{}, fmt.Errorf("standard updater requires exactly one registered SysWarden package identity; repair ambiguous native registration or use the documented installation procedure for an unregistered installation")
	}
	identity := nativeUpdateIdentity{name: registrations[0].name, manager: registrations[0].manager, state: registrations[0].state}
	if err := identity.validate(); err != nil {
		return nativeUpdateIdentity{}, err
	}
	return identity, nil
}

func (u *updater) preflightStandardNativeIdentity(ctx context.Context, timeout time.Duration) (nativeUpdateIdentity, error) {
	if ctx == nil || timeout <= 0 {
		return nativeUpdateIdentity{}, fmt.Errorf("native update package identity requires a context and positive timeout")
	}
	if u.preflightNativeIdentity == nil {
		return nativeUpdateIdentity{}, fmt.Errorf("native update package identity preflight is unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return nativeUpdateIdentity{}, err
	}
	identity, err := u.preflightNativeIdentity(bounded)
	if contextErr := bounded.Err(); contextErr != nil {
		return nativeUpdateIdentity{}, contextErr
	}
	if err != nil {
		return nativeUpdateIdentity{}, err
	}
	if err := identity.validate(); err != nil {
		return nativeUpdateIdentity{}, err
	}
	return identity, nil
}

func (u *updater) recheckStandardNativeIdentity(ctx context.Context, timeout time.Duration, expected nativeUpdateIdentity) error {
	current, err := u.preflightStandardNativeIdentity(ctx, timeout)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf("registered native package identity or authority changed during update preparation")
	}
	return nil
}

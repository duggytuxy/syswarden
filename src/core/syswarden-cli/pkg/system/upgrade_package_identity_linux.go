//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The public signed inventory still contains only the compatibility package.
// Base installations must not select that artifact or invoke retention for it.
func preflightStandardNativeUpdate(ctx context.Context) error {
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

func preflightStandardNativeUpdateWith(ctx context.Context, executor firewallManagerExecutor, exists func(string) (bool, error)) error {
	if ctx == nil {
		return fmt.Errorf("native update identity context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	registrations, err := inspectNativeProductRegistrations(executor, exists)
	if err != nil {
		return fmt.Errorf("cannot establish native update package identity: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(registrations) != 1 {
		return fmt.Errorf("standard updater requires exactly one registered SysWarden package identity; repair ambiguous native registration or use the documented installation procedure for an unregistered installation")
	}
	if registrations[0].name == baseNativePackageName {
		return fmt.Errorf("syswarden-base updates are unavailable until the authenticated release inventory supports that identity; refusing compatibility-package substitution")
	}
	if registrations[0].state != "installed" {
		return fmt.Errorf("native SysWarden package requires repair before an update")
	}
	return nil
}

func (u *updater) preflightStandardNativeIdentity(ctx context.Context, timeout time.Duration) error {
	if ctx == nil || timeout <= 0 {
		return fmt.Errorf("native update package identity requires a context and positive timeout")
	}
	if u.preflightNativeIdentity == nil {
		return fmt.Errorf("native update package identity preflight is unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return u.preflightNativeIdentity(bounded)
}

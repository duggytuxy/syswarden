//go:build linux

package system

import (
	"context"
	"errors"
	"syswarden-cli/config"
)

// Capture only a point-in-time original absent approval witness. This explicit
// entry never falls back from failed active approval and never creates defaults,
// repairs history, approves TOML, activates policy or acquires execution rights.
func captureAPKInactivePolicy(ctx context.Context) (_ apkTransitionPolicyBinding, result error) {
	policy, err := config.CaptureActivationPolicy(ctx, "/etc/syswarden/config")
	if err != nil {
		return apkTransitionPolicyBinding{}, err
	}
	absence, err := policy.ObserveActivationAbsent(ctx)
	if err != nil {
		return apkTransitionPolicyBinding{}, err
	}
	defer func() { result = errors.Join(result, absence.Close()) }()
	host, err := policy.HostSHA256()
	if err != nil {
		return apkTransitionPolicyBinding{}, err
	}
	binding := apkTransitionPolicyBinding{PolicySHA256: policy.Review().Digest, HostSHA256: host, LifecycleMode: apkInactivePreservationMode, AbsenceSHA256: absence.SHA256()}
	if !binding.valid() {
		return apkTransitionPolicyBinding{}, errors.New("inactive native policy observation is incomplete")
	}
	return binding, absence.Revalidate(ctx)
}

func captureNativeInactivePolicy(ctx context.Context, nft func(context.Context) (string, error)) (nativeActivationPolicyObservation, error) {
	return captureNativeInactivePolicyWith(ctx, captureAPKInactivePolicy, func(check context.Context) (string, error) {
		return ObserveNativeInactiveHost(check, nft)
	})
}

func captureNativeInactivePolicyWith(ctx context.Context, policy func(context.Context) (apkTransitionPolicyBinding, error), host func(context.Context) (string, error)) (nativeActivationPolicyObservation, error) {
	empty := nativeActivationPolicyObservation{}
	if ctx == nil || policy == nil || host == nil {
		return empty, errors.New("inactive native policy requires complete independent observers")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	original, err := policy(ctx)
	if err != nil {
		return empty, err
	}
	if !original.inactive() || !original.valid() {
		return empty, errors.New("inactive native preservation requires explicit absent-approval evidence")
	}
	hostSHA, err := host(ctx)
	if err != nil {
		return empty, err
	}
	if !validSHA256(hostSHA) {
		return empty, errors.New("inactive native host observation is incomplete")
	}
	verify := func(check context.Context) error {
		if check == nil {
			return errors.New("inactive native revalidation requires a context")
		}
		if err := check.Err(); err != nil {
			return err
		}
		before, err := policy(check)
		if err != nil {
			return err
		}
		if before != original {
			return errors.New("inactive native policy or absence witness changed")
		}
		current, err := host(check)
		if err != nil {
			return err
		}
		if current != hostSHA {
			return errors.New("inactive native services, schedules, processes or firewall changed")
		}
		after, err := policy(check)
		if err != nil {
			return err
		}
		if after != original {
			return errors.New("inactive native policy changed during host observation")
		}
		return check.Err()
	}
	observed := nativeActivationPolicyObservation{binding: original, hostSHA256: hostSHA, revalidate: verify, verifyPolicy: verify}
	return observed, verify(ctx)
}

// This explicit read-only binding factory is not an update command ingress.
// The executor still needs source ownership, a retained publication lease and
// independent terminal/native qualification. Active admission is unchanged.
func productionInactiveNativeBindingServices(nft func(context.Context) (string, error)) nativeActivationBindingServices {
	services := productionNativeActivationBindingServices()
	services.policy = func(ctx context.Context) (nativeActivationPolicyObservation, error) {
		return captureNativeInactivePolicy(ctx, nft)
	}
	services.publication = func(ctx context.Context) (NativeActivationCandidate, error) {
		source, _, _, err := observeNativePublicationExclusionSource(ctx, "/")
		return source, err
	}
	return services
}

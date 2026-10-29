//go:build linux

package system

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"reflect"
	"syswarden-cli/config"
)

type apkInactiveLease interface {
	SHA256() string
	Revalidate(context.Context) error
	Close() error
}

type apkInactiveCustodyServices struct {
	hold      func(context.Context, apkTransitionPolicyBinding) (apkInactiveLease, error)
	observe   func(context.Context) (nativeActivationPolicyObservation, error)
	source    func(context.Context, nativeActivationBindingPlan, NativeActivationCandidate) (func(context.Context, bool) error, error)
	installed func(context.Context, NativeActivationCandidate) error
}

// This owner outlives the execution boundary and its retained preparation.
// Only the coordinator closes it, after independent terminal verification and
// before the final positive closure record. Unclosed native debt continues to
// deny activation between lease release and that metadata-only publication.
type apkInactiveCustody struct {
	preparationSHA256 string
	executionSHA256   string
	effectSHA256      string
	original          nativeActivationBindingPlan
	candidate         NativeActivationCandidate
	lease             apkInactiveLease
	observe           func(context.Context) (nativeActivationPolicyObservation, error)
	source            func(context.Context, bool) error
	installed         func(context.Context, NativeActivationCandidate) error
	closed            bool
}

func productionAPKInactiveCustodyServices(nft func(context.Context) (string, error)) apkInactiveCustodyServices {
	return apkInactiveCustodyServices{
		hold: holdAPKInactivePolicy,
		observe: func(ctx context.Context) (nativeActivationPolicyObservation, error) {
			return captureNativeInactivePolicy(ctx, nft)
		},
		source: attestAPKInactiveCoordinator,
		installed: func(ctx context.Context, candidate NativeActivationCandidate) error {
			return candidate.VerifyInstalled(ctx)
		},
	}
}

func holdAPKInactivePolicy(ctx context.Context, expected apkTransitionPolicyBinding) (apkInactiveLease, error) {
	if !expected.valid() || !expected.inactive() {
		return nil, errors.New("APK inactive custody requires an explicit original absence witness")
	}
	policy, err := config.CaptureActivationPolicy(ctx, "/etc/syswarden/config")
	if err != nil {
		return nil, err
	}
	host, err := policy.HostSHA256()
	if err != nil || policy.Review().Digest != expected.PolicySHA256 || host != expected.HostSHA256 {
		return nil, errors.Join(errors.New("APK inactive custody differs from original TOML"), err)
	}
	return policy.HoldActivationAbsent(ctx)
}

// The exclusion of the current process from inactive host scanning is valid
// here only for this exact original installed coordinator. Replacement may
// unlink that inode, but cannot substitute another executable, PID or start.
func attestAPKInactiveCoordinator(ctx context.Context, original nativeActivationBindingPlan, candidate NativeActivationCandidate) (func(context.Context, bool) error, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("APK inactive coordinator requires original root credentials")
	}
	publication, err := captureNativePublicationExclusionAt(ctx, "/", candidate)
	if err != nil {
		return nil, err
	}
	if publication.source.SHA256() != original.SourcePublicationSHA256 || publication.runtime != original.Installed {
		return nil, errors.New("APK inactive coordinator differs from retained original publication/runtime evidence")
	}
	process, err := observeAPKNativeProcess(ctx, os.Getpid())
	if err != nil || process.Executable != original.Installed.CLI {
		return nil, errors.Join(errors.New("APK inactive coordinator is not the original installed CLI"), err)
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, err
	}
	verify := func(check context.Context, replaced bool) error {
		if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
			return errors.New("APK inactive coordinator credentials changed")
		}
		currentGroups, err := os.Getgroups()
		if err != nil || !reflect.DeepEqual(currentGroups, groups) {
			return errors.Join(errors.New("APK inactive coordinator supplementary credentials changed"), err)
		}
		current, err := observeAPKNativeProcess(check, os.Getpid())
		phase := "pre-upgrade"
		if replaced {
			phase = "post-commit"
		}
		if err != nil || !sameAPKCoordinatorProcess(current, process, phase) {
			return errors.Join(errors.New("APK inactive coordinator process changed"), err)
		}
		if !replaced {
			return publication.Revalidate(check)
		}
		return check.Err()
	}
	return verify, verify(ctx, false)
}

func openAPKInactiveCustody(ctx context.Context, prepared *verifiedPreparedAPKTransition, executionSHA256 string, services apkInactiveCustodyServices) (*apkInactiveCustody, error) {
	if !validSHA256(executionSHA256) {
		return nil, errors.New("APK inactive custody requires exact execution approval")
	}
	owner, err := openAPKInactivePreparationCustody(ctx, prepared, services)
	if err != nil {
		return nil, err
	}
	owner.executionSHA256 = executionSHA256
	return owner, nil
}

func openAPKInactivePreparationCustody(ctx context.Context, prepared *verifiedPreparedAPKTransition, services apkInactiveCustodyServices) (_ *apkInactiveCustody, result error) {
	if ctx == nil || prepared == nil || prepared.closed || !prepared.locked || !prepared.plan.Policy.inactive() || services.hold == nil || services.observe == nil || services.source == nil || services.installed == nil {
		return nil, errors.New("APK inactive custody requires verified preparation and complete independent observers")
	}
	if err := prepared.Revalidate(ctx); err != nil {
		return nil, err
	}
	raw, err := apkTerminalEffectReader(prepared)()
	if err != nil {
		return nil, err
	}
	original, err := verifyAPKTerminalEffectPlan(raw, prepared)
	if err != nil {
		return nil, err
	}
	source, err := services.source(ctx, original, prepared.capability)
	if err != nil || source == nil {
		return nil, errors.Join(errors.New("APK inactive source coordinator authority is unavailable"), err)
	}
	owner := &apkInactiveCustody{preparationSHA256: prepared.digest, effectSHA256: prepared.plan.EffectPlanSHA256, original: original, candidate: prepared.capability, observe: services.observe, source: source, installed: services.installed}
	defer func() {
		if result != nil {
			result = errors.Join(result, owner.Close())
		}
	}()
	owner.lease, err = services.hold(ctx, original.RuntimePolicy)
	if err != nil {
		return nil, err
	}
	if !apkExecutionValuePresent(owner.lease) || owner.lease.SHA256() != original.RuntimePolicy.AbsenceSHA256 {
		return nil, errors.New("APK inactive publication lease does not retain the original absence witness")
	}
	if err := owner.Revalidate(ctx, false); err != nil {
		return nil, err
	}
	return owner, nil
}

func (owner *apkInactiveCustody) Revalidate(ctx context.Context, replaced bool) error {
	if ctx == nil || owner == nil || owner.closed || !apkExecutionValuePresent(owner.lease) || owner.observe == nil || owner.source == nil || owner.installed == nil {
		return errors.New("APK inactive publication custody is unavailable")
	}
	if err := owner.lease.Revalidate(ctx); err != nil {
		return err
	}
	if owner.lease.SHA256() != owner.original.RuntimePolicy.AbsenceSHA256 {
		return errors.New("APK inactive publication witness changed")
	}
	if err := owner.source(ctx, replaced); err != nil {
		return err
	}
	observed, err := owner.observe(ctx)
	if err != nil {
		return err
	}
	if observed.binding != owner.original.RuntimePolicy || observed.hostSHA256 != owner.original.HostObservationSHA256 || observed.revalidate == nil || observed.verifyPolicy == nil {
		return errors.New("APK inactive custody changed original policy or host evidence")
	}
	if err := observed.revalidate(ctx); err != nil {
		return err
	}
	if replaced {
		if err := owner.installed(ctx, owner.candidate); err != nil {
			return err
		}
	}
	return errors.Join(observed.verifyPolicy(ctx), owner.source(ctx, replaced), owner.lease.Revalidate(ctx), ctx.Err())
}

func (owner *apkInactiveCustody) Close() error {
	if owner == nil || owner.closed {
		return nil
	}
	owner.closed = true
	if apkExecutionValuePresent(owner.lease) {
		return owner.lease.Close()
	}
	return nil
}

// This internal terminal path borrows the coordinator's existing exclusion. It
// reconstructs the original retained effect record and independently observes
// current policy/host/candidate state; it never reacquires an exclusive lease.
// The ordinary terminal entry remains closed to inactive migrations.
func finalizeAPKInactiveTransition(ctx context.Context, digest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, owner *apkInactiveCustody) (result error) {
	if owner == nil {
		return errors.New("APK inactive finalization requires retained publication custody")
	}
	defer func() { result = errors.Join(result, owner.Close()) }()
	if !validSHA256(owner.executionSHA256) || digest != owner.executionSHA256 {
		return errors.New("APK inactive terminal differs from the original execution approval")
	}
	if err := owner.Revalidate(ctx, true); err != nil {
		return err
	}
	factory := func(check context.Context, prepared *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
		if prepared.digest != owner.preparationSHA256 || prepared.plan.EffectPlanSHA256 != owner.effectSHA256 {
			return nil, errors.New("APK inactive terminal substituted the original preparation")
		}
		if err := owner.Revalidate(check, true); err != nil {
			return nil, err
		}
		return openAPKTerminalLifecycleWith(check, prepared, apkTerminalEffectReader(prepared), owner.observe, func(check context.Context) error { return owner.Revalidate(check, true) })
	}
	publish := func(check context.Context, path string, identity apkTransitionIdentity, intent, closure []byte) error {
		if err := owner.Revalidate(check, true); err != nil {
			return err
		}
		if err := owner.Close(); err != nil {
			return err
		}
		return publishAPKTerminalClosure(check, path, identity, intent, closure)
	}
	return finalizeAPKTransitionUsing(ctx, digest, keys, attest, services, factory, writeAPKTransitionBytes, publish)
}

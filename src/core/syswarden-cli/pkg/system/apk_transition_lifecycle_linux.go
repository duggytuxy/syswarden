//go:build linux

package system

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
)

// DurableEffects preserves the exact original review. It does not rebase that
// review onto a host observed after a native transaction.
func (binding *nativeActivationBinding) DurableEffects() ([]byte, error) {
	if binding == nil || !validSHA256(binding.digest) {
		return nil, errors.New("native effect review is unavailable")
	}
	raw, err := json.Marshal(binding.plan)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if apkTransitionDigest(raw) != binding.digest {
		return nil, errors.New("native effect review no longer matches its original digest")
	}
	return raw, nil
}

func verifyAPKTerminalEffectPlan(raw []byte, prepared *verifiedPreparedAPKTransition) (nativeActivationBindingPlan, error) {
	var result nativeActivationBindingPlan
	if prepared == nil || prepared.closed || !validSHA256(prepared.plan.EffectPlanSHA256) || apkTransitionDigest(raw) != prepared.plan.EffectPlanSHA256 {
		return result, errors.New("APK terminal effect review is not the original approved record")
	}
	if err := decodeAPKTransitionJSON(raw, &result); err != nil {
		return result, err
	}
	plan := prepared.plan
	capability := prepared.capability.Review()
	if !result.RuntimePolicy.valid() || result.Schema != result.RuntimePolicy.effectSchema() || result.PackageName != plan.PackageName || result.Format != packageFormatAPK || result.Installer != plan.Installer || result.CandidateVersion != plan.CandidateVersion || result.Artifact != plan.Artifact || result.ManifestSHA256 != plan.ManifestSHA256 || result.SignatureSHA256 != plan.SignatureSHA256 || result.InstalledVersion != plan.InstalledVersion || result.Installed.CLI.SHA256 != plan.InstalledCLISHA256 || !validSHA256(result.Installed.Core.SHA256) || result.RuntimePolicy != plan.Policy || result.Offline != plan.Offline || !reflect.DeepEqual(result.Capability, capability) || prepared.capability.SHA256() != plan.CandidateCapabilitySHA256 || capability.CLISHA256 != plan.CandidateCLISHA256 || !validSHA256(result.HostObservationSHA256) {
		return result, errors.New("APK terminal effect review disagrees with authenticated preparation")
	}
	if !result.validPublicationBinding(prepared.capability) {
		return result, errors.New("APK terminal runtime policy review is incomplete")
	}
	return result, nil
}

type apkTerminalLifecycle struct {
	digest     string
	original   nativeActivationBindingPlan
	record     []byte
	readRecord func() ([]byte, error)
	policy     func(context.Context) (nativeActivationPolicyObservation, error)
	installed  func(context.Context) error
	closed     bool
}

func openAPKTerminalLifecycle(ctx context.Context, prepared *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
	if prepared == nil || prepared.closed || prepared.directory == nil {
		return nil, errors.New("APK terminal preparation is unavailable")
	}
	if prepared.plan.Policy.inactive() {
		return nil, errors.New("inactive APK terminal verification requires an independent complete inactivity observer")
	}
	return openAPKTerminalLifecycleWith(ctx, prepared, apkTerminalEffectReader(prepared), captureNativeActivationPolicy, prepared.capability.VerifyInstalled)
}

func apkTerminalEffectReader(prepared *verifiedPreparedAPKTransition) func() ([]byte, error) {
	var originalIdentity *removalArtifactIdentity
	return func() ([]byte, error) {
		if prepared.closed {
			return nil, errors.New("APK terminal preparation is closed")
		}
		if err := attestRetainedDirectoryParent(prepared.path, prepared.directory, false); err != nil {
			return nil, err
		}
		before, err := prepared.directory.root.Lstat("native-effects.json")
		identity, identityErr := exactRemovalArtifactIdentity(before)
		if err != nil || identityErr != nil {
			return nil, errors.Join(err, identityErr)
		}
		if originalIdentity != nil && identity != *originalIdentity {
			return nil, errors.New("APK original effect record identity changed")
		}
		raw, err := readAPKTransitionBytes(prepared.directory, "native-effects.json", 64<<10)
		if err != nil {
			return nil, err
		}
		after, err := prepared.directory.root.Lstat("native-effects.json")
		final, identityErr := exactRemovalArtifactIdentity(after)
		if err != nil || identityErr != nil || final != identity {
			return nil, errors.Join(errors.New("APK effect record changed during terminal verification"), err, identityErr)
		}
		if originalIdentity == nil {
			originalIdentity = &identity
		}
		return raw, nil
	}
}

func openAPKTerminalLifecycleWith(ctx context.Context, prepared *verifiedPreparedAPKTransition, readRecord func() ([]byte, error), policy func(context.Context) (nativeActivationPolicyObservation, error), installed func(context.Context) error) (*apkTerminalLifecycle, error) {
	if ctx == nil || readRecord == nil || policy == nil || installed == nil {
		return nil, errors.New("APK terminal lifecycle dependencies are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := readRecord()
	if err != nil {
		return nil, err
	}
	original, err := verifyAPKTerminalEffectPlan(raw, prepared)
	if err != nil {
		return nil, err
	}
	result := &apkTerminalLifecycle{digest: prepared.plan.EffectPlanSHA256, original: original, record: bytes.Clone(raw), readRecord: readRecord, policy: policy, installed: installed}
	if err := result.AttestResult(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (boundary *apkTerminalLifecycle) EffectPlanSHA256() string {
	if boundary == nil || boundary.closed {
		return ""
	}
	return boundary.digest
}

// AttestResult compares current policy and service observations to the original
// approved effect review. It proves neither a new authenticated SSH connection
// nor causal daemon consumption, which have separate acceptance contracts.
func (boundary *apkTerminalLifecycle) AttestResult(ctx context.Context) error {
	if ctx == nil || boundary == nil || boundary.closed || boundary.readRecord == nil || boundary.policy == nil || boundary.installed == nil {
		return errors.New("APK terminal lifecycle authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	checkRecord := func() error {
		raw, err := boundary.readRecord()
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, boundary.record) || apkTransitionDigest(raw) != boundary.digest {
			return errors.New("APK original native effect record changed")
		}
		return ctx.Err()
	}
	if err := checkRecord(); err != nil {
		return err
	}
	observed, err := boundary.policy(ctx)
	if err != nil {
		return err
	}
	if observed.binding != boundary.original.RuntimePolicy || observed.hostSHA256 != boundary.original.HostObservationSHA256 || observed.revalidate == nil || observed.verifyPolicy == nil {
		return errors.New("APK result changed original policy, applied approval or host observation")
	}
	if err := observed.revalidate(ctx); err != nil {
		return err
	}
	if err := boundary.installed(ctx); err != nil {
		return err
	}
	if err := observed.revalidate(ctx); err != nil {
		return err
	}
	return checkRecord()
}
func (boundary *apkTerminalLifecycle) Close() error {
	if boundary != nil {
		boundary.closed = true
	}
	return nil
}

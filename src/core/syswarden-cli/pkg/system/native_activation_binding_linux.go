//go:build linux

package system

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"syswarden-cli/config"
)

const nativeActivationBindingSchema = "syswarden-native-activation-binding-v1"

// A runtime approval binds TOML, not replacement executable semantics. This
// additional immutable observation must enter a separately approved native
// transaction before a package manager or a candidate hook may mutate the host.
type nativeActivationBinding struct {
	plan         nativeActivationBindingPlan
	digest       string
	candidate    NativeActivationCandidate
	revalidate   func(context.Context) error
	verifyPolicy func(context.Context) error
}

type nativeActivationBindingPlan struct {
	Schema                string                          `json:"schema"`
	PackageName           string                          `json:"package_name"`
	Format                string                          `json:"format"`
	Installer             string                          `json:"installer"`
	CandidateVersion      string                          `json:"candidate_version"`
	Artifact              updateArtifact                  `json:"artifact"`
	ManifestSHA256        string                          `json:"manifest_sha256"`
	SignatureSHA256       string                          `json:"signature_sha256"`
	Capability            NativeActivationCandidateReview `json:"capability"`
	InstalledVersion      string                          `json:"installed_version"`
	Installed             nativeActivationRuntimeSnapshot `json:"installed_runtime"`
	RuntimePolicy         apkTransitionPolicyBinding      `json:"runtime_policy"`
	HostObservationSHA256 string                          `json:"host_observation_sha256"`
	Offline               bool                            `json:"offline"`
}

type nativeActivationRuntimeFile struct {
	Identity apkTransitionIdentity `json:"identity"`
	SHA256   string                `json:"sha256"`
}

type nativeActivationRuntimeSnapshot struct {
	Directory apkTransitionIdentity       `json:"directory"`
	CLI       nativeActivationRuntimeFile `json:"cli"`
	Core      nativeActivationRuntimeFile `json:"core"`
}

type nativeActivationPolicyObservation struct {
	binding      apkTransitionPolicyBinding
	hostSHA256   string
	revalidate   func(context.Context) error
	verifyPolicy func(context.Context) error
}

type nativeActivationBindingServices struct {
	classify         func(context.Context, packageTarget, *os.File) (NativeActivationCandidate, error)
	policy           func(context.Context) (nativeActivationPolicyObservation, error)
	installedRuntime func(context.Context, int) (nativeActivationRuntimeSnapshot, error)
}

func productionNativeActivationBindingServices() nativeActivationBindingServices {
	return nativeActivationBindingServices{
		classify: attestNativeActivationCandidate,
		policy:   captureNativeActivationPolicy,
		installedRuntime: func(ctx context.Context, uid int) (nativeActivationRuntimeSnapshot, error) {
			return captureNativeActivationRuntime(ctx, "/opt/syswarden/bin", uid)
		},
	}
}

func captureNativeActivationPolicy(ctx context.Context) (nativeActivationPolicyObservation, error) {
	var empty nativeActivationPolicyObservation
	policy, err := config.CaptureActivationPolicy(ctx, "/etc/syswarden/config")
	if err != nil {
		return empty, err
	}
	approval, err := policy.VerifyApproved(ctx)
	if err != nil {
		return empty, err
	}
	if approval == nil {
		return empty, errors.New("native replacement requires exact prior runtime approval")
	}
	review := approval.Review()
	if review.Operation != "install" || !review.Applied {
		return empty, errors.New("native replacement requires a successfully applied runtime install approval; pending or reload-only authority is insufficient")
	}
	configuration, err := policy.Configuration(ctx)
	if err != nil {
		return empty, err
	}
	host, err := CaptureActivationHost(ctx, configuration.FirewallBackend, configuration.HAEnabled)
	if err != nil {
		return empty, err
	}
	verifyPolicy := func(check context.Context) error {
		if check == nil {
			return errors.New("native policy revalidation requires a context")
		}
		if err := check.Err(); err != nil {
			return err
		}
		if err := policy.Revalidate(check); err != nil {
			return err
		}
		if err := approval.Revalidate(check); err != nil {
			return err
		}
		current, err := policy.VerifyApproved(check)
		if err != nil {
			return err
		}
		if current == nil || current.Review() != review {
			return errors.New("native runtime approval or applied state changed after capture")
		}
		return check.Err()
	}
	revalidate := func(check context.Context) error {
		if err := verifyPolicy(check); err != nil {
			return err
		}
		if err := host.Revalidate(check); err != nil {
			return err
		}
		return verifyPolicy(check)
	}
	result := nativeActivationPolicyObservation{
		binding:    apkTransitionPolicyBinding{review.SHA256, review.PolicySHA256, review.HostSHA256},
		hostSHA256: host.Digest(), revalidate: revalidate, verifyPolicy: verifyPolicy,
	}
	return result, revalidate(ctx)
}

func captureNativeActivationRuntime(ctx context.Context, directory string, uid int) (nativeActivationRuntimeSnapshot, error) {
	return captureNativeActivationRuntimeWith(ctx, directory, uid, nil)
}

func captureNativeActivationRuntimeWith(ctx context.Context, directory string, uid int, afterCapture func(string) error) (result nativeActivationRuntimeSnapshot, returnErr error) {
	if ctx == nil || uid < 0 {
		return result, errors.New("native runtime identity requires a context and owner")
	}
	type openedRuntime struct {
		root     *os.Root
		file     *os.File
		identity qualificationFileIdentity
		name     string
	}
	var opened []openedRuntime
	defer func() {
		for _, item := range opened {
			returnErr = errors.Join(returnErr, item.file.Close(), item.root.Close())
		}
	}()
	for index, name := range []string{"syswarden-cli", "syswarden-core"} {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		root, file, identity, err := openInstalledQualificationBinary(filepath.Join(directory, name), uid)
		if err != nil {
			return result, err
		}
		opened = append(opened, openedRuntime{root, file, identity, name})
		info, err := root.Stat(".")
		if err != nil {
			return result, err
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return result, errors.New("native runtime directory identity is unavailable")
		}
		parent := apkTransitionStat(status)
		if index == 0 {
			result.Directory = parent
		} else if parent != result.Directory {
			return result, errors.New("native runtime parent changed between executable captures")
		}
		info, err = file.Stat()
		if err != nil {
			return result, err
		}
		status, ok = info.Sys().(*syscall.Stat_t)
		if !ok {
			return result, errors.New("native runtime executable identity is unavailable")
		}
		captured := nativeActivationRuntimeFile{apkTransitionStat(status), hex.EncodeToString(identity.digest[:])}
		if index == 0 {
			result.CLI = captured
		} else {
			result.Core = captured
		}
		if afterCapture != nil {
			if err := afterCapture(name); err != nil {
				return result, err
			}
		}
	}
	// Keep both descriptors pinned until the complete captured pair has been
	// revalidated. An in-place CLI edit while core is read leaves parent metadata
	// unchanged and must not survive as a coherent original-runtime observation.
	for _, item := range opened {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := revalidateInstalledQualificationBinary(item.root, item.file, item.name, item.identity, uid); err != nil {
			return result, err
		}
		info, err := item.root.Stat(".")
		if err != nil {
			return result, err
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || apkTransitionStat(status) != result.Directory {
			return result, errors.New("native captured parent changed during pair validation")
		}
	}
	current, err := openOwnedInstalledQualificationDirectory(directory, uid)
	if err != nil {
		return result, err
	}
	currentInfo, statErr := current.Stat(".")
	closeErr := current.Close()
	if statErr != nil || closeErr != nil {
		return result, errors.Join(statErr, closeErr)
	}
	currentStatus, ok := currentInfo.Sys().(*syscall.Stat_t)
	if !ok || apkTransitionStat(currentStatus) != result.Directory {
		return result, errors.New("native runtime path no longer names its captured parent")
	}
	return result, ctx.Err()
}

func captureNativeActivationBinding(ctx context.Context, candidate authenticatedAPKCandidate) (*nativeActivationBinding, error) {
	return captureNativeActivationBindingWith(ctx, candidate, productionNativeActivationBindingServices())
}

func captureNativeActivationBindingWith(ctx context.Context, candidate authenticatedAPKCandidate, services nativeActivationBindingServices) (*nativeActivationBinding, error) {
	if ctx == nil || services.classify == nil || services.policy == nil || services.installedRuntime == nil || candidate.attestInstalled == nil {
		return nil, errors.New("native activation binding dependencies are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if candidate.uid != os.Geteuid() || candidate.target.os != "linux" || candidate.target.architecture != "amd64" || !validNativeProductPackageName(candidate.target.packageName) {
		return nil, errors.New("native activation binding requires an exact Linux AMD64 package identity and owner")
	}
	switch candidate.target.format {
	case packageFormatDEB:
		if candidate.target.installer != "/usr/bin/apt-get" {
			return nil, errors.New("native DEB manager is unsupported")
		}
	case packageFormatRPM:
		if candidate.target.installer != "/usr/bin/dnf" && candidate.target.installer != "/usr/bin/yum" {
			return nil, errors.New("native RPM manager is unsupported")
		}
	case packageFormatAPK:
		if candidate.target.installer != "/sbin/apk" && candidate.target.installer != "/usr/sbin/apk" {
			return nil, errors.New("native APK manager is unsupported")
		}
	default:
		return nil, errors.New("native activation package format is unsupported")
	}
	manifest, err := verifySignedManifest(candidate.manifest, candidate.signature, candidate.version, candidate.keys)
	if err != nil {
		return nil, err
	}
	artifact, err := manifest.artifactFor(candidate.target)
	if err != nil || artifact != candidate.artifact {
		return nil, errors.New("native activation package selection differs from its authenticated manifest")
	}
	verifyPackage := func(check context.Context) error {
		return verifyPackageAtNativeExecution(check, candidate.file, candidate.path, candidate.artifact, candidate.uid)
	}
	if err := verifyPackage(ctx); err != nil {
		return nil, err
	}
	capability, err := services.classify(ctx, candidate.target, candidate.file)
	if err != nil {
		return nil, err
	}
	review := capability.Review()
	if !validSHA256(capability.SHA256()) || review.CLISHA256 != candidate.cliSHA256 || !validSHA256(review.CoreSHA256) {
		return nil, errors.New("native activation capability disagrees with authenticated runtime payload")
	}
	if err := verifyPackage(ctx); err != nil {
		return nil, err
	}
	installed, err := candidate.attestInstalled(ctx, candidate.target, candidate.uid)
	if err != nil {
		return nil, err
	}
	comparison, err := compareReleaseVersions(installed.version, candidate.version)
	if err != nil || comparison >= 0 {
		return nil, errors.New("native activation binding refuses equal-version replacement or downgrade")
	}
	runtime, err := services.installedRuntime(ctx, candidate.uid)
	if err != nil {
		return nil, err
	}
	if !validSHA256(runtime.Core.SHA256) || runtime.CLI.SHA256 != installed.cliSHA256 || !validSHA256(installed.cliSHA256) {
		return nil, errors.New("native installed CLI and core identity is incomplete or inconsistent")
	}
	policy, err := services.policy(ctx)
	if err != nil {
		return nil, err
	}
	if policy.revalidate == nil || policy.verifyPolicy == nil || !validSHA256(policy.binding.ApprovalSHA256) || !validSHA256(policy.binding.PolicySHA256) || !validSHA256(policy.binding.HostSHA256) || !validSHA256(policy.hostSHA256) {
		return nil, errors.New("native activation policy and host binding is incomplete")
	}
	plan := nativeActivationBindingPlan{Schema: nativeActivationBindingSchema, PackageName: candidate.target.packageName, Format: candidate.target.format, Installer: candidate.target.installer, CandidateVersion: candidate.version, Artifact: artifact, ManifestSHA256: apkTransitionDigest(candidate.manifest), SignatureSHA256: apkTransitionDigest(candidate.signature), Capability: review, InstalledVersion: installed.version, Installed: runtime, RuntimePolicy: policy.binding, HostObservationSHA256: policy.hostSHA256, Offline: candidate.offline}
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	revalidate := func(check context.Context) error {
		if check == nil {
			return errors.New("native activation revalidation requires a context")
		}
		if err := check.Err(); err != nil {
			return err
		}
		if err := verifyPackage(check); err != nil {
			return err
		}
		if err := policy.revalidate(check); err != nil {
			return err
		}
		current, err := candidate.attestInstalled(check, candidate.target, candidate.uid)
		if err != nil {
			return err
		}
		if current != installed {
			return errors.New("native installed registration changed after review")
		}
		currentRuntime, err := services.installedRuntime(check, candidate.uid)
		if err != nil {
			return err
		}
		if currentRuntime != runtime {
			return errors.New("native installed executable bytes or identity changed after review")
		}
		if err := policy.revalidate(check); err != nil {
			return err
		}
		return verifyPackage(check)
	}
	binding := &nativeActivationBinding{plan: plan, digest: apkTransitionDigest(append(raw, '\n')), candidate: capability, revalidate: revalidate, verifyPolicy: policy.verifyPolicy}
	if err := binding.Revalidate(ctx); err != nil {
		return nil, err
	}
	return binding, nil
}

func (binding *nativeActivationBinding) EffectPlanSHA256() string {
	if binding == nil {
		return ""
	}
	return binding.digest
}

// Revalidate is a point-in-time before-replacement check, not a package database
// lock, execution approval, native hook authority or successful migration.
func (binding *nativeActivationBinding) Revalidate(ctx context.Context) error {
	if binding == nil || !validSHA256(binding.digest) || binding.revalidate == nil {
		return errors.New("native activation binding is unavailable")
	}
	return binding.revalidate(ctx)
}

func (binding *nativeActivationBinding) VerifyInstalledCandidate(ctx context.Context) error {
	if ctx == nil || binding == nil || binding.verifyPolicy == nil || !validSHA256(binding.digest) {
		return errors.New("native candidate acceptance binding is unavailable")
	}
	if err := binding.verifyPolicy(ctx); err != nil {
		return err
	}
	if err := binding.candidate.VerifyInstalled(ctx); err != nil {
		return err
	}
	return binding.verifyPolicy(ctx)
}

type nativeActivationTransactionRequiredError struct{ PlanSHA256 string }

func (failure *nativeActivationTransactionRequiredError) Error() string {
	return fmt.Sprintf("native replacement requires a separately approved coordinated transaction for plan SHA-256 %s; runtime TOML approval alone cannot authorize candidate package effects; no package transaction performed", failure.PlanSHA256)
}

// Until a durable native transaction supplies candidate-specific hook authority,
// DEB/RPM must stop before dependency preparation or package replacement. APK
// uses its separately preserved preparation and execution coordinator.
func requireProductionNativeActivationTransaction(ctx context.Context, candidate authenticatedAPKCandidate) error {
	binding, err := captureNativeActivationBinding(ctx, candidate)
	if err != nil {
		return err
	}
	return &nativeActivationTransactionRequiredError{PlanSHA256: binding.EffectPlanSHA256()}
}

// preflightNativeActivation runs before either native installation entry point.
// The APK route has its own immutable preparation and separately approved engine.
func (u *updater) preflightNativeActivation(ctx context.Context, target packageTarget, version string, artifact updateArtifact,
	file *os.File, path string, manifest, signature []byte, cliSHA256 string, offline bool) error {
	if ctx == nil {
		return errors.New("native activation preflight requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if target.format == packageFormatAPK {
		return nil
	}
	if u.guardNativeActivation == nil {
		return errors.New("native candidate activation authority is unavailable; replacement refused")
	}
	bounded, cancel := context.WithTimeout(ctx, u.attestTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	err := u.guardNativeActivation(bounded, authenticatedAPKCandidate{target: target, version: version, artifact: artifact, file: file, path: path,
		manifest: bytes.Clone(manifest), signature: bytes.Clone(signature), cliSHA256: cliSHA256, offline: offline,
		uid: u.effectiveUID, keys: u.trustedKeys, attestInstalled: u.attestInstalled})
	return errors.Join(err, bounded.Err())
}

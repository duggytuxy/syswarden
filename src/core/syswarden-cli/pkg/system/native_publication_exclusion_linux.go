//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// nativePublicationExclusionObservation binds both sides of a prospective
// inactive replacement to their declared cooperative publication protocol.
// It does not establish native package ownership, runtime inactivity, an
// acquired policy lease, administrator approval or permission to execute APK.
type nativePublicationExclusionObservation struct {
	source     NativeActivationCandidate
	candidate  NativeActivationCandidate
	runtime    nativeActivationRuntimeSnapshot
	descriptor apkLauncherPayloadFile
	host       string
}

func captureNativePublicationExclusionAt(ctx context.Context, host string, candidate NativeActivationCandidate) (*nativePublicationExclusionObservation, error) {
	if ctx == nil || !filepath.IsAbs(host) || filepath.Clean(host) != host || !candidate.publicationExclusion() {
		return nil, errors.New("inactive preservation requires an exact host and cooperative candidate capability")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, descriptor, runtime, err := observeNativePublicationExclusionSource(ctx, host)
	if err != nil {
		return nil, err
	}
	observation := &nativePublicationExclusionObservation{source: source, candidate: candidate, runtime: runtime, descriptor: descriptor, host: host}
	if err := observation.Revalidate(ctx); err != nil {
		return nil, err
	}
	return observation, nil
}

func observeNativePublicationExclusionSource(ctx context.Context, host string) (source NativeActivationCandidate, descriptor apkLauncherPayloadFile, runtime nativeActivationRuntimeSnapshot, result error) {
	anchor, err := os.OpenRoot(host)
	if err != nil {
		return source, descriptor, runtime, err
	}
	defer func() { result = errors.Join(result, anchor.Close()) }()
	descriptor, raw, err := apkLauncherReadFile(ctx, anchor, nativeActivationDescriptorPath, maximumNativeActivationDescriptorBytes, syscall.S_IFREG|0644, true)
	if err != nil {
		return source, descriptor, runtime, err
	}
	source, err = parseNativeActivationDescriptor(raw)
	if err != nil || !source.publicationExclusion() {
		return source, descriptor, runtime, errors.Join(errors.New("installed runtime does not declare publication exclusion; inactive preservation is unsupported"), err)
	}
	runtime, err = captureNativeActivationRuntime(ctx, filepath.Join(host, "opt/syswarden/bin"), os.Geteuid())
	if err != nil {
		return source, descriptor, runtime, err
	}
	if runtime.CLI.SHA256 != source.Review().CLISHA256 || runtime.Core.SHA256 != source.Review().CoreSHA256 {
		return source, descriptor, runtime, errors.New("installed publication capability differs from exact runtime bytes")
	}
	if err := source.verifyInstalledAt(ctx, host, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		return source, descriptor, runtime, err
	} // #nosec G115 -- Linux uid/gid values fit their native uint32 representation
	final, _, err := apkLauncherReadFile(ctx, anchor, nativeActivationDescriptorPath, maximumNativeActivationDescriptorBytes, syscall.S_IFREG|0644, true)
	if err != nil || final != descriptor {
		return source, descriptor, runtime, errors.Join(errors.New("installed publication descriptor changed during capture"), err)
	}
	return source, descriptor, runtime, ctx.Err()
}

func (observation *nativePublicationExclusionObservation) Revalidate(ctx context.Context) error {
	if ctx == nil || observation == nil || !observation.candidate.publicationExclusion() || !observation.source.publicationExclusion() {
		return errors.New("native publication exclusion observation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	source, descriptor, runtime, err := observeNativePublicationExclusionSource(ctx, observation.host)
	if err != nil {
		return err
	}
	if source != observation.source || descriptor != observation.descriptor || runtime != observation.runtime {
		return errors.New("installed publication capability or runtime changed after review")
	}
	return ctx.Err()
}

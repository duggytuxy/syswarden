package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type nativePackageHeaderIdentity struct {
	name         string
	version      string
	architecture string
}

type nativePackageHeaderReader func(context.Context, *os.File) (nativePackageHeaderIdentity, error)
type nativePackageHeaderAttestor func(context.Context, packageTarget, string, *os.File) error

// attestNativePackageHeader consumes an already authenticated descriptor. The
// caller must verify its signed digest before and after inspection. This binds
// native metadata to release selection; it does not replace native signatures
// or qualify package scripts, dependencies and lifecycle behavior.
func attestNativePackageHeader(ctx context.Context, target packageTarget, version string, file *os.File) error {
	var reader nativePackageHeaderReader
	switch target.format {
	case packageFormatDEB:
		reader = readAuthenticatedDEBIdentity
	case packageFormatRPM:
		reader = readAuthenticatedRPMIdentity
	case packageFormatAPK:
		reader = readAuthenticatedAPKIdentity
	default:
		return errors.New("unsupported authenticated native package format")
	}
	return attestNativePackageHeaderWith(ctx, target, version, file, reader)
}

func attestNativePackageHeaderWith(ctx context.Context, target packageTarget, version string, file *os.File, reader nativePackageHeaderReader) error {
	if ctx == nil || reader == nil || file == nil {
		return errors.New("authenticated native package header attestation is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if target.os != "linux" || target.architecture != "amd64" || !validNativeProductPackageName(target.packageName) {
		return errors.New("authenticated native package selection is unsupported")
	}
	filename, err := packageFilenameForName(version, target.format, target.architecture, target.packageName)
	if err != nil || target.filename != filename {
		return errors.New("authenticated native package filename does not match release selection")
	}
	if _, err := qualificationPackageDescriptorSize(file, target.format); err != nil {
		return err
	}
	identity, err := reader(ctx, file)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("read authenticated native package header: %w", err)
	}
	architecture := "x86_64"
	if target.format == packageFormatDEB {
		architecture = "amd64"
	}
	if identity.name != target.packageName || identity.architecture != architecture {
		return errors.New("authenticated native package name or architecture differs from release selection")
	}
	// The selected APK filename does not encode a revision. Only the release
	// builder's revision zero belongs to this manifest contract.
	if target.format == packageFormatAPK && identity.version != strings.TrimPrefix(version, "v")+"-r0" {
		return errors.New("authenticated APK revision differs from release selection")
	}
	canonical, err := canonicalInstalledSyswardenVersion(identity.version, target.format)
	if err != nil || canonical != version {
		return errors.New("authenticated native package version differs from release selection")
	}
	return ctx.Err()
}

func (u *updater) attestAuthenticatedPackageIdentity(ctx context.Context, target packageTarget, version string, file *os.File, timeout time.Duration) error {
	if u == nil || ctx == nil || u.attestPackageIdentity == nil || timeout <= 0 {
		return errors.New("authenticated native package header verifier is unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	err := u.attestPackageIdentity(bounded, target, version, file)
	if ctxErr := bounded.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

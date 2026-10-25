package system

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// The final guard receives the install deadline and runs after every native
// retention query or argument transformation, immediately before raw execution.
type nativePackageInstaller func(context.Context, packageTarget, string, func(context.Context) error) error

func verifyPackageAtNativeExecution(ctx context.Context, file *os.File, path string, artifact updateArtifact, uid int) error {
	if ctx == nil {
		return errors.New("native package execution context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifySecurePackageForInstallation(file, path, artifact, uid); err != nil {
		return fmt.Errorf("verify authenticated package after native preparation: %w", err)
	}
	return ctx.Err()
}

func runAuthenticatedNativeInstall(ctx context.Context, target packageTarget, path string, beforeExecute func(context.Context) error) error {
	return runAuthenticatedNativeInstallWith(ctx, target, path, false,
		func(ctx context.Context, manager string) error {
			return preserveNativeDependencyReasonsForName(ctx, manager, target.packageName)
		}, func(ctx context.Context, name string, args []string) ([]string, error) {
			return planAuthenticatedAPKInstallForName(ctx, target.packageName, name, args)
		}, func(ctx context.Context, name string, args ...string) error {
			return executeExternalCommand(ctx, name, productionCommandEnvironment(name), args...)
		}, beforeExecute)
}

func runAuthenticatedQualificationInstall(ctx context.Context, target packageTarget, path string, beforeExecute func(context.Context) error) error {
	return runAuthenticatedNativeInstallWith(ctx, target, path, true,
		func(ctx context.Context, manager string) error {
			return preserveNativeDependencyReasonsForName(ctx, manager, target.packageName)
		}, func(ctx context.Context, name string, args []string) ([]string, error) {
			return planAuthenticatedAPKInstallForName(ctx, target.packageName, name, args)
		}, executeQualificationExternalCommand, beforeExecute)
}

func planAuthenticatedAPKInstallForName(ctx context.Context, packageName, name string, args []string) ([]string, error) {
	if ctx == nil || !validNativeProductPackageName(packageName) {
		return nil, errors.New("authenticated APK planning requires an exact native identity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	planned, err := apkPreservedInstallArgumentsForName(packageName, name, args, productionOpenRCWireGuardDefinitionPaths())
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return planned, err
}

func runAuthenticatedNativeInstallWith(ctx context.Context, target packageTarget, path string, offline bool,
	prepare func(context.Context, string) error,
	planAPK func(context.Context, string, []string) ([]string, error),
	execute commandRunner, beforeExecute func(context.Context) error,
) error {
	if ctx == nil || prepare == nil || planAPK == nil || execute == nil || beforeExecute == nil {
		return errors.New("authenticated native installer dependencies are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Production base updates remain closed until selected-name retention and
	// native lifecycle qualification are completed together.
	if target.os != "linux" || target.architecture != "amd64" || target.packageName != "syswarden" {
		return errors.New("authenticated native installation target is unsupported")
	}
	validInstaller := false
	switch target.format {
	case packageFormatDEB:
		validInstaller = target.installer == "/usr/bin/apt-get"
	case packageFormatRPM:
		validInstaller = target.installer == "/usr/bin/dnf" || target.installer == "/usr/bin/yum"
	case packageFormatAPK:
		validInstaller = target.installer == "/sbin/apk" || target.installer == "/usr/sbin/apk"
	}
	if !validInstaller {
		return errors.New("authenticated native installer does not match the selected format")
	}
	name, args := target.installer, target.installArguments(path)
	if offline {
		name, args = target.qualificationInstallCommand(path)
	}
	return runWithNativeDependencyRetention(ctx, name, args, offline, prepare,
		func(ctx context.Context, name string, args ...string) error {
			if target.format == packageFormatAPK {
				planned, err := planAPK(ctx, name, args)
				if err != nil {
					return fmt.Errorf("prepare authenticated APK transaction: %w", err)
				}
				args = planned
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := beforeExecute(ctx); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return execute(ctx, name, args...)
		})
}

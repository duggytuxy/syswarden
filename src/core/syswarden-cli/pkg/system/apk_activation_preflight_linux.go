//go:build linux

package system

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// PreflightAPKConfigurationActivation refuses retained native transition debt
// before a command can approve or consume configuration. It never finalizes a
// transaction or infers success from the disappearance of its active hook.
// A qualified inactive-preservation executor must also retain policy publication
// custody until its outcome has been independently checked.
func PreflightAPKConfigurationActivation(ctx context.Context) error {
	return preflightAPKConfigurationActivationAt(ctx, "/")
}

func preflightAPKConfigurationActivationAt(ctx context.Context, host string) error {
	if ctx == nil || !filepath.IsAbs(host) || filepath.Clean(host) != host {
		return errors.New("APK activation preflight requires an exact host and context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, location := range []struct{ parent, name string }{
		{strings.TrimPrefix(apkTransitionRoot, "/"), "active-hook"},
		{apkTransitionGateDirectory, apkTransitionGateName},
	} {
		if err := refuseAPKActivationGate(filepath.Join(host, location.parent), location.name); err != nil {
			return err
		}
	}
	// Finalization publishes execution lineage before retiring either hook.
	// Its independent reader requires the positive post-Close proof. Thus a
	// crash after both unlinks still cannot authorize activation implicitly.
	path := filepath.Join(host, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"))
	directory, err := openExistingPinnedServiceDirectory(path)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if err := closeAPKExecutionDirectory(directory); err != nil {
		return err
	}
	if err := preflightAPKLauncherRemovalAt(ctx, host); err != nil {
		return errors.Join(errors.New("APK lifecycle must be resolved before configuration activation"), err)
	}
	return ctx.Err()
}

func refuseAPKActivationGate(path, name string) (result error) {
	directory, err := openExistingPinnedServiceDirectory(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(directory)) }()
	if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errors.New("APK transition is pending; configuration activation requires native recovery"), err)
	}
	entries, err := directory.file.ReadDir(1025)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > 1024 {
		return errors.New("APK activation gate inventory exceeds its bound")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".syswarden-apk-retired-") {
			return errors.New("APK gate retirement is incomplete; preserve its quarantine for native recovery")
		}
	}
	return attestRetainedDirectoryParent(path, directory, false)
}

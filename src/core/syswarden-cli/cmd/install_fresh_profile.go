package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"syswarden-cli/config"
	"syswarden-cli/pkg/platformpaths"
)

// The native hook's fresh phase can only restrict behavior. It is never inferred
// from list choice, missing runtime state or an existing administrator profile.
func freshNativePackageInstallation() bool {
	return os.Getenv("SYSWARDEN_PKG_INSTALL") == "1" && os.Getenv("SYSWARDEN_NATIVE_INSTALL_PHASE") == "fresh"
}

var stageFreshNativeConfiguration = func(root string) error {
	return stageFreshNativeConfigurationAt(root, platformpaths.LegacyConfig)
}

func stageFreshNativeConfigurationAt(root, legacyPath string) error {
	complete, err := config.ModularConfigurationComplete(root)
	if err != nil {
		return err
	}
	if complete {
		// Existing modular policy already takes precedence in initConfig. Preserve
		// its bytes, including when an old flat source remains as a recovery copy.
		_, err := config.ValidateModularConfig(root)
		return err
	}
	if err := refuseFreshNativeLegacyConfiguration(legacyPath); err != nil {
		return err
	}
	// EnsureDefaults preserves complete existing configuration and refuses partial
	// policy. Staging creates no service, schedule, feed, firewall or module state.
	if err := config.EnsureDefaults(root); err != nil {
		return err
	}
	_, err = config.ValidateModularConfig(root)
	return err
}

func refuseFreshNativeLegacyConfiguration(legacyPath string) error {
	if !filepath.IsAbs(legacyPath) || filepath.Clean(legacyPath) != legacyPath {
		return fmt.Errorf("fresh staging requires an exact absolute legacy configuration path")
	}
	// Do not follow an ambiguous ancestor and interpret its missing child as
	// proof that no retained policy exists. This inspection creates no paths.
	for parent := filepath.Dir(legacyPath); parent != string(filepath.Separator); parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect legacy configuration parent %s before fresh staging: %w", parent, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("legacy configuration parent %s is ambiguous; fresh staging cannot establish absent policy", parent)
		}
	}
	// This is the same fixed source/retention family used by deferred native
	// activation and Migrator. Existence alone requires reviewed recovery; no
	// source contents are read, migrated, renamed or deleted by fresh staging.
	for _, path := range []string{legacyPath, legacyPath + ".migration_backup", legacyPath + ".migrated", legacyPath + ".migration_backup.migrated", legacyPath + ".bak"} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("retained legacy configuration at %s requires explicit migration or recovery before fresh staging; no defaults were created", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect retained legacy configuration %s before fresh staging: %w", path, err)
		}
	}
	return nil
}

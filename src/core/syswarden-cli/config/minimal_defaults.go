package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
)

// An unpublished fresh profile can resume only while every existing module
// matches its exact template. The master is published last. Once present, a
// missing module requires recovery, including a missing administrator override.
func preflightMissingDefaults(outputDir, master string, modules []renderedModule) error {
	root, err := openConfigDirectory(outputDir, false, 0)
	if err != nil {
		return err
	}
	defer root.Close()
	moduleRoot, err := openConfigDirectory(filepath.Join(outputDir, "modules"), false, 0)
	if err != nil {
		return err
	}
	defer moduleRoot.Close()
	missing, different := false, false
	inspect := func(actual []byte, expected string, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			missing = true
			return nil
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, []byte(expected)) {
			different = true
		}
		return nil
	}
	content, err := readSecureRegularFile(root, "config.toml", filepath.Join(outputDir, "config.toml"))
	masterPresent := err == nil
	if err := inspect(content, master, err); err != nil {
		return err
	}
	known := make(map[string]bool, len(modules))
	for _, module := range modules {
		known[module.name] = true
		content, err := readSecureRegularFile(moduleRoot, module.name, filepath.Join(outputDir, "modules", module.name))
		if err := inspect(content, module.content, err); err != nil {
			return err
		}
	}
	if missing {
		// Unknown TOML modules are administrator policy, even if every surviving
		// generated module happens to match a fresh template. Do not infer that
		// lost configuration can safely be replaced with the new profile.
		directory, err := moduleRoot.Open(".")
		if err != nil {
			return err
		}
		entries, readErr := directory.ReadDir(1025)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(entries) > 1024 {
			return fmt.Errorf("incomplete existing configuration: module inventory exceeds the safe initialization bound")
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".toml" && !known[entry.Name()] {
				different = true
			}
		}
	}
	if missing && (masterPresent || different) {
		return fmt.Errorf("incomplete existing configuration: restore the missing policy modules from the installation's retained configuration before retrying; fresh defaults cannot establish the previous protection")
	}
	return nil
}

// PrepareInstallationConfiguration validates existing policy for activation.
// Fresh native staging owns initialization and exact unpublished-template retry;
// activation must never infer fresh-install authority from missing configuration.
// Preserve the previous valid snapshot and record a degraded load on refusal.
func PrepareInstallationConfiguration(root string) (err error) {
	defer func() {
		if err != nil {
			recordConfigLoadFailure(root, err)
		}
	}()
	complete, err := ModularConfigurationComplete(root)
	if err != nil {
		return fmt.Errorf("inspect existing modular configuration before activation: %w", err)
	}
	if !complete {
		return fmt.Errorf("activation requires complete existing modular configuration: restore the installation's retained policy or complete explicit legacy migration before retrying; fresh defaults cannot establish the previous protection")
	}
	if err := RemoveRetiredWebTUIConfiguration(root); err != nil {
		return fmt.Errorf("remove retired Web-TUI configuration: %w", err)
	}
	if err := ParseConfig(root); err != nil {
		return fmt.Errorf("validate modular configuration: %w", err)
	}
	return nil
}

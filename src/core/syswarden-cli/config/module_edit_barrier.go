package config

import (
	"errors"
	"fmt"
	"io/fs"
)

// RefusePendingModuleEdit treats every existing intent, including malformed or
// unsafe evidence, as unresolved. Absence is a read-only point-in-time check,
// not a lock or permission to mutate the host. Nothing is repaired or removed.
func RefusePendingModuleEdit(configDir string) error {
	root, err := openConfigDirectory(configDir, false, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Lstat(moduleEditIntentName); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect pending configuration edit: %w", err)
	}
	return errors.New("configuration edit publication requires explicit recovery; preserve its intent and private file pair")
}

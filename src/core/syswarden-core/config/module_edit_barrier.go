package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const pendingModuleEditName = ".config-edit-intent.json"

// verifyConfigurationReadBarrier refuses unresolved publication evidence before
// and after candidate reading. It neither reads nor repairs the intent. These
// observations do not lock out another process or attest runtime activation.
func verifyConfigurationReadBarrier(root *os.Root, path string) error {
	opened, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened configuration root: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		current.Mode().Perm()&0022 != 0 || !os.SameFile(opened, current) {
		return errors.New("configuration root changed during candidate reading")
	}
	if _, err := root.Lstat(pendingModuleEditName); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect pending configuration edit: %w", err)
	}
	return errors.New("configuration edit publication requires explicit recovery; preserve its intent and private file pair")
}

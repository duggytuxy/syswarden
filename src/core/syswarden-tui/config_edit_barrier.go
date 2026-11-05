package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const tuiPendingModuleEditName = ".config-edit-intent.json"

// verifyTUIConfigurationReadBarrier prevents HA peer and credential selection
// from an unresolved edit. Absence is a point-in-time observation, not a lock.
// No journal content is opened, interpreted, displayed or removed.
func verifyTUIConfigurationReadBarrier(root *os.Root, path string, before os.FileInfo) error {
	opened, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened modular HA configuration: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		current.Mode().Perm()&0022 != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return errors.New("modular HA configuration root is unsafe or changed during reading")
	}
	if _, err := root.Lstat(tuiPendingModuleEditName); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect pending configuration edit: %w", err)
	}
	return errors.New("configuration edit publication requires explicit recovery; preserve its intent and private file pair")
}

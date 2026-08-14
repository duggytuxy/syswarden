package network

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

func ensurePrivateDirectory(rootDirectory, relativePath string) error {
	if !fs.ValidPath(relativePath) || relativePath == "." {
		return fmt.Errorf("invalid private directory path %q", relativePath)
	}
	currentRoot, err := os.OpenRoot(rootDirectory)
	if err != nil {
		return fmt.Errorf("open private directory root: %w", err)
	}
	for _, component := range strings.Split(relativePath, "/") {
		info, statErr := currentRoot.Lstat(component)
		if errors.Is(statErr, fs.ErrNotExist) {
			if err := currentRoot.Mkdir(component, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
				_ = currentRoot.Close()
				return fmt.Errorf("create private directory %q: %w", relativePath, err)
			}
			info, statErr = currentRoot.Lstat(component)
		}
		if statErr != nil {
			_ = currentRoot.Close()
			return fmt.Errorf("inspect private directory %q: %w", relativePath, statErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = currentRoot.Close()
			return fmt.Errorf("private directory %q is not a real directory", relativePath)
		}
		nextRoot, err := currentRoot.OpenRoot(component)
		if err != nil {
			_ = currentRoot.Close()
			return fmt.Errorf("open private directory %q: %w", relativePath, err)
		}
		openedInfo, err := nextRoot.Stat(".")
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = nextRoot.Close()
			_ = currentRoot.Close()
			return fmt.Errorf("private directory changed while opening: %q", relativePath)
		}
		_ = currentRoot.Close()
		currentRoot = nextRoot
	}
	defer func() { _ = currentRoot.Close() }()
	directory, err := currentRoot.Open(".")
	if err != nil {
		return fmt.Errorf("open private directory handle %q: %w", relativePath, err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Chmod(0700); err != nil {
		return fmt.Errorf("restrict private directory %q: %w", relativePath, err)
	}
	return nil
}

package system

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func writeExecutableAtomically(directory, name string, content []byte) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("invalid executable filename %q", name)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open executable directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return fmt.Errorf("generate executable temporary filename: %w", err)
	}
	temporaryName := "." + name + ".tmp-" + hex.EncodeToString(randomSuffix)
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temporary executable: %w", err)
	}
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
	}()

	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary executable: %w", err)
	}
	if err := temporary.Chmod(0755); err != nil {
		return fmt.Errorf("set executable mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary executable: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary executable: %w", err)
	}
	temporaryOpen = false
	if err := root.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("replace executable atomically: %w", err)
	}

	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open executable directory for sync: %w", err)
	}
	defer func() { _ = directoryFile.Close() }()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync executable directory: %w", err)
	}
	return nil
}

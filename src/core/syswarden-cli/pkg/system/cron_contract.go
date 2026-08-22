package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const privateCronWorkRoot = "/var/tmp"

func setPrivateCronCache(command *exec.Cmd, cacheDirectory string) {
	environment := command.Environ()
	filteredEnvironment := make([]string, 0, len(environment)+1)
	for _, variable := range environment {
		if !strings.HasPrefix(variable, "XDG_CACHE_HOME=") {
			filteredEnvironment = append(filteredEnvironment, variable)
		}
	}
	command.Env = append(filteredEnvironment, "XDG_CACHE_HOME="+cacheDirectory)
}

func removePrivateCronWork(workDirectory string) error {
	if err := os.RemoveAll(workDirectory); err != nil {
		return fmt.Errorf("remove private cron work directory: %w", err)
	}
	if _, err := os.Lstat(workDirectory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify private cron work directory removal: %w", err)
	}
	return fmt.Errorf("private cron work directory remains after removal")
}

func verifyPrivateCronDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private cron directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private cron path is not a non-symlink directory")
	}
	if info.Mode().Perm() != 0700 {
		return fmt.Errorf("private cron directory mode is %04o, want 0700", info.Mode().Perm())
	}
	return nil
}

func preparePrivateCronWorkAt(rootPath string, commands ...*exec.Cmd) (string, error) {
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return "", fmt.Errorf("private cron work root is not clean and absolute")
	}
	workDirectory, err := os.MkdirTemp(rootPath, "syswarden-cron.")
	if err != nil {
		return "", fmt.Errorf("create private cron work directory: %w", err)
	}
	if err := verifyPrivateCronDirectory(workDirectory); err != nil {
		return "", errors.Join(err, removePrivateCronWork(workDirectory))
	}
	cacheDirectory := filepath.Join(workDirectory, "cache")
	if err := os.Mkdir(cacheDirectory, 0700); err != nil {
		return "", errors.Join(
			fmt.Errorf("create private cron cache directory: %w", err),
			removePrivateCronWork(workDirectory),
		)
	}
	if err := verifyPrivateCronDirectory(cacheDirectory); err != nil {
		return "", errors.Join(err, removePrivateCronWork(workDirectory))
	}
	for _, command := range commands {
		setPrivateCronCache(command, cacheDirectory)
	}
	return workDirectory, nil
}

func preparePrivateCronWork(commands ...*exec.Cmd) (string, error) {
	return preparePrivateCronWorkAt(privateCronWorkRoot, commands...)
}

package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"syswarden-cli/pkg/platformpaths"
)

func verifyAbsentRootCronSpool(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify absent root crontab spool: %w", err)
	}
	return fmt.Errorf("crontab reported no entries but the root spool path still exists")
}

func readRootCrontab(command *exec.Cmd) (string, bool, error) {
	environment := command.Environ()
	filteredEnvironment := make([]string, 0, len(environment)+1)
	for _, variable := range environment {
		if !strings.HasPrefix(variable, "LC_ALL=") {
			filteredEnvironment = append(filteredEnvironment, variable)
		}
	}
	command.Env = append(filteredEnvironment, "LC_ALL=C")

	out, err := command.Output()
	if err == nil {
		return string(out), true, nil
	}
	var exitError *exec.ExitError
	if len(out) == 0 && errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		message := strings.TrimSuffix(string(exitError.Stderr), "\n")
		if message == "no crontab for root" ||
			message == "crontab: no crontab for root" ||
			message == "crontab: can't open 'root': No such file or directory" {
			return "", false, nil
		}
	}
	return "", false, fmt.Errorf("failed to read root crontab: %w", err)
}

func writeRootCrontab(command *exec.Cmd, content string) error {
	command.Stdin = strings.NewReader(content)
	if err := command.Run(); err != nil {
		return fmt.Errorf("failed to write root crontab: %w", err)
	}
	return nil
}

// filterManagedRootCrontab removes only canonical SysWarden entries. Every
// surviving record is kept byte-for-byte, including comments, whitespace-only
// records and non-canonical lookalikes. Each surviving record keeps its LF
// terminator exactly when that record had one in the input.
func filterManagedRootCrontab(content string) string {
	var filtered strings.Builder
	for len(content) > 0 {
		line := content
		terminated := false
		if lineEnd := strings.IndexByte(content, '\n'); lineEnd >= 0 {
			line = content[:lineEnd]
			content = content[lineEnd+1:]
			terminated = true
		} else {
			content = ""
		}
		if !platformpaths.IsManagedCronLine(line) {
			filtered.WriteString(line)
			if terminated {
				filtered.WriteByte('\n')
			}
		}
	}
	return filtered.String()
}

func removeRootCrontab(removeCommand, verifyCommand *exec.Cmd) error {
	if err := removeCommand.Run(); err != nil {
		return fmt.Errorf("failed to remove root crontab: %w", err)
	}
	content, present, err := readRootCrontab(verifyCommand)
	if err != nil {
		return fmt.Errorf("verify removed root crontab: %w", err)
	}
	if present {
		return fmt.Errorf("root crontab is still present after removal (%d bytes)", len(content))
	}
	return nil
}

func removeManagedRootCronContent(
	existing string,
	present bool,
	writeCommand *exec.Cmd,
	removeCommand *exec.Cmd,
	verifyCommand *exec.Cmd,
) (bool, error) {
	if !present {
		return false, nil
	}
	filtered := filterManagedRootCrontab(existing)
	if filtered == existing {
		return false, nil
	}
	// A non-empty crontab made entirely from canonical SysWarden records did
	// not represent an operator-owned empty spool. Remove it, then prove that
	// the provider reports absence instead of replacing it with an empty spool.
	if existing != "" && filtered == "" {
		if err := removeRootCrontab(removeCommand, verifyCommand); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, writeRootCrontab(writeCommand, filtered)
}

func removeManagedRootCron(readCommand, writeCommand *exec.Cmd) error {
	existing, present, err := readRootCrontab(readCommand)
	if err != nil {
		return err
	}
	_, err = removeManagedRootCronContent(
		existing,
		present,
		writeCommand,
		exec.Command("crontab", "-r"),
		exec.Command("crontab", "-l"),
	)
	return err
}

func managedFeedCronCount(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		if platformpaths.IsManagedFeedCronLine(line) {
			count++
		}
	}
	return count
}

func inspectManagedFeedCron(command *exec.Cmd) (int, error) {
	content, _, err := readRootCrontab(command)
	if err != nil {
		return 0, err
	}
	return managedFeedCronCount(content), nil
}

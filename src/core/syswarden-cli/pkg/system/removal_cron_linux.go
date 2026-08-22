//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"syswarden-cli/pkg/cronstate"
)

func readOnlyRootCrontabArguments(path string) []string {
	arguments := []string{"-l"}
	switch filepath.Base(path) {
	case "busybox", "busybox.nosuid":
		arguments = append([]string{"crontab"}, arguments...)
	}
	return arguments
}

func runReadOnlyRootCrontabCommand(path string, cacheDirectory string) ([]byte, []byte, error) {
	return runReadOnlyRootCrontabCommandWithTimeout(
		path, cacheDirectory, firewallPreflightTimeout,
	)
}

func runReadOnlyRootCrontabCommandWithTimeout(
	path string,
	cacheDirectory string,
	timeout time.Duration,
) ([]byte, []byte, error) {
	if err := validateResolvedFirewallExecutable(path); err != nil {
		return nil, nil, err
	}
	if !filepath.IsAbs(cacheDirectory) || filepath.Clean(cacheDirectory) != cacheDirectory {
		return nil, nil, fmt.Errorf("private cron cache path is not clean and absolute")
	}
	if timeout <= 0 || timeout > firewallPreflightTimeout {
		return nil, nil, fmt.Errorf("invalid crontab command timeout %s", timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, readOnlyRootCrontabArguments(path)...) // #nosec G204 -- executable is attested and arguments are fixed
	command.Env = []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"XDG_CACHE_HOME=" + cacheDirectory,
	}
	command.WaitDelay = time.Second
	stdout := &boundedFirewallPreflightOutput{}
	stderr := &boundedFirewallPreflightOutput{}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	stdoutBytes := append([]byte(nil), stdout.content.Bytes()...)
	stderrBytes := append([]byte(nil), stderr.content.Bytes()...)
	if stdout.exceeded || stderr.exceeded {
		return stdoutBytes, stderrBytes, fmt.Errorf(
			"crontab command output exceeds %d bytes", maximumFirewallPreflightOutput,
		)
	}
	if ctx.Err() != nil {
		return stdoutBytes, stderrBytes, fmt.Errorf(
			"crontab command exceeded %s: %w", timeout, ctx.Err(),
		)
	}
	return stdoutBytes, stderrBytes, err
}

func parseReadOnlyRootCrontabResult(stdout, stderr []byte, err error) (string, bool, error) {
	if err == nil {
		return string(stdout), true, nil
	}
	code, exact := firewallRemovalExitCode(err)
	message := strings.TrimSuffix(string(stderr), "\n")
	if exact && code == 1 && len(stdout) == 0 &&
		(message == "no crontab for root" ||
			message == "crontab: no crontab for root" ||
			message == "crontab: can't open 'root': No such file or directory") {
		return "", false, nil
	}
	return "", false, fmt.Errorf("failed to read root crontab: %w", err)
}

// ReadOnlyRootCrontabEvidence returns exact root crontab bytes through a
// resolved, attested executable with a fixed read-only invocation.
func ReadOnlyRootCrontabEvidence() (content string, present bool, result error) {
	if os.Geteuid() != 0 {
		return "", false, fmt.Errorf("root crontab evidence must be read as root")
	}
	executor := hostFirewallExecutor()
	crontabPath, err := resolveFirewallExecutable(executor, "crontab")
	if err != nil {
		return "", false, err
	}
	workDirectory, err := preparePrivateCronWork()
	if err != nil {
		return "", false, err
	}
	defer func() {
		result = errors.Join(result, removePrivateCronWork(workDirectory))
	}()
	stdout, stderr, commandErr := runReadOnlyRootCrontabCommand(
		crontabPath,
		filepath.Join(workDirectory, "cache"),
	)
	return parseReadOnlyRootCrontabResult(stdout, stderr, commandErr)
}

func removeOwnedCronStateForRemovalWithOptions(options cronstate.Options) error {
	if err := cronstate.RemoveForUninstall(options); err != nil {
		return fmt.Errorf("remove attested SysWarden cron.d state: %w", err)
	}
	return nil
}

// RemoveOwnedCronStateForRemoval removes only the exact SysWarden cron.d
// artifacts. The operator-controlled root crontab is read-only evidence and is
// never filtered, replaced, or removed.
func RemoveOwnedCronStateForRemoval() error {
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("require removal barrier before cron state removal: %w", err)
	}
	options := cronstate.DefaultOptions(ReadOnlyRootCrontabEvidence)
	if err := removeOwnedCronStateForRemovalWithOptions(options); err != nil {
		return err
	}
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("reattest removal barrier after cron state removal: %w", err)
	}
	return nil
}

//go:build linux

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
	"time"
)

const (
	managedServiceOutputLimit     = 4096
	managedServiceEvidenceLimit   = 512
	managedServiceDiagnosticLimit = 4096
	managedServiceCommandTimeout  = 30 * time.Second
	trustedPathSymlinkLimit       = 40

	trustedCommandPath         = "/usr/sbin:/usr/bin:/sbin:/bin"
	trustedSystemctlPath       = "/usr/bin/systemctl"
	trustedJournalctlPath      = "/usr/bin/journalctl"
	trustedRsyslogdPath        = "/usr/sbin/rsyslogd"
	trustedOpenRCServicePath   = "/sbin/rc-service"
	trustedCheckmodulePath     = "/usr/bin/checkmodule"
	trustedSemodulePackagePath = "/usr/bin/semodule_package"
	trustedSemodulePath        = "/usr/sbin/semodule"
	selinuxRuntimeEnforcement  = "/sys/fs/selinux/enforce"
)

type managedServiceRunner func(string, ...string) ([]byte, error)
type managedServiceExecutor func(context.Context, string, ...string) ([]byte, error)
type trustedExecutableValidator func(string) error

type trustedPathMetadata struct {
	mode os.FileMode
	uid  uint32
}

type trustedPathLstat func(string) (trustedPathMetadata, error)
type trustedPathReadlink func(string) (string, error)

type selinuxRuntimeState uint8

const (
	selinuxRuntimeDisabled selinuxRuntimeState = iota
	selinuxRuntimeActive
	selinuxRuntimeIndeterminate
)

var trustedSELinuxPolicyTools = [...]string{
	trustedCheckmodulePath,
	trustedSemodulePackagePath,
	trustedSemodulePath,
}

type managedServiceDiagnosticError struct {
	message string
	cause   error
}

func (diagnostic *managedServiceDiagnosticError) Error() string { return diagnostic.message }
func (diagnostic *managedServiceDiagnosticError) Unwrap() error { return diagnostic.cause }

type boundedCombinedOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (output *boundedCombinedOutput) Write(data []byte) (int, error) {
	written := len(data)
	remaining := managedServiceOutputLimit - output.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = output.buffer.Write(data)
	}
	if written > remaining {
		output.truncated = true
	}
	return written, nil
}

func (output *boundedCombinedOutput) Bytes() []byte {
	result := append([]byte(nil), output.buffer.Bytes()...)
	if !output.truncated {
		return result
	}
	marker := []byte("\n[output truncated]")
	if len(marker) >= managedServiceOutputLimit {
		return append([]byte(nil), marker[:managedServiceOutputLimit]...)
	}
	if len(result) > managedServiceOutputLimit-len(marker) {
		result = result[:managedServiceOutputLimit-len(marker)]
	}
	return append(result, marker...)
}

const rsyslogSELinuxPolicy = `module syswarden_rsyslog 1.0;
require {
	type syslogd_t;
	type unconfined_service_t;
	type init_t;
	type var_run_t;
	class sock_file write;
	class unix_dgram_socket sendto;
}
allow syslogd_t unconfined_service_t:unix_dgram_socket sendto;
allow syslogd_t init_t:unix_dgram_socket sendto;
allow syslogd_t var_run_t:sock_file write;
`

const (
	syswardenInternalLogMarker      = "[SYSWARDEN-INTERNAL]"
	rsyslogInternalTimestampPattern = `[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} `
	rsyslogInternalRecordPattern    = `[[]SYSWARDEN-INTERNAL[]] action=[A-Z][A-Z0-9-]{0,63} ip=([0-9A-Fa-f:.]+|invalid-[0-9a-f]{16}) scope=[A-Za-z0-9._:/%-]{1,128} payload_sha256=[0-9a-f]{64} payload_bytes=[0-9]{1,20} auth=[0-9a-f]{64}`
	rsyslogDirectInternalLogPattern = `^` + rsyslogInternalTimestampPattern + rsyslogInternalRecordPattern + `$`
)

const rsyslogWAFBase = `module(load="imfile")
module(load="omuxsock")
$OMUxSockSocket /var/run/syswarden.sock

# Web Server Logs
input(type="imfile" File="/var/log/nginx/*.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/apache2/*.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/httpd/*.log" Tag="syswarden-waf" ruleset="waf_bridge")

# System & Auth Logs (HIDS)
input(type="imfile" File="/var/log/auth.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/secure" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/syslog" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/messages" Tag="syswarden-waf" ruleset="waf_bridge")
`

const rsyslogWAFRuleset = `
template(name="SYSWARDENRaw" type="string" string="%msg%\n")

ruleset(name="waf_bridge") {
    # Product-owned records are output, never fresh detection input.
    if $programname == "syswarden-core" and re_match($msg, '` + rsyslogDirectInternalLogPattern + `') then stop

    *.* :omuxsock:;SYSWARDENRaw
}
`

func renderWAFRsyslogConfig(rawPatterns string) (string, int, error) {
	patterns, err := validatedRsyslogLogPatterns(rawPatterns)
	if err != nil {
		return "", 0, err
	}
	var rendered strings.Builder
	rendered.WriteString(rsyslogWAFBase)
	if len(patterns) > 0 {
		rendered.WriteString("\n# Docker Multi-Tenant Logs\n")
	}
	for _, pattern := range patterns {
		quoted, err := quoteRsyslogString(pattern)
		if err != nil {
			return "", 0, fmt.Errorf("encode rsyslog log pattern: %w", err)
		}
		fmt.Fprintf(&rendered, "input(type=\"imfile\" File=%s Tag=\"syswarden-waf\" ruleset=\"waf_bridge\")\n", quoted)
	}
	rendered.WriteString(rsyslogWAFRuleset)
	return rendered.String(), len(patterns), nil
}

// SetupWAFLogForwarder configures Rsyslog to bridge local Web/Docker logs into the Go WAF Socket
func SetupWAFLogForwarder() error {
	fmt.Println("[INFO] Configuring WAF Multi-Tenant Log Bridge (Rsyslog -> UDS)...")

	confPath := "/etc/rsyslog.d/99-syswarden-waf-bridge.conf"

	rsyslogConf, activePatterns, err := renderWAFRsyslogConfig(config.GlobalConfig.ModsecLogs)
	if err != nil {
		return fmt.Errorf("render WAF bridge config: %w", err)
	}
	if config.GlobalConfig.ModsecLogs != "" && activePatterns == 0 {
		fmt.Println("[WARN] Configured ModSecurity log patterns have no real regular-file match; custom rsyslog input was omitted.")
	}

	selinuxState, selinuxStateErr := detectSELinuxRuntime()
	configureSELinuxPolicy, err := shouldConfigureRsyslogSELinuxPolicy(
		selinuxState,
		selinuxStateErr,
		validateTrustedExecutable,
	)
	if err != nil {
		return fmt.Errorf("prepare Rsyslog SELinux policy before writing WAF bridge config: %w", err)
	}
	if selinuxState == selinuxRuntimeIndeterminate {
		fmt.Println("[WARN] SELinux runtime state is indeterminate; applying the Rsyslog policy defensively.")
	}

	// SELinux Hardening (RHEL/Alma) - Compile and install policy to allow rsyslog -> UDS communication.
	if configureSELinuxPolicy {
		fmt.Println("[INFO] Compiling and injecting SELinux policy for Rsyslog UDS bridge...")
		if err := withPrivateSELinuxPolicyWorkspace("", func(workspace string) error {
			if err := runSELinuxPolicyCommand(
				workspace,
				"compile SELinux policy",
				trustedCheckmodulePath,
				"-M", "-m", "-o", "syswarden_rsyslog.mod", "syswarden_rsyslog.te",
			); err != nil {
				return err
			}
			if err := runSELinuxPolicyCommand(
				workspace,
				"package SELinux policy",
				trustedSemodulePackagePath,
				"-o", "syswarden_rsyslog.pp", "-m", "syswarden_rsyslog.mod",
			); err != nil {
				return err
			}
			if err := runSELinuxPolicyCommand(
				workspace,
				"install SELinux policy",
				trustedSemodulePath,
				"-i", "syswarden_rsyslog.pp",
			); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return fmt.Errorf("install Rsyslog SELinux policy before writing WAF bridge config: %w", err)
		}
	}

	_ = os.MkdirAll("/etc/rsyslog.d", 0750)
	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0600); err != nil {
		return fmt.Errorf("failed to write WAF bridge config: %w", err)
	}

	if err := restartManagedService("rsyslog"); err != nil {
		return fmt.Errorf("activate WAF bridge rsyslog configuration: %w", err)
	}

	fmt.Println("[+] WAF Log Bridge successfully configured.")
	return nil
}

func restartManagedService(service string) error {
	return restartManagedServiceUsing(
		service,
		system.ServiceManagerRuntimeState,
		system.IsAlpine,
		runManagedServiceCommand,
	)
}

func runManagedServiceCommand(name string, args ...string) ([]byte, error) {
	return runManagedServiceCommandUsing(
		context.Background(),
		managedServiceCommandTimeout,
		validateTrustedExecutable,
		executeManagedServiceCommand,
		name,
		args...,
	)
}

func runManagedServiceCommandUsing(
	parent context.Context,
	timeout time.Duration,
	validate trustedExecutableValidator,
	execute managedServiceExecutor,
	name string,
	args ...string,
) ([]byte, error) {
	if !filepath.IsAbs(name) {
		return nil, fmt.Errorf("refusing non-absolute privileged command path %q", name)
	}
	if err := validate(name); err != nil {
		return nil, fmt.Errorf("validate trusted executable %s: %w", name, err)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	output, err := execute(ctx, name, args...)
	if contextErr := ctx.Err(); contextErr != nil && !errors.Is(err, contextErr) {
		err = errors.Join(err, contextErr)
	}
	return output, err
}

func executeManagedServiceCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return executeManagedServiceCommandInDirectory(ctx, "", name, args...)
}

func executeManagedServiceCommandInDirectory(
	ctx context.Context,
	directory string,
	name string,
	args ...string,
) ([]byte, error) {
	command := newTrustedCommand(ctx, name, args...)
	command.Dir = directory
	var output boundedCombinedOutput
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	return output.Bytes(), err
}

func newTrustedCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, name, args...) // #nosec G204 -- name is an absolute, validated product constant
	command.Env = []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=" + trustedCommandPath,
	}
	return command
}

func validateTrustedExecutable(path string) error {
	return validateTrustedExecutableUsing(path, lstatTrustedPath, os.Readlink)
}

func lstatTrustedPath(path string) (trustedPathMetadata, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return trustedPathMetadata{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return trustedPathMetadata{}, fmt.Errorf("unsupported Linux file metadata")
	}
	return trustedPathMetadata{mode: info.Mode(), uid: stat.Uid}, nil
}

func validateTrustedExecutableUsing(
	path string,
	lstat trustedPathLstat,
	readlink trustedPathReadlink,
) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path is not absolute")
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("path is not canonical")
	}

	// This pre-exec check relies on immutable, root-owned ancestors to prevent
	// non-root replacement between validation and CommandContext execution.
	remaining := trustedPathComponents(path)
	current := string(os.PathSeparator)
	symlinks := 0
	for {
		metadata, err := lstat(current)
		if err != nil {
			return fmt.Errorf("lstat trusted path component %s: %w", current, err)
		}
		if metadata.uid != 0 {
			return fmt.Errorf("trusted path component %s is not root-owned", current)
		}
		if metadata.mode&os.ModeSymlink != 0 {
			// Linux ignores symlink permission bits, so root-owned 0777 usrmerge
			// links are safe when their checked parent directories are immutable.
			symlinks++
			if symlinks > trustedPathSymlinkLimit {
				return fmt.Errorf("trusted path exceeds %d symbolic links", trustedPathSymlinkLimit)
			}
			target, err := readlink(current)
			if err != nil {
				return fmt.Errorf("read trusted symbolic link %s: %w", current, err)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(current), target)
			}
			if len(remaining) > 0 {
				target = filepath.Join(target, filepath.Join(remaining...))
			}
			remaining = trustedPathComponents(filepath.Clean(target))
			current = string(os.PathSeparator)
			continue
		}
		if metadata.mode.Perm()&0022 != 0 {
			return fmt.Errorf("trusted path component %s is group/world writable", current)
		}
		if len(remaining) == 0 {
			if !metadata.mode.IsRegular() {
				return fmt.Errorf("trusted executable %s is not a regular file", current)
			}
			if metadata.mode.Perm()&0111 == 0 {
				return fmt.Errorf("trusted executable %s is not executable", current)
			}
			return nil
		}
		if !metadata.mode.IsDir() {
			return fmt.Errorf("trusted path ancestor %s is not a directory", current)
		}
		current = filepath.Join(current, remaining[0])
		remaining = remaining[1:]
	}
}

func trustedPathComponents(path string) []string {
	path = strings.TrimPrefix(path, string(os.PathSeparator))
	if path == "" {
		return nil
	}
	return strings.Split(path, string(os.PathSeparator))
}

func detectSELinuxRuntime() (selinuxRuntimeState, error) {
	return detectSELinuxRuntimeUsing(os.ReadFile)
}

func detectSELinuxRuntimeUsing(readFile func(string) ([]byte, error)) (selinuxRuntimeState, error) {
	value, err := readFile(selinuxRuntimeEnforcement)
	if errors.Is(err, os.ErrNotExist) {
		return selinuxRuntimeDisabled, nil
	}
	if err != nil {
		return selinuxRuntimeIndeterminate, fmt.Errorf("read SELinux enforcement state: %w", err)
	}
	switch strings.TrimSpace(string(value)) {
	case "0", "1":
		return selinuxRuntimeActive, nil
	default:
		return selinuxRuntimeIndeterminate, fmt.Errorf("unexpected SELinux enforcement state")
	}
}

func shouldConfigureRsyslogSELinuxPolicy(
	state selinuxRuntimeState,
	detectionErr error,
	validate trustedExecutableValidator,
) (bool, error) {
	if state == selinuxRuntimeDisabled {
		return false, nil
	}
	if state != selinuxRuntimeActive && state != selinuxRuntimeIndeterminate {
		return false, fmt.Errorf("unrecognized SELinux runtime state %d", state)
	}
	var causes []error
	if state == selinuxRuntimeIndeterminate && detectionErr != nil {
		causes = append(causes, detectionErr)
	}
	missingTool := false
	for _, tool := range trustedSELinuxPolicyTools {
		if err := validate(tool); err != nil {
			missingTool = true
			causes = append(causes, fmt.Errorf("required SELinux policy tool %s: %w", tool, err))
		}
	}
	if missingTool {
		return false, errors.Join(causes...)
	}
	return true, nil
}

func runSELinuxPolicyCommand(
	directory string,
	operation string,
	name string,
	args ...string,
) error {
	output, err := runManagedServiceCommandUsing(
		context.Background(),
		managedServiceCommandTimeout,
		validateTrustedExecutable,
		func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return executeManagedServiceCommandInDirectory(ctx, directory, name, args...)
		},
		name,
		args...,
	)
	if err == nil {
		return nil
	}
	return newManagedServiceDiagnosticError(
		fmt.Sprintf("%s: %s", operation, managedServiceEvidence(err, output)),
		err,
	)
}

func restartManagedServiceUsing(
	service string,
	classify func() (string, error),
	isAlpine func() bool,
	run managedServiceRunner,
) error {
	state, err := classify()
	if err != nil {
		return err
	}
	switch state {
	case "OFFLINE":
		fmt.Printf("[INFO] Service-manager runtime is offline; %s activation is deferred to boot.\n", service)
		return nil
	case "ACTIVE":
		if isAlpine() {
			if service == "rsyslog" {
				// The firewall OpenRC service needs rsyslog and invokes the reload
				// pipeline during start. Stopping that dependency here creates a
				// circular OpenRC wait. Rsyslog on Alpine does not apply new rules
				// after its nominal reload action, so restart it without traversing
				// the dependency graph after validating the complete configuration.
				if _, err := run(trustedRsyslogdPath, "-N1", "-f", "/etc/rsyslog.conf"); err != nil {
					return fmt.Errorf("validate rsyslog configuration before OpenRC restart: %w", err)
				}
				if _, err := run(trustedOpenRCServicePath, "--ifnotstarted", service, "start"); err != nil {
					return fmt.Errorf("conditionally start OpenRC service %s with dependencies: %w", service, err)
				}
				if _, err := run(trustedOpenRCServicePath, service, "status"); err != nil {
					return fmt.Errorf("attest active OpenRC service %s before dependency-bypassing restart: %w", service, err)
				}
				if _, err := run(trustedOpenRCServicePath, "--nodeps", service, "restart"); err != nil {
					return fmt.Errorf("restart OpenRC service %s without dependency traversal: %w", service, err)
				}
				if _, err := run(trustedOpenRCServicePath, service, "status"); err != nil {
					return fmt.Errorf("attest restarted OpenRC service %s: %w", service, err)
				}
				return nil
			}
			if _, err := run(trustedOpenRCServicePath, service, "restart"); err != nil {
				return fmt.Errorf("restart OpenRC service %s: %w", service, err)
			}
			return nil
		}
		if service == "rsyslog" {
			return restartSystemdRsyslogUsing(run)
		}
		if _, err := run(trustedSystemctlPath, "restart", service); err != nil {
			return fmt.Errorf("restart systemd service %s: %w", service, err)
		}
		return nil
	default:
		return fmt.Errorf("refusing unrecognized service-manager runtime state %q", state)
	}
}

func restartSystemdRsyslogUsing(run managedServiceRunner) error {
	validationOutput, validationErr := run(
		trustedRsyslogdPath, "-N1", "-f", "/etc/rsyslog.conf",
	)
	if validationErr != nil {
		return newManagedServiceDiagnosticError(
			fmt.Sprintf(
				"validate complete rsyslog configuration before systemd restart: %s",
				managedServiceEvidence(validationErr, validationOutput),
			),
			validationErr,
		)
	}

	firstOutput, firstErr := run(trustedSystemctlPath, "restart", "rsyslog")
	firstActiveOutput, firstActiveErr := run(
		trustedSystemctlPath, "is-active", "--quiet", "rsyslog",
	)
	if firstErr == nil && firstActiveErr == nil {
		return nil
	}

	resetOutput, resetErr := run(trustedSystemctlPath, "reset-failed", "rsyslog")
	retryOutput, retryErr := run(trustedSystemctlPath, "restart", "rsyslog")
	retryActiveOutput, retryActiveErr := run(
		trustedSystemctlPath, "is-active", "--quiet", "rsyslog",
	)
	if retryErr == nil && retryActiveErr == nil {
		fmt.Println("[WARN] Initial rsyslog restart failed; recovered after one bounded retry.")
		return nil
	}

	journalOutput, journalErr := run(
		trustedJournalctlPath, "--no-pager", "--quiet", "--boot", "--unit", "rsyslog.service", "--lines=40",
	)
	return newManagedServiceDiagnosticError(
		fmt.Sprintf(
			"restart systemd service rsyslog failed after one bounded retry: first_restart=%s; first_active=%s; reset_failed=%s; retry_restart=%s; retry_active=%s; journal=%s",
			managedServiceEvidence(firstErr, firstOutput),
			managedServiceEvidence(firstActiveErr, firstActiveOutput),
			managedServiceEvidence(resetErr, resetOutput),
			managedServiceEvidence(retryErr, retryOutput),
			managedServiceEvidence(retryActiveErr, retryActiveOutput),
			managedServiceEvidence(journalErr, journalOutput),
		),
		firstErr,
		firstActiveErr,
		resetErr,
		retryErr,
		retryActiveErr,
		journalErr,
	)
}

func managedServiceEvidence(err error, output []byte) string {
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}
	return boundedDiagnosticText(fmt.Sprintf(
		"error=%s output=%s",
		strconv.QuoteToASCII(errorText),
		strconv.QuoteToASCII(string(output)),
	), managedServiceEvidenceLimit, "[evidence truncated]")
}

func newManagedServiceDiagnosticError(message string, causes ...error) error {
	return &managedServiceDiagnosticError{
		message: boundedDiagnosticText(message, managedServiceDiagnosticLimit, "[diagnostic truncated]"),
		cause:   errors.Join(causes...),
	}
}

func boundedDiagnosticText(value string, limit int, marker string) string {
	if len(value) <= limit {
		return value
	}
	marker = "\n" + marker
	if len(marker) >= limit {
		return marker[:limit]
	}
	return value[:limit-len(marker)] + marker
}

func withPrivateSELinuxPolicyWorkspace(parent string, action func(workspace string) error) error {
	workspace, err := os.MkdirTemp(parent, "syswarden-rsyslog-")
	if err != nil {
		return fmt.Errorf("create private SELinux policy workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(workspace) }()

	tePath := filepath.Join(workspace, "syswarden_rsyslog.te")
	if err := os.WriteFile(tePath, []byte(rsyslogSELinuxPolicy), 0600); err != nil {
		return fmt.Errorf("write SELinux policy source: %w", err)
	}
	return action(workspace)
}

//go:build linux

package integration

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
	"time"

	"golang.org/x/sys/unix"
)

const (
	managedServiceOutputLimit     = 4096
	managedServiceEvidenceLimit   = 384
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

	wafRsyslogParentDirectory = "/etc"
	wafRsyslogDirectoryName   = "rsyslog.d"
	wafRsyslogConfigName      = "99-syswarden-waf-bridge.conf"
	// Keep publication and exact-removal readers on one explicit bound. A
	// moderately large glob can legitimately expand beyond 64 KiB, while a
	// finite cap still prevents privileged reads from consuming unbounded memory.
	rsyslogArtifactContentLimit = 1024 * 1024
	wafRsyslogStagingAttempts   = 128
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

	reconcileBridge := func() error {
		return reconcileRsyslogArtifactWithProvenanceAtUsing(
			wafRsyslogParentDirectory,
			0,
			0,
			wafRsyslogConfigName,
			"WAF bridge",
			[]byte(rsyslogConf),
			reconcileWAFRsyslogService,
			recordRsyslogArtifactProvenance,
			requireRsyslogMutationWithoutRemovalBarrier,
		)
	}

	// SELinux hardening (RHEL/Alma): keep the private package and any exact
	// pre-existing policy available until the rsyslog publication transaction
	// succeeds, so a later validation or activation failure can be rolled back.
	if configureSELinuxPolicy {
		fmt.Println("[INFO] Compiling and injecting SELinux policy for Rsyslog UDS bridge...")
		if err := withPrivateSELinuxPolicyWorkspace("", func(workspace string) error {
			transaction, err := installRsyslogSELinuxPolicyWithProvenance(workspace)
			if err != nil {
				return err
			}
			bridgeBaseline, err := captureRsyslogBridgeRollbackBaselineAt(
				wafRsyslogParentDirectory,
				0,
				0,
				[]byte(rsyslogConf),
			)
			if err != nil {
				return errors.Join(err, transaction.Rollback())
			}
			if err := reconcileBridge(); err != nil {
				return errors.Join(
					err,
					bridgeBaseline.Rollback(reconcileWAFRsyslogService),
					transaction.Rollback(),
				)
			}
			if err := transaction.Commit(); err != nil {
				return errors.Join(err, bridgeBaseline.Rollback(reconcileWAFRsyslogService))
			}
			return nil
		}); err != nil {
			return fmt.Errorf("install Rsyslog SELinux policy before writing WAF bridge config: %w", err)
		}
	} else if err := reconcileBridge(); err != nil {
		return err
	}

	fmt.Println("[+] WAF Log Bridge successfully configured.")
	return nil
}

func requireRsyslogMutationWithoutRemovalBarrier() error {
	return requireRsyslogMutationWithoutRemovalBarrierUsing(system.InspectRemovalTombstone)
}

func requireRsyslogMutationWithoutRemovalBarrierUsing(
	inspect func() (bool, error),
) error {
	if inspect == nil {
		return fmt.Errorf("removal barrier inspector is unavailable")
	}
	present, err := inspect()
	if err != nil {
		return fmt.Errorf("inspect durable removal barrier before rsyslog mutation: %w", err)
	}
	if present {
		return fmt.Errorf("durable removal barrier is present")
	}
	return nil
}

type wafRsyslogConfigState struct {
	exists bool
	dev    uint64
	ino    uint64
	nlink  uint64
	size   int64
	mode   uint32
	uid    uint32
	gid    uint32
	mtime  unix.Timespec
	ctime  unix.Timespec
	digest [sha256.Size]byte
}

// wafRsyslogPublicationDurabilityError means a published target directory could
// not be synced. The caller must still activate the visible file, while a later
// idempotent run retries the durability barrier before it can succeed.
type wafRsyslogPublicationDurabilityError struct {
	cause error
}

func (failure *wafRsyslogPublicationDurabilityError) Error() string { return failure.cause.Error() }
func (failure *wafRsyslogPublicationDurabilityError) Unwrap() error { return failure.cause }

func finishWAFRsyslogSetup(
	configChanged bool,
	publicationErr error,
	activate func(bool) error,
) error {
	return finishRsyslogArtifactSetup("WAF bridge", configChanged, publicationErr, activate)
}

func finishRsyslogArtifactSetup(
	label string,
	configChanged bool,
	publicationErr error,
	activate func(bool) error,
) error {
	var durabilityErr *wafRsyslogPublicationDurabilityError
	if publicationErr != nil && !errors.As(publicationErr, &durabilityErr) {
		return fmt.Errorf("publish %s rsyslog configuration: %w", label, publicationErr)
	}

	activationErr := activate(configChanged)
	if activationErr != nil {
		activationErr = fmt.Errorf("activate %s rsyslog configuration: %w", label, activationErr)
	}
	if publicationErr != nil {
		publicationErr = fmt.Errorf("publish %s rsyslog configuration: %w", label, publicationErr)
	}
	return errors.Join(publicationErr, activationErr)
}

func validateWAFRsyslogDirectoryMetadata(
	label string,
	stat *unix.Stat_t,
	expectedUID, expectedGID uint32,
) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a real directory", label)
	}
	if stat.Uid != expectedUID || stat.Gid != expectedGID {
		return fmt.Errorf(
			"%s must be owned by uid %d gid %d, got uid %d gid %d",
			label, expectedUID, expectedGID, stat.Uid, stat.Gid,
		)
	}
	if stat.Mode&0022 != 0 {
		return fmt.Errorf("%s must not be group/world writable: mode %04o", label, stat.Mode&07777)
	}
	return nil
}

func openWAFRsyslogDirectoryAt(
	parentPath string,
	expectedUID, expectedGID uint32,
) (*os.File, error) {
	parentFD, err := unix.Open(
		parentPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open anchored rsyslog parent directory %s: %w", parentPath, err)
	}
	defer unix.Close(parentFD)

	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return nil, fmt.Errorf("inspect anchored rsyslog parent directory %s: %w", parentPath, err)
	}
	if err := validateWAFRsyslogDirectoryMetadata(
		"rsyslog parent directory "+parentPath,
		&parentStat,
		expectedUID,
		expectedGID,
	); err != nil {
		return nil, err
	}

	created := false
	if err := unix.Mkdirat(parentFD, wafRsyslogDirectoryName, 0750); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("create anchored rsyslog directory: %w", err)
		}
	} else {
		created = true
	}

	directoryFD, err := unix.Openat(
		parentFD,
		wafRsyslogDirectoryName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open anchored rsyslog directory without following symlinks: %w", err)
	}
	if created {
		if err := unix.Fchmod(directoryFD, 0750); err != nil {
			_ = unix.Close(directoryFD)
			return nil, fmt.Errorf("set anchored rsyslog directory mode: %w", err)
		}
	}

	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil {
		_ = unix.Close(directoryFD)
		return nil, fmt.Errorf("inspect anchored rsyslog directory: %w", err)
	}
	if err := validateWAFRsyslogDirectoryMetadata(
		"rsyslog directory "+filepath.Join(parentPath, wafRsyslogDirectoryName),
		&directoryStat,
		expectedUID,
		expectedGID,
	); err != nil {
		_ = unix.Close(directoryFD)
		return nil, err
	}
	// Sync on every pass so a previous post-Mkdirat sync failure is recoverable
	// even though the directory is already visible on the next attempt.
	if err := unix.Fsync(parentFD); err != nil {
		_ = unix.Close(directoryFD)
		return nil, fmt.Errorf("sync rsyslog parent directory: %w", err)
	}

	directory := os.NewFile(
		uintptr(directoryFD),
		filepath.Join(parentPath, wafRsyslogDirectoryName),
	)
	if directory == nil {
		_ = unix.Close(directoryFD)
		return nil, fmt.Errorf("wrap anchored rsyslog directory descriptor")
	}
	return directory, nil
}

func sameWAFRsyslogStat(left, right *unix.Stat_t) bool {
	return uint64(left.Dev) == uint64(right.Dev) &&
		uint64(left.Ino) == uint64(right.Ino) &&
		left.Nlink == right.Nlink &&
		left.Size == right.Size &&
		left.Mode == right.Mode &&
		left.Uid == right.Uid &&
		left.Gid == right.Gid &&
		left.Mtim == right.Mtim &&
		left.Ctim == right.Ctim
}

func inspectRsyslogArtifact(
	directory *os.File,
	name string,
	expectedUID, expectedGID uint32,
) (wafRsyslogConfigState, []byte, error) {
	if !validOwnedArtifactName(name) {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("invalid rsyslog artifact name %q", name)
	}
	var pathBefore unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &pathBefore, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return wafRsyslogConfigState{}, nil, nil
	}
	if err != nil {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("inspect anchored rsyslog configuration: %w", err)
	}
	fd, err := unix.Openat(
		int(directory.Fd()),
		name,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return wafRsyslogConfigState{}, nil, fmt.Errorf(
			"open anchored rsyslog configuration without following symlinks: %w",
			err,
		)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return wafRsyslogConfigState{}, nil, fmt.Errorf("wrap anchored rsyslog configuration descriptor")
	}

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		_ = file.Close()
		return wafRsyslogConfigState{}, nil, fmt.Errorf("inspect rsyslog configuration: %w", err)
	}
	if !sameWAFRsyslogStat(&pathBefore, &before) {
		_ = file.Close()
		return wafRsyslogConfigState{}, nil, fmt.Errorf("rsyslog configuration changed while opening")
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = file.Close()
		return wafRsyslogConfigState{}, nil, fmt.Errorf("rsyslog configuration must be a regular file")
	}
	if before.Nlink != 1 {
		_ = file.Close()
		return wafRsyslogConfigState{}, nil, fmt.Errorf(
			"rsyslog configuration link count must be 1, got %d",
			before.Nlink,
		)
	}
	if before.Uid != expectedUID || before.Gid != expectedGID {
		_ = file.Close()
		return wafRsyslogConfigState{}, nil, fmt.Errorf(
			"rsyslog configuration must be owned by uid %d gid %d, got uid %d gid %d",
			expectedUID, expectedGID, before.Uid, before.Gid,
		)
	}
	if before.Mode&07777 != 0600 {
		_ = file.Close()
		return wafRsyslogConfigState{}, nil, fmt.Errorf(
			"rsyslog configuration mode must be 0600, got %04o",
			before.Mode&07777,
		)
	}
	if before.Size < 0 || before.Size > rsyslogArtifactContentLimit {
		_ = file.Close()
		return wafRsyslogConfigState{}, nil, fmt.Errorf(
			"rsyslog configuration size %d exceeds limit %d",
			before.Size,
			rsyslogArtifactContentLimit,
		)
	}

	content, readErr := io.ReadAll(io.LimitReader(file, rsyslogArtifactContentLimit+1))
	var after, pathAfter unix.Stat_t
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	pathErr := unix.Fstatat(int(directory.Fd()), name, &pathAfter, unix.AT_SYMLINK_NOFOLLOW)
	if readErr != nil {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("read bounded rsyslog configuration: %w", readErr)
	}
	if len(content) > rsyslogArtifactContentLimit {
		return wafRsyslogConfigState{}, nil, fmt.Errorf(
			"rsyslog configuration grew beyond limit %d while reading",
			rsyslogArtifactContentLimit,
		)
	}
	if statErr != nil {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("reinspect rsyslog configuration: %w", statErr)
	}
	if closeErr != nil {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("close rsyslog configuration: %w", closeErr)
	}
	if pathErr != nil {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("reinspect rsyslog configuration path: %w", pathErr)
	}
	if !sameWAFRsyslogStat(&before, &after) || !sameWAFRsyslogStat(&after, &pathAfter) ||
		int64(len(content)) != before.Size {
		return wafRsyslogConfigState{}, nil, fmt.Errorf("rsyslog configuration changed while reading")
	}

	return wafRsyslogConfigState{
		exists: true,
		dev:    uint64(after.Dev),
		ino:    uint64(after.Ino),
		nlink:  uint64(after.Nlink),
		size:   after.Size,
		mode:   after.Mode,
		uid:    after.Uid,
		gid:    after.Gid,
		mtime:  after.Mtim,
		ctime:  after.Ctim,
		digest: sha256.Sum256(content),
	}, content, nil
}

func inspectWAFRsyslogConfig(
	directory *os.File,
	expectedUID, expectedGID uint32,
) (wafRsyslogConfigState, []byte, error) {
	return inspectRsyslogArtifact(
		directory,
		wafRsyslogConfigName,
		expectedUID,
		expectedGID,
	)
}

func sameWAFRsyslogConfigState(expected, actual wafRsyslogConfigState) bool {
	return expected.exists == actual.exists &&
		expected.dev == actual.dev &&
		expected.ino == actual.ino &&
		expected.nlink == actual.nlink &&
		expected.size == actual.size &&
		expected.mode == actual.mode &&
		expected.uid == actual.uid &&
		expected.gid == actual.gid &&
		expected.mtime == actual.mtime &&
		expected.ctime == actual.ctime &&
		expected.digest == actual.digest
}

func createRsyslogStagingFile(
	directory *os.File,
	targetName string,
	expectedUID, expectedGID uint32,
) (*os.File, string, error) {
	if !validOwnedArtifactName(targetName) {
		return nil, "", fmt.Errorf("invalid rsyslog artifact name %q", targetName)
	}
	for range wafRsyslogStagingAttempts {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate rsyslog staging name: %w", err)
		}
		name := "." + targetName + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		fd, err := unix.Openat(
			int(directory.Fd()),
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0600,
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create anchored rsyslog staging file: %w", err)
		}
		if err := unix.Fchmod(fd, 0600); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
			return nil, "", fmt.Errorf("set rsyslog staging file mode: %w", err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
			return nil, "", fmt.Errorf("inspect rsyslog staging file: %w", err)
		}
		if stat.Uid != expectedUID || stat.Gid != expectedGID {
			if err := unix.Fchown(fd, int(expectedUID), int(expectedGID)); err != nil {
				_ = unix.Close(fd)
				_ = unix.Unlinkat(int(directory.Fd()), name, 0)
				return nil, "", fmt.Errorf("set rsyslog staging file owner: %w", err)
			}
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
			return nil, "", fmt.Errorf("wrap rsyslog staging file descriptor")
		}
		return file, name, nil
	}
	return nil, "", fmt.Errorf("create rsyslog staging file: too many name collisions")
}

func reconcileWAFRsyslogConfigAt(
	parentPath string,
	expectedUID, expectedGID uint32,
	desired []byte,
	beforeRename func() error,
) (bool, error) {
	return reconcileWAFRsyslogConfigAtUsing(
		parentPath,
		expectedUID,
		expectedGID,
		desired,
		beforeRename,
		func(directory *os.File) error { return directory.Sync() },
	)
}

func reconcileWAFRsyslogConfigAtUsing(
	parentPath string,
	expectedUID, expectedGID uint32,
	desired []byte,
	beforeRename func() error,
	syncDirectory func(*os.File) error,
) (bool, error) {
	return reconcileRsyslogArtifactAtUsing(
		parentPath,
		wafRsyslogConfigName,
		expectedUID,
		expectedGID,
		desired,
		beforeRename,
		syncDirectory,
	)
}

func reconcileRsyslogArtifactAtUsing(
	parentPath, name string,
	expectedUID, expectedGID uint32,
	desired []byte,
	beforeRename func() error,
	syncDirectory func(*os.File) error,
) (bool, error) {
	if !validOwnedArtifactName(name) {
		return false, fmt.Errorf("invalid rsyslog artifact name %q", name)
	}
	if len(desired) > rsyslogArtifactContentLimit {
		return false, fmt.Errorf(
			"desired rsyslog configuration size %d exceeds limit %d",
			len(desired),
			rsyslogArtifactContentLimit,
		)
	}
	directory, err := openWAFRsyslogDirectoryAt(parentPath, expectedUID, expectedGID)
	if err != nil {
		return false, err
	}
	defer directory.Close()

	return reconcileRsyslogArtifactInDirectoryUsing(
		directory,
		name,
		expectedUID,
		expectedGID,
		desired,
		beforeRename,
		syncDirectory,
	)
}

func reconcileRsyslogArtifactInDirectoryUsing(
	directory *os.File,
	name string,
	expectedUID, expectedGID uint32,
	desired []byte,
	beforeRename func() error,
	syncDirectory func(*os.File) error,
) (bool, error) {
	if !validOwnedArtifactName(name) || len(desired) > rsyslogArtifactContentLimit || syncDirectory == nil {
		return false, fmt.Errorf("invalid rsyslog artifact publication input")
	}
	initial, existing, err := inspectRsyslogArtifact(directory, name, expectedUID, expectedGID)
	if err != nil {
		return false, err
	}
	if initial.exists && bytes.Equal(existing, desired) {
		// Retrying this sync closes a prior crash or fsync-failure window after
		// Renameat. Exact content is not durable until this directory sync passes.
		if err := syncDirectory(directory); err != nil {
			return false, &wafRsyslogPublicationDurabilityError{
				cause: fmt.Errorf("sync unchanged rsyslog configuration directory: %w", err),
			}
		}
		return false, nil
	}

	staging, stagingName, err := createRsyslogStagingFile(directory, name, expectedUID, expectedGID)
	if err != nil {
		return true, err
	}
	defer func() {
		if staging != nil {
			_ = staging.Close()
		}
		if stagingName != "" {
			_ = unix.Unlinkat(int(directory.Fd()), stagingName, 0)
		}
	}()

	if written, err := staging.Write(desired); err != nil {
		return true, fmt.Errorf("write rsyslog staging file: %w", err)
	} else if written != len(desired) {
		return true, fmt.Errorf("write rsyslog staging file: %w", io.ErrShortWrite)
	}
	if err := staging.Sync(); err != nil {
		return true, fmt.Errorf("sync rsyslog staging file: %w", err)
	}
	if err := staging.Close(); err != nil {
		return true, fmt.Errorf("close rsyslog staging file: %w", err)
	}
	staging = nil
	stagedState, stagedContent, err := inspectRsyslogArtifact(
		directory, stagingName, expectedUID, expectedGID,
	)
	if err != nil || !stagedState.exists || !bytes.Equal(stagedContent, desired) {
		return true, errors.Join(fmt.Errorf("rsyslog staging file failed exact re-attestation"), err)
	}

	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return true, err
		}
	}
	current, _, err := inspectRsyslogArtifact(directory, name, expectedUID, expectedGID)
	if err != nil {
		return true, fmt.Errorf("reinspect rsyslog configuration before publication: %w", err)
	}
	if !sameWAFRsyslogConfigState(initial, current) {
		return true, fmt.Errorf("rsyslog configuration changed before publication")
	}
	if err := unix.Renameat(
		int(directory.Fd()),
		stagingName,
		int(directory.Fd()),
		name,
	); err != nil {
		return true, fmt.Errorf("atomically publish rsyslog configuration: %w", err)
	}
	stagingName = ""
	if err := syncDirectory(directory); err != nil {
		return true, &wafRsyslogPublicationDurabilityError{
			cause: fmt.Errorf("sync rsyslog configuration directory after publication: %w", err),
		}
	}
	return true, nil
}

func reconcileWAFRsyslogService(configChanged bool) error {
	return restartManagedServiceUsingConfigState(
		"rsyslog",
		configChanged,
		system.ServiceManagerRuntimeState,
		system.IsAlpine,
		runManagedServiceCommand,
	)
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

func restartManagedServiceUsing(
	service string,
	classify func() (string, error),
	isAlpine func() bool,
	run managedServiceRunner,
) error {
	return restartManagedServiceUsingConfigState(service, true, classify, isAlpine, run)
}

func restartManagedServiceUsingConfigState(
	service string,
	_ bool,
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
				// circular OpenRC wait. Alpine's nominal rsyslog reload does not apply
				// new rules, so every valid setup attempt performs one bounded nodeps
				// restart. This also recovers a crash after atomic publication but
				// before service activation.
				if _, err := run(trustedRsyslogdPath, "-N1", "-f", "/etc/rsyslog.conf"); err != nil {
					return fmt.Errorf("validate rsyslog configuration before OpenRC activation: %w", err)
				}
				if _, err := run(trustedOpenRCServicePath, "--ifnotstarted", service, "start"); err != nil {
					return fmt.Errorf("conditionally start OpenRC service %s with dependencies: %w", service, err)
				}
				if _, err := run(trustedOpenRCServicePath, service, "status"); err != nil {
					return fmt.Errorf("attest active OpenRC service %s before configuration reconciliation: %w", service, err)
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
				"validate complete rsyslog configuration before systemd activation: %s",
				managedServiceEvidence(validationErr, validationOutput),
			),
			validationErr,
		)
	}

	initialActiveOutput, initialActiveErr := run(
		trustedSystemctlPath, "is-active", "--quiet", "rsyslog",
	)
	reloadEvidence := "not-attempted"
	reloadActiveEvidence := "not-attempted"
	var reloadErr, reloadActiveErr error
	if initialActiveErr == nil {
		// Reload even exact content to recover a crash after atomic publication
		// but before the previous setup attempt reached service activation.
		reloadOutput, currentReloadErr := run(trustedSystemctlPath, "reload", "rsyslog")
		reloadErr = currentReloadErr
		reloadEvidence = managedServiceEvidence(reloadErr, reloadOutput)
		reloadActiveOutput, currentReloadActiveErr := run(
			trustedSystemctlPath, "is-active", "--quiet", "rsyslog",
		)
		reloadActiveErr = currentReloadActiveErr
		reloadActiveEvidence = managedServiceEvidence(reloadActiveErr, reloadActiveOutput)
		if reloadErr == nil && reloadActiveErr == nil {
			return nil
		}
	}

	firstOutput, firstErr := run(trustedSystemctlPath, "restart", "rsyslog")
	firstActiveOutput, firstActiveErr := run(
		trustedSystemctlPath, "is-active", "--quiet", "rsyslog",
	)
	if firstErr == nil && firstActiveErr == nil {
		fmt.Println("[WARN] Rsyslog required one bounded restart fallback after reload or active-state attestation.")
		return nil
	}

	resetOutput, resetErr := run(trustedSystemctlPath, "reset-failed", "rsyslog")
	retryOutput, retryErr := run(trustedSystemctlPath, "restart", "rsyslog")
	retryActiveOutput, retryActiveErr := run(
		trustedSystemctlPath, "is-active", "--quiet", "rsyslog",
	)
	if retryErr == nil && retryActiveErr == nil {
		fmt.Println("[WARN] Initial rsyslog restart or active-state attestation failed; recovered after one bounded retry.")
		return nil
	}

	journalOutput, journalErr := run(
		trustedJournalctlPath, "--no-pager", "--quiet", "--boot", "--unit", "rsyslog.service", "--lines=40",
	)
	return newManagedServiceDiagnosticError(
		fmt.Sprintf(
			"activate systemd service rsyslog failed after one bounded retry following reload or active-state attestation: initial_active=%s; reload=%s; reload_active=%s; first_restart=%s; first_active=%s; reset_failed=%s; retry_restart=%s; retry_active=%s; journal=%s",
			managedServiceEvidence(initialActiveErr, initialActiveOutput),
			reloadEvidence,
			reloadActiveEvidence,
			managedServiceEvidence(firstErr, firstOutput),
			managedServiceEvidence(firstActiveErr, firstActiveOutput),
			managedServiceEvidence(resetErr, resetOutput),
			managedServiceEvidence(retryErr, retryOutput),
			managedServiceEvidence(retryActiveErr, retryActiveOutput),
			managedServiceEvidence(journalErr, journalOutput),
		),
		initialActiveErr,
		reloadErr,
		reloadActiveErr,
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

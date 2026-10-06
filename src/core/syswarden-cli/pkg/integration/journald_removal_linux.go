//go:build linux

package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"syswarden-cli/pkg/security"
	"syswarden-cli/pkg/system"

	"golang.org/x/sys/unix"
)

const journaldRemovalPath = security.JournaldForwardingPolicyPath
const journaldRemovalContent = security.JournaldForwardingPolicy
const journaldRemovalMaximumOutput = 4 << 20
const journaldRemovalProperties = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,ExecMainStartTimestampMonotonic,NeedDaemonReload,RootDirectory,RootImage,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ExecCondition,FragmentPath,DropInPaths,User,Group,DynamicUser,BindPaths,BindReadOnlyPaths,TemporaryFileSystem,MountImages,ExtensionImages,ExtensionDirectories"

type journaldRemovalService struct {
	pid        uint64
	started    uint64
	invocation string
	properties map[string]string
}

func inspectJournaldRemovalService(run managedServiceRunner) (journaldRemovalService, error) {
	var empty journaldRemovalService
	output, err := run(trustedSystemctlPath, "show", "systemd-journald.service", "--no-pager", "--property="+journaldRemovalProperties)
	if err != nil {
		return empty, fmt.Errorf("inspect journald before exact fragment removal: %w", err)
	}
	if len(output) > 64<<10 || !bytes.HasSuffix(output, []byte("\n")) || bytes.ContainsAny(output, "\x00\r") {
		return empty, fmt.Errorf("invalid journald service observation")
	}
	allowed := make(map[string]bool)
	for _, key := range strings.Split(journaldRemovalProperties, ",") {
		allowed[key] = true
	}
	properties := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] {
			return empty, fmt.Errorf("unexpected journald service property")
		}
		if _, duplicate := properties[key]; duplicate {
			return empty, fmt.Errorf("duplicate journald service property")
		}
		properties[key] = value
	}
	for key, value := range map[string]string{
		"Id": "systemd-journald.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
		"ControlPID": "0", "NeedDaemonReload": "no", "DynamicUser": "no",
	} {
		if actual, present := properties[key]; !present || actual != value {
			return empty, fmt.Errorf("journald is not in the supported idle active state")
		}
	}
	for _, key := range []string{"RootDirectory", "RootImage", "User", "Group"} {
		if _, present := properties[key]; !present {
			return empty, fmt.Errorf("journald root or identity evidence is incomplete")
		}
		if properties[key] != "" && !((key == "User" || key == "Group") && properties[key] == "root") {
			return empty, fmt.Errorf("journald uses an unsupported root or identity")
		}
	}
	for _, key := range []string{"Environment", "EnvironmentFiles", "UnsetEnvironment", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "MountImages", "ExtensionImages", "ExtensionDirectories"} {
		if properties[key] != "" {
			return empty, fmt.Errorf("journald uses an unsupported auxiliary command or configuration override")
		}
	}
	// The default Debian consumer passes TERM for terminal formatting. It
	// does not select a configuration tree. No other inherited variable is
	// accepted, including loader or systemd configuration overrides.
	if inherited := properties["PassEnvironment"]; inherited != "" && inherited != "TERM" {
		return empty, fmt.Errorf("journald imports unsupported service-manager environment")
	}
	command := properties["ExecStart"]
	validCommand := false
	for _, path := range []string{"/usr/lib/systemd/systemd-journald", "/lib/systemd/systemd-journald"} {
		prefix := "{ path=" + path + " ; argv[]=" + path + " ; ignore_errors=no ; start_time=["
		validCommand = validCommand || strings.HasPrefix(command, prefix) && strings.HasSuffix(command, " ; status=0/0 }") && len(strings.Split(command, " ; ")) == 8
	}
	if !validCommand || properties["FragmentPath"] == "" {
		return empty, fmt.Errorf("journald does not use the supported default configuration consumer")
	}
	pid, pidErr := strconv.ParseUint(properties["MainPID"], 10, 32)
	started, startErr := strconv.ParseUint(properties["ExecMainStartTimestampMonotonic"], 10, 64)
	invocation := properties["InvocationID"]
	if pidErr != nil || startErr != nil || pid <= 1 || started == 0 || strconv.FormatUint(pid, 10) != properties["MainPID"] || strconv.FormatUint(started, 10) != properties["ExecMainStartTimestampMonotonic"] || len(invocation) != 32 || strings.Trim(invocation, "0123456789abcdef") != "" || strings.Trim(invocation, "0") == "" {
		return empty, fmt.Errorf("journald process identity is unavailable")
	}
	commandFields := strings.Split(command, " ; ")
	if commandFields[5] != "pid="+strconv.FormatUint(pid, 10) || commandFields[6] != "code=(null)" {
		return empty, fmt.Errorf("journald executable process does not match its active identity")
	}
	return journaldRemovalService{pid, started, invocation, properties}, nil
}

func readJournaldRemovalConfiguration(run managedServiceRunner) ([]byte, error) {
	output, err := run("/usr/bin/systemd-analyze", "cat-config", "systemd/journald.conf")
	if err != nil {
		return nil, fmt.Errorf("inspect complete journald configuration: %w", err)
	}
	if len(output) > journaldRemovalMaximumOutput || len(output) == 0 || bytes.ContainsAny(output, "\x00\r") || !bytes.HasSuffix(output, []byte("\n")) {
		return nil, fmt.Errorf("journald configuration observation is incomplete or exceeds its bound")
	}
	return append([]byte(nil), output...), nil
}

// Remove exactly the generated cat-config block. This transformation is only
// an observation expectation, never an edit to a shared configuration file.
// A forged or duplicate header cannot authorize removal: the canonical source
// is independently attested, and the observed result must match afterward.
func journaldConfigurationWithoutOwnedFragment(before []byte, present bool) ([]byte, error) {
	header := []byte("# " + journaldRemovalPath + "\n")
	if !present {
		if bytes.Contains(before, header) {
			return nil, fmt.Errorf("inactive journald fragment still appears in the effective configuration")
		}
		return append([]byte(nil), before...), nil
	}
	block := []byte("\n# " + journaldRemovalPath + "\n" + journaldRemovalContent)
	if bytes.Count(before, header) != 1 || bytes.Count(before, block) != 1 {
		return nil, fmt.Errorf("generated journald fragment is not the exact effective source block")
	}
	start := bytes.Index(before, block)
	end := start + len(block)
	if end < len(before) && !bytes.HasPrefix(before[end:], []byte("\n# /")) {
		return nil, fmt.Errorf("journald source block has unexpected trailing content")
	}
	return bytes.Replace(before, block, nil, 1), nil
}

func reapplyJournaldRemovalConfiguration(run managedServiceRunner, expected []byte, guard func() error) error {
	if err := guard(); err != nil {
		return err
	}
	before, err := inspectJournaldRemovalService(run)
	if err != nil {
		return err
	}
	configuration, err := readJournaldRemovalConfiguration(run)
	if err != nil {
		return err
	}
	if !bytes.Equal(configuration, expected) {
		return fmt.Errorf("unrelated journald configuration changed; preserve recovery evidence")
	}
	if _, err := run(trustedSystemctlPath, "restart", "systemd-journald.service"); err != nil {
		return fmt.Errorf("restart journald after exact fragment change: %w", err)
	}
	after, err := inspectJournaldRemovalService(run)
	if err != nil {
		return err
	}
	if after.pid == before.pid || after.started <= before.started || after.invocation == before.invocation {
		return fmt.Errorf("journald restart did not establish a new active process")
	}
	for _, key := range []string{"FragmentPath", "DropInPaths", "RootDirectory", "RootImage", "User", "Group", "DynamicUser", "PassEnvironment"} {
		if after.properties[key] != before.properties[key] {
			return fmt.Errorf("journald service configuration changed during restart")
		}
	}
	configuration, err = readJournaldRemovalConfiguration(run)
	if err != nil {
		return err
	}
	if !bytes.Equal(configuration, expected) {
		return fmt.Errorf("journald configuration changed during activation")
	}
	return guard()
}

func removeExactJournaldFragmentAtUsing(parent string, uid, gid uint32, options exactOwnedArtifactRemovalOptions, classify func() (string, error), run managedServiceRunner, guard func() error) error {
	if classify == nil || run == nil || guard == nil {
		return fmt.Errorf("journald removal controls are unavailable")
	}
	if err := guard(); err != nil {
		return err
	}
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(parent, "journald.conf.d", uid, gid)
	if err != nil || !exists {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	expectation := exactContentExpectation("SysWarden journald forwarding fragment", "99-syswarden.conf", []byte(journaldRemovalContent), 0600)
	canonical, err := inspectExactOwnedArtifact(directory, expectation.name, expectation, uid, gid)
	if err != nil {
		return err
	}
	quarantined, err := inspectExactOwnedArtifact(directory, exactArtifactQuarantineName(expectation.name), expectation, uid, gid)
	if err != nil {
		return err
	}
	if !canonical.identity.exists && !quarantined.identity.exists {
		return guard()
	}
	if canonical.identity.exists && !canonical.exact || quarantined.identity.exists && !quarantined.exact || canonical.identity.exists && quarantined.identity.exists {
		return fmt.Errorf("journald fragment ownership is ambiguous; preserve canonical and recovery artifacts")
	}
	state, err := classify()
	if err != nil {
		return err
	}
	if state != "ACTIVE" {
		return fmt.Errorf("journald fragment retirement requires an active service manager; preserve the exact source and quarantine")
	}
	if _, err := inspectJournaldRemovalService(run); err != nil {
		return err
	}
	original, err := readJournaldRemovalConfiguration(run)
	if err != nil {
		return err
	}
	expected, err := journaldConfigurationWithoutOwnedFragment(original, canonical.identity.exists)
	if err != nil {
		return err
	}
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	options.beforeCommit = func() error { return reapplyJournaldRemovalConfiguration(run, expected, guard) }
	options.afterRestore = func() error {
		restored := original
		if !canonical.identity.exists {
			// A pending retry started with the generated fragment quarantined.
			// After restoring that exact inode, derive the aggregate containing
			// it and prove that every other source still matches the baseline.
			var err error
			restored, err = readJournaldRemovalConfiguration(run)
			if err != nil {
				return err
			}
			without, err := journaldConfigurationWithoutOwnedFragment(restored, true)
			if err != nil {
				return err
			}
			if !bytes.Equal(without, original) {
				return fmt.Errorf("administrator journald configuration changed during pending recovery")
			}
		}
		return reapplyJournaldRemovalConfiguration(run, restored, guard)
	}
	if _, err := removeExactOwnedArtifactInDirectoryUsing(directory, uid, gid, expectation, options); err != nil {
		return err
	}
	return errors.Join(guard(), requireOwnedArtifactAbsent(directory, expectation.name, expectation.label), requireOwnedArtifactAbsent(directory, exactArtifactQuarantineName(expectation.name), "journald recovery quarantine"))
}

// RemoveExactJournaldFragmentForRemoval retires the exact generated policy and
// reactivates the shared logging consumer while retaining administrator files.
// Unsupported or changed sources are retained and prevent complete removal.
func RemoveExactJournaldFragmentForRemoval() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("journald fragment retirement requires root")
	}
	return removeExactJournaldFragmentAtUsing("/etc/systemd", 0, 0, defaultExactOwnedArtifactRemovalOptions(), system.ServiceManagerRuntimeState, runManagedServiceCommand, system.RequireRemovalTombstone)
}

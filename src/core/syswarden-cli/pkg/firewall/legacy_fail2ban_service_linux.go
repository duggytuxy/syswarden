//go:build linux

package firewall

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const legacyFail2banServer = "/usr/bin/fail2ban-server"

// Complete entry point from Debian fail2ban 1.1.0-8. A script name alone is
// not sufficient to select the supported launcher or its argument semantics.
const legacyFail2banServerSHA256 = "5b9070e939593fcd4e2639cb5f908d4f3d2bf87a8d977b57f4fdb7c69524788b"

const legacyFail2banServiceProperties = "Id,LoadState,ActiveState,SubState,Type,MainPID,ControlPID,ControlGroup,InvocationID,ExecStart,User,Group,DynamicUser,RootDirectory,RootImage,WorkingDirectory,FragmentPath,DropInPaths,NeedDaemonReload,PIDFile,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment"

type legacyFail2banServiceStatus struct {
	values    map[string]string
	peer      syscall.Ucred
	fragments []string
}

// Limit interpretation to the packaged foreground launcher. Wrapper scripts,
// asynchronous starts and alternate configuration roots require separate
// reviewed recovery instead of assuming that /etc/fail2ban is authoritative.
func decodeLegacyFail2banServiceStatus(content []byte) (legacyFail2banServiceStatus, error) {
	var empty legacyFail2banServiceStatus
	invalid := func() (legacyFail2banServiceStatus, error) {
		return empty, fmt.Errorf("Fail2ban service has an unsupported or changing launch configuration")
	}
	if len(content) == 0 || len(content) > 65536 || content[len(content)-1] != '\n' || strings.ContainsAny(string(content), "\x00\r") {
		return invalid()
	}
	wanted := make(map[string]bool)
	for _, name := range strings.Split(legacyFail2banServiceProperties, ",") {
		wanted[name] = true
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || !wanted[key] {
			return invalid()
		}
		if _, duplicate := values[key]; duplicate {
			return invalid()
		}
		values[key] = value
	}
	// systemctl renders EnvironmentFiles once per array entry, even with --all.
	// An empty array therefore has no line. Only this property may be omitted;
	// nonempty entries remain unsupported and duplicate entries are rejected.
	if _, present := values["EnvironmentFiles"]; !present {
		values["EnvironmentFiles"] = ""
	}
	if len(values) != len(wanted) {
		return invalid()
	}
	for key, expected := range map[string]string{
		"Id": "fail2ban.service", "LoadState": "loaded", "ActiveState": "active",
		"SubState": "running", "Type": "simple", "ControlPID": "0", "DynamicUser": "no",
		"RootDirectory": "", "RootImage": "", "NeedDaemonReload": "no",
		"EnvironmentFiles": "", "PassEnvironment": "", "UnsetEnvironment": "",
	} {
		if values[key] != expected {
			return empty, fmt.Errorf("Fail2ban service property %s is unsupported or changed; recheck the shared service before recovery", key)
		}
	}
	for _, key := range []string{"User", "Group"} {
		if values[key] != "" && values[key] != "root" && values[key] != "0" {
			return invalid()
		}
	}
	if values["WorkingDirectory"] != "" && values["WorkingDirectory"] != "/" ||
		!canonicalNFTPersistencePath(values["ControlGroup"], false) || len(values["InvocationID"]) != 32 {
		return invalid()
	}
	for _, c := range values["InvocationID"] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return invalid()
		}
	}
	if values["InvocationID"] == strings.Repeat("0", 32) {
		return invalid()
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil || pid <= 1 || strconv.FormatInt(pid, 10) != values["MainPID"] {
		return invalid()
	}
	start := values["ExecStart"]
	if !strings.HasPrefix(start, "{ ") || !strings.HasSuffix(start, " }") {
		return invalid()
	}
	fields := strings.Split(start[2:len(start)-2], " ; ")
	if len(fields) != 8 || fields[0] != "path="+legacyFail2banServer ||
		fields[1] != "argv[]="+legacyFail2banServer+" -xf start" || fields[2] != "ignore_errors=no" ||
		!strings.HasPrefix(fields[3], "start_time=[") || !strings.HasSuffix(fields[3], "]") ||
		!strings.HasPrefix(fields[4], "stop_time=[") || !strings.HasSuffix(fields[4], "]") ||
		fields[6] != "code=(null)" || fields[7] != "status=0/0" {
		return invalid()
	}
	// A daemon-reload can reset per-command accounting while the same
	// foreground MainPID and invocation remain active. Accept only the exact
	// empty accounting tuple; the process, argv, PID file and invocation are
	// independently pinned below before any runtime observation or mutation.
	accountingReset := fields[3] == "start_time=[n/a]" && fields[4] == "stop_time=[n/a]" && fields[5] == "pid=0"
	if fields[5] != "pid="+values["MainPID"] && !accountingReset {
		return invalid()
	}
	paths := []string{values["FragmentPath"]}
	if values["DropInPaths"] != "" {
		paths = append(paths, strings.Split(values["DropInPaths"], " ")...)
	}
	if len(paths) > 65 {
		return invalid()
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		if !canonicalNFTPersistencePath(path, false) || strings.ContainsAny(path, "\\\t ") || seen[path] {
			return invalid()
		}
		seen[path] = true
	}
	if !canonicalNFTPersistencePath(values["PIDFile"], false) {
		return invalid()
	}
	return legacyFail2banServiceStatus{values: values, peer: syscall.Ucred{Pid: int32(pid)}, fragments: paths}, nil
}

func queryLegacyFail2banService(ctx context.Context, host nftPersistenceFilesystem, expected nftPersistenceRead) (legacyFail2banServiceStatus, error) {
	var empty legacyFail2banServiceStatus
	current, err := host.snapshot("/usr/bin/systemctl")
	if err != nil || !sameLegacyFail2banSource(expected, current) || current.identity.Mode().Perm()&0111 == 0 {
		return empty, fmt.Errorf("systemctl differs from the inspected executable")
	}
	parent, err := host.openDirectory("/usr/bin")
	if err != nil {
		return empty, err
	}
	defer func() { _ = parent.Close() }()
	binary, err := parent.OpenFile("systemctl", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	defer func() { _ = binary.Close() }()
	identity, err := binary.Stat()
	if err != nil || !sameNFTPersistenceIdentity(expected.identity, identity) {
		return empty, fmt.Errorf("systemctl changed before the read-only query")
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(child, "/proc/self/fd/3", "--system", "--no-pager", "--all", "show", "--property="+legacyFail2banServiceProperties, "--", "fail2ban.service")
	command.ExtraFiles = []*os.File{binary}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_LOG_LEVEL=err"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	stdout, stderr := &boundedNFTCommandOutput{limit: 65536}, &boundedNFTCommandOutput{limit: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || child.Err() != nil || stdout.exceeded || stderr.exceeded {
		return empty, fmt.Errorf("read-only Fail2ban service query failed; service details are withheld")
	}
	current, err = host.snapshot("/usr/bin/systemctl")
	if err != nil || !sameLegacyFail2banSource(expected, current) {
		return empty, fmt.Errorf("systemctl changed during the read-only query")
	}
	return decodeLegacyFail2banServiceStatus(stdout.content.Bytes())
}

// Only the standard root-owned /var/run -> /run alias is supported. Every
// other component remains subject to the existing no-symlink filesystem guard.
func resolveLegacyFail2banRuntimePath(host nftPersistenceFilesystem, path string) (string, error) {
	if !canonicalNFTPersistencePath(path, false) {
		return "", fmt.Errorf("Fail2ban runtime endpoint is not a canonical path")
	}
	if strings.HasPrefix(path, "/var/run/") {
		parent, err := host.openDirectory("/var")
		if err != nil {
			return "", err
		}
		defer func() { _ = parent.Close() }()
		before, err := parent.Lstat("run")
		if err != nil {
			return "", err
		}
		stat, ok := before.Sys().(*syscall.Stat_t)
		target, linkErr := parent.Readlink("run")
		after, statErr := parent.Lstat("run")
		if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != host.expectedUID || stat.Gid != host.expectedGID ||
			linkErr != nil || statErr != nil || target != "/run" && target != "../run" || !sameNFTPersistenceIdentity(before, after) {
			return "", fmt.Errorf("Fail2ban runtime alias is not the trusted /var/run link")
		}
		path = "/run/" + strings.TrimPrefix(path, "/var/run/")
	}
	if !strings.HasPrefix(path, "/run/") {
		return "", fmt.Errorf("Fail2ban runtime endpoint is outside the supported runtime directory")
	}
	return path, nil
}

type legacyFail2banServiceInspection struct {
	host          nftPersistenceFilesystem
	manager       nftPersistenceRead
	status        legacyFail2banServiceStatus
	files         map[string]nftPersistenceRead
	parser        legacyFail2banParserSnapshot
	inventory     legacyFail2banInventory
	process       *legacyFail2banProcessBinding
	client        legacyFail2banReadOnlySocket
	socket        string
	pidfile       string
	actions       legacyFail2banConfiguredActions
	actionsSource []byte
}

// This is a read-only production inspection adapter, not a retirement guard.
// It binds the service manager, packaged launcher, installed trusted parser,
// configuration root, runtime endpoint and live process before returning any
// socket observations. Loaded Python memory, live action ownership, target
// quiescence and kernel dependencies still need independent validation before
// mutation. No whole-service stop, reload, restart or signal is issued here.
func inspectLegacyFail2banService(ctx context.Context, host nftPersistenceFilesystem, parser legacyFail2banParserSnapshot, inventory legacyFail2banInventory, view legacyFail2banConfigurationView) (*legacyFail2banServiceInspection, error) {
	return inspectLegacyFail2banServiceForRecovery(ctx, host, parser, inventory, view, nil)
}

// Recovery reconstructs the original parser input from exact retained inodes.
// Only journal-bound paths may move; all other process and service evidence
// remains subject to the ordinary inspection contract.
func inspectLegacyFail2banServiceForRecovery(ctx context.Context, host nftPersistenceFilesystem, parser legacyFail2banParserSnapshot, inventory legacyFail2banInventory, view legacyFail2banConfigurationView, recovery *legacyFail2banPlanRecord) (*legacyFail2banServiceInspection, error) {
	if host.root == nil || host.expectedUID != 0 || host.expectedGID != 0 || !inventory.present || parser.digest == ([sha256.Size]byte{}) || view.parserSHA256 != parser.digest {
		return nil, fmt.Errorf("Fail2ban service inspection lacks trusted parser and configuration evidence")
	}
	hostRoot, rootErr := host.root.Stat(".")
	actualRoot, actualErr := os.Stat("/")
	if rootErr != nil || actualErr != nil || !os.SameFile(hostRoot, actualRoot) {
		return nil, fmt.Errorf("Fail2ban service inspection requires the current host root")
	}
	inspection := &legacyFail2banServiceInspection{host: host, parser: parser, inventory: cloneLegacyFail2banInventory(inventory), files: make(map[string]nftPersistenceRead), socket: view.socket, pidfile: view.pidfile}
	var err error
	inspection.actions, err = decodeLegacyFail2banConfiguredActions(view.actionsEnabled)
	if err != nil {
		return nil, err
	}
	inspection.actionsSource = append([]byte(nil), view.actionsEnabled...)
	inspection.manager, err = host.snapshot("/usr/bin/systemctl")
	if err != nil {
		return nil, err
	}
	inspection.status, err = queryLegacyFail2banService(ctx, host, inspection.manager)
	if err != nil {
		return nil, err
	}
	for _, path := range append([]string{legacyFail2banServer}, inspection.status.fragments...) {
		source, err := host.snapshot(path)
		if err != nil {
			return nil, err
		}
		inspection.files[path] = source
	}
	script := inspection.files[legacyFail2banServer]
	if fmt.Sprintf("%x", sha256.Sum256(script.content)) != legacyFail2banServerSHA256 || script.identity.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("Fail2ban server launcher differs from the supported packaged entry point")
	}
	socket, err := resolveLegacyFail2banRuntimePath(host, view.socket)
	if err != nil {
		return nil, err
	}
	pidfile, err := resolveLegacyFail2banRuntimePath(host, view.pidfile)
	if err != nil {
		return nil, err
	}
	servicePIDFile, err := resolveLegacyFail2banRuntimePath(host, inspection.status.values["PIDFile"])
	if err != nil || pidfile != servicePIDFile || socket == pidfile {
		return nil, fmt.Errorf("Fail2ban configuration and service runtime paths disagree")
	}
	pidSource, err := host.snapshot(pidfile)
	if err != nil || string(pidSource.content) != inspection.status.values["MainPID"]+"\n" {
		return nil, fmt.Errorf("Fail2ban PID file does not identify the inspected service")
	}
	inspection.files[pidfile] = pidSource
	paths := make(map[string]os.FileInfo)
	paths[parser.executable] = parser.binary.identity
	for path, source := range inspection.files {
		paths[path] = source.identity
	}
	for path, source := range parser.sources {
		paths[path] = source.identity
	}
	for path, identity := range parser.directories {
		paths[path] = identity
	}
	for _, source := range inventory.sources {
		paths[source.path] = source.snapshot.identity
	}
	for _, directory := range inventory.directories {
		paths[directory.path] = directory.identity
	}
	if recovery != nil {
		paths, _, err = legacyFail2banRetirementProcessPaths(host, *recovery, paths)
		if err != nil {
			return nil, err
		}
	}
	inspection.process, err = bindLegacyFail2banProcess(inspection.status.peer, legacyFail2banProcessExpectation{
		executable: parser.binary.identity,
		arguments:  []string{"/usr/bin/python3", legacyFail2banServer, "-xf", "start"},
		cgroup:     []byte("0::" + inspection.status.values["ControlGroup"] + "\n"), paths: paths,
	})
	if err != nil {
		return nil, err
	}
	inspection.client = legacyFail2banReadOnlySocket{host: host, path: socket, peer: inspection.status.peer, guard: inspection.process.verify}
	verify := func() error { return inspection.verify(ctx) }
	if recovery != nil {
		verify = func() error { return inspection.verifyFileRetirement(ctx, *recovery) }
	}
	if err := verify(); err != nil {
		_ = inspection.process.Close()
		return nil, err
	}
	return inspection, nil
}

func (inspection *legacyFail2banServiceInspection) verify(ctx context.Context) error {
	if inspection == nil || inspection.process == nil {
		return fmt.Errorf("Fail2ban service inspection is absent")
	}
	return inspection.verifyEvidence(ctx, inspection.process.verify, func() error {
		return reattestLegacyFail2banPlanInventory(inspection.host, inspection.inventory)
	})
}

func (inspection *legacyFail2banServiceInspection) verifyEvidence(ctx context.Context, process, inventory func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := process(); err != nil {
		return err
	}
	for path, expected := range inspection.files {
		current, err := inspection.host.snapshot(path)
		if err != nil || !sameLegacyFail2banSource(expected, current) {
			return fmt.Errorf("Fail2ban service evidence changed during inspection")
		}
	}
	if err := inspection.parser.reattest(inspection.host); err != nil {
		return err
	}
	if err := inventory(); err != nil {
		return err
	}
	socket, err := resolveLegacyFail2banRuntimePath(inspection.host, inspection.socket)
	if err != nil || socket != inspection.client.path {
		return fmt.Errorf("Fail2ban control endpoint changed during inspection")
	}
	pidfile, err := resolveLegacyFail2banRuntimePath(inspection.host, inspection.pidfile)
	if err != nil {
		return err
	}
	if _, found := inspection.files[pidfile]; !found {
		return fmt.Errorf("Fail2ban PID endpoint changed during inspection")
	}
	if err := inspection.process.verifyServiceEnvironment(inspection.status.values["InvocationID"]); err != nil {
		return err
	}
	current, err := queryLegacyFail2banService(ctx, inspection.host, inspection.manager)
	if err != nil || !sameLegacyFail2banServiceIdentity(inspection.status, current) {
		return fmt.Errorf("Fail2ban service configuration or invocation changed")
	}
	return process()
}

// Both observations have passed decodeLegacyFail2banServiceStatus. Its exact
// launcher and argument checks remain mandatory. A daemon-reload may clear
// command accounting without replacing the MainPID or service invocation;
// process start ticks, pidfd identity and every non-accounting property remain
// independently checked. Do not rewrite either observed property map.
func sameLegacyFail2banServiceIdentity(before, after legacyFail2banServiceStatus) bool {
	if before.peer != after.peer || len(before.values) != len(after.values) {
		return false
	}
	for key, value := range before.values {
		current, found := after.values[key]
		if !found {
			return false
		}
		if key != "ExecStart" || value == current {
			if value != current {
				return false
			}
			continue
		}
		originalFields, currentFields := strings.Split(value, " ; "), strings.Split(current, " ; ")
		if len(originalFields) != 8 || len(currentFields) != 8 {
			return false
		}
		reset := func(fields []string) bool {
			return fields[3] == "start_time=[n/a]" && fields[4] == "stop_time=[n/a]" && fields[5] == "pid=0"
		}
		if !reset(originalFields) && !reset(currentFields) {
			return false
		}
		for index := range originalFields {
			if index >= 3 && index <= 5 {
				continue
			}
			if originalFields[index] != currentFields[index] {
				return false
			}
		}
	}
	return true
}

func (inspection *legacyFail2banServiceInspection) runtime(ctx context.Context) (legacyFail2banRuntimeSnapshot, error) {
	state, err := inspection.readRuntime(ctx)
	if err != nil {
		return legacyFail2banRuntimeSnapshot{}, err
	}
	if err := verifyLegacyFail2banConfiguredRuntime(inspection.actions, state); err != nil {
		return legacyFail2banRuntimeSnapshot{}, err
	}
	return state, nil
}

// The retirement coordinator checks permitted journal-bound transitions
// separately. This reader still reattests all service and source evidence.
func (inspection *legacyFail2banServiceInspection) readRuntime(ctx context.Context) (legacyFail2banRuntimeSnapshot, error) {
	if inspection == nil || inspection.process == nil {
		return legacyFail2banRuntimeSnapshot{}, fmt.Errorf("Fail2ban runtime inspection is absent")
	}
	return inspection.readRuntimeUsing(ctx, inspection.verify)
}

func (inspection *legacyFail2banServiceInspection) readRuntimeUsing(ctx context.Context, verify func(context.Context) error) (legacyFail2banRuntimeSnapshot, error) {
	var empty legacyFail2banRuntimeSnapshot
	if err := verify(ctx); err != nil {
		return empty, err
	}
	client := inspection.client
	client.guard = inspection.process.verifyReadOnlyPeer
	query := func(ctx context.Context, args []string) (legacyFail2banValue, error) {
		child, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return client.query(child, args)
	}
	state, err := inspectLegacyFail2banRuntime(ctx, query)
	if err != nil {
		return empty, err
	}
	if err := verify(ctx); err != nil {
		return empty, err
	}
	return state, nil
}

func (inspection *legacyFail2banServiceInspection) Close() error {
	if inspection == nil {
		return nil
	}
	return inspection.process.Close()
}

func verifyLegacyFail2banServiceEnvironment(content []byte, invocation string) error {
	invalid := func() error {
		return fmt.Errorf("Fail2ban service environment has unsupported import or invocation settings")
	}
	if len(content) == 0 || len(content) > 65536 || content[len(content)-1] != 0 {
		return invalid()
	}
	seen := make(map[string]string)
	for _, entry := range strings.Split(string(content[:len(content)-1]), "\x00") {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return invalid()
		}
		if _, duplicate := seen[name]; duplicate {
			return invalid()
		}
		if strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "PYTHON") && name != "PYTHONNOUSERSITE" && name != "PYTHONDONTWRITEBYTECODE" {
			return invalid()
		}
		seen[name] = value
	}
	if seen["PYTHONNOUSERSITE"] == "" || seen["INVOCATION_ID"] != invocation {
		return invalid()
	}
	return nil
}

func (binding *legacyFail2banProcessBinding) verifyServiceEnvironment(invocation string) error {
	binding.mu.Lock()
	defer binding.mu.Unlock()
	content, err := readLegacyFail2banProcessFile(binding.proc, "environ", 65536)
	if err != nil {
		return err
	}
	if err := verifyLegacyFail2banServiceEnvironment(content, invocation); err != nil {
		return err
	}
	return binding.alive()
}

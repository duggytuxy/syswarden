//go:build linux

package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const nftPersistenceLoaderProperties = "Id,LoadState,ActiveState,SubState,Type,MainPID,ControlPID,RemainAfterExit,ExecStart,ExecReload,ExecStop,ExecStartPre,ExecStartPost,ExecStopPost,ExecCondition,User,Group,DynamicUser,RootDirectory,RootImage,WorkingDirectory,FragmentPath,DropInPaths,NeedDaemonReload,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,BindPaths,BindReadOnlyPaths,TemporaryFileSystem,MountImages,ExtensionImages,ExtensionDirectories,PrivateNetwork,NetworkNamespacePath,JoinsNamespaceOf,PrivateUsers"

type nftPersistenceLoaderStatus struct {
	values    map[string]string
	entries   []string
	fragments []string
	binary    string
}

// This decoder accepts only an idle standard nft loader with absolute literal
// entry points. Additional commands, imports and alternate filesystem views
// require separate recovery. No stop or reload operation is ever issued.
func decodeNFTPersistenceLoaderStatus(content []byte) (nftPersistenceLoaderStatus, error) {
	var empty nftPersistenceLoaderStatus
	invalid := func() (nftPersistenceLoaderStatus, error) {
		return empty, fmt.Errorf("nftables persistence loader has unsupported or changing service properties")
	}
	if len(content) == 0 || len(content) > 65536 || content[len(content)-1] != '\n' || strings.ContainsAny(string(content), "\x00\r") {
		return invalid()
	}
	wanted, values := make(map[string]bool), make(map[string]string)
	for _, key := range strings.Split(nftPersistenceLoaderProperties, ",") {
		wanted[key] = true
	}
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
	// systemctl omits empty arrays even with --all. Only these known array
	// properties may be absent. Nonempty imports or auxiliary commands fail.
	for _, key := range []string{"EnvironmentFiles", "ExecReload", "ExecStop", "ExecStartPre", "ExecStartPost", "ExecStopPost", "ExecCondition", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "MountImages", "ExtensionImages", "ExtensionDirectories"} {
		if _, exists := values[key]; !exists {
			values[key] = ""
		}
	}
	if len(values) != len(wanted) {
		return invalid()
	}
	for key, expected := range map[string]string{
		"Id": "nftables.service", "LoadState": "loaded", "Type": "oneshot", "RemainAfterExit": "yes",
		"MainPID": "0", "ControlPID": "0", "DynamicUser": "no", "NeedDaemonReload": "no",
		"RootDirectory": "", "RootImage": "", "Environment": "", "EnvironmentFiles": "", "PassEnvironment": "", "UnsetEnvironment": "",
		"ExecStartPre": "", "ExecStartPost": "", "ExecStopPost": "", "ExecCondition": "",
		"BindPaths": "", "BindReadOnlyPaths": "", "TemporaryFileSystem": "", "MountImages": "", "ExtensionImages": "", "ExtensionDirectories": "",
		"PrivateNetwork": "no", "NetworkNamespacePath": "", "JoinsNamespaceOf": "", "PrivateUsers": "no",
	} {
		if values[key] != expected {
			return invalid()
		}
	}
	if !(values["ActiveState"] == "active" && values["SubState"] == "exited" || values["ActiveState"] == "inactive" && values["SubState"] == "dead") ||
		values["WorkingDirectory"] != "" && values["WorkingDirectory"] != "/" {
		return invalid()
	}
	for _, key := range []string{"User", "Group"} {
		if values[key] != "" && values[key] != "0" && values[key] != "root" {
			return invalid()
		}
	}
	status := nftPersistenceLoaderStatus{values: values}
	for _, key := range []string{"ExecStart", "ExecReload", "ExecStop"} {
		if key != "ExecStart" && values[key] == "" {
			continue
		}
		binary, entry, err := decodeNFTPersistenceLoaderCommand(values[key], key == "ExecStop")
		if err != nil || status.binary != "" && status.binary != binary {
			return invalid()
		}
		status.binary = binary
		if entry != "" && !slices.Contains(status.entries, entry) {
			status.entries = append(status.entries, entry)
		}
	}
	sort.Strings(status.entries)
	status.fragments = []string{values["FragmentPath"]}
	if values["DropInPaths"] != "" {
		status.fragments = append(status.fragments, strings.Split(values["DropInPaths"], " ")...)
	}
	if len(status.fragments) > 65 {
		return invalid()
	}
	seen := make(map[string]bool)
	for _, path := range status.fragments {
		if !canonicalNFTPersistencePath(path, false) || strings.ContainsAny(path, "\\\t ") || seen[path] {
			return invalid()
		}
		seen[path] = true
	}
	return status, nil
}

func decodeNFTPersistenceLoaderCommand(value string, stop bool) (string, string, error) {
	invalid := func() (string, string, error) { return "", "", fmt.Errorf("unsupported nftables loader command") }
	if !strings.HasPrefix(value, "{ ") || !strings.HasSuffix(value, " }") {
		return invalid()
	}
	fields := strings.Split(value[2:len(value)-2], " ; ")
	if len(fields) != 8 || fields[2] != "ignore_errors=no" || !strings.HasPrefix(fields[0], "path=") || !strings.HasPrefix(fields[1], "argv[]=") ||
		!strings.HasPrefix(fields[3], "start_time=[") || !strings.HasSuffix(fields[3], "]") || !strings.HasPrefix(fields[4], "stop_time=[") || !strings.HasSuffix(fields[4], "]") ||
		!strings.HasPrefix(fields[5], "pid=") || !(fields[6] == "code=(null)" && fields[7] == "status=0/0" || fields[6] == "code=exited" && fields[7] == "status=0") {
		return invalid()
	}
	pid, err := strconv.ParseInt(strings.TrimPrefix(fields[5], "pid="), 10, 32)
	if err != nil || pid < 0 || fields[5] != "pid="+strconv.FormatInt(pid, 10) {
		return invalid()
	}
	binary := strings.TrimPrefix(fields[0], "path=")
	if binary != "/usr/sbin/nft" && binary != "/usr/bin/nft" {
		return invalid()
	}
	arguments := strings.Split(strings.TrimPrefix(fields[1], "argv[]="), " ")
	if len(arguments) != 3 || arguments[0] != binary {
		return invalid()
	}
	if stop {
		// Observe the packaged stop command only. Calling it would flush
		// unrelated protection, so retirement never stops this shared service.
		if arguments[1] != "flush" || arguments[2] != "ruleset" {
			return invalid()
		}
		return binary, "", nil
	}
	entry := arguments[2]
	if arguments[1] != "-f" || !canonicalNFTPersistencePath(entry, false) || strings.ContainsAny(entry, "\"' ") || len(entry) > 4096 {
		return invalid()
	}
	return binary, entry, nil
}

func queryNFTPersistenceLoader(ctx context.Context, host nftPersistenceFilesystem, expected nftPersistenceRead) (nftPersistenceLoaderStatus, error) {
	content, err := queryNFTPersistenceLoaderProperties(ctx, host, expected, nftPersistenceLoaderProperties)
	if err != nil {
		return nftPersistenceLoaderStatus{}, err
	}
	return decodeNFTPersistenceLoaderStatus(content)
}

// Both property sets are internal fixed contracts. Callers cannot select a unit,
// execute a service action or introduce arbitrary service-manager arguments.
func queryNFTPersistenceLoaderProperties(ctx context.Context, host nftPersistenceFilesystem, expected nftPersistenceRead, properties string) ([]byte, error) {
	var empty []byte
	if properties != nftPersistenceLoaderProperties && properties != nftOperatorBootProperties {
		return empty, fmt.Errorf("unsupported read-only loader property set")
	}
	current, err := host.snapshot("/usr/bin/systemctl")
	if err != nil || !sameLegacyFail2banSource(expected, current) || current.identity.Mode().Perm()&0111 == 0 {
		return empty, fmt.Errorf("nftables loader inspection lost the exact service-manager executable")
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
		return empty, fmt.Errorf("nftables loader service manager changed before observation")
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var command *exec.Cmd
	switch properties {
	case nftPersistenceLoaderProperties:
		command = exec.CommandContext(child, "/proc/self/fd/3", "--system", "--no-pager", "--all", "show", "--property="+nftPersistenceLoaderProperties, "--", "nftables.service")
	case nftOperatorBootProperties:
		command = exec.CommandContext(child, "/proc/self/fd/3", "--system", "--no-pager", "--all", "show", "--property="+nftOperatorBootProperties, "--", "nftables.service")
	default:
		return empty, fmt.Errorf("unsupported read-only loader property set")
	}
	command.ExtraFiles = []*os.File{binary}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_LOG_LEVEL=err"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	stdout, stderr := &boundedNFTCommandOutput{limit: 65536}, &boundedNFTCommandOutput{limit: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || child.Err() != nil || stdout.exceeded || stderr.exceeded {
		return empty, fmt.Errorf("read-only nftables loader query failed; service details are withheld")
	}
	current, err = host.snapshot("/usr/bin/systemctl")
	if err != nil || !sameLegacyFail2banSource(expected, current) {
		return empty, fmt.Errorf("nftables loader service manager changed during observation")
	}
	return stdout.content.Bytes(), nil
}

type nftPersistenceLoaderInspection struct {
	host    nftPersistenceFilesystem
	manager nftPersistenceRead
	status  nftPersistenceLoaderStatus
	files   map[string]nftPersistenceRead
	xattrs  map[string]string
	digest  string
}

// A loader attestation binds only this shared service and its effective entry
// points. It does not attest product file ownership, other services, cron or
// Fail2ban actions. Those producer guards remain independently required.
func inspectNFTPersistenceLoader(ctx context.Context, host nftPersistenceFilesystem) (*nftPersistenceLoaderInspection, error) {
	inspection := &nftPersistenceLoaderInspection{host: host, files: make(map[string]nftPersistenceRead), xattrs: make(map[string]string)}
	var err error
	inspection.manager, err = host.snapshot("/usr/bin/systemctl")
	if err != nil {
		return nil, err
	}
	inspection.status, err = queryNFTPersistenceLoader(ctx, host, inspection.manager)
	if err != nil {
		return nil, err
	}
	paths := append([]string{"/usr/bin/systemctl", inspection.status.binary}, inspection.status.fragments...)
	sort.Strings(paths)
	var evidence []nftPersistenceGraphSourceRecord
	for _, path := range paths {
		if _, duplicate := inspection.files[path]; duplicate {
			return nil, fmt.Errorf("nftables loader evidence aliases an executable or unit")
		}
		snapshot, attrs, err := snapshotNFTPersistenceMetadata(host, path)
		if err != nil {
			return nil, err
		}
		if (path == "/usr/bin/systemctl" || path == inspection.status.binary) && snapshot.identity.Mode().Perm()&0111 == 0 {
			return nil, fmt.Errorf("nftables loader executable lacks executable permissions")
		}
		bound, err := bindNFTPersistenceGraphSource(path, snapshot, attrs, snapshot.content)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, bound)
		inspection.files[path], inspection.xattrs[path] = snapshot, bound.Xattrs
	}
	content, err := json.Marshal(struct {
		Schema string                            `json:"schema"`
		Values map[string]string                 `json:"values"`
		Files  []nftPersistenceGraphSourceRecord `json:"files"`
	}{"syswarden-nftables-loader-observation-v1", inspection.status.values, evidence})
	if err != nil {
		return nil, err
	}
	inspection.digest = fmt.Sprintf("%x", sha256.Sum256(content))
	return inspection, inspection.verify(ctx)
}

func (inspection *nftPersistenceLoaderInspection) verify(ctx context.Context) error {
	if inspection == nil || !validLegacyRetirementDigest(inspection.digest) || len(inspection.files) < 3 || len(inspection.status.entries) == 0 {
		return fmt.Errorf("nftables loader inspection is incomplete")
	}
	status, err := queryNFTPersistenceLoader(ctx, inspection.host, inspection.manager)
	if err != nil || !reflect.DeepEqual(status, inspection.status) {
		return fmt.Errorf("nftables loader effective properties changed after inspection")
	}
	for path, expected := range inspection.files {
		actual, attrs, err := snapshotNFTPersistenceMetadata(inspection.host, path)
		if err != nil || !sameLegacyFail2banSource(expected, actual) || nftPersistenceXattrDigest(attrs) != inspection.xattrs[path] {
			return fmt.Errorf("nftables loader executable or service file changed after inspection")
		}
	}
	return nil
}

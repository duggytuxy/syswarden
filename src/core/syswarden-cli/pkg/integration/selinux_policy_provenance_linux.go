//go:build linux

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	rsyslogSELinuxModuleName        = "syswarden_rsyslog"
	rsyslogSELinuxModulePriority    = 400
	rsyslogSELinuxModuleLanguage    = "pp"
	rsyslogSELinuxProvenanceName    = ".syswarden-rsyslog-selinux-provenance-v1"
	rsyslogSELinuxProvenanceSchema  = "syswarden-rsyslog-selinux-provenance-v1"
	selinuxModuleCommandOutputLimit = 1024 * 1024
	selinuxModuleListingLineLimit   = 4096
	selinuxModuleListingRecordLimit = 8192
	selinuxPrivateArtifactSizeLimit = 16 * 1024 * 1024
)

type selinuxModuleIdentity struct {
	priority uint16
	name     string
	language string
	enabled  bool
	checksum string
}

type selinuxModuleProvenance struct {
	exists   bool
	content  []byte
	identity selinuxModuleIdentity
}

type selinuxModuleCommandRunner func(string, string, ...string) ([]byte, error)

type boundedSELinuxModuleOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (output *boundedSELinuxModuleOutput) Write(data []byte) (int, error) {
	written := len(data)
	remaining := selinuxModuleCommandOutputLimit - output.buffer.Len()
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

func (output *boundedSELinuxModuleOutput) Bytes() []byte {
	return append([]byte(nil), output.buffer.Bytes()...)
}

func runSELinuxModuleCommand(directory, name string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !filepath.IsAbs(name) {
		return nil, fmt.Errorf("refusing non-absolute SELinux command directory or path %q %q", directory, name)
	}
	if err := validateTrustedExecutable(name); err != nil {
		return nil, fmt.Errorf("validate trusted SELinux executable %s: %w", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), managedServiceCommandTimeout)
	defer cancel()
	command := newTrustedCommand(ctx, name, args...)
	command.Dir = directory
	var output boundedSELinuxModuleOutput
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if contextErr := ctx.Err(); contextErr != nil && !errors.Is(err, contextErr) {
		err = errors.Join(err, contextErr)
	}
	if output.truncated {
		err = errors.Join(err, fmt.Errorf(
			"SELinux command output exceeded %d bytes",
			selinuxModuleCommandOutputLimit,
		))
	}
	return output.Bytes(), err
}

func runSELinuxModuleOperationUsing(
	run selinuxModuleCommandRunner,
	directory, operation, name string,
	args ...string,
) ([]byte, error) {
	if run == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !filepath.IsAbs(name) {
		return nil, fmt.Errorf("invalid SELinux module command input")
	}
	output, err := run(directory, name, args...)
	if err == nil {
		return output, nil
	}
	return output, newManagedServiceDiagnosticError(
		fmt.Sprintf("%s: %s", operation, managedServiceEvidence(err, output)),
		err,
	)
}

func validSELinuxModuleToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validSELinuxModuleChecksum(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == 32
}

func parseSELinuxModuleListingLine(line string) (selinuxModuleIdentity, error) {
	fields := strings.Fields(line)
	if len(fields) != 4 && len(fields) != 5 {
		return selinuxModuleIdentity{}, fmt.Errorf("unexpected semodule full-list field count")
	}
	priorityValue, err := strconv.ParseUint(fields[0], 10, 16)
	canonicalPriority := strconv.FormatUint(priorityValue, 10)
	paddedPriority := fmt.Sprintf("%03d", priorityValue)
	if err != nil || priorityValue < 1 || priorityValue > 999 ||
		fields[0] != canonicalPriority && fields[0] != paddedPriority {
		return selinuxModuleIdentity{}, fmt.Errorf("invalid semodule priority")
	}
	if !validSELinuxModuleToken(fields[1], 255) || !validSELinuxModuleToken(fields[2], 32) {
		return selinuxModuleIdentity{}, fmt.Errorf("invalid semodule identity token")
	}
	enabled := true
	checksumField := 3
	if len(fields) == 5 {
		if fields[3] != "disabled" {
			return selinuxModuleIdentity{}, fmt.Errorf("invalid semodule enablement state")
		}
		enabled = false
		checksumField = 4
	}
	if !validSELinuxModuleChecksum(fields[checksumField]) {
		return selinuxModuleIdentity{}, fmt.Errorf("invalid semodule SHA-256 checksum")
	}
	return selinuxModuleIdentity{
		priority: uint16(priorityValue),
		name:     fields[1],
		language: fields[2],
		enabled:  enabled,
		checksum: fields[checksumField],
	}, nil
}

func parseSELinuxModuleListing(content []byte) ([]selinuxModuleIdentity, error) {
	if len(content) == 0 || len(content) > selinuxModuleCommandOutputLimit || bytes.IndexByte(content, 0) >= 0 {
		return nil, fmt.Errorf("semodule full listing is empty, oversized, or contains NUL")
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 1024), selinuxModuleListingLineLimit)
	identities := make([]selinuxModuleIdentity, 0)
	records := 0
	sawNoModules := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		records++
		if records > selinuxModuleListingRecordLimit {
			return nil, fmt.Errorf("semodule full listing exceeds %d records", selinuxModuleListingRecordLimit)
		}
		if line == "No modules." {
			sawNoModules = true
			continue
		}
		identity, err := parseSELinuxModuleListingLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse semodule full listing record %d: %w", records, err)
		}
		identities = append(identities, identity)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan bounded semodule full listing: %w", err)
	}
	if records == 0 || sawNoModules && (records != 1 || len(identities) != 0) {
		return nil, fmt.Errorf("semodule full listing has contradictory empty-state output")
	}
	return identities, nil
}

func listSELinuxModulesUsing(
	directory string,
	run selinuxModuleCommandRunner,
) ([]selinuxModuleIdentity, error) {
	output, err := runSELinuxModuleOperationUsing(
		run,
		directory,
		"list SELinux modules with checksums",
		trustedSemodulePath,
		"-lfull", "-m",
	)
	if err != nil {
		return nil, err
	}
	identities, err := parseSELinuxModuleListing(output)
	if err != nil {
		return nil, fmt.Errorf("attest semodule -lfull -m output: %w", err)
	}
	return identities, nil
}

func exactRsyslogSELinuxModule(
	identities []selinuxModuleIdentity,
) (selinuxModuleIdentity, bool, error) {
	var selected selinuxModuleIdentity
	found := false
	for _, identity := range identities {
		if identity.name != rsyslogSELinuxModuleName || identity.priority != rsyslogSELinuxModulePriority {
			continue
		}
		if found {
			return selinuxModuleIdentity{}, false, fmt.Errorf(
				"duplicate priority %d SELinux module identity for %s",
				rsyslogSELinuxModulePriority,
				rsyslogSELinuxModuleName,
			)
		}
		selected = identity
		found = true
	}
	return selected, found, nil
}

func rejectRsyslogSELinuxModuleAtOtherPriority(
	identities []selinuxModuleIdentity,
) error {
	for _, identity := range identities {
		if identity.name == rsyslogSELinuxModuleName && identity.priority != rsyslogSELinuxModulePriority {
			return fmt.Errorf(
				"refusing priority %d SELinux module %s while an operator instance exists at priority %d",
				rsyslogSELinuxModulePriority,
				rsyslogSELinuxModuleName,
				identity.priority,
			)
		}
	}
	return nil
}

func renderSELinuxModuleProvenance(identity selinuxModuleIdentity) ([]byte, error) {
	if identity.priority != rsyslogSELinuxModulePriority ||
		identity.name != rsyslogSELinuxModuleName ||
		identity.language != rsyslogSELinuxModuleLanguage ||
		!identity.enabled ||
		!validSELinuxModuleChecksum(identity.checksum) {
		return nil, fmt.Errorf("invalid SysWarden SELinux module provenance identity")
	}
	return []byte(fmt.Sprintf(
		"%s\n%d\t%s\t%s\t%s\t%s\n",
		rsyslogSELinuxProvenanceSchema,
		identity.priority,
		identity.name,
		identity.language,
		"enabled",
		identity.checksum,
	)), nil
}

func parseSELinuxModuleProvenance(content []byte) (selinuxModuleIdentity, error) {
	if len(content) == 0 || len(content) > 1024 || content[len(content)-1] != '\n' || bytes.IndexByte(content, 0) >= 0 {
		return selinuxModuleIdentity{}, fmt.Errorf("SELinux module provenance is empty, oversized, unterminated, or contains NUL")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) != 2 || lines[0] != rsyslogSELinuxProvenanceSchema {
		return selinuxModuleIdentity{}, fmt.Errorf("unsupported SELinux module provenance schema")
	}
	fields := strings.Split(lines[1], "\t")
	if len(fields) != 5 {
		return selinuxModuleIdentity{}, fmt.Errorf("invalid SELinux module provenance record")
	}
	priority, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil || priority != rsyslogSELinuxModulePriority || fields[0] != strconv.Itoa(rsyslogSELinuxModulePriority) {
		return selinuxModuleIdentity{}, fmt.Errorf("invalid SELinux module provenance priority")
	}
	enabled := false
	switch fields[3] {
	case "enabled":
		enabled = true
	case "disabled":
	default:
		return selinuxModuleIdentity{}, fmt.Errorf("invalid SELinux module provenance state")
	}
	identity := selinuxModuleIdentity{
		priority: uint16(priority),
		name:     fields[1],
		language: fields[2],
		enabled:  enabled,
		checksum: fields[4],
	}
	canonical, renderErr := renderSELinuxModuleProvenance(identity)
	if renderErr != nil || !bytes.Equal(canonical, content) {
		return selinuxModuleIdentity{}, errors.Join(
			fmt.Errorf("SELinux module provenance is not canonical"),
			renderErr,
		)
	}
	return identity, nil
}

func readSELinuxModuleProvenanceInDirectory(
	directory *os.File,
	uid, gid uint32,
) (selinuxModuleProvenance, error) {
	if directory == nil {
		return selinuxModuleProvenance{}, fmt.Errorf("SELinux provenance directory is unavailable")
	}
	state, content, err := inspectRsyslogArtifact(
		directory,
		rsyslogSELinuxProvenanceName,
		uid,
		gid,
	)
	if err != nil || !state.exists {
		return selinuxModuleProvenance{}, err
	}
	identity, err := parseSELinuxModuleProvenance(content)
	if err != nil {
		return selinuxModuleProvenance{}, err
	}
	return selinuxModuleProvenance{
		exists:   true,
		content:  append([]byte(nil), content...),
		identity: identity,
	}, nil
}

func recordSELinuxModuleProvenanceInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	identity selinuxModuleIdentity,
	syncDirectory func(*os.File) error,
) error {
	if directory == nil || syncDirectory == nil {
		return fmt.Errorf("invalid SELinux module provenance publication input")
	}
	desired, err := renderSELinuxModuleProvenance(identity)
	if err != nil {
		return err
	}
	if _, err := reconcileRsyslogArtifactInDirectoryUsing(
		directory,
		rsyslogSELinuxProvenanceName,
		uid,
		gid,
		desired,
		nil,
		syncDirectory,
	); err != nil {
		return fmt.Errorf("publish SELinux module provenance: %w", err)
	}
	observed, err := readSELinuxModuleProvenanceInDirectory(directory, uid, gid)
	if err != nil || !observed.exists || observed.identity != identity || !bytes.Equal(observed.content, desired) {
		return errors.Join(fmt.Errorf("re-attest published SELinux module provenance"), err)
	}
	return nil
}

func removeSELinuxModuleProvenanceInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	provenance selinuxModuleProvenance,
	options exactOwnedArtifactRemovalOptions,
) error {
	if directory == nil || !provenance.exists {
		return fmt.Errorf("invalid SELinux module provenance removal input")
	}
	removed, err := removeExactOwnedArtifactDirectInDirectoryUsing(
		directory,
		uid,
		gid,
		exactContentExpectation(
			"SysWarden rsyslog SELinux module provenance",
			rsyslogSELinuxProvenanceName,
			provenance.content,
			0600,
		),
		options,
	)
	if err != nil || !removed {
		return errors.Join(fmt.Errorf("remove exact SELinux module provenance"), err)
	}
	state, _, err := inspectRsyslogArtifact(
		directory,
		rsyslogSELinuxProvenanceName,
		uid,
		gid,
	)
	if err != nil || state.exists {
		return errors.Join(fmt.Errorf("verify exact SELinux module provenance absence"), err)
	}
	return nil
}

func attestPrivateSELinuxWorkspace(workspace string, uid, gid uint32) error {
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return fmt.Errorf("SELinux policy workspace path must be absolute and canonical")
	}
	fd, err := unix.Open(
		workspace,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open private SELinux policy workspace: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect private SELinux policy workspace: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Gid != gid || stat.Mode&07777 != 0700 {
		return fmt.Errorf("private SELinux policy workspace must be a real uid %d gid %d mode 0700 directory", uid, gid)
	}
	return nil
}

func attestPrivateSELinuxArtifact(
	path string,
	uid, gid uint32,
	expected []byte,
	forcePrivateMode bool,
) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("private SELinux artifact path must be absolute and canonical")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open private SELinux artifact: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("wrap private SELinux artifact descriptor")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return fmt.Errorf("inspect private SELinux artifact: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uid || before.Gid != gid ||
		before.Size <= 0 || before.Size > selinuxPrivateArtifactSizeLimit {
		return fmt.Errorf("private SELinux artifact must be a bounded regular uid %d gid %d single-link file", uid, gid)
	}
	if forcePrivateMode && before.Mode&07777 != 0600 {
		if err := unix.Fchmod(fd, 0600); err != nil {
			return fmt.Errorf("set private SELinux artifact mode: %w", err)
		}
		if err := unix.Fstat(fd, &before); err != nil {
			return fmt.Errorf("reinspect private SELinux artifact mode: %w", err)
		}
	}
	if before.Mode&07777 != 0600 {
		return fmt.Errorf("private SELinux artifact mode must be 0600")
	}
	if expected != nil {
		content, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
		if err != nil || !bytes.Equal(content, expected) {
			return errors.Join(fmt.Errorf("private SELinux artifact content changed"), err)
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return fmt.Errorf("final private SELinux artifact inspection: %w", err)
	}
	if uint64(before.Dev) != uint64(after.Dev) || uint64(before.Ino) != uint64(after.Ino) ||
		before.Nlink != after.Nlink || before.Size != after.Size || before.Mode != after.Mode ||
		before.Uid != after.Uid || before.Gid != after.Gid || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return fmt.Errorf("private SELinux artifact changed during attestation")
	}
	return nil
}

func readPrivateSELinuxArtifact(path string, uid, gid uint32) ([]byte, error) {
	if err := attestPrivateSELinuxArtifact(path, uid, gid, nil, true); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open attested private SELinux artifact: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap attested private SELinux artifact descriptor")
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect private SELinux artifact before read: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uid || before.Gid != gid ||
		before.Mode&07777 != 0600 || before.Size <= 0 || before.Size > selinuxPrivateArtifactSizeLimit {
		_ = file.Close()
		return nil, fmt.Errorf("private SELinux artifact changed before bounded read")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, selinuxPrivateArtifactSizeLimit+1))
	var after unix.Stat_t
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(content) > selinuxPrivateArtifactSizeLimit {
		return nil, errors.Join(fmt.Errorf("read bounded private SELinux artifact"), readErr, statErr, closeErr)
	}
	if uint64(before.Dev) != uint64(after.Dev) || uint64(before.Ino) != uint64(after.Ino) ||
		before.Nlink != after.Nlink || before.Size != after.Size || before.Mode != after.Mode ||
		before.Uid != after.Uid || before.Gid != after.Gid || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, fmt.Errorf("private SELinux artifact changed during bounded read")
	}
	if err := attestPrivateSELinuxArtifact(path, uid, gid, content, false); err != nil {
		return nil, fmt.Errorf("re-attest private SELinux artifact after read: %w", err)
	}
	return content, nil
}

func exactSELinuxModuleState(
	modules []selinuxModuleIdentity,
) (selinuxModuleIdentity, bool, error) {
	identity, exists, err := exactRsyslogSELinuxModule(modules)
	if err != nil {
		return selinuxModuleIdentity{}, false, err
	}
	if exists && (identity.language != rsyslogSELinuxModuleLanguage || !identity.enabled) {
		return selinuxModuleIdentity{}, false, fmt.Errorf(
			"priority %d SELinux module %s is not an enabled %s module",
			rsyslogSELinuxModulePriority,
			rsyslogSELinuxModuleName,
			rsyslogSELinuxModuleLanguage,
		)
	}
	return identity, exists, nil
}

func extractRsyslogSELinuxModuleUsing(
	workspace string,
	uid, gid uint32,
	run selinuxModuleCommandRunner,
) (string, []byte, error) {
	return extractRsyslogSELinuxModuleIntoUsing(
		workspace,
		"baseline",
		uid,
		gid,
		run,
	)
}

func extractRsyslogSELinuxModuleIntoUsing(
	workspace, extractionName string,
	uid, gid uint32,
	run selinuxModuleCommandRunner,
) (string, []byte, error) {
	if !validOwnedArtifactName(extractionName) {
		return "", nil, fmt.Errorf("invalid private SELinux extraction directory name")
	}
	if err := attestPrivateSELinuxWorkspace(workspace, uid, gid); err != nil {
		return "", nil, err
	}
	extractionDirectory := filepath.Join(workspace, extractionName)
	if err := os.Mkdir(extractionDirectory, 0700); err != nil {
		return "", nil, fmt.Errorf("create private SELinux baseline directory: %w", err)
	}
	if err := os.Chmod(extractionDirectory, 0700); err != nil { // #nosec G302 -- owner-only execute access is required for the private extraction directory
		return "", nil, fmt.Errorf("set private SELinux baseline directory mode: %w", err)
	}
	if err := attestPrivateSELinuxWorkspace(extractionDirectory, uid, gid); err != nil {
		return "", nil, err
	}
	if _, err := runSELinuxModuleOperationUsing(
		run,
		extractionDirectory,
		"extract priority 400 rsyslog SELinux policy",
		trustedSemodulePath,
		"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-H", "-E", rsyslogSELinuxModuleName,
	); err != nil {
		return "", nil, err
	}
	packagePath := filepath.Join(extractionDirectory, rsyslogSELinuxModuleName+".pp")
	content, err := readPrivateSELinuxArtifact(packagePath, uid, gid)
	if err != nil {
		return "", nil, fmt.Errorf("attest extracted priority 400 rsyslog SELinux policy: %w", err)
	}
	return packagePath, content, nil
}

type rsyslogSELinuxPolicyTransaction struct {
	parentPath          string
	workspace           string
	candidatePackage    []byte
	baselinePackagePath string
	uid                 uint32
	gid                 uint32
	run                 selinuxModuleCommandRunner
	preflight           rsyslogMutationPreflight
	syncDirectory       func(*os.File) error
	baselineProvenance  selinuxModuleProvenance
	baselineIdentity    selinuxModuleIdentity
	installedIdentity   selinuxModuleIdentity
	baselineExists      bool
	moduleMutated       bool
	provenanceMutated   bool
	finished            bool
}

type rsyslogBridgeRollbackBaseline struct {
	parentPath                string
	uid                       uint32
	gid                       uint32
	configState               wafRsyslogConfigState
	configContent             []byte
	registryState             wafRsyslogConfigState
	registryContent           []byte
	expectedPublishedConfig   []byte
	expectedPublishedRegistry []byte
}

func captureRsyslogBridgeRollbackBaselineAt(
	parentPath string,
	uid, gid uint32,
	desiredConfig []byte,
) (rsyslogBridgeRollbackBaseline, error) {
	if !filepath.IsAbs(parentPath) || filepath.Clean(parentPath) != parentPath ||
		len(desiredConfig) > rsyslogArtifactContentLimit {
		return rsyslogBridgeRollbackBaseline{}, fmt.Errorf("invalid rsyslog bridge rollback baseline input")
	}
	directory, err := openWAFRsyslogDirectoryAt(parentPath, uid, gid)
	if err != nil {
		return rsyslogBridgeRollbackBaseline{}, err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return rsyslogBridgeRollbackBaseline{}, fmt.Errorf("lock rsyslog bridge rollback baseline: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	configState, configContent, err := snapshotRsyslogArtifactInDirectory(
		directory, uid, gid, wafRsyslogConfigName,
	)
	if err != nil {
		return rsyslogBridgeRollbackBaseline{}, fmt.Errorf("snapshot WAF bridge before coordinated setup: %w", err)
	}
	registryState, registryContent, err := snapshotRsyslogArtifactInDirectory(
		directory, uid, gid, rsyslogProvenanceName,
	)
	if err != nil {
		return rsyslogBridgeRollbackBaseline{}, fmt.Errorf("snapshot rsyslog provenance before coordinated setup: %w", err)
	}
	records := make(map[string]rsyslogArtifactProvenance, 2)
	if registryState.exists {
		records, err = parseRsyslogProvenanceRegistry(registryContent)
		if err != nil {
			return rsyslogBridgeRollbackBaseline{}, fmt.Errorf("parse rsyslog provenance rollback baseline: %w", err)
		}
	}
	records[wafRsyslogConfigName] = rsyslogArtifactProvenance{
		size:   int64(len(desiredConfig)),
		digest: sha256.Sum256(desiredConfig),
	}
	expectedRegistry, err := renderRsyslogProvenanceRegistry(records)
	if err != nil {
		return rsyslogBridgeRollbackBaseline{}, err
	}
	return rsyslogBridgeRollbackBaseline{
		parentPath:                parentPath,
		uid:                       uid,
		gid:                       gid,
		configState:               configState,
		configContent:             append([]byte(nil), configContent...),
		registryState:             registryState,
		registryContent:           append([]byte(nil), registryContent...),
		expectedPublishedConfig:   append([]byte(nil), desiredConfig...),
		expectedPublishedRegistry: expectedRegistry,
	}, nil
}

func rsyslogArtifactNeedsCoordinatedRollback(
	directory *os.File,
	uid, gid uint32,
	name, label string,
	baseline wafRsyslogConfigState,
	baselineContent, expectedPublished []byte,
) (bool, error) {
	current, content, err := snapshotRsyslogArtifactInDirectory(directory, uid, gid, name)
	if err != nil {
		return false, err
	}
	if baseline.exists && current.exists && bytes.Equal(content, baselineContent) ||
		!baseline.exists && !current.exists {
		return false, nil
	}
	if !current.exists || !bytes.Equal(content, expectedPublished) {
		return false, fmt.Errorf("preserving %s changed after coordinated publication", label)
	}
	return true, nil
}

func restoreRsyslogArtifactRollbackBaseline(
	directory *os.File,
	uid, gid uint32,
	name, label string,
	baseline wafRsyslogConfigState,
	baselineContent, expectedPublished []byte,
) error {
	if baseline.exists {
		_, err := reconcileRsyslogArtifactInDirectoryUsing(
			directory,
			name,
			uid,
			gid,
			baselineContent,
			nil,
			func(directory *os.File) error { return directory.Sync() },
		)
		return err
	}
	removed, err := removeExactOwnedArtifactDirectInDirectoryUsing(
		directory,
		uid,
		gid,
		exactContentExpectation(label, name, expectedPublished, 0600),
		defaultExactOwnedArtifactRemovalOptions(),
	)
	if err != nil || !removed {
		return errors.Join(fmt.Errorf("remove newly published %s", label), err)
	}
	return nil
}

func (baseline rsyslogBridgeRollbackBaseline) Rollback(
	activate func(bool) error,
) error {
	if activate == nil || !filepath.IsAbs(baseline.parentPath) ||
		len(baseline.expectedPublishedConfig) > rsyslogArtifactContentLimit ||
		len(baseline.expectedPublishedRegistry) > rsyslogArtifactContentLimit {
		return fmt.Errorf("invalid coordinated rsyslog bridge rollback transaction")
	}
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(
		baseline.parentPath,
		wafRsyslogDirectoryName,
		baseline.uid,
		baseline.gid,
	)
	if err != nil || !exists {
		return errors.Join(fmt.Errorf("rsyslog bridge directory disappeared before coordinated rollback"), err)
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock coordinated rsyslog bridge rollback: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	configNeedsRollback, err := rsyslogArtifactNeedsCoordinatedRollback(
		directory,
		baseline.uid,
		baseline.gid,
		wafRsyslogConfigName,
		"WAF bridge",
		baseline.configState,
		baseline.configContent,
		baseline.expectedPublishedConfig,
	)
	if err != nil {
		return err
	}
	registryNeedsRollback, err := rsyslogArtifactNeedsCoordinatedRollback(
		directory,
		baseline.uid,
		baseline.gid,
		rsyslogProvenanceName,
		"rsyslog provenance registry",
		baseline.registryState,
		baseline.registryContent,
		baseline.expectedPublishedRegistry,
	)
	if err != nil {
		return err
	}
	if configNeedsRollback {
		if err := restoreRsyslogArtifactRollbackBaseline(
			directory,
			baseline.uid,
			baseline.gid,
			wafRsyslogConfigName,
			"WAF bridge",
			baseline.configState,
			baseline.configContent,
			baseline.expectedPublishedConfig,
		); err != nil {
			return err
		}
	}
	if registryNeedsRollback {
		if err := restoreRsyslogArtifactRollbackBaseline(
			directory,
			baseline.uid,
			baseline.gid,
			rsyslogProvenanceName,
			"rsyslog provenance registry",
			baseline.registryState,
			baseline.registryContent,
			baseline.expectedPublishedRegistry,
		); err != nil {
			return err
		}
	}
	if configNeedsRollback {
		if err := activate(true); err != nil {
			return fmt.Errorf("reactivate rsyslog after coordinated bridge rollback: %w", err)
		}
	}
	return nil
}

func (transaction *rsyslogSELinuxPolicyTransaction) Commit() error {
	if transaction == nil || transaction.finished || transaction.preflight == nil {
		return fmt.Errorf("SELinux policy transaction is unavailable or already finalized")
	}
	err := func() error {
		if err := attestPrivateSELinuxWorkspace(transaction.workspace, transaction.uid, transaction.gid); err != nil {
			return fmt.Errorf("attest SELinux policy workspace before commit: %w", err)
		}
		if err := transaction.preflight(); err != nil {
			return fmt.Errorf("refuse stale SELinux policy transaction commit: %w", err)
		}
		directory, exists, err := openExistingOwnedArtifactDirectoryAt(
			transaction.parentPath,
			wafRsyslogDirectoryName,
			transaction.uid,
			transaction.gid,
		)
		if err != nil || !exists {
			return errors.Join(fmt.Errorf("SELinux policy provenance directory disappeared before commit"), err)
		}
		defer directory.Close()
		if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
			return fmt.Errorf("lock SELinux policy commit attestation: %w", err)
		}
		defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
		if err := transaction.preflight(); err != nil {
			return fmt.Errorf("refuse stale SELinux policy transaction commit: %w", err)
		}
		modules, err := listSELinuxModulesUsing(transaction.workspace, transaction.run)
		if err != nil {
			return err
		}
		if err := rejectRsyslogSELinuxModuleAtOtherPriority(modules); err != nil {
			return err
		}
		identity, exists, err := exactSELinuxModuleState(modules)
		if err != nil || !exists || identity != transaction.installedIdentity {
			return errors.Join(fmt.Errorf("SELinux module changed before transaction commit"), err)
		}
		provenance, err := readSELinuxModuleProvenanceInDirectory(
			directory,
			transaction.uid,
			transaction.gid,
		)
		if err != nil || !provenance.exists || provenance.identity != identity {
			return errors.Join(fmt.Errorf("SELinux module provenance changed before transaction commit"), err)
		}
		modules, err = listSELinuxModulesUsing(transaction.workspace, transaction.run)
		if err != nil {
			return err
		}
		if err := rejectRsyslogSELinuxModuleAtOtherPriority(modules); err != nil {
			return err
		}
		rechecked, exists, err := exactSELinuxModuleState(modules)
		if err != nil || !exists || rechecked != identity {
			return errors.Join(fmt.Errorf("SELinux module changed during transaction commit"), err)
		}
		if err := transaction.preflight(); err != nil {
			return fmt.Errorf("refuse stale SELinux policy transaction commit: %w", err)
		}
		return nil
	}()
	if err != nil {
		return errors.Join(err, transaction.Rollback())
	}
	transaction.finished = true
	return nil
}

func restoreSELinuxModuleProvenanceBaselineInDirectoryUsing(
	directory *os.File,
	transaction *rsyslogSELinuxPolicyTransaction,
	options exactOwnedArtifactRemovalOptions,
) error {
	current, err := readSELinuxModuleProvenanceInDirectory(directory, transaction.uid, transaction.gid)
	if err != nil {
		return fmt.Errorf("inspect current SELinux provenance before rollback: %w", err)
	}
	if transaction.baselineProvenance.exists {
		if !current.exists {
			return fmt.Errorf("preserving concurrently removed SELinux module provenance during rollback")
		}
		if current.exists && !bytes.Equal(current.content, transaction.baselineProvenance.content) &&
			current.identity != transaction.installedIdentity {
			return fmt.Errorf("preserving concurrently changed SELinux module provenance during rollback")
		}
		if err := recordSELinuxModuleProvenanceInDirectoryUsing(
			directory,
			transaction.uid,
			transaction.gid,
			transaction.baselineProvenance.identity,
			transaction.syncDirectory,
		); err != nil {
			return fmt.Errorf("restore baseline SELinux module provenance: %w", err)
		}
		return nil
	}
	if !current.exists {
		if err := options.syncDirectory(directory); err != nil {
			return fmt.Errorf("sync absent SELinux module provenance during rollback: %w", err)
		}
		return nil
	}
	if current.identity != transaction.installedIdentity {
		return fmt.Errorf("preserving concurrently changed SELinux module provenance during rollback")
	}
	return removeSELinuxModuleProvenanceInDirectoryUsing(
		directory,
		transaction.uid,
		transaction.gid,
		current,
		options,
	)
}

func attestSELinuxModuleProvenanceRollbackState(
	directory *os.File,
	transaction *rsyslogSELinuxPolicyTransaction,
) error {
	current, err := readSELinuxModuleProvenanceInDirectory(
		directory,
		transaction.uid,
		transaction.gid,
	)
	if err != nil {
		return fmt.Errorf("attest SELinux module provenance before policy rollback: %w", err)
	}
	if transaction.baselineProvenance.exists {
		if !current.exists {
			return fmt.Errorf("preserving SELinux policy after tracked provenance disappeared")
		}
		if bytes.Equal(current.content, transaction.baselineProvenance.content) {
			return nil
		}
		if transaction.installedIdentity != (selinuxModuleIdentity{}) &&
			current.identity == transaction.installedIdentity {
			return nil
		}
		return fmt.Errorf("preserving SELinux policy after tracked provenance changed")
	}
	if !current.exists {
		return nil
	}
	if transaction.installedIdentity != (selinuxModuleIdentity{}) &&
		current.identity == transaction.installedIdentity {
		return nil
	}
	return fmt.Errorf("preserving SELinux policy after untracked provenance appeared")
}

func (transaction *rsyslogSELinuxPolicyTransaction) rollbackInDirectory(
	directory *os.File,
) error {
	if transaction == nil || directory == nil {
		return fmt.Errorf("SELinux policy rollback transaction is unavailable")
	}
	if err := attestPrivateSELinuxWorkspace(transaction.workspace, transaction.uid, transaction.gid); err != nil {
		return fmt.Errorf("attest SELinux policy workspace before rollback: %w", err)
	}
	options := defaultExactOwnedArtifactRemovalOptions()
	modules, err := listSELinuxModulesUsing(transaction.workspace, transaction.run)
	if err != nil {
		return err
	}
	current, currentExists, err := exactRsyslogSELinuxModule(modules)
	if err != nil {
		return err
	}
	var rollbackOperationErr error
	if transaction.moduleMutated {
		if err := attestSELinuxModuleProvenanceRollbackState(directory, transaction); err != nil {
			return err
		}
		atBaseline := currentExists == transaction.baselineExists &&
			(!currentExists || current == transaction.baselineIdentity)
		if !atBaseline && transaction.installedIdentity == (selinuxModuleIdentity{}) {
			if !currentExists {
				return fmt.Errorf("preserving SELinux module with an unattestable post-install state")
			}
			_, currentPackage, extractErr := extractRsyslogSELinuxModuleIntoUsing(
				transaction.workspace,
				"rollback-current",
				transaction.uid,
				transaction.gid,
				transaction.run,
			)
			if extractErr != nil || !bytes.Equal(currentPackage, transaction.candidatePackage) {
				return errors.Join(
					fmt.Errorf("preserving SELinux module whose post-install policy cannot be attributed exactly"),
					extractErr,
				)
			}
			transaction.installedIdentity = current
		}
		if atBaseline {
			transaction.moduleMutated = false
		} else if !currentExists || current != transaction.installedIdentity {
			return fmt.Errorf("preserving SELinux module changed after the SysWarden transaction")
		} else {
			modules, err = listSELinuxModulesUsing(transaction.workspace, transaction.run)
			if err != nil {
				return err
			}
			rechecked, recheckedExists, err := exactRsyslogSELinuxModule(modules)
			if err != nil {
				return err
			}
			atBaseline = recheckedExists == transaction.baselineExists &&
				(!recheckedExists || rechecked == transaction.baselineIdentity)
			if atBaseline {
				transaction.moduleMutated = false
			} else if !recheckedExists || rechecked != transaction.installedIdentity {
				return fmt.Errorf("preserving SELinux module changed immediately before rollback")
			} else if err := attestSELinuxModuleProvenanceRollbackState(directory, transaction); err != nil {
				return err
			} else if transaction.baselineExists {
				if _, err := runSELinuxModuleOperationUsing(
					transaction.run,
					transaction.workspace,
					"restore baseline priority 400 rsyslog SELinux policy",
					trustedSemodulePath,
					"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-i", transaction.baselinePackagePath,
				); err != nil {
					rollbackOperationErr = err
				}
			} else {
				if _, err := runSELinuxModuleOperationUsing(
					transaction.run,
					transaction.workspace,
					"remove newly-created priority 400 rsyslog SELinux policy",
					trustedSemodulePath,
					"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-r", rsyslogSELinuxModuleName,
				); err != nil {
					rollbackOperationErr = err
				}
			}
		}
		if transaction.moduleMutated {
			modules, err = listSELinuxModulesUsing(transaction.workspace, transaction.run)
			if err != nil {
				return errors.Join(rollbackOperationErr, err)
			}
			rolledBack, rolledBackExists, err := exactRsyslogSELinuxModule(modules)
			if err != nil || rolledBackExists != transaction.baselineExists ||
				rolledBackExists && rolledBack != transaction.baselineIdentity {
				return errors.Join(
					fmt.Errorf("SELinux module baseline was not restored exactly"),
					rollbackOperationErr,
					err,
				)
			}
		}
	} else if currentExists != transaction.baselineExists ||
		currentExists && current != transaction.baselineIdentity {
		return fmt.Errorf("preserving SELinux module changed before provenance rollback")
	}
	if transaction.provenanceMutated {
		if err := restoreSELinuxModuleProvenanceBaselineInDirectoryUsing(
			directory,
			transaction,
			options,
		); err != nil {
			return errors.Join(rollbackOperationErr, err)
		}
	}
	return rollbackOperationErr
}

func (transaction *rsyslogSELinuxPolicyTransaction) Rollback() error {
	if transaction == nil || transaction.finished {
		return fmt.Errorf("SELinux policy transaction is unavailable or already finalized")
	}
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(
		transaction.parentPath,
		wafRsyslogDirectoryName,
		transaction.uid,
		transaction.gid,
	)
	if err != nil || !exists {
		return errors.Join(fmt.Errorf("SELinux policy provenance directory disappeared before rollback"), err)
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock SELinux policy rollback transaction: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	err = transaction.rollbackInDirectory(directory)
	if err == nil {
		transaction.finished = true
	}
	return err
}

func installRsyslogSELinuxPolicyWithProvenance(
	workspace string,
) (*rsyslogSELinuxPolicyTransaction, error) {
	return installRsyslogSELinuxPolicyWithProvenanceAtUsing(
		workspace,
		wafRsyslogParentDirectory,
		0,
		0,
		runSELinuxModuleCommand,
		requireRsyslogMutationWithoutRemovalBarrier,
		func(directory *os.File) error { return directory.Sync() },
	)
}

func installRsyslogSELinuxPolicyWithProvenanceAtUsing(
	workspace, parentPath string,
	uid, gid uint32,
	run selinuxModuleCommandRunner,
	preflight rsyslogMutationPreflight,
	syncDirectory func(*os.File) error,
) (*rsyslogSELinuxPolicyTransaction, error) {
	if run == nil || preflight == nil || syncDirectory == nil {
		return nil, fmt.Errorf("SELinux policy runner, mutation preflight, or directory sync is unavailable")
	}
	if !filepath.IsAbs(parentPath) || filepath.Clean(parentPath) != parentPath {
		return nil, fmt.Errorf("SELinux provenance parent path must be absolute and canonical")
	}
	if err := attestPrivateSELinuxWorkspace(workspace, uid, gid); err != nil {
		return nil, err
	}
	tePath := filepath.Join(workspace, rsyslogSELinuxModuleName+".te")
	modPath := filepath.Join(workspace, rsyslogSELinuxModuleName+".mod")
	packagePath := filepath.Join(workspace, rsyslogSELinuxModuleName+".pp")
	if err := attestPrivateSELinuxArtifact(tePath, uid, gid, []byte(rsyslogSELinuxPolicy), false); err != nil {
		return nil, fmt.Errorf("attest SELinux policy source: %w", err)
	}
	for _, outputPath := range []string{
		modPath,
		packagePath,
		filepath.Join(workspace, "baseline"),
		filepath.Join(workspace, "installed"),
		filepath.Join(workspace, "rollback-current"),
	} {
		if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(fmt.Errorf("private SELinux output path is not absent: %s", outputPath), err)
		}
	}
	if _, err := runSELinuxModuleOperationUsing(
		run,
		workspace,
		"compile rsyslog SELinux policy",
		trustedCheckmodulePath,
		"-M", "-m", "-o", modPath, tePath,
	); err != nil {
		return nil, err
	}
	if err := attestPrivateSELinuxArtifact(modPath, uid, gid, nil, true); err != nil {
		return nil, fmt.Errorf("attest compiled rsyslog SELinux policy: %w", err)
	}
	if _, err := runSELinuxModuleOperationUsing(
		run,
		workspace,
		"package rsyslog SELinux policy",
		trustedSemodulePackagePath,
		"-o", packagePath, "-m", modPath,
	); err != nil {
		return nil, err
	}
	candidatePackage, err := readPrivateSELinuxArtifact(packagePath, uid, gid)
	if err != nil {
		return nil, fmt.Errorf("attest packaged rsyslog SELinux policy: %w", err)
	}
	if err := preflight(); err != nil {
		return nil, fmt.Errorf("refuse stale SELinux policy producer transaction: %w", err)
	}
	directory, err := openWAFRsyslogDirectoryAt(parentPath, uid, gid)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock complete SELinux policy producer transaction: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	if err := preflight(); err != nil {
		return nil, fmt.Errorf("refuse stale SELinux policy producer transaction: %w", err)
	}
	provenance, err := readSELinuxModuleProvenanceInDirectory(directory, uid, gid)
	if err != nil {
		return nil, fmt.Errorf("verify SELinux module provenance before installation: %w", err)
	}
	modules, err := listSELinuxModulesUsing(workspace, run)
	if err != nil {
		return nil, err
	}
	if err := rejectRsyslogSELinuxModuleAtOtherPriority(modules); err != nil {
		return nil, err
	}
	baselineIdentity, baselineExists, err := exactSELinuxModuleState(modules)
	if err != nil {
		return nil, err
	}
	transaction := &rsyslogSELinuxPolicyTransaction{
		parentPath:         parentPath,
		workspace:          workspace,
		candidatePackage:   append([]byte(nil), candidatePackage...),
		uid:                uid,
		gid:                gid,
		run:                run,
		preflight:          preflight,
		syncDirectory:      syncDirectory,
		baselineProvenance: provenance,
		baselineIdentity:   baselineIdentity,
		baselineExists:     baselineExists,
	}
	var baselinePackage []byte
	if provenance.exists && !baselineExists {
		return nil, fmt.Errorf(
			"refusing to recreate SELinux module %s at priority %d because tracked policy is absent",
			rsyslogSELinuxModuleName,
			rsyslogSELinuxModulePriority,
		)
	}
	if baselineExists {
		if provenance.exists && provenance.identity != baselineIdentity {
			return nil, fmt.Errorf(
				"refusing to overwrite SELinux module %s at priority %d because its identity or checksum changed",
				rsyslogSELinuxModuleName,
				rsyslogSELinuxModulePriority,
			)
		}
		transaction.baselinePackagePath, baselinePackage, err = extractRsyslogSELinuxModuleUsing(
			workspace,
			uid,
			gid,
			run,
		)
		if err != nil {
			return nil, err
		}
		if !provenance.exists && !bytes.Equal(candidatePackage, baselinePackage) {
			return nil, fmt.Errorf(
				"refusing to adopt or overwrite unprovenanced SELinux module %s at priority %d because its extracted policy differs",
				rsyslogSELinuxModuleName,
				rsyslogSELinuxModulePriority,
			)
		}
	}
	if err := preflight(); err != nil {
		return nil, fmt.Errorf("refuse stale SELinux policy installation: %w", err)
	}
	recheckedModules, err := listSELinuxModulesUsing(workspace, run)
	if err != nil {
		return nil, err
	}
	if err := rejectRsyslogSELinuxModuleAtOtherPriority(recheckedModules); err != nil {
		return nil, err
	}
	recheckedIdentity, recheckedExists, err := exactSELinuxModuleState(recheckedModules)
	if err != nil || recheckedExists != baselineExists || recheckedExists && recheckedIdentity != baselineIdentity {
		return nil, errors.Join(fmt.Errorf("priority 400 rsyslog SELinux module changed before reconciliation"), err)
	}
	needsInstall := !baselineExists || !bytes.Equal(candidatePackage, baselinePackage)
	if needsInstall {
		transaction.moduleMutated = true
		if _, err := runSELinuxModuleOperationUsing(
			run,
			workspace,
			"install rsyslog SELinux policy at priority 400",
			trustedSemodulePath,
			"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-i", packagePath,
		); err != nil {
			return nil, errors.Join(err, transaction.rollbackInDirectory(directory))
		}
	}
	installed, err := listSELinuxModulesUsing(workspace, run)
	if err != nil {
		if transaction.moduleMutated {
			return nil, errors.Join(err, transaction.rollbackInDirectory(directory))
		}
		return nil, err
	}
	if err := rejectRsyslogSELinuxModuleAtOtherPriority(installed); err != nil {
		if transaction.moduleMutated {
			return nil, errors.Join(err, transaction.rollbackInDirectory(directory))
		}
		return nil, err
	}
	identity, installedExists, err := exactSELinuxModuleState(installed)
	if err != nil || !installedExists {
		cause := errors.Join(fmt.Errorf("installed rsyslog SELinux module lacks the exact enabled priority 400 identity"), err)
		if transaction.moduleMutated {
			return nil, errors.Join(cause, transaction.rollbackInDirectory(directory))
		}
		return nil, cause
	}
	transaction.installedIdentity = identity
	if needsInstall {
		_, installedPackage, extractErr := extractRsyslogSELinuxModuleIntoUsing(
			workspace,
			"installed",
			uid,
			gid,
			run,
		)
		if extractErr != nil || !bytes.Equal(installedPackage, candidatePackage) {
			return nil, errors.Join(
				fmt.Errorf("installed rsyslog SELinux policy does not match the compiled package exactly"),
				extractErr,
				transaction.rollbackInDirectory(directory),
			)
		}
	}
	if err := preflight(); err != nil {
		return nil, errors.Join(
			fmt.Errorf("refuse stale SELinux policy provenance publication: %w", err),
			transaction.rollbackInDirectory(directory),
		)
	}
	transaction.provenanceMutated = !provenance.exists || provenance.identity != identity
	if err := recordSELinuxModuleProvenanceInDirectoryUsing(
		directory,
		uid,
		gid,
		identity,
		syncDirectory,
	); err != nil {
		transaction.provenanceMutated = true
		return nil, errors.Join(
			fmt.Errorf("record installed rsyslog SELinux module provenance: %w", err),
			transaction.rollbackInDirectory(directory),
		)
	}
	finalModules, err := listSELinuxModulesUsing(workspace, run)
	if err != nil {
		return nil, errors.Join(err, transaction.rollbackInDirectory(directory))
	}
	if err := rejectRsyslogSELinuxModuleAtOtherPriority(finalModules); err != nil {
		return nil, errors.Join(err, transaction.rollbackInDirectory(directory))
	}
	finalIdentity, finalExists, err := exactSELinuxModuleState(finalModules)
	if err != nil || !finalExists || finalIdentity != identity {
		return nil, errors.Join(
			fmt.Errorf("SELinux module changed after provenance publication"),
			err,
			transaction.rollbackInDirectory(directory),
		)
	}
	return transaction, nil
}

// RemoveOwnedRsyslogSELinuxPolicyForPackageRemoval removes only the exact,
// provenanced priority-400 module. Callers must first attest that rsyslog has
// restarted without the SysWarden socket producer and remove the exact socket.
func RemoveOwnedRsyslogSELinuxPolicyForPackageRemoval() error {
	return removeOwnedRsyslogSELinuxPolicyForPackageRemovalAtUsing(
		wafRsyslogParentDirectory,
		0,
		0,
		defaultExactOwnedArtifactRemovalOptions(),
		runSELinuxModuleCommand,
	)
}

func removeOwnedRsyslogSELinuxPolicyForPackageRemovalAtUsing(
	parentPath string,
	uid, gid uint32,
	options exactOwnedArtifactRemovalOptions,
	run selinuxModuleCommandRunner,
) error {
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	if run == nil {
		return fmt.Errorf("SELinux policy runner is unavailable")
	}
	if !filepath.IsAbs(parentPath) || filepath.Clean(parentPath) != parentPath {
		return fmt.Errorf("SELinux provenance parent path must be absolute and canonical")
	}
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(
		parentPath,
		wafRsyslogDirectoryName,
		uid,
		gid,
	)
	if err != nil || !exists {
		return err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock complete SELinux policy removal transaction: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	provenance, err := readSELinuxModuleProvenanceInDirectory(directory, uid, gid)
	if err != nil {
		return fmt.Errorf("verify SELinux module provenance before removal: %w", err)
	}
	if !provenance.exists {
		if err := options.syncDirectory(directory); err != nil {
			return fmt.Errorf("sync absent SELinux module provenance before removal: %w", err)
		}
		return nil
	}
	modules, err := listSELinuxModulesUsing(parentPath, run)
	if err != nil {
		options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because its current identity could not be attested.")
		return err
	}
	identity, moduleExists, err := exactRsyslogSELinuxModule(modules)
	if err != nil {
		options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because its current identity is ambiguous.")
		return err
	}
	if moduleExists && identity != provenance.identity {
		options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because its identity or SHA-256 checksum no longer matches provenance.")
		return nil
	}
	// Re-attest immediately before the destructive command. semodule provides no
	// checksum-conditional remove primitive, so this is the narrowest safe CLI
	// boundary available while its own transaction lock protects store mutation.
	modules, err = listSELinuxModulesUsing(parentPath, run)
	if err != nil {
		options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because its pre-removal identity could not be re-attested.")
		return err
	}
	rechecked, recheckedExists, err := exactRsyslogSELinuxModule(modules)
	if err != nil {
		options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because its pre-removal identity is ambiguous.")
		return err
	}
	if recheckedExists != moduleExists || recheckedExists && rechecked != provenance.identity {
		options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because it changed before removal.")
		return nil
	}
	if recheckedExists {
		currentProvenance, err := readSELinuxModuleProvenanceInDirectory(directory, uid, gid)
		if err != nil {
			options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because provenance could not be re-attested immediately before removal.")
			return err
		}
		if !currentProvenance.exists || !bytes.Equal(currentProvenance.content, provenance.content) {
			options.warn("Preserving the priority 400 syswarden_rsyslog SELinux module because provenance changed immediately before removal.")
			return nil
		}
		if _, err := runSELinuxModuleOperationUsing(
			run,
			parentPath,
			"remove exact rsyslog SELinux policy at priority 400",
			trustedSemodulePath,
			"-X", strconv.Itoa(rsyslogSELinuxModulePriority), "-r", rsyslogSELinuxModuleName,
		); err != nil {
			return err
		}
	}
	finalModules, err := listSELinuxModulesUsing(parentPath, run)
	if err != nil {
		return fmt.Errorf("verify exact rsyslog SELinux module absence: %w", err)
	}
	if _, stillExists, err := exactRsyslogSELinuxModule(finalModules); err != nil || stillExists {
		return errors.Join(fmt.Errorf(
			"priority %d SELinux module %s remains after exact removal",
			rsyslogSELinuxModulePriority,
			rsyslogSELinuxModuleName,
		), err)
	}
	if err := removeSELinuxModuleProvenanceInDirectoryUsing(
		directory,
		uid,
		gid,
		provenance,
		options,
	); err != nil {
		return err
	}
	return nil
}

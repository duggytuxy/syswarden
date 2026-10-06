//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
)

const legacyRetirementBackupRoot = "/var/backups/syswarden-retired-v1"

func legacyFail2banPlanPath(digest string) string {
	return legacyRetirementBackupRoot + "/" + digest
}

// File metadata and hashes are private recovery evidence, not authority to
// stop a service. Every execution still needs the caller's held removal locks,
// durable removal barrier, attested quiescent producers and live safety guard.
// The guard is read-only. Targeted runtime changes belong to the caller's
// preceding phase, never to the repeated file-retirement checks below.
func encodeLegacyFail2banPlan(record legacyFail2banPlanRecord, uid, gid uint32) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", fmt.Errorf("invalid or unbounded historical Fail2ban recovery plan")
	}
	if record.Schema != legacyFail2banPlanSchema || record.ParserSHA256 == ([sha256.Size]byte{}) || len(record.Sources) == 0 ||
		len(record.Sources) > maximumLegacyFail2banFiles || len(record.Directories) < 2 ||
		len(record.Directories) > maximumLegacyFail2banFiles+1 || len(record.Targets) == 0 || len(record.Targets) > 256 {
		return invalid()
	}
	for _, digest := range record.Views {
		if digest == ([sha256.Size]byte{}) {
			return invalid()
		}
	}
	directories := make(map[string]bool, len(record.Directories))
	for index, directory := range record.Directories {
		if !canonicalNFTPersistencePath(directory.Path, false) ||
			directory.Path != "/etc" && directory.Path != legacyFail2banDirectory && !strings.HasPrefix(directory.Path, legacyFail2banDirectory+"/") ||
			index > 0 && record.Directories[index-1].Path >= directory.Path || directory.Inode == 0 || directory.NLink == 0 ||
			directory.Mode&syscall.S_IFMT != syscall.S_IFDIR || directory.Mode & ^uint32(syscall.S_IFDIR|0777) != 0 || directory.Mode&0022 != 0 ||
			directory.UID != uid || directory.GID != gid || !wireguardstate.ValidFilesystemUUID(directory.FilesystemUUID) {
			return invalid()
		}
		directories[directory.Path] = true
	}
	if !directories["/etc"] || !directories[legacyFail2banDirectory] {
		return invalid()
	}
	for path := range directories {
		if path != "/etc" && !directories[filepath.Dir(path)] {
			return invalid()
		}
	}
	sources := make(map[string]bool, len(record.Sources))
	var total int64
	for index, source := range record.Sources {
		path := source.Source.Path
		if source.PlanSHA256 != strings.Repeat("0", 64) || validateLegacyRetirementFileRecord(source, uid, gid) != nil ||
			!strings.HasPrefix(path, legacyFail2banDirectory+"/") || !directories[filepath.Dir(path)] || directories[path] ||
			index > 0 && record.Sources[index-1].Source.Path >= path || total > maximumLegacyFail2banTreeBytes-source.Size {
			return invalid()
		}
		total += source.Size
		sources[path] = true
	}
	for index, target := range record.Targets {
		if !sources[target] || index > 0 && record.Targets[index-1] >= target {
			return invalid()
		}
	}
	content, err := json.Marshal(record)
	if err != nil || len(content) > 2<<20 {
		return invalid()
	}
	return content, fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func openLegacyFail2banPlanDirectory(host nftPersistenceFilesystem, digest string) (*os.Root, error) {
	if !validLegacyRetirementDigest(digest) {
		return nil, fmt.Errorf("invalid historical Fail2ban plan digest")
	}
	for _, path := range []string{legacyRetirementBackupRoot, legacyFail2banPlanPath(digest)} {
		directory, err := host.openDirectory(path)
		if err != nil {
			return nil, err
		}
		info, err := directory.Stat(".")
		if err != nil || info.Mode().Perm() != 0700 {
			_ = directory.Close()
			return nil, fmt.Errorf("historical Fail2ban recovery directory is not private")
		}
		if path == legacyFail2banPlanPath(digest) {
			return directory, nil
		}
		if err := directory.Close(); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("historical Fail2ban recovery directory is unavailable")
}

func readLegacyFail2banPlan(host nftPersistenceFilesystem, digest string) (legacyFail2banPlanRecord, error) {
	var empty legacyFail2banPlanRecord
	directory, err := openLegacyFail2banPlanDirectory(host, digest)
	if err != nil {
		return empty, err
	}
	defer func() { _ = directory.Close() }()
	snapshot, err := host.snapshot(legacyFail2banPlanPath(digest) + "/plan.json")
	if err != nil {
		return empty, err
	}
	if snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 2<<20 {
		return empty, fmt.Errorf("historical Fail2ban plan is not a bounded private file")
	}
	var record legacyFail2banPlanRecord
	decoder := json.NewDecoder(bytes.NewReader(snapshot.content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return empty, fmt.Errorf("invalid historical Fail2ban plan encoding")
	}
	canonical, actual, err := encodeLegacyFail2banPlan(record, host.expectedUID, host.expectedGID)
	if err != nil || actual != digest || !bytes.Equal(canonical, snapshot.content) {
		return empty, fmt.Errorf("historical Fail2ban plan does not match its canonical reviewed digest")
	}
	return record, nil
}

// Only the private subtree is created. The shared /var/backups parent must
// already be trusted. Existing directories are verified, never chmodded or
// adopted from unsafe metadata. Every directory and parent are synced even
// when retrying a creation whose previous sync may have failed.
func ensureLegacyRetirementPrivateDirectory(host nftPersistenceFilesystem, path string, ops legacyRetirementFileOps) error {
	return prepareLegacyRetirementPrivateDirectory(host, path, ops, true)
}

func prepareLegacyRetirementPrivateDirectory(host nftPersistenceFilesystem, path string, ops legacyRetirementFileOps, create bool) error {
	if !canonicalNFTPersistencePath(path, false) || path != legacyRetirementBackupRoot && !strings.HasPrefix(path, legacyRetirementBackupRoot+"/") {
		return fmt.Errorf("legacy retirement directory lies outside the private backup subtree")
	}
	parentPath := filepath.Dir(path)
	if parentPath != "/var/backups" {
		if err := prepareLegacyRetirementPrivateDirectory(host, parentPath, ops, create); err != nil {
			return err
		}
	}
	parent, err := host.openDirectory(parentPath)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	before, err := parent.Stat(".")
	if err != nil {
		return err
	}
	if create {
		if err := parent.Mkdir(filepath.Base(path), 0700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create private legacy retirement directory: %w", err)
		}
	}
	child, err := host.openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = child.Close() }()
	info, err := child.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return fmt.Errorf("legacy retirement directory has unsafe existing permissions")
	}
	childFD, err := child.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = childFD.Close() }()
	parentFD, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = parentFD.Close() }()
	if err := errors.Join(ops.sync(childFD), ops.sync(parentFD)); err != nil {
		return fmt.Errorf("private legacy retirement directory is not durable: %w", err)
	}
	if err := errors.Join(attestLegacyRetirementDirectory(host, parentPath, before), attestLegacyRetirementDirectory(host, path, info)); err != nil {
		return err
	}
	return ops.checkpoint("backup-directory-durable")
}

func sameLegacyFail2banPlanDirectory(actual, expected legacyFail2banPlanDirectory) bool {
	if expected.FilesystemUUID != "" {
		if !wireguardstate.ValidFilesystemUUID(expected.FilesystemUUID) || actual.FilesystemUUID != expected.FilesystemUUID {
			return false
		}
		actual.Device = expected.Device
	} else {
		actual.FilesystemUUID = ""
	}
	return actual == expected
}

type legacyFail2banPlanState struct {
	baseline legacyFail2banInventory
	retired  map[string]bool
}

// Reconstruction uses the original inode at either its active path or its
// exact private backup. Retained sources are never reconstructed from a backup:
// they must still exist unchanged at their original paths. Directory membership
// must be exactly the recorded tree less the declared retired files.
func inspectLegacyFail2banPlanState(host nftPersistenceFilesystem, record legacyFail2banPlanRecord) (legacyFail2banPlanState, error) {
	var empty legacyFail2banPlanState
	_, digest, err := encodeLegacyFail2banPlan(record, host.expectedUID, host.expectedGID)
	if err != nil {
		return empty, err
	}
	current, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		return empty, err
	}
	if !current.present || len(current.directories)+1 != len(record.Directories) {
		return empty, fmt.Errorf("historical Fail2ban configuration directory membership changed")
	}
	directories := make(map[string]os.FileInfo, len(current.directories)+1)
	directories["/etc"] = current.parent
	for _, directory := range current.directories {
		directories[directory.path] = directory.identity
	}
	for _, expected := range record.Directories {
		actual, err := bindLegacyFail2banPlanDirectory(host, expected.Path, directories[expected.Path])
		if err != nil || !sameLegacyFail2banPlanDirectory(actual, expected) {
			return empty, fmt.Errorf("historical Fail2ban configuration directory changed: %q", expected.Path)
		}
	}
	targets := make(map[string]bool, len(record.Targets))
	for _, target := range record.Targets {
		targets[target] = true
	}
	sources := make(map[string]legacyFail2banSource, len(current.sources))
	for _, source := range current.sources {
		sources[source.path] = source
	}
	state := legacyFail2banPlanState{baseline: current, retired: make(map[string]bool)}
	state.baseline.sources = nil
	var retiring []nftPersistenceRetiredSource
	for _, source := range record.Sources {
		path := source.Source.Path
		snapshot := sources[path].snapshot
		if targets[path] {
			source.PlanSHA256 = digest
			retired, err := legacyRetirementSourceState(host, source)
			if err != nil {
				return empty, err
			}
			intent, err := readLegacyRetirementFileRecord(host, legacyRetirementBackupDirectory(source))
			if err != nil && !(errors.Is(err, fs.ErrNotExist) && !retired) || err == nil && intent != source {
				return empty, fmt.Errorf("historical Fail2ban file has missing or inconsistent retirement intent: %q", path)
			}
			if retired {
				snapshot, err = host.snapshot(legacyRetirementBackupDirectory(source) + "/original")
				if err != nil {
					return empty, err
				}
				state.retired[path] = true
			}
			match, exact := matchLegacyFail2banTemplate(path, snapshot.content)
			if !exact || fmt.Sprintf("%x", match.sha256) != source.Source.SHA256 {
				return empty, fmt.Errorf("historical Fail2ban target no longer matches its exact official template: %q", path)
			}
			retiring = append(retiring, nftPersistenceRetiredSource{path, match.sha256})
		}
		if !matchesLegacyRetirementSource(source, snapshot) {
			return empty, fmt.Errorf("historical Fail2ban recovery source changed or is absent: %q", path)
		}
		state.baseline.sources = append(state.baseline.sources, legacyFail2banSource{path, snapshot, sha256.Sum256(snapshot.content)})
		delete(sources, path)
	}
	if len(sources) != 0 {
		return empty, fmt.Errorf("historical Fail2ban recovery found an unreviewed configuration file")
	}
	if err := verifyLegacyFail2banIncludeRetirement(state.baseline, retiring); err != nil {
		return empty, err
	}
	if err := reattestLegacyFail2banPlanInventory(host, current); err != nil {
		return empty, err
	}
	return state, nil
}

func legacyFail2banPlanFileRecords(record legacyFail2banPlanRecord, digest string) []legacyRetirementFileRecord {
	targets := make(map[string]bool, len(record.Targets))
	for _, path := range record.Targets {
		targets[path] = true
	}
	var result []legacyRetirementFileRecord
	for _, source := range record.Sources {
		if targets[source.Source.Path] {
			source.PlanSHA256 = digest
			result = append(result, source)
		}
	}
	// Ordering is not ownership evidence. Exact template checks happen in
	// the state inspector. Quiescent jail definitions are retired first.
	rank := func(path string) int {
		if strings.HasPrefix(path, legacyFail2banDirectory+"/jail.d/") {
			return 0
		}
		if strings.HasPrefix(path, legacyFail2banDirectory+"/filter.d/") {
			return 1
		}
		return 2
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].Source.Path, result[j].Source.Path
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return a < b
	})
	return result
}

func validLegacyRetirementOperations(guard func() error, ops legacyRetirementFileOps) bool {
	return guard != nil && ops.rename != nil && ops.sync != nil && ops.checkpoint != nil
}

func verifyLegacyFail2banBackupFilesystem(host nftPersistenceFilesystem, source legacyRetirementFileRecord) error {
	backup, err := host.openDirectory(legacyRetirementBackupDirectory(source))
	if err != nil {
		return err
	}
	info, statErr := backup.Stat(".")
	closeErr := backup.Close()
	parent, err := host.openDirectory(filepath.Dir(source.Source.Path))
	if err != nil {
		return err
	}
	parentInfo, parentErr := parent.Stat(".")
	parentClose := parent.Close()
	if statErr != nil || closeErr != nil || parentErr != nil || parentClose != nil {
		return fmt.Errorf("historical Fail2ban source or backup filesystem is unavailable")
	}
	retired, err := legacyRetirementSourceState(host, source)
	if err != nil {
		return err
	}
	path := source.Source.Path
	if retired {
		path = legacyRetirementBackupDirectory(source) + "/original"
	}
	original, err := host.snapshot(path)
	if err != nil {
		return err
	}
	device := info.Sys().(*syscall.Stat_t).Dev
	if info.Mode().Perm() != 0700 || device != parentInfo.Sys().(*syscall.Stat_t).Dev || device != original.identity.Sys().(*syscall.Stat_t).Dev {
		return fmt.Errorf("historical Fail2ban plan requires every private backup on its source filesystem")
	}
	return nil
}

func syncLegacyFail2banPlan(host nftPersistenceFilesystem, digest string, ops legacyRetirementFileOps) error {
	if _, err := readLegacyFail2banPlan(host, digest); err != nil {
		return err
	}
	path := legacyFail2banPlanPath(digest) + "/plan.json"
	before, err := host.snapshot(path)
	if err != nil {
		return err
	}
	directory, err := openLegacyFail2banPlanDirectory(host, digest)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	info, err := directory.Stat(".")
	if err != nil {
		return err
	}
	file, err := directory.OpenFile("plan.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !sameNFTPersistenceIdentity(before.identity, opened) {
		_ = file.Close()
		return fmt.Errorf("historical Fail2ban journal changed before synchronization")
	}
	syncErr := ops.sync(file)
	closeErr := file.Close()
	fd, err := directory.Open(".")
	if err != nil {
		return err
	}
	dirSyncErr := ops.sync(fd)
	dirCloseErr := fd.Close()
	if err := errors.Join(syncErr, closeErr, dirSyncErr, dirCloseErr); err != nil {
		return err
	}
	after, err := host.snapshot(path)
	if err != nil || !sameLegacyFail2banSource(before, after) {
		return fmt.Errorf("historical Fail2ban journal changed during synchronization")
	}
	if _, err := readLegacyFail2banPlan(host, digest); err != nil {
		return err
	}
	return attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(digest), info)
}

// Persist before any file move. An existing journal must have exactly the
// same canonical digest. Interrupted staging files are never accepted as a
// journal, overwritten or removed. Private directories may remain after an
// error, but every active configuration remains in place during this phase.
func persistLegacyFail2banPlanUsing(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, guard func() error, ops legacyRetirementFileOps) error {
	if !validLegacyRetirementOperations(guard, ops) {
		return fmt.Errorf("historical Fail2ban planning requires complete guards and filesystem operations")
	}
	content, digest, err := encodeLegacyFail2banPlan(plan.binding, host.expectedUID, host.expectedGID)
	if err != nil || digest != plan.sha256 {
		return fmt.Errorf("historical Fail2ban plan differs from its reviewed digest")
	}
	if _, err := inspectLegacyFail2banPlanState(host, plan.binding); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if _, err := inspectLegacyFail2banPlanState(host, plan.binding); err != nil {
		return err
	}
	if err := ensureLegacyRetirementPrivateDirectory(host, legacyFail2banPlanPath(digest), ops); err != nil {
		return err
	}
	for _, source := range legacyFail2banPlanFileRecords(plan.binding, digest) {
		if err := ensureLegacyRetirementPrivateDirectory(host, legacyRetirementBackupDirectory(source), ops); err != nil {
			return err
		}
		if err := verifyLegacyFail2banBackupFilesystem(host, source); err != nil {
			return err
		}
	}
	directory, err := openLegacyFail2banPlanDirectory(host, digest)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	info, err := directory.Stat(".")
	if err != nil {
		return err
	}
	fd, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()
	_, err = readLegacyFail2banPlan(host, digest)
	if errors.Is(err, fs.ErrNotExist) {
		state, stateErr := inspectLegacyFail2banPlanState(host, plan.binding)
		if stateErr != nil || len(state.retired) != 0 {
			return errors.Join(fmt.Errorf("cannot publish a missing plan after file retirement has started"), stateErr)
		}
		if err := guard(); err != nil {
			return err
		}
		if _, err := inspectLegacyFail2banPlanState(host, plan.binding); err != nil {
			return err
		}
		if err := attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(digest), info); err != nil {
			return err
		}
		if err := publishLegacyRetirementJSON(directory, fd, "plan", content, ops); err != nil {
			return err
		}
		if err := ops.checkpoint("plan-published"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if _, err := inspectLegacyFail2banPlanState(host, plan.binding); err != nil {
		return err
	}
	if err := syncLegacyFail2banPlan(host, digest, ops); err != nil {
		return err
	}
	return attestLegacyRetirementDirectory(host, legacyFail2banPlanPath(digest), info)
}

// Resume only from the exact, already durable plan. Every individual file
// move rechecks the whole retained configuration and the mandatory live guard.
// A successful result means file retirement only, never complete host removal.
func resumeLegacyFail2banPlanUsing(host nftPersistenceFilesystem, digest string, guard func() error, ops legacyRetirementFileOps) error {
	if !validLegacyRetirementOperations(guard, ops) {
		return fmt.Errorf("historical Fail2ban recovery requires complete live guards")
	}
	record, err := readLegacyFail2banPlan(host, digest)
	if err != nil {
		return err
	}
	observedRetired := make(map[string]bool)
	requireComplete := false
	checkState := func(current legacyFail2banPlanRecord) error {
		state, err := inspectLegacyFail2banPlanState(host, current)
		if err != nil {
			return err
		}
		for path := range observedRetired {
			if !state.retired[path] {
				return fmt.Errorf("historical Fail2ban recovery observed a retired file reappear: %q", path)
			}
		}
		for path := range state.retired {
			observedRetired[path] = true
		}
		if requireComplete && len(state.retired) != len(record.Targets) {
			return fmt.Errorf("historical Fail2ban file retirement remains incomplete")
		}
		return nil
	}
	check := func() error {
		current, err := readLegacyFail2banPlan(host, digest)
		if err != nil {
			return err
		}
		if err := checkState(current); err != nil {
			return err
		}
		if err := guard(); err != nil {
			return err
		}
		current, err = readLegacyFail2banPlan(host, digest)
		if err != nil {
			return err
		}
		return checkState(current)
	}
	if err := check(); err != nil {
		return err
	}
	// Re-sync existing evidence before resuming. Never recreate a missing
	// journal or backup directory during recovery.
	for _, source := range legacyFail2banPlanFileRecords(record, digest) {
		if err := prepareLegacyRetirementPrivateDirectory(host, legacyRetirementBackupDirectory(source), ops, false); err != nil {
			return err
		}
		if err := verifyLegacyFail2banBackupFilesystem(host, source); err != nil {
			return err
		}
	}
	if err := syncLegacyFail2banPlan(host, digest, ops); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	for _, source := range legacyFail2banPlanFileRecords(record, digest) {
		if err := retireLegacyConfigurationFileUsing(host, source, func(bool) error { return check() }, ops); err != nil {
			return err
		}
	}
	requireComplete = true
	if err := check(); err != nil {
		return err
	}
	if err := ops.checkpoint("plan-complete"); err != nil {
		return err
	}
	return check()
}

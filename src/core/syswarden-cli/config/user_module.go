package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

const userModuleName = "99-user.toml"

type validatedUserModulePublisher func(
	directory, name string,
	content []byte,
	expected *secureFileIdentity,
	preCommit, prePublish, postCommit func() error,
) error

var (
	userModuleWriteMu          sync.Mutex
	publishValidatedUserModule validatedUserModulePublisher = replaceSecureFileAtomicallyIfUnchangedValidated
	applySecureFileOwnership                                = func(file *os.File, uid, gid int) error {
		return file.Chown(uid, gid)
	}
)

type mergedConfigSnapshot struct {
	configRootInfo  os.FileInfo
	modulesRootInfo os.FileInfo
	marker          *secureFileIdentity
	master          *secureFileIdentity
	moduleNames     []string
	modules         map[string]*secureFileIdentity
	user            *secureFileIdentity
}

func ReadUserModule(configDir string) ([]byte, error) {
	content, _, err := readUserModuleIdentity(configDir)
	return content, err
}

func readUserModuleIdentity(configDir string) ([]byte, *secureFileIdentity, error) {
	modulesDir := filepath.Join(configDir, "modules")
	root, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	return readSecureRegularFileIdentity(root, userModuleName, filepath.Join(modulesDir, userModuleName))
}

func ImportValidatedUserModule(configDir, sourcePath string) error {
	content, err := readSecureFileByPathBounded(sourcePath, maximumUserModuleSize)
	if err != nil {
		return fmt.Errorf("read import source securely: %w", err)
	}
	return WriteValidatedUserModule(configDir, content)
}

func SetValidatedProfileName(configDir, profileName string) error {
	userModuleWriteMu.Lock()
	defer userModuleWriteMu.Unlock()

	content, expected, err := readUserModuleIdentity(configDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read operator user module: %w", err)
		}
		content = nil
		expected = nil
	}
	return writeValidatedUserModuleLocked(configDir, updateProfileInUserModule(content, profileName), expected)
}

// WriteValidatedUserModule validates the complete merged modular candidate
// before atomically replacing the operator module. Existing symlinks, unsafe
// modes, and inode substitutions are rejected.
func WriteValidatedUserModule(configDir string, content []byte) error {
	userModuleWriteMu.Lock()
	defer userModuleWriteMu.Unlock()

	_, expected, err := readUserModuleIdentity(configDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("inspect operator user module: %w", err)
		}
		expected = nil
	}
	return writeValidatedUserModuleLocked(configDir, content, expected)
}

func writeValidatedUserModuleLocked(configDir string, content []byte, expected *secureFileIdentity) error {
	if int64(len(content)) > maximumUserModuleSize {
		return fmt.Errorf("operator user module exceeds the %d-byte limit", maximumUserModuleSize)
	}
	if err := rejectMigrationInProgress(configDir); err != nil {
		return err
	}
	snapshot, err := validateModularUserCandidate(configDir, content, expected)
	if err != nil {
		return fmt.Errorf("validate merged user configuration: %w", err)
	}
	preCommit := func() error {
		return snapshot.revalidate(configDir, false, nil)
	}
	prePublish := func() error {
		return snapshot.revalidateMigrationMarker(configDir)
	}
	postCommit := func() error {
		return snapshot.revalidate(configDir, true, content)
	}
	modulesDir := filepath.Join(configDir, "modules")
	if err := publishValidatedUserModule(modulesDir, userModuleName, content, expected, preCommit, prePublish, postCommit); err != nil {
		return fmt.Errorf("publish validated user configuration: %w", err)
	}
	return nil
}

func validateModularUserCandidate(configDir string, userContent []byte, expectedUser *secureFileIdentity) (*mergedConfigSnapshot, error) {
	if err := rejectOperatorPolicyEnvironment(); err != nil {
		return nil, err
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	configRootInfo, err := rootDirectoryInfo(root)
	if err != nil {
		return nil, err
	}
	markerIdentity, err := readOptionalSecureFileIdentity(
		root,
		migrationMarkerName,
		filepath.Join(configDir, migrationMarkerName),
	)
	if err != nil {
		return nil, err
	}
	if markerIdentity != nil {
		return nil, fmt.Errorf("configuration migration is incomplete; rerun syswarden migrate-config before editing operator state")
	}

	v := viper.New()
	v.SetConfigType("toml")
	setDefaults(v, configDir)
	var masterIdentity *secureFileIdentity
	if _, err := root.Lstat("config.toml"); err == nil {
		content, identity, readErr := readSecureRegularFileIdentity(root, "config.toml", filepath.Join(configDir, "config.toml"))
		if readErr != nil {
			return nil, readErr
		}
		if _, err := parseTOMLDocument(content, "config.toml"); err != nil {
			return nil, err
		}
		if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
			return nil, err
		}
		masterIdentity = identity
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	modulesDir := filepath.Join(configDir, "modules")
	modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = modulesRoot.Close() }()
	modulesRootInfo, err := rootDirectoryInfo(modulesRoot)
	if err != nil {
		return nil, err
	}
	directory, err := modulesRoot.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	snapshot := &mergedConfigSnapshot{
		configRootInfo:  configRootInfo,
		modulesRootInfo: modulesRootInfo,
		marker:          markerIdentity,
		master:          masterIdentity,
		modules:         make(map[string]*secureFileIdentity),
		user:            expectedUser,
	}
	mergedUser := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".toml" {
			continue
		}
		snapshot.moduleNames = append(snapshot.moduleNames, entry.Name())
		content, identity, readErr := readSecureRegularFileIdentity(modulesRoot, entry.Name(), filepath.Join(modulesDir, entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		if entry.Name() == userModuleName {
			if expectedUser == nil || !expectedUser.matches(content, identity.info) {
				return nil, fmt.Errorf("operator user module changed before merged validation")
			}
			content = userContent
			mergedUser = true
		} else {
			snapshot.modules[entry.Name()] = identity
		}
		if _, err := parseTOMLDocument(content, filepath.ToSlash(filepath.Join("modules", entry.Name()))); err != nil {
			return nil, err
		}
		if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
			return nil, fmt.Errorf("merge module %s: %w", entry.Name(), err)
		}
	}
	if !mergedUser {
		if expectedUser != nil {
			return nil, fmt.Errorf("operator user module disappeared before merged validation")
		}
		if _, err := parseTOMLDocument(userContent, filepath.ToSlash(filepath.Join("modules", userModuleName))); err != nil {
			return nil, err
		}
		if err := v.MergeConfig(bytes.NewReader(userContent)); err != nil {
			return nil, fmt.Errorf("merge new operator module: %w", err)
		}
	}
	var candidate ModularConfig
	if err := v.Unmarshal(&candidate); err != nil {
		return nil, err
	}
	if err := validateConfig(&candidate); err != nil {
		return nil, err
	}
	if err := snapshot.revalidate(configDir, false, nil); err != nil {
		return nil, fmt.Errorf("configuration changed during merged validation: %w", err)
	}
	return snapshot, nil
}

func readOptionalSecureFileIdentity(root *os.Root, name, displayPath string) (*secureFileIdentity, error) {
	_, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_, identity, err := readSecureRegularFileIdentity(root, name, displayPath)
	return identity, err
}

func (snapshot *mergedConfigSnapshot) revalidateMigrationMarker(configDir string) error {
	if snapshot == nil {
		return fmt.Errorf("merged configuration snapshot is missing")
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := rootDirectoryInfo(root)
	if err != nil || !sameFileAndMode(snapshot.configRootInfo, rootInfo) {
		return fmt.Errorf("configuration root changed during user-module transaction")
	}
	return revalidateOptionalSecureFile(
		root,
		migrationMarkerName,
		filepath.Join(configDir, migrationMarkerName),
		snapshot.marker,
	)
}

func (snapshot *mergedConfigSnapshot) revalidate(configDir string, published bool, publishedContent []byte) error {
	if snapshot == nil {
		return fmt.Errorf("merged configuration snapshot is missing")
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := rootDirectoryInfo(root)
	if err != nil || !sameFileAndMode(snapshot.configRootInfo, rootInfo) {
		return fmt.Errorf("configuration root changed during user-module transaction")
	}
	if err := revalidateOptionalSecureFile(
		root,
		migrationMarkerName,
		filepath.Join(configDir, migrationMarkerName),
		snapshot.marker,
	); err != nil {
		return err
	}
	if err := revalidateOptionalSecureFile(root, "config.toml", filepath.Join(configDir, "config.toml"), snapshot.master); err != nil {
		return err
	}

	modulesDir := filepath.Join(configDir, "modules")
	modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = modulesRoot.Close() }()
	modulesInfo, err := rootDirectoryInfo(modulesRoot)
	if err != nil || !sameFileAndMode(snapshot.modulesRootInfo, modulesInfo) {
		return fmt.Errorf("modules root changed during user-module transaction")
	}
	directory, err := modulesRoot.Open(".")
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	var names []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".toml" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	expectedNames := append([]string(nil), snapshot.moduleNames...)
	if published && snapshot.user == nil {
		expectedNames = append(expectedNames, userModuleName)
		sort.Strings(expectedNames)
	}
	if !reflect.DeepEqual(names, expectedNames) {
		return fmt.Errorf("TOML module inventory changed during user-module transaction")
	}
	for name, identity := range snapshot.modules {
		if err := revalidateOptionalSecureFile(modulesRoot, name, filepath.Join(modulesDir, name), identity); err != nil {
			return err
		}
	}
	if published {
		content, _, err := readSecureRegularFileSnapshot(modulesRoot, userModuleName, filepath.Join(modulesDir, userModuleName))
		if err != nil {
			return err
		}
		if !bytes.Equal(content, publishedContent) {
			return fmt.Errorf("published operator user module changed during commit")
		}
		return nil
	}
	return revalidateOptionalSecureFile(modulesRoot, userModuleName, filepath.Join(modulesDir, userModuleName), snapshot.user)
}

func sameFileAndMode(expected, current os.FileInfo) bool {
	return expected != nil && current != nil && os.SameFile(expected, current) && expected.Mode() == current.Mode()
}

func revalidateOptionalSecureFile(root *os.Root, name, displayPath string, expected *secureFileIdentity) error {
	content, info, err := readSecureRegularFileSnapshot(root, name, displayPath)
	if expected == nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err == nil {
			return fmt.Errorf("configuration file %s appeared during user-module transaction", displayPath)
		}
		return err
	}
	if err != nil {
		return err
	}
	if !expected.matches(content, info) {
		return fmt.Errorf("configuration file %s changed during user-module transaction", displayPath)
	}
	return nil
}

func replaceSecureFileAtomicallyIfUnchanged(directory, name string, content []byte, expected *secureFileIdentity) error {
	return replaceSecureFileAtomicallyIfUnchangedValidated(directory, name, content, expected, nil, nil, nil)
}

func replaceSecureFileAtomicallyIfUnchangedValidated(
	directory, name string,
	content []byte,
	expected *secureFileIdentity,
	preCommit, prePublish, postCommit func() error,
) error {
	root, err := openConfigDirectory(directory, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return err
	}
	suffix := hex.EncodeToString(randomSuffix)
	temporaryName := "." + name + ".tmp-" + suffix
	backupName := "." + name + ".rollback-" + suffix
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	temporaryOpen := true
	backupExists := false
	preserveBackup := false
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
		if backupExists && !preserveBackup {
			_ = root.Remove(backupName)
		}
	}()
	if expected != nil && expected.info != nil {
		uid, gid, ok := fileOwnerUIDGID(expected.info)
		if !ok {
			return fmt.Errorf("capture existing secure file ownership")
		}
		if err := applySecureFileOwnership(temporary, int(uid), int(gid)); err != nil {
			return fmt.Errorf("preserve existing secure file ownership: %w", err)
		}
		// Apply the mode after chown because some kernels clear special mode bits
		// when ownership changes.
		if err := temporary.Chmod(expected.info.Mode().Perm()); err != nil {
			return err
		}
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporaryOpen = false

	revalidateDestination := func() error {
		currentContent, currentInfo, readErr := readSecureRegularFileSnapshot(root, name, filepath.Join(directory, name))
		if expected == nil {
			if errors.Is(readErr, fs.ErrNotExist) {
				return nil
			}
			if readErr == nil {
				return fmt.Errorf("secure file appeared before publish")
			}
			return readErr
		}
		if readErr != nil || !expected.matches(currentContent, currentInfo) {
			return fmt.Errorf("secure file changed before publish")
		}
		return nil
	}
	if err := revalidateDestination(); err != nil {
		return err
	}
	if preCommit != nil {
		if err := preCommit(); err != nil {
			return fmt.Errorf("pre-commit configuration CAS: %w", err)
		}
	}
	if err := revalidateDestination(); err != nil {
		return err
	}

	restoreBackup := func() error {
		if !backupExists {
			return nil
		}
		if _, err := root.Lstat(name); err == nil {
			preserveBackup = true
			return fmt.Errorf("destination reappeared before rollback")
		} else if !errors.Is(err, fs.ErrNotExist) {
			preserveBackup = true
			return err
		}
		if err := root.Link(backupName, name); err != nil {
			preserveBackup = true
			return err
		}
		if err := root.Remove(backupName); err != nil {
			preserveBackup = true
			return err
		}
		backupExists = false
		return nil
	}
	restoreBackupAfterPublishConflict := func() error {
		if !backupExists {
			return nil
		}
		conflictName := "." + name + ".conflict-" + suffix
		if _, err := root.Lstat(conflictName); err == nil {
			preserveBackup = true
			return fmt.Errorf("operator-module conflict quarantine already exists")
		} else if !errors.Is(err, fs.ErrNotExist) {
			preserveBackup = true
			return err
		}
		conflictInfo, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			return restoreBackup()
		}
		if err != nil {
			preserveBackup = true
			return err
		}
		if err := root.Rename(name, conflictName); err != nil {
			preserveBackup = true
			return fmt.Errorf("quarantine conflicting operator-module publication: %w", err)
		}
		quarantined, err := root.Lstat(conflictName)
		if err != nil || !os.SameFile(conflictInfo, quarantined) {
			preserveBackup = true
			return fmt.Errorf("conflicting operator-module inode changed during quarantine")
		}
		// The previous operator inode remains authoritative until this writer has
		// committed. In particular, a migration that observed the temporary name
		// gap must not make its generated 99-user.toml effective.
		if err := root.Rename(backupName, name); err != nil {
			preserveBackup = true
			_ = root.Rename(conflictName, name)
			return fmt.Errorf("restore previous operator module after publication conflict: %w", err)
		}
		backupExists = false
		restoredContent, restoredInfo, err := readSecureRegularFileSnapshot(root, name, filepath.Join(directory, name))
		if err != nil || expected == nil || !expected.matches(restoredContent, restoredInfo) {
			return fmt.Errorf("restored operator module failed identity verification")
		}
		if err := root.Remove(conflictName); err != nil {
			return fmt.Errorf("remove conflicting operator-module inode: %w", err)
		}
		return syncRootDirectory(root)
	}
	if expected != nil {
		if err := root.Rename(name, backupName); err != nil {
			return fmt.Errorf("quarantine previous operator module: %w", err)
		}
		backupExists = true
		backupContent, backupInfo, readErr := readSecureRegularFileSnapshot(root, backupName, filepath.Join(directory, backupName))
		if readErr != nil || !expected.matches(backupContent, backupInfo) {
			restoreErr := restoreBackup()
			return fmt.Errorf("secure file changed while quarantining previous inode (restore: %v)", restoreErr)
		}
	}
	if prePublish != nil {
		if err := prePublish(); err != nil {
			restoreErr := restoreBackup()
			return fmt.Errorf("pre-publication configuration CAS: %w (restore: %v)", err, restoreErr)
		}
	}
	// Link is the no-replace publication primitive. A destination created after
	// the last CAS check is never overwritten by the candidate. When replacing
	// an existing operator module, however, the quarantined previous inode stays
	// authoritative until commit and is restored over the conflicting publish.
	if err := root.Link(temporaryName, name); err != nil {
		restoreErr := restoreBackupAfterPublishConflict()
		return fmt.Errorf("publish operator module without replacement: %w (restore: %v)", err, restoreErr)
	}

	rollback := func() error {
		failedName := "." + name + ".failed-" + suffix
		if err := root.Rename(name, failedName); err != nil {
			if backupExists {
				preserveBackup = true
			}
			return fmt.Errorf("quarantine published inode for rollback: %w", err)
		}
		failed, statErr := root.Lstat(failedName)
		if statErr != nil || !os.SameFile(temporaryInfo, failed) {
			if _, err := root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
				if linkErr := root.Link(failedName, name); linkErr == nil {
					_ = root.Remove(failedName)
				}
			}
			if backupExists {
				preserveBackup = true
			}
			return fmt.Errorf("published inode changed before rollback")
		}
		if err := restoreBackup(); err != nil {
			return err
		}
		if err := root.Remove(failedName); err != nil {
			return err
		}
		return syncRootDirectory(root)
	}
	if err := root.Remove(temporaryName); err != nil {
		rollbackErr := rollback()
		return fmt.Errorf("remove operator module publication link: %w (rollback: %v)", err, rollbackErr)
	}
	if err := syncRootDirectory(root); err != nil {
		rollbackErr := rollback()
		return fmt.Errorf("sync operator module replacement: %w (rollback: %v)", err, rollbackErr)
	}
	revalidatePublishedInode := func() error {
		current, err := root.Lstat(name)
		temporaryUID, temporaryGID, temporaryOwnerOK := fileOwnerUIDGID(temporaryInfo)
		currentUID, currentGID, currentOwnerOK := fileOwnerUIDGID(current)
		if err != nil || !os.SameFile(temporaryInfo, current) || current.Mode() != temporaryInfo.Mode() ||
			!temporaryOwnerOK || !currentOwnerOK || temporaryUID != currentUID || temporaryGID != currentGID {
			return fmt.Errorf("published operator-module inode changed during commit")
		}
		return nil
	}
	if err := revalidatePublishedInode(); err != nil {
		rollbackErr := rollback()
		return fmt.Errorf("post-publication inode CAS: %w (rollback: %v)", err, rollbackErr)
	}
	if postCommit != nil {
		if err := postCommit(); err != nil {
			rollbackErr := rollback()
			return fmt.Errorf("post-commit configuration CAS: %w (rollback: %v)", err, rollbackErr)
		}
	}
	if err := revalidatePublishedInode(); err != nil {
		rollbackErr := rollback()
		return fmt.Errorf("post-commit inode CAS: %w (rollback: %v)", err, rollbackErr)
	}
	if expected != nil {
		if err := root.Remove(backupName); err != nil {
			rollbackErr := rollback()
			return fmt.Errorf("remove operator module rollback inode: %w (rollback: %v)", err, rollbackErr)
		}
		backupExists = false
	}
	_ = syncRootDirectory(root)
	return nil
}

func updateProfileInUserModule(content []byte, profileName string) []byte {
	lines := strings.Split(string(content), "\n")
	var updated []string
	inUserBlock := false
	profileSet := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if trimmed == "[user]" {
				inUserBlock = true
			} else {
				if inUserBlock && !profileSet {
					updated = append(updated, fmt.Sprintf("profile_name = %q", profileName))
					profileSet = true
				}
				inUserBlock = false
			}
		}
		if inUserBlock && strings.HasPrefix(trimmed, "profile_name") {
			updated = append(updated, fmt.Sprintf("profile_name = %q", profileName))
			profileSet = true
			continue
		}
		updated = append(updated, line)
	}
	if inUserBlock && !profileSet {
		updated = append(updated, fmt.Sprintf("profile_name = %q", profileName))
		profileSet = true
	}
	if !profileSet {
		updated = append(updated, "", "[user]", fmt.Sprintf("profile_name = %q", profileName))
	}
	return []byte(strings.Join(updated, "\n"))
}

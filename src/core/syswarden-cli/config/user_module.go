package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
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
	report          ValidationReport
	effects         []ConfigurationEffect
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
	return validateModuleCandidate(configDir, userTOMLTarget(), userContent, expectedUser)
}

func rejectNewRetiredUnspecifiedWhitelistEntriesAt(relative string, previousContent []byte, candidate map[string]any) error {
	previous := map[string]int{}
	if len(previousContent) != 0 {
		if document, err := parseTOMLDocument(previousContent, relative); err == nil {
			previous = retiredUnspecifiedWhitelistEntryCounts(document)
		}
	}
	candidateCounts := retiredUnspecifiedWhitelistEntryCounts(candidate)
	for _, value := range []string{"0.0.0.0", "0.0.0.0/32"} {
		if candidateCounts[value] > previous[value] {
			return fmt.Errorf(
				"%s cannot add retired network.whitelist_ips value %q; remove it because exact IGMP control traffic is handled internally",
				relative,
				value,
			)
		}
	}
	return nil
}

func retiredUnspecifiedWhitelistEntryCounts(document map[string]any) map[string]int {
	counts := make(map[string]int, 2)
	for key, rawNetwork := range document {
		if !strings.EqualFold(key, "network") {
			continue
		}
		network, ok := rawNetwork.(map[string]any)
		if !ok {
			continue
		}
		for networkKey, rawWhitelist := range network {
			if !strings.EqualFold(networkKey, "whitelist_ips") {
				continue
			}
			switch values := rawWhitelist.(type) {
			case []any:
				for _, rawValue := range values {
					if value, ok := rawValue.(string); ok && IsRetiredUnspecifiedWhitelistEntry(value) {
						counts[value]++
					}
				}
			case []string:
				for _, value := range values {
					if IsRetiredUnspecifiedWhitelistEntry(value) {
						counts[value]++
					}
				}
			}
		}
	}
	return counts
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
	target := tomlEditTarget{}
	if published {
		target = userTOMLTarget()
	}
	return snapshot.revalidateTarget(configDir, target, publishedContent)
}

func (snapshot *mergedConfigSnapshot) revalidateTarget(configDir string, publishedTarget tomlEditTarget, publishedContent []byte) error {
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
	if publishedTarget.master {
		if err := revalidatePublishedTOML(root, "config.toml", filepath.Join(configDir, "config.toml"), publishedContent); err != nil {
			return err
		}
	} else if err := revalidateOptionalSecureFile(root, "config.toml", filepath.Join(configDir, "config.toml"), snapshot.master); err != nil {
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
	entries, err := readBoundedEditEntries(directory)
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
	if publishedTarget.relative != "" && !publishedTarget.master && snapshot.identity(publishedTarget) == nil {
		expectedNames = append(expectedNames, publishedTarget.name)
		sort.Strings(expectedNames)
	}
	if !reflect.DeepEqual(names, expectedNames) {
		return fmt.Errorf("TOML module inventory changed during user-module transaction")
	}
	for name, identity := range snapshot.modules {
		if publishedTarget.relative != "" && !publishedTarget.master && name == publishedTarget.name {
			continue
		}
		if err := revalidateOptionalSecureFile(modulesRoot, name, filepath.Join(modulesDir, name), identity); err != nil {
			return err
		}
	}
	if publishedTarget.relative != "" && !publishedTarget.master {
		if err := revalidatePublishedTOML(modulesRoot, publishedTarget.name, filepath.Join(modulesDir, publishedTarget.name), publishedContent); err != nil {
			return err
		}
		if publishedTarget.name == userModuleName {
			return nil
		}
	}

	return revalidateOptionalSecureFile(modulesRoot, userModuleName, filepath.Join(modulesDir, userModuleName), snapshot.user)
}

func revalidatePublishedTOML(root *os.Root, name, path string, expected []byte) error {
	content, _, err := readSecureRegularFileSnapshotBounded(root, name, path, max(int64(len(expected)), 1))
	if err != nil {
		return err
	}
	if !bytes.Equal(content, expected) {
		return fmt.Errorf("published configuration file %s changed during commit", name)
	}
	return nil
}

func sameFileAndMode(expected, current os.FileInfo) bool {
	if expected == nil || current == nil {
		return false
	}
	expectedUID, expectedGID, expectedOK := fileOwnerUIDGID(expected)
	currentUID, currentGID, currentOK := fileOwnerUIDGID(current)
	return expectedOK && currentOK && expectedUID == currentUID && expectedGID == currentGID && os.SameFile(expected, current) && expected.Mode() == current.Mode()
}

func revalidateOptionalSecureFile(root *os.Root, name, displayPath string, expected *secureFileIdentity) error {
	if expected == nil {
		if _, err := root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("configuration file %s appeared during user-module transaction", displayPath)
	}
	content, info, err := readSecureRegularFileSnapshotBounded(root, name, displayPath, max(expected.info.Size(), 1))

	if err != nil {
		return err
	}
	if !expected.matches(content, info) || !sameSecureFileMetadata(expected.info, info) {
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
	return replaceSecureConfigFile(directory, name, content, expected, preCommit, prePublish, postCommit)
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
		key, _, assignment := strings.Cut(trimmed, "=")
		if inUserBlock && assignment && strings.TrimSpace(key) == "profile_name" {
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

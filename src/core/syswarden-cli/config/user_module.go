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

	"syswarden-cli/pkg/sshselection"

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
	report          ValidationReport
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
	if err := sshselection.RejectEnvironment(); err != nil {
		return nil, err
	}
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
	var profileInventory unconfiguredProfileInventory
	observed := make(map[string]struct{})
	if _, err := root.Lstat("config.toml"); err == nil {
		content, identity, readErr := readSecureRegularFileIdentity(root, "config.toml", filepath.Join(configDir, "config.toml"))
		if readErr != nil {
			return nil, readErr
		}
		document, err := parseTOMLDocument(content, "config.toml")
		if err != nil {
			return nil, err
		}
		profileInventory.record("config.toml", document)
		flattenTOMLKeys("", document, observed)
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
		var previousUserContent []byte
		if entry.Name() == userModuleName {
			if expectedUser == nil || !expectedUser.matches(content, identity.info) {
				return nil, fmt.Errorf("operator user module changed before merged validation")
			}
			previousUserContent = content
			content = userContent
			mergedUser = true
		} else {
			snapshot.modules[entry.Name()] = identity
		}
		relative := filepath.ToSlash(filepath.Join("modules", entry.Name()))
		document, err := parseTOMLDocument(content, relative)
		if err != nil {
			return nil, err
		}
		profileInventory.record(relative, document)
		flattenTOMLKeys("", document, observed)
		if entry.Name() == userModuleName {
			if err := rejectNewRetiredUnspecifiedWhitelistEntries(previousUserContent, document); err != nil {
				return nil, err
			}
		}
		if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
			return nil, fmt.Errorf("merge module %s: %w", entry.Name(), err)
		}
	}
	if !mergedUser {
		if expectedUser != nil {
			return nil, fmt.Errorf("operator user module disappeared before merged validation")
		}
		document, err := parseTOMLDocument(userContent, filepath.ToSlash(filepath.Join("modules", userModuleName)))
		if err != nil {
			return nil, err
		}
		profileInventory.recordProfile(filepath.ToSlash(filepath.Join("modules", userModuleName)), document)
		flattenTOMLKeys("", document, observed)
		if err := rejectNewRetiredUnspecifiedWhitelistEntries(nil, document); err != nil {
			return nil, err
		}
		if err := v.MergeConfig(bytes.NewReader(userContent)); err != nil {
			return nil, fmt.Errorf("merge new operator module: %w", err)
		}
	}
	if err := profileInventory.validate(); err != nil {
		return nil, err
	}
	if err := resolveOptionalModules(v); err != nil {
		return nil, err
	}
	var candidate ModularConfig
	if err := v.Unmarshal(&candidate); err != nil {
		return nil, err
	}
	classifyModularKeys(observed, &snapshot.report)
	snapshot.report.SchemaVersion = candidate.SchemaVersion
	snapshot.report.Historical = candidate.SchemaVersion == 0
	for _, entry := range neutralizeRetiredUnspecifiedWhitelistConfig(&candidate) {
		snapshot.report.DeprecatedKeys = append(snapshot.report.DeprecatedKeys, retiredUnspecifiedWhitelistDiagnostic(entry))
	}
	sort.Strings(snapshot.report.DeprecatedKeys)
	if err := validateConfig(&candidate); err != nil {
		return nil, err
	}
	if err := snapshot.revalidate(configDir, false, nil); err != nil {
		return nil, fmt.Errorf("configuration changed during merged validation: %w", err)
	}
	snapshot.report.ModulePlan = ModulePlan(mapModularToLegacy(&candidate))
	return snapshot, nil
}

func rejectNewRetiredUnspecifiedWhitelistEntries(previousContent []byte, candidate map[string]any) error {
	previous := map[string]int{}
	if len(previousContent) != 0 {
		if document, err := parseTOMLDocument(previousContent, filepath.ToSlash(filepath.Join("modules", userModuleName))); err == nil {
			previous = retiredUnspecifiedWhitelistEntryCounts(document)
		}
	}
	candidateCounts := retiredUnspecifiedWhitelistEntryCounts(candidate)
	for _, value := range []string{"0.0.0.0", "0.0.0.0/32"} {
		if candidateCounts[value] > previous[value] {
			return fmt.Errorf(
				"modules/%s cannot add retired network.whitelist_ips value %q; remove it because exact IGMP control traffic is handled internally",
				userModuleName,
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

package config

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/viper"
)

type Migrator struct {
	SourcePath string
	OutputDir  string
	DryRun     bool
}

func (m *Migrator) Run() error {
	marker, err := readMigrationMarker(m.OutputDir)
	if err != nil {
		return fmt.Errorf("read migration transaction: %w", err)
	}
	snapshot, sourceErr := openLegacySourceSnapshot(m.SourcePath)
	if sourceErr != nil {
		if marker != nil && (marker.State == migrationPublished || marker.State == migrationWipeStaged) {
			return m.recoverPublishedMigration(marker, sourceErr)
		}
		return fmt.Errorf("parse source config %s: %w", m.SourcePath, sourceErr)
	}
	defer func() { _ = snapshot.Close() }()
	if marker != nil {
		if marker.SourcePath != snapshot.path || !marker.matchesSourceIdentity(snapshot) {
			return fmt.Errorf("migration source does not match the in-progress transaction")
		}
		if marker.State == migrationPublished && marker.SecureWipe {
			if err := verifyMigrationArtifacts(m.OutputDir, marker.ArtifactSHA256); err != nil {
				return fmt.Errorf("verify published migration before secure-wipe recovery: %w", err)
			}
			if err := m.runSecureWipe(snapshot, marker); err != nil {
				return fmt.Errorf("resume secure wipe of migrated source %s: %w", m.SourcePath, err)
			}
			if err := removeMigrationMarker(m.OutputDir); err != nil {
				return fmt.Errorf("finalize recovered secure-wipe transaction: %w", err)
			}
			return nil
		}
		if marker.SourceSHA256 != snapshot.digest {
			return fmt.Errorf("migration source content does not match the in-progress transaction")
		}
	}

	oldConfig, err := parseLegacyConfig(bytes.NewReader(snapshot.content))
	if err != nil {
		return fmt.Errorf("parse source config %s: %w", m.SourcePath, err)
	}
	oldConfig, err = normalizeHistoricalLegacyMap(oldConfig)
	if err != nil {
		return fmt.Errorf("normalize legacy HA configuration: %w", err)
	}
	modules, err := m.renderModules(oldConfig)
	if err != nil {
		return err
	}
	master, err := m.masterConfigContent(oldConfig)
	if err != nil {
		return fmt.Errorf("generate master configuration: %w", err)
	}
	if err := m.validateRenderedMigration(master, modules); err != nil {
		return fmt.Errorf("validate migrated configuration: %w", err)
	}

	if err := ensureConfigDirectory(m.OutputDir, 0750); err != nil {
		return err
	}
	if err := ensureConfigDirectory(filepath.Join(m.OutputDir, "modules"), 0750); err != nil {
		return err
	}
	if m.DryRun {
		if marker != nil {
			return fmt.Errorf("dry-run cannot resume an in-progress migration transaction")
		}
		if err := m.generateAllModules(oldConfig); err != nil {
			return err
		}
		return m.generateMasterConfig(oldConfig)
	}

	artifacts, preserveUser, err := m.migrationArtifacts(master, modules, marker)
	if err != nil {
		return err
	}
	if err := m.validateEffectiveMigrationArtifacts(master, artifacts); err != nil {
		return fmt.Errorf("validate effective migration artifacts: %w", err)
	}
	wipeText, err := legacyBoolText(oldConfig, "SYSWARDEN_SECURE_WIPE_CONF", false)
	if err != nil {
		return err
	}
	if marker == nil {
		device, inode, ok := fileDeviceInode(snapshot.info)
		owner, ownerOK := fileOwnerUID(snapshot.info)
		parentDevice, parentInode, parentOK := fileDeviceInode(snapshot.parentInfo)
		parentOwner, parentOwnerOK := fileOwnerUID(snapshot.parentInfo)
		if !ok || !ownerOK || !parentOK || !parentOwnerOK {
			return fmt.Errorf("capture migration source identity")
		}
		marker = &migrationMarker{
			Version:        migrationMarkerVersion,
			State:          migrationPublishing,
			SourcePath:     snapshot.path,
			SourceSHA256:   snapshot.digest,
			SourceDevice:   device,
			SourceInode:    inode,
			SourceMode:     uint32(snapshot.info.Mode()),
			SourceOwner:    owner,
			ParentDevice:   parentDevice,
			ParentInode:    parentInode,
			ParentMode:     uint32(snapshot.parentInfo.Mode()),
			ParentOwner:    parentOwner,
			SecureWipe:     wipeText == "true",
			PreserveUser:   preserveUser,
			ArtifactSHA256: make(map[string]string, len(artifacts)),
		}
		for _, artifact := range artifacts {
			marker.ArtifactSHA256[artifact.relative] = digestBytes(artifact.content)
		}
		if err := writeMigrationMarker(m.OutputDir, marker, false); err != nil {
			return fmt.Errorf("start migration transaction: %w", err)
		}
	} else {
		if marker.SecureWipe != (wipeText == "true") {
			return fmt.Errorf("migration inputs changed during transaction retry")
		}
		// A validated operator write may atomically win after the first
		// publishing marker was created. While the transaction is still in its
		// publishing state, adopt that secure module and its digest instead of
		// overwriting it. Published transactions remain immutable.
		adoptPublishingUser := marker.State == migrationPublishing && preserveUser
		if marker.PreserveUser != preserveUser && !(adoptPublishingUser && !marker.PreserveUser) {
			return fmt.Errorf("migration inputs changed during transaction retry")
		}
		userRelative := filepath.ToSlash(filepath.Join("modules", userModuleName))
		markerChanged := false
		for _, artifact := range artifacts {
			digest := digestBytes(artifact.content)
			if adoptPublishingUser && artifact.relative == userRelative && artifact.preserve {
				if marker.ArtifactSHA256[artifact.relative] != digest {
					marker.ArtifactSHA256[artifact.relative] = digest
					markerChanged = true
				}
				continue
			}
			if marker.ArtifactSHA256[artifact.relative] != digest {
				return fmt.Errorf("migration artifact %s changed during transaction retry", artifact.relative)
			}
		}
		if adoptPublishingUser && !marker.PreserveUser {
			marker.PreserveUser = true
			markerChanged = true
		}
		if markerChanged {
			if err := writeMigrationMarker(m.OutputDir, marker, true); err != nil {
				return fmt.Errorf("adopt concurrent operator user module: %w", err)
			}
		}
	}

	if marker.State == migrationPublishing {
		if err := m.publishMigrationArtifacts(artifacts); err != nil {
			return err
		}
		if err := verifyMigrationArtifacts(m.OutputDir, marker.ArtifactSHA256); err != nil {
			return err
		}
		marker.State = migrationPublished
		if err := writeMigrationMarker(m.OutputDir, marker, true); err != nil {
			return fmt.Errorf("commit migration transaction: %w", err)
		}
		if err := migrationCommitHook(); err != nil {
			return fmt.Errorf("migration commit hook: %w", m.reopenPublishedMigration(marker, err))
		}
	}
	// The marker transition and the complete TOML inventory form one logical
	// commit. Revalidate after publishing the marker so an unexpected module or
	// artifact mutation cannot be followed by source finalization. Reopening the
	// transaction lets a bounded retry republish the generated artifacts after
	// the operator removes the unexpected module.
	if err := verifyMigrationArtifacts(m.OutputDir, marker.ArtifactSHA256); err != nil {
		return fmt.Errorf("verify committed migration before source finalization: %w", m.reopenPublishedMigration(marker, err))
	}

	if marker.SecureWipe {
		if err := m.runSecureWipe(snapshot, marker); err != nil {
			return fmt.Errorf("securely wipe migrated source %s: %w", m.SourcePath, err)
		}
	} else {
		if err := renameLegacyFile(snapshot); err != nil {
			return fmt.Errorf("retain migrated source %s: %w", m.SourcePath, err)
		}
	}
	if err := removeMigrationMarker(m.OutputDir); err != nil {
		return fmt.Errorf("finalize migration transaction: %w", err)
	}
	return nil
}

func (m *Migrator) reopenPublishedMigration(marker *migrationMarker, validationErr error) error {
	if marker == nil || marker.State != migrationPublished {
		return validationErr
	}
	marker.State = migrationPublishing
	marker.WipeStaging = ""
	if err := writeMigrationMarker(m.OutputDir, marker, true); err != nil {
		return fmt.Errorf("%v (reopen migration transaction: %w)", validationErr, err)
	}
	return validationErr
}

func (m *Migrator) runSecureWipe(snapshot *legacySourceSnapshot, marker *migrationMarker) error {
	if marker == nil || marker.State != migrationPublished || !marker.SecureWipe {
		return fmt.Errorf("secure wipe requires a published migration transaction")
	}
	return shredLegacyFile(snapshot, func(staging string) error {
		marker.State = migrationWipeStaged
		marker.WipeStaging = staging
		return writeMigrationMarker(m.OutputDir, marker, true)
	})
}

// InitializeDefaults initializes the default modular configuration from the hardcoded DefaultConfig memory string.
func InitializeDefaults(outputDir string) error {
	if err := ensureConfigDirectory(outputDir, 0750); err != nil {
		return err
	}
	if err := ensureConfigDirectory(filepath.Join(outputDir, "modules"), 0750); err != nil {
		return err
	}
	m := &Migrator{
		OutputDir: outputDir,
		DryRun:    false,
	}

	configData, err := m.ParseFromMemory(DefaultConfig)
	if err != nil {
		return err
	}

	if err := m.generateAllModules(configData); err != nil {
		return err
	}

	if err := m.generateMasterConfig(configData); err != nil {
		return err
	}

	return nil
}

// EnsureDefaults creates only missing modular configuration files. Existing
// regular files remain byte-for-byte untouched so operator overrides and local
// permissions are never replaced during install or upgrade.
func EnsureDefaults(outputDir string) error {
	if err := ensureConfigDirectory(outputDir, 0750); err != nil {
		return err
	}
	if err := rejectMigrationInProgress(outputDir); err != nil {
		return err
	}
	modulesDir := filepath.Join(outputDir, "modules")
	if err := ensureConfigDirectory(modulesDir, 0750); err != nil {
		return err
	}

	m := &Migrator{OutputDir: outputDir}
	configData, err := m.ParseFromMemory(DefaultConfig)
	if err != nil {
		return err
	}

	modules, err := m.renderModules(configData)
	if err != nil {
		return fmt.Errorf("generate default modules: %w", err)
	}
	master, err := m.masterConfigContent(configData)
	if err != nil {
		return fmt.Errorf("generate default master configuration: %w", err)
	}
	for _, module := range modules {
		if err := ensureMissingConfigFile(modulesDir, module.name, []byte(module.content)); err != nil {
			return err
		}
	}
	return ensureMissingConfigFile(outputDir, "config.toml", []byte(master))
}

func ensureConfigDirectory(path string, mode os.FileMode) error {
	root, err := openConfigDirectory(path, true, mode)
	if err != nil {
		return err
	}
	info, statErr := rootDirectoryInfo(root)
	closeErr := root.Close()
	if statErr != nil {
		return fmt.Errorf("inspect configuration directory %s: %w", path, statErr)
	}
	if info.Mode().Perm()&0027 != 0 {
		return fmt.Errorf("configuration directory %s has unsafe mode %#o", path, info.Mode().Perm())
	}
	return closeErr
}

func ensureMissingConfigFile(directory, name string, content []byte) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("invalid configuration filename %q", name)
	}
	path := filepath.Join(directory, name)
	root, err := openConfigDirectory(directory, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(name)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("configuration file %s is not a regular file", path)
		}
		if info.Mode().Perm()&0037 != 0 {
			return fmt.Errorf("configuration file %s has unsafe mode %#o", path, info.Mode().Perm())
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("inspect configuration file %s: %w", path, err)
	}
	return writeMissingSecureFile(directory, name, content)
}

func (m *Migrator) parseOldConfig() (map[string]string, error) {
	content, err := readSecureFileByPath(m.SourcePath)
	if err != nil {
		return nil, err
	}
	return parseLegacyConfig(bytes.NewReader(content))
}

// ParseFromMemory parses the legacy flat configuration format directly from a string in memory
func (m *Migrator) ParseFromMemory(content string) (map[string]string, error) {
	return parseLegacyConfig(strings.NewReader(content))
}

func parseLegacyConfig(reader io.Reader) (map[string]string, error) {
	config := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("legacy configuration contains invalid UTF-8")
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value, err := parseLegacyValue(parts[1])
		if err != nil {
			return nil, fmt.Errorf("parse legacy key %s: %w", key, err)
		}
		config[key] = value
	}
	return config, scanner.Err()
}

func parseLegacyValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if raw[0] != '\'' && raw[0] != '"' {
		if index := strings.Index(raw, " #"); index >= 0 {
			raw = strings.TrimSpace(raw[:index])
		}
		return raw, nil
	}

	quote := raw[0]
	escaped := false
	for index := 1; index < len(raw); index++ {
		character := raw[index]
		if quote == '"' && character == '\\' && !escaped {
			escaped = true
			continue
		}
		if character == quote && !escaped {
			remainder := strings.TrimSpace(raw[index+1:])
			if remainder != "" && !strings.HasPrefix(remainder, "#") {
				return "", fmt.Errorf("unexpected content after quoted value")
			}
			value := raw[1:index]
			if quote == '"' {
				value = unquoteLegacyDouble(value)
			}
			return value, nil
		}
		escaped = false
	}
	return "", fmt.Errorf("unterminated quoted value")
}

func unquoteLegacyDouble(value string) string {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index+1 >= len(value) {
			result.WriteByte(value[index])
			continue
		}
		next := value[index+1]
		switch next {
		case '\\', '"', '$', '`':
			result.WriteByte(next)
			index++
		default:
			result.WriteByte('\\')
		}
	}
	return result.String()
}

type moduleGenerator struct {
	name      string
	generator func(map[string]string) (string, error)
}

type renderedModule struct {
	name    string
	content string
}

func (m *Migrator) moduleGenerators() []moduleGenerator {
	return []moduleGenerator{
		{"00-core.toml", m.generateCore},
		{"10-network.toml", m.generateNetwork},
		{"20-security.toml", m.generateSecurity},
		{"30-waap.toml", m.generateWAAP},
		{"40-integrations.toml", m.generateIntegrations},
		{"99-user.toml", m.generateUser},
	}
}

func (m *Migrator) renderModules(oldConfig map[string]string) ([]renderedModule, error) {
	modules := make([]renderedModule, 0, len(m.moduleGenerators()))
	for _, generator := range m.moduleGenerators() {
		content, err := generator.generator(oldConfig)
		if err != nil {
			return nil, fmt.Errorf("generate module %s: %w", generator.name, err)
		}
		modules = append(modules, renderedModule{name: generator.name, content: content})
	}
	return modules, nil
}

func (m *Migrator) validateRenderedMigration(master string, modules []renderedModule) error {
	v := viper.New()
	v.SetConfigType("toml")
	setDefaults(v, m.OutputDir)
	if err := v.MergeConfig(strings.NewReader(master)); err != nil {
		return fmt.Errorf("parse rendered master configuration: %w", err)
	}
	for _, module := range modules {
		if err := v.MergeConfig(strings.NewReader(module.content)); err != nil {
			return fmt.Errorf("parse rendered module %s: %w", module.name, err)
		}
	}
	var candidate ModularConfig
	if err := v.Unmarshal(&candidate); err != nil {
		return fmt.Errorf("decode rendered configuration: %w", err)
	}
	return validateConfig(&candidate)
}

func (m *Migrator) generateAllModules(oldConfig map[string]string) error {
	modules, err := m.renderModules(oldConfig)
	if err != nil {
		return err
	}
	for _, module := range modules {
		outputPath := filepath.Join(m.OutputDir, "modules", module.name)
		if m.DryRun {
			fmt.Printf("[DRY RUN] Would create: %s\n", outputPath)
		} else {
			if module.name == "99-user.toml" {
				if err := ensureMissingConfigFile(filepath.Dir(outputPath), filepath.Base(outputPath), []byte(module.content)); err != nil {
					return err
				}
				fmt.Printf("Preserved or created: %s\n", outputPath)
				continue
			}
			if err := writeSecureFileAtomically(filepath.Dir(outputPath), filepath.Base(outputPath), []byte(module.content)); err != nil {
				return err
			}
			fmt.Printf("Created: %s\n", outputPath)
		}
	}
	return nil
}

func (m *Migrator) generateMasterConfig(oldConfig map[string]string) error {
	content, err := m.masterConfigContent(oldConfig)
	if err != nil {
		return err
	}
	outputPath := filepath.Join(m.OutputDir, "config.toml")
	if m.DryRun {
		fmt.Printf("[DRY RUN] Would create: %s\n", outputPath)
	} else {
		if err := writeSecureFileAtomically(filepath.Dir(outputPath), filepath.Base(outputPath), []byte(content)); err != nil {
			return err
		}
		fmt.Printf("Created: %s\n", outputPath)
	}
	return nil
}

func (m *Migrator) masterConfigContent(oldConfig map[string]string) (string, error) {
	enterpriseMode, err := legacyBoolText(oldConfig, "SYSWARDEN_ENTERPRISE_MODE", false)
	if err != nil {
		return "", err
	}
	return `# SYSWARDEN MODULAR CONFIGURATION
# Load order: 00-*.toml -> 99-*.toml
# Environment variables override: SYSWARDEN_<SECTION>_<KEY>

[core]
config_dir = ` + quoteTOML(filepath.Join(m.OutputDir, "modules")) + `
enterprise_mode = ` + enterpriseMode + `
log_level = "INFO"
`, nil
}

func writeSecureFileAtomically(directory, name string, content []byte) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("invalid configuration filename %q", name)
	}

	root, err := openConfigDirectory(directory, false, 0)
	if err != nil {
		return fmt.Errorf("open configuration directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return fmt.Errorf("generate temporary filename: %w", err)
	}
	temporaryName := "." + name + ".tmp-" + hex.EncodeToString(randomSuffix)
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temporary configuration file: %w", err)
	}
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
	}()

	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary configuration file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary configuration file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary configuration file: %w", err)
	}
	temporaryOpen = false
	if err := root.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("replace configuration file atomically: %w", err)
	}

	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open configuration directory for sync: %w", err)
	}
	defer func() { _ = directoryFile.Close() }()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync configuration directory: %w", err)
	}
	return nil
}

func writeMissingSecureFile(directory, name string, content []byte) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("invalid configuration filename %q", name)
	}

	root, err := openConfigDirectory(directory, false, 0)
	if err != nil {
		return fmt.Errorf("open configuration directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return fmt.Errorf("generate temporary filename: %w", err)
	}
	temporaryName := "." + name + ".tmp-" + hex.EncodeToString(randomSuffix)
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temporary configuration file: %w", err)
	}
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
	}()

	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary configuration file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary configuration file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary configuration file: %w", err)
	}
	temporaryOpen = false

	// A hard link publishes the completed inode without replacing a file that
	// appeared concurrently between the initial inspection and this point.
	if err := root.Link(temporaryName, name); err != nil {
		return fmt.Errorf("publish missing configuration file: %w", err)
	}
	if err := root.Remove(temporaryName); err != nil {
		return fmt.Errorf("remove temporary configuration link: %w", err)
	}

	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open configuration directory for sync: %w", err)
	}
	defer func() { _ = directoryFile.Close() }()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync configuration directory: %w", err)
	}
	return nil
}

func legacyValue(config map[string]string, key, defaultValue string, aliases ...string) string {
	for _, candidate := range append([]string{key}, aliases...) {
		if value, ok := config[candidate]; ok {
			return value
		}
	}
	return defaultValue
}

func normalizeHistoricalLegacyMap(config map[string]string) (map[string]string, error) {
	normalized := make(map[string]string, len(config)+1)
	for key, value := range config {
		normalized[key] = value
	}
	haEnabled, err := legacyBoolText(normalized, "SYSWARDEN_HA_ENABLED", false)
	if err != nil {
		return nil, err
	}
	if haEnabled != "true" {
		return normalized, nil
	}
	bunkerWebEnabled, err := legacyBoolText(normalized, "SYSWARDEN_BUNKERWEB_ENABLED", false)
	if err != nil {
		return nil, err
	}
	tokenEmpty := legacyValue(normalized, "SYSWARDEN_HA_TOKEN", "") == ""
	peersEmpty := len(strings.Fields(strings.ReplaceAll(legacyValue(normalized, "SYSWARDEN_HA_PEER_IP", ""), ",", " "))) == 0
	if tokenEmpty && peersEmpty && bunkerWebEnabled == "false" {
		normalized["SYSWARDEN_HA_ENABLED"] = "n"
		normalized["SYSWARDEN_BUNKERWEB_ENABLED"] = "n"
		return normalized, nil
	}
	if tokenEmpty != peersEmpty {
		return nil, fmt.Errorf("legacy HA configuration is partial: token and peer_ips must be configured together")
	}
	return normalized, nil
}

func legacyBoolText(config map[string]string, key string, defaultValue bool, aliases ...string) (string, error) {
	var selected *bool
	selectedKey := ""
	for _, candidate := range append([]string{key}, aliases...) {
		raw, present := config[candidate]
		if !present {
			continue
		}
		value, err := parseLegacyBoolValue(candidate, raw)
		if err != nil {
			return "", err
		}
		if selected != nil && *selected != value {
			return "", fmt.Errorf("legacy boolean aliases %s and %s conflict", selectedKey, candidate)
		}
		copy := value
		selected = &copy
		selectedKey = candidate
	}
	if selected == nil {
		return strconv.FormatBool(defaultValue), nil
	}
	return strconv.FormatBool(*selected), nil
}

func parseLegacyBoolValue(key, raw string) (bool, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "y", "yes", "true", "1":
		return true, nil
	case "", "n", "no", "false", "0":
		// The v4.02.8 parser treats an explicitly empty value as false. Keep
		// that distinction from an absent key, which may have a true default.
		return false, nil
	default:
		return false, fmt.Errorf("legacy key %s has invalid boolean value %q", key, value)
	}
}

func legacyPositiveIntText(config map[string]string, key string, defaultValue int) (string, error) {
	raw := legacyValue(config, key, strconv.Itoa(defaultValue))
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return "", fmt.Errorf("legacy key %s has invalid positive integer %q", key, raw)
	}
	return strconv.Itoa(value), nil
}

func legacyPortText(config map[string]string, key string, defaultValue int) (string, error) {
	port, err := legacyPositiveIntText(config, key, defaultValue)
	if err != nil {
		return "", err
	}
	value, _ := strconv.Atoi(port)
	if value > 65535 {
		return "", fmt.Errorf("legacy key %s has invalid port %q", key, port)
	}
	return port, nil
}

func legacyOptionalPort(config map[string]string, key, defaultValue string) (string, error) {
	raw := legacyValue(config, key, defaultValue)
	if raw == "" {
		return "", nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 65535 {
		return "", fmt.Errorf("legacy key %s has invalid port %q", key, raw)
	}
	return strconv.Itoa(value), nil
}

func legacyDurationSecondsText(config map[string]string, key string, defaultSeconds int) (string, error) {
	raw := legacyValue(config, key, strconv.Itoa(defaultSeconds))
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds < 1 {
			return "", fmt.Errorf("legacy key %s has invalid duration %q", key, raw)
		}
		return strconv.Itoa(seconds), nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 || duration%time.Second != 0 {
		return "", fmt.Errorf("legacy key %s has invalid whole-second duration %q", key, raw)
	}
	return strconv.FormatInt(int64(duration/time.Second), 10), nil
}

func quoteTOML(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\b':
			quoted.WriteString(`\b`)
		case '\t':
			quoted.WriteString(`\t`)
		case '\n':
			quoted.WriteString(`\n`)
		case '\f':
			quoted.WriteString(`\f`)
		case '\r':
			quoted.WriteString(`\r`)
		case '"':
			quoted.WriteString(`\"`)
		case '\\':
			quoted.WriteString(`\\`)
		default:
			if character < 0x20 || character == 0x7f {
				_, _ = fmt.Fprintf(&quoted, `\u%04X`, character)
			} else {
				quoted.WriteRune(character)
			}
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

func legacySliceText(value string) string {
	if value == "" || value == "false" || value == "none" || value == "0" {
		return ""
	}
	value = strings.ReplaceAll(value, ",", " ")
	items := strings.Fields(value)
	valid := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" && item != "false" && item != "none" {
			valid = append(valid, quoteTOML(item))
		}
	}
	return strings.Join(valid, ", ")
}

func (m *Migrator) generateCore(oldConfig map[string]string) (string, error) {
	hardening, err := legacyBoolText(oldConfig, "SYSWARDEN_HARDENING", false)
	if err != nil {
		return "", err
	}
	cisL2, err := legacyBoolText(oldConfig, "APPLY_CIS_L2_HARDENING", false, "SYSWARDEN_CIS_L2")
	if err != nil {
		return "", err
	}
	secureWipe, err := legacyBoolText(oldConfig, "SYSWARDEN_SECURE_WIPE_CONF", false)
	if err != nil {
		return "", err
	}
	sshPort, err := legacyOptionalPort(oldConfig, "SYSWARDEN_SSH_PORT", "")
	if err != nil {
		return "", err
	}
	return `# [00] CORE SYSTEM CONFIGURATION
# Priority: 00 (loaded first, lowest precedence)

[core]
# Supported backends (RHEL/Alma/Fedora ONLY): "nftables", "iptables", "keep"
firewall_backend = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_FIREWALL_BACKEND", "keep")) + `

# Boolean values: true or false (no quotes)
hardening_enabled = ` + hardening + `
cis_l2_hardening = ` + cisL2 + `
secure_wipe_conf = ` + secureWipe + `

# SSH Port string (e.g. "2222")
ssh_port = ` + quoteTOML(sshPort) + `
`, nil
}

func (m *Migrator) generateNetwork(oldConfig map[string]string) (string, error) {
	whitelistInfra, err := legacyBoolText(oldConfig, "SYSWARDEN_WHITELIST_INFRA", true)
	if err != nil {
		return "", err
	}
	geoEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_ENABLE_GEO", true)
	if err != nil {
		return "", err
	}
	asnEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_ENABLE_ASN", true)
	if err != nil {
		return "", err
	}
	allowMonitors, err := legacyBoolText(oldConfig, "SYSWARDEN_ALLOW_SAAS_MONITORS", false, "SYSWARDEN_ALLOW_MONITORS")
	if err != nil {
		return "", err
	}
	useSpamhaus, err := legacyBoolText(oldConfig, "SYSWARDEN_USE_SPAMHAUS", false)
	if err != nil {
		return "", err
	}
	wireguardEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_ENABLE_WG", false)
	if err != nil {
		return "", err
	}
	wireguardPort, err := legacyOptionalPort(oldConfig, "SYSWARDEN_WG_PORT", "")
	if err != nil {
		return "", err
	}

	geoListStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_GEO_CODES", ""))
	asnListStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_ASN_LIST", ""))
	geoAllowedStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_GEO_ALLOWED", ""))
	asnAllowedStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_ASN_ALLOWED", ""))
	lanListStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_LAN_SUBNETS", ""))
	whitelistIPsStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_WHITELIST_IPS", ""))

	return `# [10] NETWORK & THREAT INTELLIGENCE
# Priority: 10

[network]
# Boolean values: true or false (no quotes)
whitelist_infra = ` + whitelistInfra + `

# Arrays MUST be formatted with brackets, quotes, and commas.
# Example: ["10.0.0.0/8", "192.168.1.0/24"]
lan_subnets = [` + lanListStr + `]
whitelist_ips = [` + whitelistIPsStr + `]

# String (e.g. "eth0,ens33")
interfaces = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_INTERFACES", "")) + `

[network.geo]
enabled = ` + geoEnabled + `
# Format requires quotes (ISO 3166-1 alpha-2): ["ru", "cn", "fr"]
blocked_countries = [` + geoListStr + `]
allowed_countries = [` + geoAllowedStr + `]

[network.asn]
enabled = ` + asnEnabled + `
# Format requires quotes: ["AS1234", "AS5678"]
blocked_asns = [` + asnListStr + `]
allowed_asns = [` + asnAllowedStr + `]

[network.saas]
allow_monitors = ` + allowMonitors + `

[network.blocklists]
# Threat Intel Data-Shield lists configuration
# Choices: 1=standard, 2=critical, 3=custom, 4=none
list_choice = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_LIST_CHOICE", "1")) + `
custom_url = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_CUSTOM_URL", "")) + `
custom_url_ipv6 = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_CUSTOM_URL_IPV6", "")) + `
custom_hash = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_CUSTOM_HASH", "")) + `
custom_hash_ipv6 = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_CUSTOM_HASH_IPV6", "")) + `
use_spamhaus = ` + useSpamhaus + `

[network.wireguard]
enabled = ` + wireguardEnabled + `
port = ` + quoteTOML(wireguardPort) + `
subnet = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_WG_SUBNET", "")) + `
`, nil
}

func (m *Migrator) generateSecurity(oldConfig map[string]string) (string, error) {
	enableL2, err := legacyBoolText(oldConfig, "SYSWARDEN_ENABLE_L2", false)
	if err != nil {
		return "", err
	}
	arpProtect, err := legacyBoolText(oldConfig, "SYSWARDEN_ARP_PROTECT", false)
	if err != nil {
		return "", err
	}
	lanMode, err := legacyBoolText(oldConfig, "SYSWARDEN_LAN_MODE", false)
	if err != nil {
		return "", err
	}
	honeyPortsStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_HONEYPORTS", ""))

	return `# [20] SECURITY & COMPLIANCE
# Priority: 20

[security]
# Format requires quotes: ["6379", "23"]
honeyports = [` + honeyPortsStr + `]

[security.l2]
enable_l2 = ` + enableL2 + `
arp_protect = ` + arpProtect + `
lan_mode = ` + lanMode + `

[security.compliance]
enable_watchdog = true
check_interval = "24h"
`, nil
}

func (m *Migrator) generateWAAP(oldConfig map[string]string) (string, error) {
	enforcementMode := legacyValue(oldConfig, "SYSWARDEN_ENFORCEMENT_MODE", "enforcing")
	if enforcementMode != "enforcing" && enforcementMode != "audit" {
		return "", fmt.Errorf("legacy key SYSWARDEN_ENFORCEMENT_MODE has invalid mode %q", enforcementMode)
	}
	threshold, err := legacyPositiveIntText(oldConfig, "SYSWARDEN_BRUTEFORCE_THRESHOLD", 5)
	if err != nil {
		return "", err
	}
	window, err := legacyDurationSecondsText(oldConfig, "SYSWARDEN_BRUTEFORCE_WINDOW", 60)
	if err != nil {
		return "", err
	}

	return `# [30] WAAP (Web Application & API Protection)
# Priority: 30

[waap]
# Modes: "enforcing", "audit"
enforcement_mode = ` + quoteTOML(enforcementMode) + `
bruteforce_logs = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_BRUTEFORCE_LOGS", "auto")) + `
bruteforce_threshold = ` + threshold + `
bruteforce_window_seconds = ` + window + `
modsec_logs = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_MODSEC_LOGS", "")) + `
`, nil
}

func (m *Migrator) generateIntegrations(oldConfig map[string]string) (string, error) {
	haEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_HA_ENABLED", false)
	if err != nil {
		return "", err
	}
	haPeerPort, err := legacyPortText(oldConfig, "SYSWARDEN_HA_PEER_PORT", 62026)
	if err != nil {
		return "", err
	}
	siemEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_SIEM_ENABLED", false)
	if err != nil {
		return "", err
	}
	siemPort, err := legacyOptionalPort(oldConfig, "SYSWARDEN_SIEM_PORT", "6514")
	if err != nil {
		return "", err
	}
	abuseEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_ENABLE_ABUSE", false)
	if err != nil {
		return "", err
	}
	webhookEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_ENABLE_WEBHOOK", false)
	if err != nil {
		return "", err
	}
	bunkerWebEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_BUNKERWEB_ENABLED", false)
	if err != nil {
		return "", err
	}
	wazuhEnabled, err := legacyBoolText(oldConfig, "SYSWARDEN_ENABLE_WAZUH", false)
	if err != nil {
		return "", err
	}
	wazuhCommPort, err := legacyOptionalPort(oldConfig, "SYSWARDEN_WAZUH_COMM_PORT", "1514")
	if err != nil {
		return "", err
	}
	wazuhEnrollPort, err := legacyOptionalPort(oldConfig, "SYSWARDEN_WAZUH_ENROLL_PORT", "1515")
	if err != nil {
		return "", err
	}

	peerIPsStr := legacySliceText(legacyValue(oldConfig, "SYSWARDEN_HA_PEER_IP", ""))

	return `# [40] INTEGRATIONS & NOTIFICATIONS
# Priority: 40

[integrations.ha]
enabled = ` + haEnabled + `
# IPs and CIDRs require quotes: ["10.0.0.1", "10.20.30.0/29"]
# Exact IPs are outbound sync destinations; CIDRs authorize inbound peers only.
peer_ips = [` + peerIPsStr + `]
peer_port = ` + haPeerPort + `

# HA Shared Secret Token for API Authentication (Required when enabled; must be identical on all nodes)
# Generate a secure token using: openssl rand -hex 32
token = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_HA_TOKEN", "")) + `

[integrations.siem]
enabled = ` + siemEnabled + `
ip = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_SIEM_IP", "")) + `
port = ` + quoteTOML(siemPort) + `
protocol = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_SIEM_PROTO", "tls")) + `
tls_ca = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_SIEM_TLS_CA", "/etc/ssl/certs/ca-certificates.crt")) + `

[integrations.abuseipdb]
enabled = ` + abuseEnabled + `
api_key = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_ABUSE_API_KEY", "")) + `

[integrations.webhooks]
enabled = ` + webhookEnabled + `
discord_url = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_WEBHOOK_URL_DISCORD", "")) + `
teams_url = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_WEBHOOK_URL_TEAMS", "")) + `
slack_url = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_WEBHOOK_URL_SLACK", "")) + `

[integrations.bunkerweb]
# Enables the enriched BunkerWeb TTL and provenance contract over authenticated HA.
enabled = ` + bunkerWebEnabled + `

[integrations.wazuh]
enabled = ` + wazuhEnabled + `
ip = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_WAZUH_IP", "")) + `
name = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_WAZUH_NAME", "")) + `
group = ` + quoteTOML(legacyValue(oldConfig, "SYSWARDEN_WAZUH_GROUP", "default")) + `
comm_port = ` + quoteTOML(wazuhCommPort) + `
enroll_port = ` + quoteTOML(wazuhEnrollPort) + `
`, nil
}

func (m *Migrator) generateUser(oldConfig map[string]string) (string, error) {
	webToken := legacyValue(oldConfig, "SYSWARDEN_WEB_TOKEN", "")
	return `# [99] USER CUSTOM OVERRIDES
# Priority: 99 (highest - overrides all other modules)
# 
# This configuration file (99-user.toml) has absolute priority.
# Any value defined here will override defaults or values defined in other
# modules (00-core.toml to 40-integrations.toml).
# Use this file to customize your SysWarden environment without modifying
# the other files, which might be updated by the application.
#
# NOTE: Everything below is commented out by default. Remove the '#' to activate an override.
# Arrays MUST be formatted with brackets, quotes, and commas. Example: ["value1", "value2"]
# 
# [network.geo]
# blocked_countries = ["ru", "cn"]
#
# [waap]
# bruteforce_threshold = 3

[user]
webtui_password = ` + quoteTOML(webToken) + `
`, nil
}

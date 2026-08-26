package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
)

type ValidationReport struct {
	SchemaVersion  int
	Historical     bool
	UnknownKeys    []string
	DeprecatedKeys []string
}

var deprecatedModularKeys = map[string]string{ // #nosec G101 -- keys name retired credential settings but contain no credential values
	"integrations.saas.enabled": "network.saas.allow_monitors",
	"user.webtui_password":      "removed Web-TUI credential",
}

// ValidateModularConfig validates descriptor-rooted file reads without applying environment overrides, rewriting compatibility state, or changing the process-global configuration.
func ValidateModularConfig(configDir string) (ValidationReport, error) {
	report := ValidationReport{}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return report, fmt.Errorf("open modular config directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := rejectMigrationInProgress(configDir); err != nil {
		return report, err
	}

	v := viper.New()
	v.SetConfigType("toml")
	setDefaults(v, configDir)
	observed := make(map[string]struct{})
	merge := func(relative string, content []byte) error {
		document, err := parseTOMLDocument(content, relative)
		if err != nil {
			return err
		}
		flattenTOMLKeys("", document, observed)
		if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
			return fmt.Errorf("merge %s: %w", relative, err)
		}
		return nil
	}

	if _, err := root.Lstat("config.toml"); err == nil {
		content, readErr := readSecureRegularFile(root, "config.toml", filepath.Join(configDir, "config.toml"))
		if readErr != nil {
			return report, readErr
		}
		if err := merge("config.toml", content); err != nil {
			return report, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return report, fmt.Errorf("inspect master config: %w", err)
	}

	modulesDir := filepath.Join(configDir, "modules")
	if info, err := root.Lstat("modules"); err == nil {
		if info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return report, fmt.Errorf("modules path %s is not a real directory", modulesDir)
		}
		modulesRoot, openErr := openConfigDirectory(modulesDir, false, 0)
		if openErr != nil {
			return report, openErr
		}
		defer func() { _ = modulesRoot.Close() }()
		directory, openErr := modulesRoot.Open(".")
		if openErr != nil {
			return report, openErr
		}
		entries, readErr := directory.ReadDir(-1)
		_ = directory.Close()
		if readErr != nil {
			return report, readErr
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".toml" {
				continue
			}
			content, readErr := readSecureRegularFile(modulesRoot, entry.Name(), filepath.Join(modulesDir, entry.Name()))
			if readErr != nil {
				return report, readErr
			}
			if err := merge(filepath.ToSlash(filepath.Join("modules", entry.Name())), content); err != nil {
				return report, err
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return report, fmt.Errorf("inspect modules directory: %w", err)
	}

	known := make(map[string]struct{})
	collectMapstructureKeys(reflect.TypeOf(ModularConfig{}), "", known)
	for key := range observed {
		if replacement, deprecated := deprecatedModularKeys[key]; deprecated {
			report.DeprecatedKeys = append(report.DeprecatedKeys, key+" (use "+replacement+")")
			continue
		}
		if _, ok := known[key]; !ok {
			report.UnknownKeys = append(report.UnknownKeys, key)
		}
	}
	sort.Strings(report.UnknownKeys)
	sort.Strings(report.DeprecatedKeys)

	var candidate ModularConfig
	if err := v.Unmarshal(&candidate); err != nil {
		return report, fmt.Errorf("unmarshal modular configuration: %w", err)
	}
	report.SchemaVersion = candidate.SchemaVersion
	report.Historical = candidate.SchemaVersion == 0
	validationCandidate := candidate
	if historicalDefaultHAState(&validationCandidate) {
		validationCandidate.Integrations.HA.Enabled = false
		validationCandidate.Integrations.BunkerWeb.Enabled = false
	}
	if err := validateConfig(&validationCandidate); err != nil {
		return report, err
	}
	return report, nil
}

// GetValidatedModularValue reads one effective value only after the same typed
// schema and policy validation used by the runtime loader. All files are read
// through descriptor-rooted paths and module precedence is deterministic.
func GetValidatedModularValue(configDir, key string) (string, bool, error) {
	if key == "" || strings.IndexFunc(key, func(character rune) bool {
		return !(character == '.' || character == '-' || character == '_' ||
			character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9')
	}) >= 0 {
		return "", false, fmt.Errorf("invalid configuration key %q", key)
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = root.Close() }()
	if err := rejectMigrationInProgress(configDir); err != nil {
		return "", false, err
	}
	v := viper.New()
	v.SetConfigType("toml")
	v.AutomaticEnv()
	v.SetEnvPrefix("SYSWARDEN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	setDefaults(v, configDir)
	merge := func(relative string, content []byte) error {
		if _, err := parseTOMLDocument(content, relative); err != nil {
			return err
		}
		if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
			return fmt.Errorf("merge %s: %w", relative, err)
		}
		return nil
	}
	if _, err := root.Lstat("config.toml"); err == nil {
		content, readErr := readSecureRegularFile(root, "config.toml", filepath.Join(configDir, "config.toml"))
		if readErr != nil {
			return "", false, readErr
		}
		if err := merge("config.toml", content); err != nil {
			return "", false, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	modulesDir := filepath.Join(configDir, "modules")
	if info, err := root.Lstat("modules"); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", false, fmt.Errorf("modules path %s is not a real directory", modulesDir)
		}
		modulesRoot, openErr := openConfigDirectory(modulesDir, false, 0)
		if openErr != nil {
			return "", false, openErr
		}
		defer func() { _ = modulesRoot.Close() }()
		directory, openErr := modulesRoot.Open(".")
		if openErr != nil {
			return "", false, openErr
		}
		entries, readErr := directory.ReadDir(-1)
		_ = directory.Close()
		if readErr != nil {
			return "", false, readErr
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".toml" {
				continue
			}
			content, readErr := readSecureRegularFile(modulesRoot, entry.Name(), filepath.Join(modulesDir, entry.Name()))
			if readErr != nil {
				return "", false, readErr
			}
			if err := merge(filepath.ToSlash(filepath.Join("modules", entry.Name())), content); err != nil {
				return "", false, err
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	var candidate ModularConfig
	if err := v.Unmarshal(&candidate); err != nil {
		return "", false, fmt.Errorf("unmarshal modular configuration: %w", err)
	}
	if historicalDefaultHAState(&candidate) {
		candidate.Integrations.HA.Enabled = false
		candidate.Integrations.BunkerWeb.Enabled = false
	}
	if err := validateConfig(&candidate); err != nil {
		return "", false, err
	}
	if !v.IsSet(key) {
		return "", false, nil
	}
	value := v.Get(key)
	if text, ok := value.(string); ok {
		return text, true, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false, fmt.Errorf("encode configuration value %q: %w", key, err)
	}
	return string(encoded), true, nil
}

func parseTOMLDocument(content []byte, relative string) (map[string]any, error) {
	var document map[string]any
	if err := toml.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("parse %s as TOML: %w", relative, err)
	}
	if raw, present := document["schema_version"]; present {
		version, ok := raw.(int64)
		if !ok {
			return nil, fmt.Errorf("%s schema_version must be an integer", relative)
		}
		if version < 0 || version > int64(CurrentSchemaVersion) {
			return nil, fmt.Errorf("%s has unsupported schema_version %d", relative, version)
		}
	}
	return document, nil
}

func historicalDefaultHAState(candidate *ModularConfig) bool {
	return candidate != nil && candidate.Integrations.HA.Enabled &&
		candidate.Integrations.HA.Token == "" && len(candidate.Integrations.HA.PeerIPs) == 0 &&
		!candidate.Integrations.BunkerWeb.Enabled
}

func flattenTOMLKeys(prefix string, value map[string]any, keys map[string]struct{}) {
	for name, child := range value {
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		if nested, ok := child.(map[string]any); ok {
			flattenTOMLKeys(key, nested, keys)
			continue
		}
		keys[strings.ToLower(key)] = struct{}{}
	}
}

func collectMapstructureKeys(value reflect.Type, prefix string, keys map[string]struct{}) {
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name := strings.Split(field.Tag.Get("mapstructure"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		fieldType := field.Type
		if fieldType.Kind() == reflect.Struct {
			collectMapstructureKeys(fieldType, key, keys)
			continue
		}
		keys[strings.ToLower(key)] = struct{}{}
	}
}

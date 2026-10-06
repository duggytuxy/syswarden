package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

//go:embed historical_defaults_v4028.json
var historicalDefaultModelsV4028 []byte

// CheckModularRetirementState preserves the recoverable source and destination
// of an interrupted configuration migration before any default is retired.
func CheckModularRetirementState(outputDir string) error {
	return rejectMigrationInProgress(outputDir)
}

// DefaultModularFileModels returns the complete current default templates.
// It does not load operator data, inspect the filesystem or authorize removal
// of a modified or migrated configuration.
func DefaultModularFileModels(outputDir string) (map[string]string, error) {
	m := &Migrator{OutputDir: outputDir}
	data, err := m.freshDefaultConfigData()
	if err != nil {
		return nil, err
	}
	modules, err := m.renderModules(data)
	if err != nil {
		return nil, err
	}
	master, err := m.masterConfigContent(data)
	if err != nil {
		return nil, err
	}
	models := map[string]string{"config.toml": master}
	for _, module := range modules {
		models[filepath.Join("modules", module.name)] = module.content
	}
	return models, nil
}

// DefaultModularFileVariants adds complete, byte-pinned official v4.02.8
// defaults and its already verified backend-compatibility replacement. It
// never treats arbitrary migrated or customized TOML as generated content.
func DefaultModularFileVariants(outputDir string) (map[string][]string, error) {
	current, err := DefaultModularFileModels(outputDir)
	if err != nil {
		return nil, err
	}
	var historical map[string]string
	if err := json.Unmarshal(historicalDefaultModelsV4028, &historical); err != nil || len(historical) != len(current) {
		return nil, fmt.Errorf("historical default template inventory is invalid")
	}
	variants := make(map[string][]string, len(current))
	for path, content := range current {
		old, exists := historical[filepath.ToSlash(path)]
		if !exists || old == "" {
			return nil, fmt.Errorf("historical default template is unavailable")
		}
		old = strings.ReplaceAll(old, "/etc/syswarden/config", outputDir)
		variants[path] = []string{content, old}
	}
	path := filepath.Join("modules", historicalDefaultCoreModuleName)
	if historical[filepath.ToSlash(path)] != historicalDefaultCoreModule {
		return nil, fmt.Errorf("historical core default differs from its pinned compatibility input")
	}
	variants[path] = append(variants[path], historicalDefaultCompatibleCoreModule)
	// Normalize only the immutable historical literal with the same bounded
	// rewrite used by the supported HA compatibility migration.
	integrationPath := filepath.Join("modules", "40-integrations.toml")
	integration, found, enabled, err := rewriteTOMLBoolAssignment([]byte(historical["modules/40-integrations.toml"]), "integrations.ha", "enabled", false)
	if err != nil || !found || !enabled {
		return nil, fmt.Errorf("historical integration default cannot be normalized exactly")
	}
	integration = append(integration, []byte("\n[integrations.bunkerweb]\nenabled = false\n")...)
	variants[integrationPath] = append(variants[integrationPath], string(integration))
	return variants, nil
}

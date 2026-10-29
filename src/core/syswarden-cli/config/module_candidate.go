package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"syswarden-cli/pkg/sshselection"

	"github.com/spf13/viper"
)

type tomlEditTarget struct {
	relative string
	name     string
	master   bool
}

func ordinaryTOMLTarget(relative string) (tomlEditTarget, error) {
	switch relative {
	case "config.toml":
		return tomlEditTarget{relative: relative, name: relative, master: true}, nil
	case "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml", "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml":
		return tomlEditTarget{relative: relative, name: filepath.Base(relative)}, nil
	default:
		return tomlEditTarget{}, errors.New("configuration target is not an ordinary editable TOML file; dedicated SSH policy requires its protected workflow")
	}
}

func userTOMLTarget() tomlEditTarget {
	return tomlEditTarget{relative: "modules/" + userModuleName, name: userModuleName}
}
func (target tomlEditTarget) directory(root string) string {
	if target.master {
		return root
	}
	return filepath.Join(root, "modules")
}
func (snapshot *mergedConfigSnapshot) identity(target tomlEditTarget) *secureFileIdentity {
	if target.master {
		return snapshot.master
	}
	if target.name == userModuleName {
		return snapshot.user
	}
	return snapshot.modules[target.name]
}

// Validate against actual captured files, replacing exactly one candidate in
// memory at its original lexical position. Missing files never count as an
// already complete fresh installation merely because an edit proposes them.
func validateModuleCandidate(configDir string, target tomlEditTarget, content []byte, expected *secureFileIdentity) (*mergedConfigSnapshot, error) {
	return validateModuleCandidateWithIntent(configDir, target, content, expected, nil)
}

func validateModuleCandidateWithIntent(configDir string, target tomlEditTarget, content []byte, expected, intent *secureFileIdentity) (*mergedConfigSnapshot, error) {
	if err := sshselection.RejectEnvironment(); err != nil {
		return nil, err
	}
	if err := rejectOperatorPolicyEnvironment(); err != nil {
		return nil, err
	}
	snapshot, previous, err := captureModuleInputs(configDir, target, intent)
	if err != nil {
		return nil, err
	}
	if !sameUserModuleIdentity(snapshot.identity(target), expected) {
		return nil, errors.New("edited configuration changed before merged validation")
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	modules, err := openConfigDirectory(filepath.Join(configDir, "modules"), false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = modules.Close() }()
	v := viper.New()
	v.SetConfigType("toml")
	setDefaults(v, configDir)
	observed := make(map[string]struct{})
	var inventory unconfiguredProfileInventory
	merge := func(relative string, raw []byte, present bool) error {
		document, err := parseTOMLDocument(raw, relative)
		if err != nil {
			return err
		}
		if present {
			inventory.record(relative, document)
		} else {
			inventory.recordProfile(relative, document)
		}
		flattenTOMLKeys("", document, observed)
		if relative == target.relative {
			if err := rejectNewRetiredUnspecifiedWhitelistEntriesAt(relative, previous, document); err != nil {
				return err
			}
		}
		if err := v.MergeConfig(bytes.NewReader(raw)); err != nil {
			return fmt.Errorf("merge %s: %w", relative, err)
		}
		return nil
	}
	if snapshot.master != nil || target.master {
		raw := content
		if !target.master {
			var identity *secureFileIdentity
			raw, identity, err = readEditFileIdentity(root, "config.toml", filepath.Join(configDir, "config.toml"))
			if err != nil {
				return nil, err
			}
			if !sameUserModuleIdentity(snapshot.master, identity) {
				return nil, errors.New("master configuration changed during merged validation")
			}
		}
		if err := merge("config.toml", raw, snapshot.master != nil); err != nil {
			return nil, err
		}
	}
	names := append([]string(nil), snapshot.moduleNames...)
	if !target.master && expected == nil {
		names = append(names, target.name)
		sort.Strings(names)
	}
	for _, name := range names {
		relative := "modules/" + name
		selected := relative == target.relative
		identity := snapshot.modules[name]
		if name == userModuleName {
			identity = snapshot.user
		}
		raw := content
		if !selected {
			var actual *secureFileIdentity
			raw, actual, err = readEditFileIdentity(modules, name, filepath.Join(configDir, "modules", name))
			if err != nil {
				return nil, err
			}
			if !sameUserModuleIdentity(identity, actual) {
				return nil, fmt.Errorf("configuration module %s changed during merged validation", name)
			}
		}
		if err := merge(relative, raw, identity != nil); err != nil {
			return nil, err
		}
	}
	if err := inventory.validate(); err != nil {
		return nil, err
	}
	resolveModularSaaSAliasFromTOML(v, observed)
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
	snapshot.effects = configurationEffects(&candidate)
	return snapshot, nil
}

// An interactive proposal has bounded per-file reads, even when a file grows
// between capture and validation. The normal runtime loader is unchanged.
func readEditFileIdentity(root *os.Root, name, display string) ([]byte, *secureFileIdentity, error) {
	content, info, err := readSecureRegularFileSnapshotBounded(root, name, display, maximumUserModuleSize)
	if err != nil {
		return nil, nil, err
	}
	return content, newSecureFileIdentity(content, info), nil
}

// Bound directory inventory independently of individual TOML sizes. Readers of
// runtime configuration retain their existing limits; this applies to editing,
// recovery review and preview snapshots only.
func readBoundedEditEntries(directory *os.File) ([]os.DirEntry, error) {
	entries, err := directory.ReadDir(maximumModuleEditInputs + 16)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) == maximumModuleEditInputs+16 {
		return nil, errors.New("configuration directory exceeds the edit/preview inventory limit")
	}
	return entries, nil
}

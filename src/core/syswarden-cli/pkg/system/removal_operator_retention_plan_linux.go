//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syswarden-cli/config"

	"github.com/pelletier/go-toml/v2"
)

const operatorRetentionSchema = "SYSWARDEN_OPERATOR_CONFIGURATION_RETENTION_V1"

// This decision grants retention at the original paths, never deletion or
// product ownership. Content fingerprints bind the initial review; subsequent
// administrator edits do not revoke the decision to preserve these paths.
type OperatorConfigurationRetentionPlan struct {
	Schema    string                   `json:"schema"`
	Authority string                   `json:"authority"`
	Files     []LegacyLogRetentionFile `json:"files"`
}

func operatorRetentionPath(path string) bool {
	if path == "/etc/syswarden/config/config.toml" {
		return true
	}
	const prefix = "/etc/syswarden/config/modules/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	name := strings.TrimPrefix(path, prefix)
	if len(name) < 6 || len(name) > 128 || !strings.HasSuffix(name, ".toml") || name[0] == '.' || name[0] == '-' {
		return false
	}
	for _, char := range name {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func inspectOperatorConfigurationRetention(directory string) (OperatorConfigurationRetentionPlan, error) {
	plan := OperatorConfigurationRetentionPlan{Schema: operatorRetentionSchema, Authority: operatorRetentionAuthority}
	if err := config.CheckModularRetirementState(directory); err != nil {
		return plan, err
	}
	models, err := config.DefaultModularFileVariants(directory)
	if err != nil {
		return plan, err
	}
	root, err := openExistingPinnedServiceDirectory(directory)
	if err != nil {
		return plan, err
	}
	defer root.close()
	before, err := root.root.Stat(".")
	if err != nil {
		return plan, err
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil {
		return plan, err
	}
	entries, err := readBoundedSharedRemovalEntries(root.root)
	if err != nil || len(entries) > 2 {
		return plan, fmt.Errorf("configuration retention requires the bounded master and module inventory")
	}
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		switch name {
		case "config.toml":
			if err := appendOperatorRetentionFile(&plan, root, name, name, models, &total); err != nil {
				return plan, err
			}
		case "modules":
			if err := appendOperatorRetentionModules(&plan, root, directory, models, &total); err != nil {
				return plan, err
			}
		default:
			return plan, fmt.Errorf("unrecognized configuration entry requires separate review: %q", name)
		}
	}
	slices.SortFunc(plan.Files, func(a, b LegacyLogRetentionFile) int { return strings.Compare(a.Path, b.Path) })
	if len(plan.Files) == 0 || len(plan.Files) > 128 {
		return plan, fmt.Errorf("no customized configuration requires explicit retention")
	}
	after, err := root.root.Stat(".")
	actual, identityErr := exactRemovalArtifactIdentity(after)
	named, namedErr := os.Lstat(directory)
	if err != nil || identityErr != nil || namedErr != nil || actual != identity || !os.SameFile(before, named) {
		return plan, fmt.Errorf("configuration inventory changed during inspection")
	}
	return plan, nil
}

func appendOperatorRetentionModules(plan *OperatorConfigurationRetentionPlan, parent *pinnedServiceDirectory, directory string, models map[string][]string, total *int64) error {
	before, err := parent.root.Lstat("modules")
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("configuration modules must be a real directory")
	}
	modules, err := openExistingPinnedServiceDirectory(filepath.Join(directory, "modules"))
	if err != nil {
		return err
	}
	defer modules.close()
	opened, err := modules.root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return fmt.Errorf("configuration module directory changed while opening")
	}
	entries, err := readBoundedSharedRemovalEntries(modules.root)
	if err != nil || len(entries) > 128 {
		return fmt.Errorf("configuration module inventory exceeds its bound")
	}
	for _, entry := range entries {
		name := entry.Name()
		if err := appendOperatorRetentionFile(plan, modules, name, "modules/"+name, models, total); err != nil {
			return err
		}
	}
	after, err := parent.root.Lstat("modules")
	if err != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		return fmt.Errorf("configuration module inventory changed during inspection")
	}
	return nil
}

func appendOperatorRetentionFile(plan *OperatorConfigurationRetentionPlan, directory *pinnedServiceDirectory, name, relative string, models map[string][]string, total *int64) error {
	path := "/etc/syswarden/config/" + relative
	if !operatorRetentionPath(path) {
		return fmt.Errorf("unsupported configuration retention path: %q", path)
	}
	before, err := directory.root.Lstat(name)
	if err != nil {
		return err
	}
	content, err := readRetirementCandidateBounded(directory, name, before, 256<<10)
	if err != nil || before.Mode().Perm() != 0600 && before.Mode().Perm() != 0640 {
		return fmt.Errorf("configuration retention requires a private exclusive regular file: %q", path)
	}
	*total += int64(len(content))
	if *total > 8<<20 {
		return fmt.Errorf("configuration retention exceeds its total byte bound")
	}
	var document map[string]any
	if !bytes.Equal(bytes.ToValidUTF8(content, nil), content) || bytes.IndexByte(content, 0) >= 0 || toml.Unmarshal(content, &document) != nil {
		return fmt.Errorf("configuration retention requires a valid bounded TOML document: %q", path)
	}
	if slices.Contains(models[filepath.FromSlash(relative)], string(content)) {
		return nil
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil {
		return err
	}
	plan.Files = append(plan.Files, LegacyLogRetentionFile{Path: path, Identity: legacyLogPlanIdentity(identity), Size: identity.size, Modified: identity.mtime, Changed: identity.ctime, SHA256: fmt.Sprintf("%x", sha256.Sum256(content))})
	return nil
}

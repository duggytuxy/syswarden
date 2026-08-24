package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/viper"
)

const (
	historicalDefaultCoreModuleName = "00-core.toml"

	historicalDefaultCoreModule = `# [00] CORE SYSTEM CONFIGURATION
# Priority: 00 (loaded first, lowest precedence)

[core]
# Supported backends (RHEL/Alma/Fedora ONLY): "nftables", "iptables", "keep"
firewall_backend = "nftables"

# Boolean values: true or false (no quotes)
hardening_enabled = true
cis_l2_hardening = false
secure_wipe_conf = false

# SSH Port string (e.g. "2222")
ssh_port = ""
`

	historicalDefaultCompatibleCoreModule = `# [00] CORE SYSTEM CONFIGURATION
# Priority: 00 (loaded first, lowest precedence)

[core]
# Supported backends (RHEL/Alma/Fedora ONLY): "nftables", "iptables", "keep"
firewall_backend = "keep"

# Boolean values: true or false (no quotes)
hardening_enabled = true
cis_l2_hardening = false
secure_wipe_conf = false

# SSH Port string (e.g. "2222")
ssh_port = ""
`

	historicalDefaultCoreModuleSHA256           = "a722075360f380f84558d0cddcc558de917a899900fef1845fbc5ef3cf93a70a"
	historicalDefaultCompatibleCoreModuleSHA256 = "c3f37d2d67d581fd50417ee5b1b5b337ae234bc4126d5a26d48b7dcf4ee8a145"
)

var (
	historicalDefaultFirewallCompatibilityOwner                                = func() (uint32, uint32) { return 0, 0 }
	publishHistoricalDefaultFirewallCompatibility validatedUserModulePublisher = replaceSecureFileAtomicallyIfUnchangedValidated
)

// HistoricalDefaultFirewallCompatibilityPlan is an opaque, identity-bound plan
// for the historical default firewall byte family anchored to v4.02.8 that
// cannot satisfy the current nftables preflight on a dormant nftables.service
// host.
// Callers may only apply a plan returned by InspectHistoricalDefaultFirewallCompatibility.
type HistoricalDefaultFirewallCompatibilityPlan struct {
	configDir   string
	snapshot    *historicalDefaultFirewallSnapshot
	target      *secureFileIdentity
	replacement []byte
}

type historicalDefaultFirewallSnapshot struct {
	configRootInfo  os.FileInfo
	modulesRootInfo os.FileInfo
	marker          *secureFileIdentity
	master          *secureFileIdentity
	moduleNames     []string
	modules         map[string]*secureFileIdentity
}

type historicalDefaultFirewallModule struct {
	name     string
	content  []byte
	identity *secureFileIdentity
}

type historicalDefaultSnapshotState int

const (
	historicalDefaultSnapshotBefore historicalDefaultSnapshotState = iota
	historicalDefaultSnapshotTargetQuarantined
	historicalDefaultSnapshotAfter
)

// InspectHistoricalDefaultFirewallCompatibility returns a plan only for the
// historical default firewall byte family anchored to v4.02.8. It does not
// claim which historical version produced the bytes. Arbitrary, modified, and
// current fresh nftables configurations are deliberately non-applicable and
// continue through the normal strict nftables.service preflight.
func InspectHistoricalDefaultFirewallCompatibility(configDir string) (*HistoricalDefaultFirewallCompatibilityPlan, error) {
	if !filepath.IsAbs(configDir) || filepath.Clean(configDir) != configDir {
		return nil, fmt.Errorf("historical default firewall compatibility configuration root is not clean and absolute")
	}
	info, err := os.Lstat(configDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect historical default firewall compatibility configuration root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("historical default firewall compatibility configuration root is not a real directory")
	}

	modulesDir := filepath.Join(configDir, "modules")
	modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open historical default firewall compatibility modules: %w", err)
	}
	coreContent, coreIdentity, err := readSecureRegularFileIdentity(
		modulesRoot,
		historicalDefaultCoreModuleName,
		filepath.Join(modulesDir, historicalDefaultCoreModuleName),
	)
	_ = modulesRoot.Close()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read historical default firewall compatibility core module: %w", err)
	}
	if bytes.Equal(coreContent, []byte(historicalDefaultCompatibleCoreModule)) {
		return nil, nil
	}
	if !bytes.Equal(coreContent, []byte(historicalDefaultCoreModule)) {
		return nil, nil
	}
	if fmt.Sprintf("%x", sha256.Sum256(coreContent)) != historicalDefaultCoreModuleSHA256 {
		return nil, fmt.Errorf("historical default firewall compatibility core module digest is not exact")
	}
	if coreIdentity.info.Mode().Perm() != 0640 {
		return nil, fmt.Errorf("historical default firewall compatibility core module mode is %#o, want 0640", coreIdentity.info.Mode().Perm())
	}
	if err := attestHistoricalDefaultOwnedSingleLink(coreIdentity.info, "historical default firewall compatibility core module"); err != nil {
		return nil, err
	}

	for _, key := range []string{
		"SYSWARDEN_CORE_FIREWALL_BACKEND",
		"SYSWARDEN_NETWORK_WIREGUARD_ENABLED",
	} {
		if _, present := os.LookupEnv(key); present {
			return nil, fmt.Errorf("historical default firewall compatibility refuses environment override %s", key)
		}
	}

	snapshot, masterContent, modules, err := captureHistoricalDefaultFirewallSnapshot(configDir)
	if err != nil {
		return nil, err
	}
	if snapshot.modules[historicalDefaultCoreModuleName] == nil ||
		!snapshot.modules[historicalDefaultCoreModuleName].matches(coreContent, coreIdentity.info) {
		return nil, fmt.Errorf("historical default firewall compatibility core module changed during inspection")
	}
	for _, required := range []string{
		"00-core.toml",
		"10-network.toml",
		"20-security.toml",
		"30-waap.toml",
		"40-integrations.toml",
		"99-user.toml",
	} {
		if snapshot.modules[required] == nil {
			return nil, fmt.Errorf("historical default firewall compatibility configuration is incomplete: missing modules/%s", required)
		}
	}

	backendAssignments := 0
	if document, parseErr := parseTOMLDocument(masterContent, "config.toml"); parseErr != nil {
		return nil, parseErr
	} else if tomlDocumentHasPath(document, "core", "firewall_backend") {
		return nil, fmt.Errorf("historical default firewall compatibility refuses a master firewall backend override")
	}
	for _, module := range modules {
		document, parseErr := parseTOMLDocument(
			module.content,
			filepath.ToSlash(filepath.Join("modules", module.name)),
		)
		if parseErr != nil {
			return nil, parseErr
		}
		if !tomlDocumentHasPath(document, "core", "firewall_backend") {
			continue
		}
		backendAssignments++
		if module.name != historicalDefaultCoreModuleName {
			return nil, fmt.Errorf("historical default firewall compatibility refuses firewall backend override in modules/%s", module.name)
		}
	}
	if backendAssignments != 1 {
		return nil, fmt.Errorf("historical default firewall compatibility requires one exact persistent firewall backend assignment")
	}

	before, err := mergeHistoricalDefaultFirewallCandidate(configDir, masterContent, modules, nil)
	if err != nil {
		return nil, fmt.Errorf("validate historical default firewall compatibility input: %w", err)
	}
	if before.Core.FirewallBackend != "nftables" {
		return nil, fmt.Errorf("historical default firewall compatibility input backend is %q, want nftables", before.Core.FirewallBackend)
	}
	if before.Network.Wireguard.Enabled {
		return nil, fmt.Errorf("historical default firewall compatibility refuses enabled WireGuard")
	}

	replacement := []byte(historicalDefaultCompatibleCoreModule)
	if fmt.Sprintf("%x", sha256.Sum256(replacement)) != historicalDefaultCompatibleCoreModuleSHA256 {
		return nil, fmt.Errorf("historical default firewall compatibility replacement digest is not exact")
	}
	after, err := mergeHistoricalDefaultFirewallCandidate(configDir, masterContent, modules, replacement)
	if err != nil {
		return nil, fmt.Errorf("validate historical default firewall compatibility output: %w", err)
	}
	wantAfter := before
	wantAfter.Core.FirewallBackend = "keep"
	if !reflect.DeepEqual(after, wantAfter) {
		return nil, fmt.Errorf("historical default firewall compatibility changes configuration beyond the firewall backend")
	}
	if err := snapshot.revalidate(configDir, historicalDefaultSnapshotBefore, nil); err != nil {
		return nil, fmt.Errorf("historical default firewall compatibility configuration changed during inspection: %w", err)
	}

	return &HistoricalDefaultFirewallCompatibilityPlan{
		configDir:   configDir,
		snapshot:    snapshot,
		target:      snapshot.modules[historicalDefaultCoreModuleName],
		replacement: replacement,
	}, nil
}

// ApplyHistoricalDefaultFirewallCompatibility atomically publishes a previously
// inspected plan. The caller-supplied host revalidation must prove the typed
// dormant nftables state without mutation at every transaction barrier. The
// target module is rolled back if either bound configuration or host state
// changes before, during, or immediately after publication.
func ApplyHistoricalDefaultFirewallCompatibility(
	plan *HistoricalDefaultFirewallCompatibilityPlan,
	revalidateHost func() error,
) error {
	if plan == nil || plan.snapshot == nil || plan.target == nil || plan.configDir == "" {
		return fmt.Errorf("historical default firewall compatibility plan is invalid")
	}
	if revalidateHost == nil {
		return fmt.Errorf("historical default firewall compatibility host revalidation is unavailable")
	}
	if !bytes.Equal(plan.replacement, []byte(historicalDefaultCompatibleCoreModule)) {
		return fmt.Errorf("historical default firewall compatibility replacement is invalid")
	}
	preCommit := func() error {
		if err := plan.snapshot.revalidate(plan.configDir, historicalDefaultSnapshotBefore, nil); err != nil {
			return err
		}
		return revalidateHost()
	}
	prePublish := func() error {
		if err := plan.snapshot.revalidate(plan.configDir, historicalDefaultSnapshotTargetQuarantined, nil); err != nil {
			return err
		}
		return revalidateHost()
	}
	postCommit := func() error {
		if err := plan.snapshot.revalidate(plan.configDir, historicalDefaultSnapshotAfter, plan.replacement); err != nil {
			return err
		}
		return revalidateHost()
	}
	if err := publishHistoricalDefaultFirewallCompatibility(
		filepath.Join(plan.configDir, "modules"),
		historicalDefaultCoreModuleName,
		plan.replacement,
		plan.target,
		preCommit,
		prePublish,
		postCommit,
	); err != nil {
		return fmt.Errorf("publish historical default firewall compatibility: %w", err)
	}
	return nil
}

func captureHistoricalDefaultFirewallSnapshot(configDir string) (*historicalDefaultFirewallSnapshot, []byte, []historicalDefaultFirewallModule, error) {
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = root.Close() }()
	configRootInfo, err := rootDirectoryInfo(root)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := attestHistoricalDefaultOwner(configRootInfo, "historical default firewall compatibility configuration root"); err != nil {
		return nil, nil, nil, err
	}
	marker, err := readOptionalSecureFileIdentity(root, migrationMarkerName, filepath.Join(configDir, migrationMarkerName))
	if err != nil {
		return nil, nil, nil, err
	}
	if marker != nil {
		return nil, nil, nil, fmt.Errorf("historical default firewall compatibility refuses an incomplete configuration migration")
	}
	masterContent, master, err := readSecureRegularFileIdentity(root, "config.toml", filepath.Join(configDir, "config.toml"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read historical default firewall compatibility master config: %w", err)
	}

	modulesDir := filepath.Join(configDir, "modules")
	modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = modulesRoot.Close() }()
	modulesRootInfo, err := rootDirectoryInfo(modulesRoot)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := attestHistoricalDefaultOwner(modulesRootInfo, "historical default firewall compatibility modules root"); err != nil {
		return nil, nil, nil, err
	}
	directory, err := modulesRoot.Open(".")
	if err != nil {
		return nil, nil, nil, err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	snapshot := &historicalDefaultFirewallSnapshot{
		configRootInfo:  configRootInfo,
		modulesRootInfo: modulesRootInfo,
		marker:          marker,
		master:          master,
		modules:         make(map[string]*secureFileIdentity),
	}
	var modules []historicalDefaultFirewallModule
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".toml" {
			continue
		}
		content, identity, readErr := readSecureRegularFileIdentity(
			modulesRoot,
			entry.Name(),
			filepath.Join(modulesDir, entry.Name()),
		)
		if readErr != nil {
			return nil, nil, nil, readErr
		}
		snapshot.moduleNames = append(snapshot.moduleNames, entry.Name())
		snapshot.modules[entry.Name()] = identity
		modules = append(modules, historicalDefaultFirewallModule{name: entry.Name(), content: content, identity: identity})
	}
	return snapshot, masterContent, modules, nil
}

func mergeHistoricalDefaultFirewallCandidate(
	configDir string,
	master []byte,
	modules []historicalDefaultFirewallModule,
	replacement []byte,
) (ModularConfig, error) {
	v := viper.New()
	v.SetConfigType("toml")
	v.AutomaticEnv()
	v.SetEnvPrefix("SYSWARDEN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	_ = v.BindEnv("network.saas.allow_monitors")
	_ = v.BindEnv("integrations.saas.enabled")
	setDefaults(v, configDir)
	observed := make(map[string]struct{})
	masterDocument, err := parseTOMLDocument(master, "config.toml")
	if err != nil {
		return ModularConfig{}, err
	}
	flattenTOMLKeys("", masterDocument, observed)
	if err := v.MergeConfig(bytes.NewReader(master)); err != nil {
		return ModularConfig{}, err
	}
	for _, module := range modules {
		content := module.content
		if module.name == historicalDefaultCoreModuleName && replacement != nil {
			content = replacement
		}
		document, err := parseTOMLDocument(content, filepath.ToSlash(filepath.Join("modules", module.name)))
		if err != nil {
			return ModularConfig{}, err
		}
		flattenTOMLKeys("", document, observed)
		if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
			return ModularConfig{}, err
		}
	}
	resolveModularSaaSAlias(v, observed)
	var candidate ModularConfig
	if err := v.Unmarshal(&candidate); err != nil {
		return ModularConfig{}, err
	}
	if err := validateConfig(&candidate); err != nil {
		return ModularConfig{}, err
	}
	return candidate, nil
}

func (snapshot *historicalDefaultFirewallSnapshot) revalidate(
	configDir string,
	state historicalDefaultSnapshotState,
	replacement []byte,
) error {
	if snapshot == nil {
		return fmt.Errorf("historical default firewall compatibility snapshot is missing")
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := rootDirectoryInfo(root)
	if err != nil || !sameFileAndMode(snapshot.configRootInfo, rootInfo) {
		return fmt.Errorf("historical default firewall compatibility configuration root changed")
	}
	if err := attestHistoricalDefaultOwner(rootInfo, "historical default firewall compatibility configuration root"); err != nil {
		return err
	}
	if err := revalidateOptionalSecureFile(root, migrationMarkerName, filepath.Join(configDir, migrationMarkerName), snapshot.marker); err != nil {
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
		return fmt.Errorf("historical default firewall compatibility modules root changed")
	}
	if err := attestHistoricalDefaultOwner(modulesInfo, "historical default firewall compatibility modules root"); err != nil {
		return err
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
	wantNames := append([]string(nil), snapshot.moduleNames...)
	if state == historicalDefaultSnapshotTargetQuarantined {
		wantNames = removeHistoricalDefaultModuleName(wantNames, historicalDefaultCoreModuleName)
	}
	if !reflect.DeepEqual(names, wantNames) {
		return fmt.Errorf("historical default firewall compatibility TOML module inventory changed")
	}
	for name, identity := range snapshot.modules {
		if name != historicalDefaultCoreModuleName {
			if err := revalidateOptionalSecureFile(modulesRoot, name, filepath.Join(modulesDir, name), identity); err != nil {
				return err
			}
			continue
		}
		switch state {
		case historicalDefaultSnapshotBefore:
			if err := revalidateOptionalSecureFile(modulesRoot, name, filepath.Join(modulesDir, name), identity); err != nil {
				return err
			}
			info, err := modulesRoot.Lstat(name)
			if err != nil {
				return err
			}
			if err := attestHistoricalDefaultOwnedSingleLink(info, "historical default firewall compatibility core module"); err != nil {
				return err
			}
		case historicalDefaultSnapshotTargetQuarantined:
			if _, err := modulesRoot.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("historical default firewall compatibility core module was not quarantined exactly")
			}
		case historicalDefaultSnapshotAfter:
			content, info, err := readSecureRegularFileSnapshot(modulesRoot, name, filepath.Join(modulesDir, name))
			if err != nil {
				return err
			}
			if !bytes.Equal(content, replacement) || info.Mode().Perm() != 0640 {
				return fmt.Errorf("historical default firewall compatibility core module publication is not exact")
			}
			if err := attestHistoricalDefaultOwnedSingleLink(info, "historical default firewall compatibility core module"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("historical default firewall compatibility snapshot state is invalid")
		}
	}
	return nil
}

func removeHistoricalDefaultModuleName(names []string, target string) []string {
	result := make([]string, 0, len(names))
	for _, name := range names {
		if name != target {
			result = append(result, name)
		}
	}
	return result
}

func tomlDocumentHasPath(document map[string]any, path ...string) bool {
	var current any = document
	for _, name := range path {
		mapping, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = mapping[name]
		if !ok {
			return false
		}
	}
	return true
}

func attestHistoricalDefaultOwner(info os.FileInfo, description string) error {
	uid, gid, ok := fileOwnerUIDGID(info)
	wantUID, wantGID := historicalDefaultFirewallCompatibilityOwner()
	if !ok || uid != wantUID || gid != wantGID {
		return fmt.Errorf("%s owner is not %d:%d", description, wantUID, wantGID)
	}
	return nil
}

func attestHistoricalDefaultOwnedSingleLink(info os.FileInfo, description string) error {
	if err := attestHistoricalDefaultOwner(info, description); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("%s link count is not one", description)
	}
	return nil
}

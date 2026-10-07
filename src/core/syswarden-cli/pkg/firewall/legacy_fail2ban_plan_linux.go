//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
)

// Both views come from successful read-only evaluation by the installed,
// trusted Fail2ban parser. allJails forces option resolution for disabled
// jails without starting them. Neither stream may be sent to a running server.
type legacyFail2banConfigurationView struct {
	enabled        []byte
	allJails       []byte
	parserSHA256   [sha256.Size]byte
	socket         string
	pidfile        string
	actionsEnabled []byte
	actionsAll     []byte
}

// The probe must evaluate immutable copies of the inspected inventory, with
// only the supplied files omitted. It must validate enabled configurations,
// reject unresolved includes or parser errors, and never edit the live tree.
// Service entry points, external dependencies and parser identity must be
// attested by the production adapter. A successful file plan is not permission
// to stop a live jail or delete any runtime rule.
type legacyFail2banConfigurationProbe func(legacyFail2banInventory, []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error)

type legacyFail2banRetirementPlan struct {
	sha256   string
	binding  legacyFail2banPlanRecord
	baseline legacyFail2banInventory
	retiring []nftPersistenceRetiredSource
	records  []legacyRetirementFileRecord
}

type legacyFail2banPlanDirectory struct {
	Path           string `json:"path"`
	Device         uint64 `json:"device"`
	Inode          uint64 `json:"inode"`
	Mode           uint32 `json:"mode"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	NLink          uint64 `json:"nlink"`
	FilesystemUUID string `json:"filesystem_uuid,omitempty"`
}

const legacyFail2banPlanSchema = "syswarden-legacy-fail2ban-file-plan-v2"

type legacyFail2banPlanRecord struct {
	Schema       string                        `json:"schema"`
	Sources      []legacyRetirementFileRecord  `json:"sources"`
	Directories  []legacyFail2banPlanDirectory `json:"directories"`
	Targets      []string                      `json:"targets"`
	Views        [4][sha256.Size]byte          `json:"views_sha256"`
	ParserSHA256 [sha256.Size]byte             `json:"parser_sha256"`
}

func bindLegacyFail2banPlanDirectory(host nftPersistenceFilesystem, path string, info os.FileInfo) (legacyFail2banPlanDirectory, error) {
	if info == nil || !info.IsDir() {
		return legacyFail2banPlanDirectory{}, fmt.Errorf("Fail2ban plan directory has no inspected identity")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return legacyFail2banPlanDirectory{}, fmt.Errorf("Fail2ban plan directory has an unsupported identity")
	}
	directory, err := host.openDirectory(path)
	if err != nil {
		return legacyFail2banPlanDirectory{}, err
	}
	defer func() { _ = directory.Close() }()
	file, err := directory.Open(".")
	if err != nil {
		return legacyFail2banPlanDirectory{}, err
	}
	defer func() { _ = file.Close() }()
	actual, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(info, actual) {
		return legacyFail2banPlanDirectory{}, fmt.Errorf("Fail2ban plan directory changed while binding its filesystem")
	}
	uuid, err := wireguardstate.CaptureFilesystemUUID(file)
	if err != nil {
		return legacyFail2banPlanDirectory{}, err
	}
	return legacyFail2banPlanDirectory{path, uint64(stat.Dev), stat.Ino, stat.Mode, stat.Uid, stat.Gid, uint64(stat.Nlink), uuid}, nil
}

// prepareLegacyFail2banRetirement joins file ownership, complete inventory,
// include safety and both effective views before producing file intents. It
// is read-only and returns no partially approved plan on failure. Durable
// multi-file recovery and live protection remain separate mandatory phases.
func prepareLegacyFail2banRetirement(host nftPersistenceFilesystem, paths []string, probe legacyFail2banConfigurationProbe) (legacyFail2banRetirementPlan, error) {
	var empty legacyFail2banRetirementPlan
	if len(paths) == 0 || len(paths) > 256 || probe == nil {
		return empty, fmt.Errorf("historical Fail2ban retirement requires bounded targets and a trusted configuration probe")
	}
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		return empty, err
	}
	sources := make(map[string]legacyFail2banSource, len(inventory.sources))
	for _, source := range inventory.sources {
		sources[source.path] = source
	}
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)
	retiring := make([]nftPersistenceRetiredSource, 0, len(paths))
	jails := make(map[string]bool)
	for index, path := range ordered {
		if index > 0 && ordered[index-1] == path {
			return empty, fmt.Errorf("historical Fail2ban retirement has a duplicate target")
		}
		source, found := sources[path]
		if !found {
			return empty, fmt.Errorf("historical Fail2ban retirement target is absent from the inspected inventory: %q", path)
		}
		match, exact := matchLegacyFail2banTemplate(path, source.snapshot.content)
		if !exact || match.sha256 != source.sha256 {
			return empty, fmt.Errorf("historical Fail2ban file does not match a complete official template: %q", path)
		}
		if match.kind == "jail" {
			if !validLegacyFail2banJailName(match.jail) || jails[match.jail] {
				return empty, fmt.Errorf("historical Fail2ban retirement has an ambiguous jail identity")
			}
			jails[match.jail] = true
		}
		retiring = append(retiring, nftPersistenceRetiredSource{path, source.sha256})
	}
	if err := verifyLegacyFail2banIncludeRetirement(inventory, retiring); err != nil {
		return empty, err
	}
	before, err := probe(cloneLegacyFail2banInventory(inventory), nil)
	if err != nil {
		return empty, fmt.Errorf("validate original Fail2ban configuration before retirement: %w", err)
	}
	before = cloneLegacyFail2banView(before)
	if err := reattestLegacyFail2banPlanInventory(host, inventory); err != nil {
		return empty, err
	}
	after, err := probe(cloneLegacyFail2banInventory(inventory), append([]nftPersistenceRetiredSource(nil), retiring...))
	if err != nil {
		return empty, fmt.Errorf("validate staged Fail2ban configuration before retirement: %w", err)
	}
	after = cloneLegacyFail2banView(after)
	if err := reattestLegacyFail2banPlanInventory(host, inventory); err != nil {
		return empty, err
	}
	if err := verifyLegacyFail2banConfigurationViews(before, after, jails); err != nil {
		return empty, err
	}
	// Logical action/filter readers are evaluated by Fail2ban itself above.
	// Also preserve a target referenced directly in a retained command, such
	// as a custom action that reads another action's source file. This check
	// does not claim to resolve arbitrary shell or external script behavior.
	for _, stream := range [][]byte{after.enabled, after.allJails} {
		for _, target := range retiring {
			if bytes.Contains(stream, []byte(target.path)) || bytes.Contains(stream, []byte(filepath.Base(target.path))) {
				return empty, fmt.Errorf("retained Fail2ban commands reference a retirement target; preserve it for reviewed recovery")
			}
		}
	}

	// Bind every source, not just the removed files, and both parser views.
	// The zero digest is a domain-specific placeholder within this binding;
	// individual file intents receive the resulting digest below.
	binding := legacyFail2banPlanRecord{
		Schema: legacyFail2banPlanSchema, Targets: ordered,
		ParserSHA256: before.parserSHA256,
		Views:        [4][sha256.Size]byte{sha256.Sum256(before.enabled), sha256.Sum256(before.allJails), sha256.Sum256(after.enabled), sha256.Sum256(after.allJails)},
	}
	for _, source := range inventory.sources {
		record, err := makeLegacyRetirementFileRecord(source.path, strings.Repeat("0", 64), source.snapshot)
		if err != nil {
			return empty, err
		}
		binding.Sources = append(binding.Sources, record)
	}
	parent, err := bindLegacyFail2banPlanDirectory(host, "/etc", inventory.parent)
	if err != nil {
		return empty, err
	}
	binding.Directories = append(binding.Directories, parent)
	for _, directory := range inventory.directories {
		record, err := bindLegacyFail2banPlanDirectory(host, directory.path, directory.identity)
		if err != nil {
			return empty, err
		}
		binding.Directories = append(binding.Directories, record)
	}
	sort.Slice(binding.Sources, func(i, j int) bool { return binding.Sources[i].Source.Path < binding.Sources[j].Source.Path })
	sort.Slice(binding.Directories, func(i, j int) bool { return binding.Directories[i].Path < binding.Directories[j].Path })
	if err := reattestLegacyFail2banPlanInventory(host, inventory); err != nil {
		return empty, err
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return empty, fmt.Errorf("encode historical Fail2ban file plan: %w", err)
	}
	plan := legacyFail2banRetirementPlan{
		sha256: fmt.Sprintf("%x", sha256.Sum256(encoded)), binding: binding, baseline: inventory, retiring: retiring,
	}
	for _, target := range retiring {
		record, err := makeLegacyRetirementFileRecord(target.path, plan.sha256, sources[target.path].snapshot)
		if err != nil {
			return empty, err
		}
		plan.records = append(plan.records, record)
	}
	return plan, nil
}

func cloneLegacyFail2banView(view legacyFail2banConfigurationView) legacyFail2banConfigurationView {
	view.enabled = bytes.Clone(view.enabled)
	view.allJails = bytes.Clone(view.allJails)
	view.actionsEnabled = bytes.Clone(view.actionsEnabled)
	view.actionsAll = bytes.Clone(view.actionsAll)
	return view
}

func cloneLegacyFail2banInventory(inventory legacyFail2banInventory) legacyFail2banInventory {
	inventory.sources = append([]legacyFail2banSource(nil), inventory.sources...)
	for index := range inventory.sources {
		inventory.sources[index].snapshot.content = bytes.Clone(inventory.sources[index].snapshot.content)
	}
	inventory.directories = append([]legacyFail2banDirectorySnapshot(nil), inventory.directories...)
	return inventory
}

func reattestLegacyFail2banPlanInventory(host nftPersistenceFilesystem, before legacyFail2banInventory) error {
	after, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		return err
	}
	if err := verifyLegacyFail2banInventoryRetirement(before, after, nil); err != nil {
		return fmt.Errorf("Fail2ban configuration changed during retirement planning: %w", err)
	}
	return nil
}

func verifyLegacyFail2banConfigurationViews(before, after legacyFail2banConfigurationView, jails map[string]bool) error {
	if before.socket != after.socket || before.pidfile != after.pidfile {
		return fmt.Errorf("Fail2ban retirement changes a shared service endpoint")
	}
	if before.parserSHA256 == ([sha256.Size]byte{}) || before.parserSHA256 != after.parserSHA256 {
		return fmt.Errorf("Fail2ban configuration views do not share an attested parser identity")
	}
	for _, view := range []struct {
		name          string
		before, after []byte
		requireTarget bool
	}{
		{"enabled", before.enabled, after.enabled, false},
		{"all-jails", before.allJails, after.allJails, true},
	} {
		retained, err := retainedLegacyFail2banCommandsWithPresence(view.before, jails, true, view.requireTarget)
		if err != nil {
			return fmt.Errorf("invalid original Fail2ban %s view: %w", view.name, err)
		}
		remaining, err := retainedLegacyFail2banCommands(view.after, jails, false)
		if err != nil {
			return fmt.Errorf("invalid staged Fail2ban %s view: %w", view.name, err)
		}
		if !bytes.Equal(retained, remaining) {
			return fmt.Errorf("historical Fail2ban retirement changes unrelated %s configuration", view.name)
		}
	}
	return nil
}

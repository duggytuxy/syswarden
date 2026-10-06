//go:build linux

package firewall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
)

// The active alternative may expose only nf_tables while the older kernel
// backend still has rules. Its kernel inventory is a read-only refusal signal,
// never authority to delete a shared table or import a historical manifest.
func preflightLegacyIPTablesBackend(ctx context.Context) error {
	file, err := os.Open("/proc/net/ip_tables_names")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy iptables backend before removal: %w", err)
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(content) > 4096 {
		return fmt.Errorf("legacy iptables kernel table inventory is unavailable or unbounded")
	}
	present := false
	for _, name := range strings.Fields(string(content)) {
		present = present || name == "filter"
	}
	if !present {
		return nil
	}
	path, err := exec.LookPath("iptables-legacy-save")
	if err != nil {
		return fmt.Errorf("legacy filter table is present without its read-only observer; preserve shared rules and product payload")
	}
	path, err = resolveLinuxWrapperExecutable(path)
	if err != nil {
		return err
	}
	descriptor, identity, err := pinNFTExecutable(path)
	if err != nil {
		return err
	}
	if err := descriptor.Close(); err != nil {
		return err
	}
	previous, exists, migration, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil {
		return err
	}
	save, err := readLegacyIPTablesSave(ctx, path, identity, "legacy")
	if err != nil {
		return err
	}
	needsCleanup, err := preflightLegacyIPTablesBackendSave(save, previous)
	if err != nil {
		return err
	}
	if needsCleanup {
		if err := requireLegacyIPTablesCleanupBackend(identity); err != nil {
			return err
		}
	}
	repeated, repeatedExists, repeatedMigration, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil || exists != repeatedExists || migration != repeatedMigration || !sameLinuxWrapperRules(previous, repeated) {
		return fmt.Errorf("legacy compatibility ownership changed during removal preflight")
	}
	return nil
}

func preflightLegacyIPTablesBackendSave(save []byte, owned map[string]linuxWrapperRule) (bool, error) {
	chains, err := legacyIPTablesSaveRules(save)
	if err != nil {
		return false, err
	}
	seen := make(map[string]bool)
	profiles := legacyIPTablesOwnedProfiles(owned)
	for _, line := range chains["INPUT"] {
		if !strings.Contains(line, "SYSWARDEN_CORE") {
			continue
		}
		profile, exists := profiles[line]
		if !exists || profile.key == "" || seen[profile.key] {
			return false, fmt.Errorf("unresolved historical permissions remain in the legacy iptables backend; preserve its shared rules, original evidence and product payload for separate verified recovery; nf_tables recovery cannot retire legacy-backend rules")
		}
		seen[profile.key] = true
	}
	return len(seen) != 0, nil
}

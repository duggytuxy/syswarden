//go:build linux

package system

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Only historical direct dependencies that the minimal profile will stop
// requiring are eligible. This is not a package-name prefix or a list of all
// installed packages. Dependencies independently rooted in world are left
// untouched, including their version and repository constraints.
var apkOptionalDependencyNames = [...]string{
	"e2fsprogs-extra", "libqrencode-tools", "rsyslog", "rsyslog-uxsock", "wireguard-tools",
}

type apkRetentionRecord struct {
	name, version, dependencies, flags string
	seen                               map[byte]bool
}

func apkRetentionName(token string) string {
	if index := strings.IndexAny(token, "@<>=~"); index >= 0 {
		return token[:index]
	}
	return token
}

func apkRetentionRelevant(name string) bool {
	if name == "syswarden" {
		return true
	}
	for _, allowed := range apkOptionalDependencyNames {
		if name == allowed {
			return true
		}
	}
	return false
}

// apkDependencyRetentionNames requires well-formed installed records and a direct
// dependency declared by the old package. It does not infer disuse from TOML.
// It is read-only and returns only compiled-in bare package names, never data
// suitable for injecting APK options, constraints, repositories or file paths.
func apkDependencyRetentionNames(world, installed []byte) ([]string, error) {
	if len(world) == 0 || len(world) > 1<<20 || len(installed) == 0 || len(installed) > maximumAPKInstalledDatabaseSize ||
		bytes.IndexByte(world, 0) >= 0 || bytes.IndexByte(installed, 0) >= 0 ||
		bytes.ContainsAny(world, "\r\t") || bytes.ContainsRune(installed, '\r') {
		return nil, errors.New("APK retention inventory is empty, oversized or malformed")
	}
	records := make(map[string]apkRetentionRecord)
	for _, block := range strings.Split(strings.TrimRight(string(installed), "\n"), "\n\n") {
		if block == "" {
			continue
		}
		record := apkRetentionRecord{seen: make(map[byte]bool)}
		for _, line := range strings.Split(block, "\n") {
			if len(line) < 2 || line[1] != ':' || len(line) > 64<<10 {
				return nil, errors.New("APK installed record is malformed")
			}
			key, value := line[0], line[2:]
			if !strings.ContainsRune("PVDf", rune(key)) {
				continue
			}
			if record.seen[key] {
				return nil, errors.New("APK installed record has duplicate identity fields")
			}
			record.seen[key] = true
			switch key {
			case 'P':
				record.name = value
			case 'V':
				record.version = value
			case 'D':
				record.dependencies = value
			case 'f':
				record.flags = value
			}
		}
		if record.name == "" || record.version == "" {
			return nil, errors.New("APK installed record lacks package identity")
		}
		if !apkRetentionRelevant(record.name) {
			continue
		}
		if _, exists := records[record.name]; exists {
			return nil, errors.New("APK retention package identity is duplicated")
		}
		records[record.name] = record
	}
	owner, exists := records["syswarden"]
	if !exists {
		return nil, errors.New("APK update requires an installed SysWarden package")
	}
	// APK v2's S flag describes the checksum representation. Other flags
	// report broken files/scripts/xattrs or an unknown state. Inspect only
	// the updating product and its historical dependencies, not unrelated
	// installed modules that the minimal package does not require.
	if strings.Trim(owner.flags, "S") != "" {
		return nil, errors.New("APK product package requires native repair")
	}
	declared := make(map[string]bool)
	for _, dependency := range strings.Fields(owner.dependencies) {
		name := apkRetentionName(dependency)
		if !apkRetentionRelevant(name) || name == "syswarden" {
			continue
		}
		// Published historical metadata uses bare names. Preserve ambiguous
		// vendor-specific constraints for review rather than weakening them.
		if dependency != name || declared[name] {
			return nil, errors.New("APK historical dependency is constrained or duplicated")
		}
		declared[name] = true
		record, installed := records[name]
		if !installed {
			return nil, errors.New("APK historical dependency is missing; native repair is required")
		}
		if strings.Trim(record.flags, "S") != "" {
			return nil, errors.New("APK historical dependency requires native repair")
		}
	}
	rooted := make(map[string]bool)
	for _, line := range strings.Split(string(world), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) != line || strings.Contains(line, " ") {
			return nil, errors.New("APK world contains an ambiguous requirement")
		}
		name := apkRetentionName(strings.TrimPrefix(line, "!"))
		if !declared[name] {
			continue
		}
		if strings.HasPrefix(line, "!") || rooted[name] {
			return nil, errors.New("APK world has conflicting or duplicate retention requirements")
		}
		rooted[name] = true
	}
	var names []string
	for _, name := range apkOptionalDependencyNames {
		if declared[name] && !rooted[name] {
			names = append(names, name)
		}
	}
	return names, nil
}

// Retention shares the native add transaction, so APK resolves these roots
// before scheduling removal. No package scripts run an inner APK command and
// SysWarden never edits world directly. Administrators must serialize migration
// with other configuration operations; this snapshot is not an APK lock lease.
func apkPreservedInstallArguments(name string, args []string, paths openRCWireGuardDefinitionPaths) ([]string, error) {
	if name != "/sbin/apk" && name != "/usr/sbin/apk" {
		return nil, errors.New("APK retention requires a trusted installer path")
	}
	if validateExternalCommand(name, args) != nil && validateQualificationExternalCommand(name, args) != nil {
		return nil, errors.New("APK retention requires the exact verified package install command")
	}
	worldPath, err := paths.hostPath("/etc/apk/world")
	if err != nil {
		return nil, err
	}
	databasePath, err := paths.hostPath("/lib/apk/db/installed")
	if err != nil {
		return nil, err
	}
	world, err := paths.readFile(worldPath, 1<<20, nil)
	if err != nil {
		return nil, fmt.Errorf("read protected APK world: %w", err)
	}
	database, err := paths.readFile(databasePath, maximumAPKInstalledDatabaseSize, nil)
	if err != nil {
		return nil, fmt.Errorf("read protected APK installed database: %w", err)
	}
	names, err := apkDependencyRetentionNames(world.content, database.content)
	if err != nil {
		return nil, err
	}
	worldAfter, err := paths.readFile(worldPath, 1<<20, nil)
	if err != nil || !sameWireGuardDefinitionIdentity(world.identity, worldAfter.identity) || !bytes.Equal(world.content, worldAfter.content) {
		return nil, errors.New("APK world changed during dependency retention inspection")
	}
	databaseAfter, err := paths.readFile(databasePath, maximumAPKInstalledDatabaseSize, nil)
	if err != nil || !sameWireGuardDefinitionIdentity(database.identity, databaseAfter.identity) || !bytes.Equal(database.content, databaseAfter.content) {
		return nil, errors.New("APK installed database changed during dependency retention inspection")
	}
	return append(append([]string(nil), args...), names...), nil
}

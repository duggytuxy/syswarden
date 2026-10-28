//go:build linux

package system

import (
	"bytes"
	"encoding/base64"
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
	name, version, architecture, checksum, dependencies, flags, provides string
	seen                                                                 map[byte]bool
}

// Q1 is the installed identity encoding observed for APK v2 packages with both
// observed apk-tools generations. This is a native identity comparison, not a
// package authentication algorithm or evidence of administrator intent.
func validAPKRetentionChecksum(checksum string) bool {
	if len(checksum) != 30 || !strings.HasPrefix(checksum, "Q1") {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(checksum[2:])
	return err == nil && len(decoded) == 20 && base64.StdEncoding.EncodeToString(decoded) == checksum[2:]
}

func apkRetentionName(token string) string {
	if index := strings.IndexAny(token, "@<>=~"); index >= 0 {
		return token[:index]
	}
	return token
}

func apkRetentionRelevant(name string) bool {
	if validNativeProductPackageName(name) {
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
	return apkDependencyRetentionNamesForName(compatibilityNativePackageName, world, installed)
}

func apkDependencyRetentionNamesForName(packageName string, world, installed []byte) ([]string, error) {
	if !validNativeProductPackageName(packageName) {
		return nil, errors.New("APK retention requires an exact product identity")
	}
	if len(world) == 0 || len(world) > 1<<20 || len(installed) == 0 || len(installed) > maximumAPKInstalledDatabaseSize ||
		bytes.IndexByte(world, 0) >= 0 || bytes.IndexByte(installed, 0) >= 0 ||
		bytes.ContainsAny(world, "\r\t") || bytes.ContainsRune(installed, '\r') {
		return nil, errors.New("APK retention inventory is empty, oversized or malformed")
	}
	records := make(map[string]apkRetentionRecord)
	providers := make(map[string][]apkRetentionProvider)
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
			if !strings.ContainsRune("PVCADfp", rune(key)) {
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
			case 'A':
				record.architecture = value
			case 'C':
				record.checksum = value
			case 'D':
				record.dependencies = value
			case 'f':
				record.flags = value
			case 'p':
				record.provides = value
			}
		}
		if record.name == "" || record.version == "" {
			return nil, errors.New("APK installed record lacks package identity")
		}
		for _, token := range strings.Fields(record.provides) {
			name := apkRetentionName(token)
			if apkRetentionRelevant(name) && !validNativeProductPackageName(name) {
				providers[name] = append(providers[name], apkRetentionProvider{record.name, token})
			}
		}
		if !apkRetentionRelevant(record.name) {
			continue
		}
		if _, exists := records[record.name]; exists {
			return nil, errors.New("APK retention package identity is duplicated")
		}
		records[record.name] = record
	}
	owner, exists := records[packageName]
	if !exists {
		return nil, errors.New("APK update requires the selected installed SysWarden package")
	}
	for _, other := range nativeProductPackageNames {
		if _, exists := records[other]; other != packageName && exists {
			return nil, errors.New("APK update refuses coexisting SysWarden package identities")
		}
	}
	if owner.architecture != "x86_64" || !retentionVersion(owner.version) {
		return nil, errors.New("APK product package has an unsupported architecture or version")
	}
	if !validAPKRetentionChecksum(owner.checksum) {
		return nil, errors.New("APK product package lacks a supported canonical installed checksum")
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
		if !apkRetentionRelevant(name) || validNativeProductPackageName(name) {
			continue
		}
		// Published historical metadata uses bare names. Preserve ambiguous
		// vendor-specific constraints for review rather than weakening them.
		if dependency != name || declared[name] {
			return nil, errors.New("APK historical dependency is constrained or duplicated")
		}
		declared[name] = true
		record, err := apkRetentionDependencyRecord(name, records, providers)
		if err != nil {
			return nil, err
		}
		if strings.Trim(record.flags, "S") != "" {
			return nil, errors.New("APK historical dependency requires native repair")
		}
	}
	rooted := make(map[string]bool)
	productRoot := false
	for _, line := range strings.Split(string(world), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) != line || strings.Contains(line, " ") {
			return nil, errors.New("APK world contains an ambiguous requirement")
		}
		name := apkRetentionName(strings.TrimPrefix(line, "!"))
		if validNativeProductPackageName(name) {
			// A same-name local-file update rebinds a checksum root to the new
			// package. Only an exact binding to the selected installed C field
			// is accepted. Version pins, tags and other constraints stay intact
			// through refusal, never through normalization or direct world edits.
			if name != packageName || productRoot || (line != packageName && line != packageName+"><"+owner.checksum) {
				return nil, errors.New("APK update requires one bare or exact installed-checksum product root; preserve administrator constraints for manual review")
			}
			productRoot = true
			continue
		}
		if !declared[name] {
			continue
		}
		if strings.HasPrefix(line, "!") || rooted[name] {
			return nil, errors.New("APK world has conflicting or duplicate retention requirements")
		}
		rooted[name] = true
	}
	if !productRoot {
		return nil, errors.New("APK update refuses to create a new explicit product root")
	}
	var names []string
	for _, name := range apkOptionalDependencyNames {
		if declared[name] && !rooted[name] {
			names = append(names, name)
		}
	}
	return names, nil
}

type apkRetentionProvider struct{ name, token string }

// Alpine can fold the uxsock module into rsyslog while retaining its versioned
// virtual dependency. Recognize only that exact installed provider, without
// translating or dropping the administrator's original world requirement.
func apkRetentionDependencyRecord(name string, records map[string]apkRetentionRecord, providers map[string][]apkRetentionProvider) (apkRetentionRecord, error) {
	record, installed := records[name]
	claims := providers[name]
	if installed && len(claims) == 0 {
		return record, nil
	}
	if !installed && name == "rsyslog-uxsock" && len(claims) == 1 && claims[0].name == "rsyslog" {
		provider, present := records["rsyslog"]
		if present && provider.architecture == "x86_64" && retentionVersion(provider.version) && validAPKRetentionChecksum(provider.checksum) && claims[0].token == name+"="+provider.version {
			return provider, nil
		}
	}
	return apkRetentionRecord{}, errors.New("APK historical dependency is missing or its provider is ambiguous; native repair is required")
}

// Retention shares the native add transaction, so APK resolves these roots
// before scheduling removal. No package scripts run an inner APK command and
// SysWarden never edits world directly. Administrators must serialize migration
// with other configuration operations; this snapshot is not an APK lock lease.
func apkPreservedInstallArguments(name string, args []string, paths openRCWireGuardDefinitionPaths) ([]string, error) {
	return apkPreservedInstallArgumentsForName(compatibilityNativePackageName, name, args, paths)
}

func apkPreservedInstallArgumentsForName(packageName, name string, args []string, paths openRCWireGuardDefinitionPaths) ([]string, error) {
	if !validNativeProductPackageName(packageName) {
		return nil, errors.New("APK retention requires an exact product identity")
	}
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
	names, err := apkDependencyRetentionNamesForName(packageName, world.content, database.content)
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

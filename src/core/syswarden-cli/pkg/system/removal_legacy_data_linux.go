//go:build linux

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type legacyRetentionProfile struct {
	directory, backupKind, schema, authority string
	names                                    map[string]string
	inspect                                  func(*pinnedServiceDirectory, string, string, bool) (removalArtifactIdentity, string, bool, error)
}

func legacyLogsProfile() legacyRetentionProfile {
	return legacyRetentionProfile{
		directory: "/var/log/syswarden", backupKind: "legacy-logs",
		schema: "syswarden-legacy-log-retention-v1", authority: "explicit-operator-confirmation-of-exact-legacy-log-retention",
		names: map[string]string{"core.log": "core", "waf.json": "telemetry", "waf.json.1": "telemetry"}, inspect: inspectLegacyProductLogFile,
	}
}

func legacyDataProfile(kind string) (legacyRetentionProfile, error) {
	profile := legacyRetentionProfile{inspect: inspectLegacyDataFile}
	switch kind {
	case "lists":
		profile.directory, profile.backupKind = "/etc/syswarden/lists", "legacy-lists"
		profile.names = map[string]string{
			"syswarden_blacklist.ipv4": "list", "syswarden_blacklist.ipv6": "list",
			"syswarden_whitelist.ipv4": "list", "syswarden_whitelist.ipv6": "list",
			".syswarden_blacklist_pair_v1": "blocklist-pair", ".syswarden_whitelist_pair_v1": "whitelist-pair",
			"syswarden_saas_monitors.ipv4": "saas-cache", "syswarden_saas_monitors.ipv6": "saas-cache",
			"syswarden_saas_monitors.pair": "saas-cache",
		}
	case "ui":
		profile.directory, profile.backupKind = "/var/lib/syswarden/ui", "legacy-ui"
		profile.names = map[string]string{"data.json": "dashboard", "metrics_24h.json": "metrics"}
	default:
		return profile, fmt.Errorf("unsupported bounded legacy data retention selection")
	}
	profile.schema = "syswarden-legacy-" + kind + "-retention-v1"
	profile.authority = "explicit-operator-confirmation-of-exact-legacy-" + kind + "-retention"
	return profile, nil
}

// Explicit retention preserves originals without assigning ownership to old
// lists or snapshots. The operator must confirm the exact inventory and the
// absence of another producer. A present but invalid marker cannot be bypassed.
func inspectLegacyDataFile(directory *pinnedServiceDirectory, name, kind string, syncData bool) (removalArtifactIdentity, string, bool, error) {
	before, err := directory.root.Lstat(name)
	if err != nil {
		return removalArtifactIdentity{}, "", false, err
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil || before.Mode().Perm() != 0600 {
		return identity, "", false, fmt.Errorf("legacy data must have private metadata")
	}
	content, err := readRetirementCandidateBounded(directory, name, before, 16<<20)
	if err != nil {
		return identity, "", false, err
	}
	digest := sha256.Sum256(content)
	file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return identity, "", false, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	actual, identityErr := exactRemovalArtifactIdentity(opened)
	if err != nil || identityErr != nil || actual != identity {
		return identity, "", false, fmt.Errorf("legacy data changed while opening")
	}
	proven := false
	if kind == "blocklist-pair" || kind == "whitelist-pair" {
		expected := "SYSWARDEN_PERSISTENT_BLOCKLIST_PAIR_V1\n"
		if kind == "whitelist-pair" {
			expected = "SYSWARDEN_PERSISTENT_WHITELIST_PAIR_V1\n"
		}
		if string(content) != expected {
			return identity, "", false, fmt.Errorf("legacy list initialization marker differs from the exact format")
		}
		// Pair markers describe initialization, not provenance of list contents.
	} else {
		attribute := productSnapshotOriginAttribute
		if kind == "list" || kind == "saas-cache" {
			attribute = generatedListOriginAttribute
		}
		var marker [512]byte
		_, originErr := unix.Fgetxattr(int(file.Fd()), attribute, marker[:])
		if originErr == nil {
			// SaaS publication has no creation-origin contract. Names and pair
			// hashes cannot confer ownership, and an unexpected marker must not
			// become a way to bypass the exact-content retirement boundary.
			if kind == "saas-cache" {
				return identity, "", false, fmt.Errorf("legacy SaaS retention cannot override an unsupported creation marker")
			}
			if kind == "list" {
				proven, err = HasGeneratedListOrigin(file, name, digest)
			} else {
				checked, _, checkErr := inspectCreatedProductSnapshot(directory, name, kind, false)
				proven, err = checked == identity, checkErr
			}
			if err != nil || !proven {
				return identity, "", false, fmt.Errorf("legacy retention cannot override a modified creation marker")
			}
		} else if !errors.Is(originErr, unix.ENODATA) && !errors.Is(originErr, unix.ENOTSUP) {
			return identity, "", false, originErr
		}
	}
	if syncData {
		if err := file.Sync(); err != nil {
			return identity, "", false, err
		}
	}
	after, err := directory.root.Lstat(name)
	actual, identityErr = exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != identity {
		return identity, "", false, fmt.Errorf("legacy data changed during inspection")
	}
	return identity, fmt.Sprintf("%x", digest), proven, nil
}

func InspectLegacyDataRetention(kind string) (LegacyLogRetentionPlan, error) {
	profile, err := legacyDataProfile(kind)
	if err != nil {
		return LegacyLogRetentionPlan{}, err
	}
	return inspectLegacyRetention(profile)
}

func ApplyLegacyDataRetention(kind, expected string) (LegacyLogRetentionPlan, string, error) {
	profile, err := legacyDataProfile(kind)
	if err != nil {
		return LegacyLogRetentionPlan{}, "", err
	}
	return applyLegacyRetention(filepath.Dir(profile.directory), "/var/backups", expected,
		func() error { return legacyRetentionGuard(profile) }, unix.Renameat2, profile)
}

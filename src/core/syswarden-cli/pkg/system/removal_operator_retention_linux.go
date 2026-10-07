//go:build linux

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const operatorRetentionRecordsPath = "/var/backups/syswarden-retired-v1/operator-configuration"

func isRetainedOperatorConfiguration(path string, approved map[string]bool) bool {
	return path == "/etc/syswarden/config/modules/99-user.toml" || approved[path] && operatorRetentionPath(path)
}

func operatorConfigurationRetentionGuard() error {
	return legacyRetentionGuard(legacyRetentionProfile{directory: "/etc/syswarden/config", backupKind: "operator-configuration"})
}

func InspectOperatorConfigurationRetention() (OperatorConfigurationRetentionPlan, error) {
	if err := operatorConfigurationRetentionGuard(); err != nil {
		return OperatorConfigurationRetentionPlan{}, err
	}
	plan, err := inspectOperatorConfigurationRetention("/etc/syswarden/config")
	if err != nil {
		return plan, err
	}
	return plan, operatorConfigurationRetentionGuard()
}

func ApplyOperatorConfigurationRetention(expected string) (OperatorConfigurationRetentionPlan, string, error) {
	return applyOperatorConfigurationRetention("/etc/syswarden/config", "/var/backups", expected, operatorConfigurationRetentionGuard)
}

func applyOperatorConfigurationRetention(directory, backupParent, expected string, guard func() error) (OperatorConfigurationRetentionPlan, string, error) {
	var empty OperatorConfigurationRetentionPlan
	digest, err := hex.DecodeString(expected)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != expected || guard == nil {
		return empty, "", fmt.Errorf("operator configuration retention requires the exact reviewed lowercase SHA-256 and complete guards")
	}
	if err := guard(); err != nil {
		return empty, "", err
	}
	records := filepath.Join(backupParent, "syswarden-retired-v1/operator-configuration")
	path := filepath.Join(records, expected+".retention")
	// An acknowledged decision survives later administrator edits. Exact retry
	// validates the immutable decision, rather than adopting new paths or bytes.
	if plan, err := readOperatorRetentionDecision(records, expected+".retention"); err == nil {
		return plan, path, guard()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return empty, "", err
	}
	plan, err := inspectOperatorConfigurationRetention(directory)
	if err != nil {
		return empty, "", err
	}
	wire, err := encodeOperatorConfigurationRetention(plan)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(wire)) != expected {
		return empty, "", fmt.Errorf("operator configuration inventory changed; repeat the read-only inspection")
	}
	if err := ensureOperatorRetentionRecords(backupParent); err != nil {
		return empty, "", err
	}
	if err := guard(); err != nil {
		return empty, "", err
	}
	confirmed, err := inspectOperatorConfigurationRetention(directory)
	actual, digestErr := OperatorConfigurationRetentionPlanSHA256(confirmed)
	if err != nil || digestErr != nil || actual != expected {
		return empty, "", fmt.Errorf("operator configuration changed before recording its retention decision")
	}
	owner := plan.Files[0].Identity
	if err := publishExactRemovalRecordAt(path, string(wire), owner.UID, owner.GID); err != nil {
		return empty, "", err
	}
	if _, err := readOperatorRetentionDecision(records, expected+".retention"); err != nil {
		return empty, "", err
	}
	return plan, path, guard()
}

func ensureOperatorRetentionRecords(parentPath string) error {
	for _, name := range []string{"syswarden-retired-v1", "operator-configuration"} {
		parent, err := openExistingPinnedServiceDirectory(parentPath)
		if err != nil {
			return err
		}
		err = parent.root.Mkdir(name, 0700)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			parent.close()
			return err
		}
		info, err := parent.root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !serviceFileOwnedByCurrentUser(info) {
			parent.close()
			return fmt.Errorf("operator retention records require a private owner-controlled directory")
		}
		err = parent.sync()
		parent.close()
		if err != nil {
			return err
		}
		parentPath = filepath.Join(parentPath, name)
	}
	return nil
}

func readOperatorRetentionDecision(directory, name string) (OperatorConfigurationRetentionPlan, error) {
	var empty OperatorConfigurationRetentionPlan
	if len(name) != 64+len(".retention") || filepath.Base(name) != name {
		return empty, fmt.Errorf("invalid operator retention decision name")
	}
	if err := attestOperatorRetentionAncestry(directory); err != nil {
		return empty, err
	}
	parent, err := openExistingPinnedServiceDirectory(directory)
	if err != nil {
		return empty, err
	}
	defer parent.close()
	info, err := parent.root.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return empty, fmt.Errorf("operator retention decision directory is not private")
	}
	before, err := parent.root.Lstat(name)
	if err != nil {
		return empty, err
	}
	wire, err := readRetirementCandidateBounded(parent, name, before, 64<<10)
	if err != nil || before.Mode().Perm() != 0600 || name != fmt.Sprintf("%x.retention", sha256.Sum256(wire)) {
		return empty, fmt.Errorf("operator retention decision differs from its private canonical record")
	}
	plan, err := decodeOperatorConfigurationRetention(wire)
	if err != nil {
		return empty, err
	}
	for _, file := range plan.Files {
		if int64(file.Identity.UID) != int64(os.Geteuid()) || int64(file.Identity.GID) != int64(os.Getegid()) {
			return empty, fmt.Errorf("operator retention decision has an unexpected original owner")
		}
	}
	return plan, nil
}

func retainedOperatorConfigurationPaths(directory string) (map[string]bool, error) {
	retained := make(map[string]bool)
	if err := attestOperatorRetentionAncestry(directory); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return retained, nil
		}
		return nil, err
	}
	root, err := openExistingPinnedServiceDirectory(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return retained, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.close()
	info, err := root.root.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("operator retention decisions require private storage")
	}
	entries, err := readBoundedSharedRemovalEntries(root.root)
	if err != nil || len(entries) > 128 {
		return nil, fmt.Errorf("operator retention decision inventory exceeds its bound")
	}
	for _, entry := range entries {
		plan, err := readOperatorRetentionDecision(directory, entry.Name())
		if err != nil {
			return nil, err
		}
		for _, file := range plan.Files {
			retained[file.Path] = true
		}
	}
	after, err := root.root.Stat(".")
	if err != nil || !os.SameFile(info, after) || info.ModTime() != after.ModTime() {
		return nil, fmt.Errorf("operator retention decision inventory changed")
	}
	return retained, nil
}

func attestOperatorRetentionAncestry(directory string) error {
	parentPath := filepath.Dir(filepath.Dir(directory))
	if filepath.Join(parentPath, "syswarden-retired-v1/operator-configuration") != directory {
		return fmt.Errorf("operator retention records escaped the bounded backup layout")
	}
	parent, err := openExistingPinnedServiceDirectory(parentPath)
	if err != nil {
		return err
	}
	defer parent.close()
	info, err := parent.root.Stat(".")
	if err != nil {
		return err
	}
	identity, err := exactRemovalArtifactIdentity(info)
	if err != nil {
		return err
	}
	present, err := historicalRemovalCandidatePresent(parent.root, "/syswarden-retired-v1/operator-configuration", identity.uid, identity.gid, nil)
	if err != nil {
		return err
	}
	if !present {
		return fs.ErrNotExist
	}
	retired, err := parent.root.Lstat("syswarden-retired-v1")
	if err != nil || retired.Mode().Perm() != 0700 {
		return fmt.Errorf("operator retention backup parent is not private")
	}
	return preflightRemovalMountBoundariesAt([]string{directory}, readProcRemovalMountInfo)
}

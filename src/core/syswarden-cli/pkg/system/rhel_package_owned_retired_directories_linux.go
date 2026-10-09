//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

var rhelRetirableRuntimeDirectories = []string{"/etc/syswarden/lists", "/var/lib/syswarden/ui", "/var/log/syswarden"}

// Whole-directory archival preserves original inodes. Only removal, protected
// by its durable barrier, can attest these exact missing RPM-owned directories.
// Ordinary activation still requires the complete installed directory tree.
func inspectRetiredRHELDirectory(path string, uid, gid uint32) (string, removalArtifactIdentity, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "missing", removalArtifactIdentity{}, nil
	}
	if err != nil {
		return "", removalArtifactIdentity{}, err
	}
	identity, err := exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		identity.uid != uid || identity.gid != gid {
		return "", removalArtifactIdentity{}, fmt.Errorf("retired RPM directory is neither absent nor an exact restrictive skeleton")
	}
	directory, err := openExistingRemovalStateDirectory(path, uid, gid)
	if err != nil {
		return "", removalArtifactIdentity{}, err
	}
	defer directory.close()
	entries, err := readBoundedRemovalDirectory(directory)
	if err != nil || len(entries) != 0 {
		return "", removalArtifactIdentity{}, errors.Join(fmt.Errorf("restrictive RPM skeleton is not empty"), err)
	}
	return "restricted", identity, nil
}

func (host rhelPackageOwnedAttestationHost) attestRetiredRuntimeDirectory(logical, path string) (string, error) {
	if host.removalBarrier == nil || !slices.Contains(rhelRetirableRuntimeDirectories, logical) {
		return "", fmt.Errorf("directory recovery is not authorized for this RPM operation")
	}
	if err := host.removalBarrier(); err != nil {
		return "", err
	}
	if err := attestApprovedSystemdServiceDropInParents(path, host.root, host.expectedUID, host.expectedGID); err != nil {
		return "", err
	}
	before, identity, err := inspectRetiredRHELDirectory(path, host.expectedUID, host.expectedGID)
	if err != nil {
		return "", err
	}
	for attempt := 0; attempt < 2; attempt++ {
		owner, err := host.queryFileOwner(logical)
		if err != nil {
			return "", err
		}
		if err := exactRHELPackageOwnedRPMIdentity(owner, host.runningVersion); err != nil {
			return "", err
		}
		after, current, err := inspectRetiredRHELDirectory(path, host.expectedUID, host.expectedGID)
		if err != nil || before != after || identity != current {
			return "", errors.Join(fmt.Errorf("retired RPM directory changed during attestation"), err)
		}
	}
	return before, host.removalBarrier()
}

func attestRHELPackageOwnedVerification(wire []byte, queryErr error, retired map[string]string) error {
	if len(retired) == 0 {
		if queryErr != nil {
			return fmt.Errorf("verify exact RHEL package-owned RPM payload: %w", queryErr)
		}
		if len(wire) != 0 {
			return fmt.Errorf("rpm verification reported RHEL package-owned payload deviations")
		}
		return nil
	}
	code, known := firewallRemovalExitCode(queryErr)
	if !known || code != 1 || len(wire) > 1024 || len(wire) == 0 || wire[len(wire)-1] != '\n' {
		return fmt.Errorf("RPM verification did not prove only the retired runtime directories")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(wire[:len(wire)-1]), "\n") {
		path, ok := strings.CutPrefix(line, "missing     ")
		state := "missing"
		if !ok {
			path, ok = strings.CutPrefix(line, ".M.......    ")
			state = "restricted"
		}
		if !ok || retired[path] != state || seen[path] || !slices.Contains(rhelRetirableRuntimeDirectories, path) {
			return fmt.Errorf("RPM verification contains an unapproved payload deviation")
		}
		seen[path] = true
	}
	if len(seen) != len(retired) {
		return fmt.Errorf("RPM verification omitted a retired directory")
	}
	return nil
}

// Recreate only the empty RPM skeleton after runtime retirement and complete
// package attestation. No archived bytes or administrator entries are moved.
// An interruption is safe to retry: existing directories remain fully attested,
// and the remaining absences still require RPM ownership and the same barrier.
func restoreRetiredRHELPackageOwnedDirectories(root string, uid, gid uint32, attestPayload func() error) error {
	if attestPayload == nil {
		return fmt.Errorf("RPM payload attestation is unavailable")
	}
	requireBarrier := func() error {
		state, err := openExistingRemovalStateDirectory(filepath.Join(root, "var/lib/syswarden"), uid, gid)
		if err != nil {
			return err
		}
		defer state.close()
		_, err = attestRemovalTombstone(state, uid, gid)
		return err
	}
	for _, logical := range rhelRetirableRuntimeDirectories {
		path := filepath.Join(root, strings.TrimPrefix(logical, "/"))
		if _, err := attestRHELPackageOwnedRuntimeDirectory(path, root, uid, gid); err == nil {
			continue
		}
		state, identity, err := inspectRetiredRHELDirectory(path, uid, gid)
		if err != nil {
			return err
		}
		if err := requireBarrier(); err != nil {
			return err
		}
		if err := attestPayload(); err != nil {
			return err
		}
		if err := attestApprovedSystemdServiceDropInParents(path, root, uid, gid); err != nil {
			return err
		}
		parent, err := openExistingPinnedServiceDirectory(filepath.Dir(path))
		if err != nil {
			return err
		}
		if err := requireBarrier(); err != nil {
			parent.close()
			return err
		}
		if state == "missing" {
			err = parent.root.Mkdir(filepath.Base(path), 0700)
		}
		if err == nil {
			err = finalizeRetiredRHELDirectory(parent, filepath.Base(path), state, identity, uid, gid)
		}
		if err == nil {
			err = parent.sync()
		}
		parent.close()
		if err != nil {
			return fmt.Errorf("restore empty RPM-owned directory %s: %w", logical, err)
		}
		if err := requireBarrier(); err != nil {
			return err
		}
		if _, err := attestRHELPackageOwnedRuntimeDirectory(path, root, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// The descriptor fixes the object while restoring its RPM mode. Only an empty,
// root-owned restrictive skeleton is eligible, including a retry after mkdir.
func finalizeRetiredRHELDirectory(parent *pinnedServiceDirectory, name, state string, before removalArtifactIdentity, uid, gid uint32) error {
	file, err := parent.root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	identity, err := exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || identity.uid != uid || identity.gid != gid ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (state == "restricted" && identity != before) {
		return errors.Join(fmt.Errorf("RPM skeleton changed before permission finalization"), err)
	}
	entries, err := file.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("RPM skeleton acquired content before permission finalization")
	}
	if err := file.Chmod(0750); err != nil {
		return err
	}
	return file.Sync()
}

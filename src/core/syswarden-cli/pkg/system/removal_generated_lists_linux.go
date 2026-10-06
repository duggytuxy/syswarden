//go:build linux

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

const generatedListOriginAttribute = "user.syswarden.list-origin-v1"

func isGeneratedListName(name string) bool {
	return slices.Contains([]string{"syswarden_blacklist.ipv4", "syswarden_blacklist.ipv6", "syswarden_whitelist.ipv4", "syswarden_whitelist.ipv6"}, name)
}

func generatedListOriginRecord(file *os.File, name string, digest [sha256.Size]byte) ([]byte, error) {
	if file == nil || !isGeneratedListName(name) {
		return nil, fmt.Errorf("invalid generated list origin request")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	identity, err := exactRemovalArtifactIdentity(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || identity.nlink != 1 || !serviceFileOwnedByCurrentUser(info) {
		return nil, fmt.Errorf("generated list origin requires an exclusive private owned inode")
	}
	var birth unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &birth); err != nil {
		return nil, err
	}
	if birth.Mask&unix.STATX_BTIME == 0 || birth.Ino != identity.ino {
		return nil, fmt.Errorf("stable generated list creation identity is unavailable")
	}
	return []byte(fmt.Sprintf("SYSWARDEN_LIST_ORIGIN_V1\nname=%s\ninode=%d\nbirth_sec=%d\nbirth_nsec=%d\nsha256=%x\n", name, identity.ino, birth.Btime.Sec, birth.Btime.Nsec, digest)), nil
}

// MarkCreatedGeneratedList records only an exclusive creation or an automatic
// replacement of an already proven generated list. Callers must not adopt an
// existing list. The content hash invalidates authority after manual edits.
func MarkCreatedGeneratedList(file *os.File, name string, content []byte) error {
	record, err := generatedListOriginRecord(file, name, sha256.Sum256(content))
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || info.Size() != int64(len(content)) {
		return fmt.Errorf("generated list size does not match the written content")
	}
	if err := unix.Fsetxattr(int(file.Fd()), generatedListOriginAttribute, record, unix.XATTR_CREATE); err != nil {
		return err
	}
	return file.Sync()
}

// HasGeneratedListOrigin consumes a digest from the caller's stable snapshot.
// Missing, copied or changed provenance cannot authorize deletion or renewed
// ownership. Automatic append may still preserve the file without adopting it.
func HasGeneratedListOrigin(file *os.File, name string, digest [sha256.Size]byte) (bool, error) {
	if file == nil || !isGeneratedListName(name) {
		return false, fmt.Errorf("invalid generated list origin request")
	}
	var marker [512]byte
	size, err := unix.Fgetxattr(int(file.Fd()), generatedListOriginAttribute, marker[:])
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	expected, err := generatedListOriginRecord(file, name, digest)
	if err != nil {
		return false, err
	}
	return string(marker[:size]) == string(expected), nil
}

func inspectGeneratedListDirectory(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
	result := retainedDirectorySnapshot{files: map[string]removalArtifactIdentity{}, content: map[string][]byte{}}
	info, err := directory.root.Stat(".")
	if err != nil {
		return result, err
	}
	result.directory, err = exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || !slices.Contains([]os.FileMode{0700, 0750}, info.Mode().Perm()) || !serviceFileOwnedByCurrentUser(info) {
		return result, fmt.Errorf("generated list directory must be private and owner controlled")
	}
	entries, err := readBoundedSharedRemovalEntries(directory.root)
	if err != nil {
		return result, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	expectedNames := []string{".syswarden_blacklist_pair_v1", ".syswarden_whitelist_pair_v1", "syswarden_blacklist.ipv4", "syswarden_blacklist.ipv6", "syswarden_whitelist.ipv4", "syswarden_whitelist.ipv6"}
	if !slices.Equal(names, expectedNames) {
		return result, fmt.Errorf("list inventory includes missing or unrelated entries; preserve it for explicit recovery")
	}
	digest := sha256.New()
	for _, name := range names {
		before, err := directory.root.Lstat(name)
		if err != nil || before.Mode().Perm() != 0600 {
			return result, fmt.Errorf("generated list entry must be private")
		}
		content, err := readRetirementCandidateBounded(directory, name, before, 16<<20)
		if err != nil {
			return result, err
		}
		identity, err := exactRemovalArtifactIdentity(before)
		if err != nil {
			return result, err
		}
		if isGeneratedListName(name) {
			file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return result, err
			}
			opened, statErr := file.Stat()
			openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
			owned, originErr := HasGeneratedListOrigin(file, name, sha256.Sum256(content))
			closeErr := file.Close()
			if statErr != nil || identityErr != nil || openedIdentity != identity || originErr != nil || closeErr != nil || !owned {
				return result, fmt.Errorf("list %s lacks exact generated-content provenance; preserve administrator input and inspect explicit recovery", name)
			}
		} else {
			expected := "SYSWARDEN_PERSISTENT_BLOCKLIST_PAIR_V1\n"
			if name == ".syswarden_whitelist_pair_v1" {
				expected = "SYSWARDEN_PERSISTENT_WHITELIST_PAIR_V1\n"
			}
			if string(content) != expected {
				return result, fmt.Errorf("list initialization marker differs from the exact producer format")
			}
		}
		result.files[name], result.content[name] = identity, content
		_, _ = digest.Write([]byte(name + "\x00"))
		_, _ = digest.Write(content)
	}
	result.digest = fmt.Sprintf("%x", digest.Sum(nil))
	return result, nil
}

func RetireGeneratedListsForRemoval() error {
	guard := func() error {
		if err := RequireRemovalTombstone(); err != nil {
			return err
		}
		if err := preflightHostRemovalMountBoundaries(); err != nil {
			return err
		}
		root, err := os.OpenRoot("/")
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		for _, path := range []string{"/etc/syswarden/lists/syswarden_whitelist.ipv4", "/var/backups/syswarden-retired-v1/generated-lists"} {
			if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, func() {}); err != nil {
				return err
			}
		}
		return ReattestFirewallStatePreparedForRemoval()
	}
	if err := guard(); err != nil {
		return err
	}
	directory, err := openExistingPinnedServiceDirectory("/etc/syswarden/lists")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := readBoundedSharedRemovalEntries(directory.root)
	directory.close()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return guard()
	}
	backup, err := retireAttestedDirectory("/etc/syswarden", "lists", "/var/backups", "generated-lists", guard, inspectGeneratedListDirectory, unix.Renameat2)
	if err == nil && backup != "" {
		fmt.Printf("[INFO] Retained exact generated lists in private recovery backup: %s\n", backup)
	}
	return err
}

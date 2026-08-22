package firewall

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"syswarden-cli/pkg/network"
	"syswarden-cli/pkg/system"
)

type approvedListFile struct {
	directory string
	name      string
}

const legacyMetadataWhitelistIPv4 = "169.254.169.254"

func approvedListFileForPath(path string) (approvedListFile, error) {
	switch path {
	case WhitelistV4:
		return approvedListFile{directory: "/etc/syswarden/lists", name: "syswarden_whitelist.ipv4"}, nil
	case WhitelistV6:
		return approvedListFile{directory: "/etc/syswarden/lists", name: "syswarden_whitelist.ipv6"}, nil
	case BlocklistV4:
		return approvedListFile{directory: "/etc/syswarden/lists", name: "syswarden_blacklist.ipv4"}, nil
	case BlocklistV6:
		return approvedListFile{directory: "/etc/syswarden/lists", name: "syswarden_blacklist.ipv6"}, nil
	case SSHBypass:
		return approvedListFile{directory: "/etc/syswarden", name: "ssh_whitelist.txt"}, nil
	default:
		return approvedListFile{}, fmt.Errorf("list path is not approved: %q", path)
	}
}

func validateListFileTarget(target approvedListFile) error {
	if !filepath.IsAbs(target.directory) || filepath.Clean(target.directory) != target.directory {
		return fmt.Errorf("list directory must be an absolute canonical path: %q", target.directory)
	}
	for _, component := range strings.Split(filepath.ToSlash(target.directory), "/") {
		if component == "." || component == ".." {
			return fmt.Errorf("list directory contains a traversal component: %q", target.directory)
		}
	}
	if target.name == "" || target.name == "." || target.name == ".." ||
		filepath.Base(target.name) != target.name || strings.ContainsAny(target.name, `/\\`) {
		return fmt.Errorf("list file name must be a single safe basename: %q", target.name)
	}
	return nil
}

func openListDirectory(target approvedListFile, create bool) (*os.Root, error) {
	if err := validateListFileTarget(target); err != nil {
		return nil, err
	}
	currentRoot, err := os.OpenRoot("/")
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(target.directory, "/"), "/") {
		if component == "" {
			continue
		}
		info, statErr := currentRoot.Lstat(component)
		if errors.Is(statErr, fs.ErrNotExist) && create {
			if mkdirErr := currentRoot.Mkdir(component, 0750); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
				_ = currentRoot.Close()
				return nil, fmt.Errorf("create list directory %s: %w", target.directory, mkdirErr)
			}
			info, statErr = currentRoot.Lstat(component)
		}
		if statErr != nil {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("inspect list directory %s: %w", target.directory, statErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("list directory component is not a real directory: %s", component)
		}
		nextRoot, err := currentRoot.OpenRoot(component)
		if err != nil {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("open list directory component %s: %w", component, err)
		}
		openedInfo, err := nextRoot.Stat(".")
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = nextRoot.Close()
			_ = currentRoot.Close()
			return nil, fmt.Errorf("list directory component changed while opening: %s", component)
		}
		_ = currentRoot.Close()
		currentRoot = nextRoot
	}
	return currentRoot, nil
}

func readListFileAt(target approvedListFile) ([]byte, error) {
	directory, err := openListDirectory(target, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	return readListFileInDirectory(directory, target)
}

func readListFileInDirectory(directory *os.Root, target approvedListFile) ([]byte, error) {
	file, _, err := openListFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(file)
}

func lockListDirectory(directory *os.Root) (*os.File, error) {
	lockFile, err := directory.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open list directory lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock list directory: %w", err)
	}
	return lockFile, nil
}

func unlockListDirectory(lockFile *os.File) {
	_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	_ = lockFile.Close()
}

func openListFileInRoot(directory *os.Root, target approvedListFile, flags int, create bool) (*os.File, bool, error) {
	pathInfo, statErr := directory.Lstat(target.name)
	created := false
	mode := fs.FileMode(0)
	if errors.Is(statErr, fs.ErrNotExist) && create {
		flags |= os.O_CREATE | os.O_EXCL
		mode = 0600
		created = true
	} else if statErr != nil {
		return nil, false, statErr
	} else if !pathInfo.Mode().IsRegular() {
		return nil, false, fmt.Errorf("list target is not a regular file: %s", target.name)
	}
	file, err := directory.OpenFile(target.name, flags, mode)
	if err != nil {
		return nil, false, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, false, err
	}
	if !openedInfo.Mode().IsRegular() || (!created && !os.SameFile(pathInfo, openedInfo)) {
		_ = file.Close()
		return nil, false, fmt.Errorf("list target changed while opening: %s", target.name)
	}
	return file, created, nil
}

type listFileIdentity struct {
	info       fs.FileInfo
	digest     [sha256.Size]byte
	uid        int
	gid        int
	ownerKnown bool
}

func snapshotListFile(file *os.File) (fs.FileInfo, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	before, err := file.Stat()
	if err != nil {
		return nil, digest, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, digest, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, digest, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, digest, fmt.Errorf("list target changed while snapshotting")
	}
	copy(digest[:], hash.Sum(nil))
	return after, digest, nil
}

func sameListFileState(expected listFileIdentity, actualInfo fs.FileInfo, actualDigest [sha256.Size]byte) bool {
	if !os.SameFile(expected.info, actualInfo) || expected.info.Size() != actualInfo.Size() ||
		!expected.info.ModTime().Equal(actualInfo.ModTime()) || expected.info.Mode() != actualInfo.Mode() ||
		expected.digest != actualDigest {
		return false
	}
	if expected.ownerKnown {
		stat, ok := actualInfo.Sys().(*syscall.Stat_t)
		return ok && int(stat.Uid) == expected.uid && int(stat.Gid) == expected.gid
	}
	return true
}

func inspectListDestination(directory *os.Root, target approvedListFile) (listFileIdentity, bool, error) {
	pathInfo, err := directory.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return listFileIdentity{}, false, nil
	}
	if err != nil {
		return listFileIdentity{}, false, err
	}
	if !pathInfo.Mode().IsRegular() {
		return listFileIdentity{}, false, fmt.Errorf("list target is not a regular file: %s", target.name)
	}
	file, _, err := openListFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return listFileIdentity{}, false, err
	}
	openedInfo, digest, statErr := snapshotListFile(file)
	closeErr := file.Close()
	if statErr != nil {
		return listFileIdentity{}, false, statErr
	}
	if closeErr != nil {
		return listFileIdentity{}, false, closeErr
	}
	identity := listFileIdentity{info: openedInfo, digest: digest}
	if stat, ok := openedInfo.Sys().(*syscall.Stat_t); ok {
		identity.uid = int(stat.Uid)
		identity.gid = int(stat.Gid)
		identity.ownerKnown = true
	}
	return identity, true, nil
}

func createListStagingFile(directory *os.Root, target approvedListFile) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate list staging name: %w", err)
		}
		name := "." + target.name + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create list staging file: %w", err)
		}
		return file, name, nil
	}
	return nil, "", fmt.Errorf("create list staging file: too many name collisions")
}

func verifyListDestination(directory *os.Root, target approvedListFile, identity listFileIdentity, existed bool) error {
	current, err := directory.Lstat(target.name)
	if !existed {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("list target appeared before publication: %s", target.name)
	}
	if err != nil {
		return fmt.Errorf("reinspect list target %s: %w", target.name, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(identity.info, current) {
		return fmt.Errorf("list target changed before publication: %s", target.name)
	}
	file, _, err := openListFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return fmt.Errorf("reopen list target %s before publication: %w", target.name, err)
	}
	actualInfo, actualDigest, snapshotErr := snapshotListFile(file)
	closeErr := file.Close()
	if snapshotErr != nil {
		return fmt.Errorf("resnapshot list target %s: %w", target.name, snapshotErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close list target %s after resnapshot: %w", target.name, closeErr)
	}
	if !sameListFileState(identity, actualInfo, actualDigest) {
		return fmt.Errorf("list target content or metadata changed before publication: %s", target.name)
	}
	return nil
}

func syncListDirectory(directory *os.Root) error {
	directoryFile, err := directory.Open(".")
	if err != nil {
		return fmt.Errorf("open list directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync list directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close list directory: %w", err)
	}
	return nil
}

func writeListFileAt(target approvedListFile, content []byte) error {
	return writeListFileAtBeforeRename(target, content, nil)
}

func writeListFileAtBeforeRename(target approvedListFile, content []byte, beforeRename func() error) error {
	directory, err := openListDirectory(target, true)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockListDirectory(lockFile)
	return writeListFileInDirectoryBeforeRename(directory, target, content, beforeRename)
}

func writeListFileInDirectoryBeforeRename(directory *os.Root, target approvedListFile, content []byte, beforeRename func() error) error {
	return writeListFileInDirectoryExpected(directory, target, content, nil, beforeRename)
}

func writeListFileInDirectoryFromSnapshot(directory *os.Root, target approvedListFile, content, snapshot []byte) error {
	digest := sha256.Sum256(snapshot)
	return writeListFileInDirectoryExpected(directory, target, content, &digest, nil)
}

func writeListFileInDirectoryExpected(directory *os.Root, target approvedListFile, content []byte, expectedDigest *[sha256.Size]byte, beforeRename func() error) error {
	identity, existed, err := inspectListDestination(directory, target)
	if err != nil {
		return fmt.Errorf("inspect list target %s: %w", target.name, err)
	}
	if expectedDigest != nil && (!existed || identity.digest != *expectedDigest) {
		return fmt.Errorf("list target changed after it was read: %s", target.name)
	}
	file, stagingName, err := createListStagingFile(directory, target)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if stagingName != "" {
			_ = directory.Remove(stagingName)
		}
	}()
	if identity.ownerKnown {
		if err := file.Chown(identity.uid, identity.gid); err != nil {
			return fmt.Errorf("preserve list target owner %s: %w", target.name, err)
		}
	}
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict list staging file for %s: %w", target.name, err)
	}
	if written, err := file.Write(content); err != nil {
		return fmt.Errorf("write list staging file for %s: %w", target.name, err)
	} else if written != len(content) {
		return fmt.Errorf("write list staging file for %s: %w", target.name, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync list staging file for %s: %w", target.name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close list staging file for %s: %w", target.name, err)
	}
	file = nil
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return err
		}
	}
	if err := verifyListDestination(directory, target, identity, existed); err != nil {
		return err
	}
	if err := directory.Rename(stagingName, target.name); err != nil {
		return fmt.Errorf("publish list target %s: %w", target.name, err)
	}
	stagingName = ""
	return syncListDirectory(directory)
}

func appendListFileAt(target approvedListFile, content []byte) (resultErr error) {
	directory, err := openListDirectory(target, true)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockListDirectory(lockFile)
	return appendListFileInDirectory(directory, target, content)
}

func appendListFileInDirectory(directory *os.Root, target approvedListFile, content []byte) (resultErr error) {
	file, created, err := openListFileInRoot(directory, target, os.O_WRONLY|os.O_APPEND, true)
	if err != nil {
		return fmt.Errorf("open list target %s for append: %w", target.name, err)
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil {
			resultErr = closeErr
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict list target %s: %w", target.name, err)
	}
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("append list target %s: %w", target.name, err)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if created {
		directoryFile, err := directory.Open(".")
		if err != nil {
			return err
		}
		if err := directoryFile.Sync(); err != nil {
			_ = directoryFile.Close()
			return err
		}
		return directoryFile.Close()
	}
	return nil
}

func removeFromListFileAt(target approvedListFile, line string) error {
	requested, err := parseCanonicalRecoveryListEntry(line, true)
	if err != nil {
		return fmt.Errorf("invalid recovery list entry: %w", err)
	}
	directory, err := openListDirectory(target, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockListDirectory(lockFile)
	content, err := readListFileInDirectory(directory, target)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	var newLines []string
	changed := false
	for _, existing := range lines {
		cleanExisting := strings.TrimSpace(existing)
		if cleanExisting == "" {
			continue
		}
		if strings.HasPrefix(cleanExisting, "#") {
			newLines = append(newLines, existing)
			continue
		}
		parsedExisting, parseErr := parseCanonicalRecoveryListEntry(cleanExisting, true)
		_, strictErr := parseCanonicalListEntry(cleanExisting, true)
		if parseErr != nil || strictErr != nil {
			changed = true
			continue
		}
		if sameListEntry(parsedExisting, requested) {
			changed = true
			continue
		}
		newLines = append(newLines, existing)
	}
	if !changed {
		return nil
	}
	return writeListFileInDirectoryFromSnapshot(directory, target, []byte(strings.Join(newLines, "\n")+"\n"), content)
}

func sanitizeLegacyListFileAt(target approvedListFile) (bool, error) {
	directory, err := openListDirectory(target, false)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return false, err
	}
	defer unlockListDirectory(lockFile)
	content, err := readListFileInDirectory(directory, target)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(content), "\n")
	newLines := make([]string, 0, len(lines))
	changed := false
	for _, line := range lines {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" {
			continue
		}
		if strings.HasPrefix(cleanLine, "#") {
			newLines = append(newLines, cleanLine)
			continue
		}
		if _, err := parseCanonicalListEntry(cleanLine, true); err != nil {
			changed = true
			continue
		}
		newLines = append(newLines, cleanLine)
	}
	if !changed {
		return false, nil
	}
	updated := []byte(strings.Join(newLines, "\n") + "\n")
	if err := writeListFileInDirectoryFromSnapshot(directory, target, updated, content); err != nil {
		return false, err
	}
	return true, nil
}

func sanitizeLegacyOperatorLists() (bool, error) {
	paths := []string{WhitelistV4, WhitelistV6, BlocklistV4, BlocklistV6, SSHBypass}
	targets := make([]approvedListFile, 0, len(paths))
	for _, path := range paths {
		target, err := approvedListFileForPath(path)
		if err != nil {
			return false, err
		}
		targets = append(targets, target)
	}
	return sanitizeLegacyListTargets(targets)
}

func sanitizeLegacyListTargets(targets []approvedListFile) (bool, error) {
	changed := false
	for _, target := range targets {
		fileChanged, err := sanitizeLegacyListFileAt(target)
		if err != nil {
			return false, fmt.Errorf("sanitize legacy operator list %s: %w", target.name, err)
		}
		changed = changed || fileChanged
	}
	return changed, nil
}

func removeExactListLine(content []byte, exactLine string) ([]byte, bool) {
	if len(content) == 0 {
		return content, false
	}
	exact := []byte(exactLine)
	updated := make([]byte, 0, len(content))
	changed := false
	for start := 0; start < len(content); {
		lineEnd := len(content)
		recordEnd := len(content)
		if offset := bytes.IndexByte(content[start:], '\n'); offset >= 0 {
			lineEnd = start + offset
			recordEnd = lineEnd + 1
		}
		if bytes.Equal(content[start:lineEnd], exact) {
			changed = true
		} else {
			updated = append(updated, content[start:recordEnd]...)
		}
		start = recordEnd
	}
	if !changed {
		return content, false
	}
	return updated, true
}

func retireLegacyMetadataWhitelistEntryAtBeforeRename(target approvedListFile, beforeRename func() error) (bool, error) {
	directory, err := openListDirectory(target, false)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return false, err
	}
	defer unlockListDirectory(lockFile)
	content, err := readListFileInDirectory(directory, target)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	updated, changed := removeExactListLine(content, legacyMetadataWhitelistIPv4)
	if !changed {
		return false, nil
	}
	expectedDigest := sha256.Sum256(content)
	if err := writeListFileInDirectoryExpected(directory, target, updated, &expectedDigest, beforeRename); err != nil {
		return false, err
	}
	return true, nil
}

func retireLegacyMetadataWhitelistEntryAt(target approvedListFile) (bool, error) {
	return retireLegacyMetadataWhitelistEntryAtBeforeRename(target, nil)
}

func retireLegacyMetadataWhitelistEntry() (bool, error) {
	target, err := approvedListFileForPath(WhitelistV4)
	if err != nil {
		return false, err
	}
	return retireLegacyMetadataWhitelistEntryAt(target)
}

func addToListFileAt(target approvedListFile, line string) error {
	requested, err := parseCanonicalListEntry(line, true)
	if err != nil {
		return fmt.Errorf("invalid list entry: %w", err)
	}
	canonicalLine := requested.String()
	directory, err := openListDirectory(target, true)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockListDirectory(lockFile)
	content, err := readListFileInDirectory(directory, target)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, existing := range strings.Split(string(content), "\n") {
		cleanExisting := strings.TrimSpace(existing)
		if cleanExisting == canonicalLine {
			return nil
		}
		parsedExisting, parseErr := parseCanonicalListEntry(cleanExisting, true)
		if parseErr == nil && sameListEntry(parsedExisting, requested) {
			return nil
		}
	}
	return appendListFileInDirectory(directory, target, []byte(canonicalLine+"\n"))
}

func removeIPFromListFileAt(target approvedListFile, ip string) (bool, bool, error) {
	directory, err := openListDirectory(target, false)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return false, false, err
	}
	defer unlockListDirectory(lockFile)
	content, err := readListFileInDirectory(directory, target)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	newContent, found, changed := removeListEntriesForIP(content, ip)
	if !changed {
		return false, false, nil
	}
	if err := writeListFileInDirectoryFromSnapshot(directory, target, newContent, content); err != nil {
		return false, false, err
	}
	return found, true, nil
}

const (
	WhitelistV4 = "/etc/syswarden/lists/syswarden_whitelist.ipv4"
	WhitelistV6 = "/etc/syswarden/lists/syswarden_whitelist.ipv6"
	BlocklistV4 = "/etc/syswarden/lists/syswarden_blacklist.ipv4"
	BlocklistV6 = "/etc/syswarden/lists/syswarden_blacklist.ipv6"
	SSHBypass   = "/etc/syswarden/ssh_whitelist.txt" // #nosec
)

// IsValidIP checks whether a string is a canonicalizable IPv4, IPv6, or CIDR value.
func IsValidIP(ip string) (bool, bool) {
	if strings.TrimSpace(ip) != ip {
		return false, false
	}
	entry, err := parseCanonicalListEntry(ip, false)
	return err == nil, err == nil && entry.isIPv4
}

func canonicalWhitelistCandidates(candidates ...string) ([]string, []string) {
	ipv4 := make([]string, 0, len(candidates))
	ipv6 := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		entry, err := parseCanonicalListEntry(candidate, false)
		if err != nil {
			continue
		}
		if _, exists := seen[entry.network]; exists {
			continue
		}
		seen[entry.network] = struct{}{}
		if entry.isIPv4 {
			ipv4 = append(ipv4, entry.network)
		} else {
			ipv6 = append(ipv6, entry.network)
		}
	}
	return ipv4, ipv6
}

// addToFile safely appends a line to a file if it doesn't already exist
func addToFile(path, line string) error {
	target, err := approvedListFileForPath(path)
	if err != nil {
		return err
	}
	return addToListFileAt(target, line)
}

// removeFromFile removes a line from a file
func removeFromFile(path, line string) error {
	target, err := approvedListFileForPath(path)
	if err != nil {
		return err
	}
	return removeFromListFileAt(target, line)
}

// AddToWhitelist appends an IP securely to the whitelist and reloads
func AddToWhitelist(ip string, port string) error {
	entry, err := newCanonicalListEntry(ip, port)
	if err != nil {
		return fmt.Errorf("invalid whitelist entry: %w", err)
	}
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before whitelist mutation: %w", err)
	}

	// Remove from blocklist just in case
	fileToRemove := BlocklistV6
	if entry.isIPv4 {
		fileToRemove = BlocklistV4
	}
	if err := removeFromFile(fileToRemove, entry.network); err != nil {
		return fmt.Errorf("remove IP from blocklist before whitelisting: %w", err)
	}

	file := WhitelistV6
	if entry.isIPv4 {
		file = WhitelistV4
	}

	if err := addToFile(file, entry.String()); err != nil {
		return err
	}
	if err := ApplyPolicies(); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s safely whitelisted.\n", entry.String())
	return nil
}

// RemoveFromWhitelist removes an IP from the whitelist
func RemoveFromWhitelist(ip string) error {
	entry, err := parseCanonicalRecoveryListEntry(ip, false)
	if err != nil {
		return fmt.Errorf("invalid IP address: %w", err)
	}
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before whitelist mutation: %w", err)
	}
	file := WhitelistV6
	if entry.isIPv4 {
		file = WhitelistV4
	}
	target, err := approvedListFileForPath(file)
	if err != nil {
		return err
	}
	found, changed, err := removeIPFromListFileAt(target, entry.network)
	if err != nil {
		return fmt.Errorf("remove IP from whitelist: %w", err)
	}
	cleanupChanged, err := sanitizeLegacyOperatorLists()
	if err != nil {
		return err
	}
	if changed || cleanupChanged {
		if err := ApplyPolicies(); err != nil {
			return err
		}
	}
	if found {
		fmt.Printf("[SUCCESS] IP %s removed from whitelist.\n", ip)
		return nil
	}
	fmt.Printf("[INFO] IP %s not found in whitelist.\n", ip)
	return nil
}

// AddToBlocklist appends an IP securely to the blocklist and reloads
func AddToBlocklist(ip string) error {
	entry, err := parseCanonicalListEntry(ip, false)
	if err != nil {
		return fmt.Errorf("invalid IP address: %w", err)
	}
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before blocklist mutation: %w", err)
	}

	file := BlocklistV6
	if entry.isIPv4 {
		file = BlocklistV4
	}

	if err := addToFile(file, entry.network); err != nil {
		return err
	}

	if err := ApplyPolicies(); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s safely blocklisted.\n", ip)
	return nil
}

func completeBlocklistRemoval(
	ip string,
	output io.Writer,
	applyPolicies func() error,
	syncHAUnban func([]string) error,
) error {
	if err := applyPolicies(); err != nil {
		return fmt.Errorf("apply firewall policies after blocklist removal: %w", err)
	}
	if err := syncHAUnban([]string{ip}); err != nil {
		return fmt.Errorf("synchronize HA unban after blocklist removal: %w", err)
	}
	_, err := fmt.Fprintf(output, "[SUCCESS] IP %s removed from blocklist.\n", ip)
	return err
}

// RemoveFromBlocklist removes an IP from the blocklist
func RemoveFromBlocklist(ip string) error {
	entry, err := parseCanonicalRecoveryListEntry(ip, false)
	if err != nil {
		return fmt.Errorf("invalid IP address: %w", err)
	}
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before blocklist mutation: %w", err)
	}

	file := BlocklistV6
	if entry.isIPv4 {
		file = BlocklistV4
	}

	if err := removeFromFile(file, entry.network); err != nil {
		return err
	}
	if _, err := sanitizeLegacyOperatorLists(); err != nil {
		return err
	}
	return completeBlocklistRemoval(entry.network, os.Stdout, ApplyPolicies, network.SyncHAUnban)
}

// AllowSSH adds an IP to the SSH bypass list
func AllowSSH(ip string, port string) error {
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before SSH bypass mutation: %w", err)
	}
	configuredPort := ""
	if config.GlobalConfig != nil {
		configuredPort = config.GlobalConfig.SSHPort
	}
	effectivePort, err := effectiveSSHPort(configuredPort)
	if err != nil {
		return err
	}
	entry, err := newCanonicalSSHBypassEntry(ip, port, effectivePort)
	if err != nil {
		return fmt.Errorf("invalid SSH bypass entry: %w", err)
	}
	if err := addToFile(SSHBypass, entry.String()); err != nil {
		return err
	}
	if err := ApplyPolicies(); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] SSH Bypass granted for %s.\n", entry.String())
	return nil
}

// RevokeSSH removes an IP from the SSH bypass list
func RevokeSSH(ip string) error {
	entry, err := parseCanonicalRecoveryListEntry(ip, false)
	if err != nil {
		return fmt.Errorf("invalid IP address: %w", err)
	}
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before SSH bypass mutation: %w", err)
	}
	target, err := approvedListFileForPath(SSHBypass)
	if err != nil {
		return err
	}
	found, changed, err := removeIPFromListFileAt(target, entry.network)
	if err != nil {
		return fmt.Errorf("remove IP from SSH bypass list: %w", err)
	}
	cleanupChanged, err := sanitizeLegacyOperatorLists()
	if err != nil {
		return err
	}
	if changed || cleanupChanged {
		if err := ApplyPolicies(); err != nil {
			return err
		}
	}
	if found {
		fmt.Printf("[SUCCESS] SSH Bypass revoked for %s.\n", ip)
		return nil
	}
	fmt.Printf("[INFO] IP %s not found in SSH bypass list.\n", ip)
	return nil
}

func listEntryIP(entry string) string {
	parsed, err := parseCanonicalListEntry(entry, true)
	if err != nil {
		return ""
	}
	return parsed.network
}

func formatListEntry(ip, port string) string {
	entry, err := newCanonicalListEntry(ip, port)
	if err != nil {
		return ""
	}
	return entry.String()
}

func removeListEntriesForIP(content []byte, ip string) ([]byte, bool, bool) {
	target, targetErr := parseCanonicalRecoveryListEntry(ip, false)
	lines := strings.Split(string(content), "\n")
	newLines := make([]string, 0, len(lines))
	found := false
	changed := false
	for _, line := range lines {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" {
			continue
		}
		if strings.HasPrefix(cleanLine, "#") {
			newLines = append(newLines, cleanLine)
			continue
		}
		entry, entryErr := parseCanonicalRecoveryListEntry(cleanLine, true)
		_, strictErr := parseCanonicalListEntry(cleanLine, true)
		if entryErr != nil || strictErr != nil {
			changed = true
			if targetErr == nil && entryErr == nil && sameListNetwork(entry, target) {
				found = true
			}
			continue
		}
		if targetErr == nil && entryErr == nil && sameListNetwork(entry, target) {
			found = true
			changed = true
			continue
		}
		newLines = append(newLines, cleanLine)
	}
	return []byte(strings.Join(newLines, "\n") + "\n"), found, changed
}

func WhitelistInfra() error {
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before infrastructure whitelist mutation: %w", err)
	}
	retiredLegacyMetadata, err := retireLegacyMetadataWhitelistEntry()
	if err != nil {
		return fmt.Errorf("retire legacy metadata whitelist entry: %w", err)
	}
	fmt.Println("[INFO] SYSWARDEN Auto-Whitelist Infrastructure")

	// 1. Admin IP Detection
	adminIP := ""
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		adminIP = strings.Split(sshConn, " ")[0]
	} else {
		sshClient := os.Getenv("SSH_CLIENT")
		if sshClient != "" {
			adminIP = strings.Split(sshClient, " ")[0]
		}
	}
	// Read DNS
	var dnsIPs []string
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil { // #nosec
		lines := strings.Split(string(b), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "nameserver ") {
				parts := strings.Fields(l)
				if len(parts) >= 2 {
					dnsIPs = append(dnsIPs, parts[1])
				}
			}
		}
	}

	// Read Gateway
	var gatewayIPs []string
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output() // #nosec
	if err == nil {
		fields := strings.Fields(string(out))
		for i, v := range fields {
			if v == "via" && i+1 < len(fields) {
				gatewayIPs = append(gatewayIPs, fields[i+1])
			}
		}
	}
	ips := whitelistInfraIPv4Candidates(adminIP, dnsIPs, gatewayIPs)
	if entry, parseErr := parseCanonicalListEntry(adminIP, false); parseErr == nil && entry.isIPv4 {
		for _, ip := range ips {
			if ip == entry.network {
				fmt.Printf("[+] Auto-detected Admin SSH IP: %s\n", entry.network)
				break
			}
		}
	}

	added := false
	for _, ip := range ips {
		valid, isIPv4 := IsValidIP(ip)
		if valid && isIPv4 {
			content, _ := os.ReadFile(WhitelistV4) // #nosec
			entry, parseErr := parseCanonicalListEntry(ip, false)
			if parseErr == nil && !listContentContainsNetwork(content, entry) {
				if err := addToFile(WhitelistV4, entry.network); err != nil {
					return fmt.Errorf("persist infrastructure whitelist entry %s: %w", entry.network, err)
				}
				fmt.Printf("[+] Auto-whitelisted: %s\n", ip)
				added = true
			}
		}
	}

	return applyWhitelistInfraChanges(added, retiredLegacyMetadata, ApplyPolicies)
}

func whitelistInfraIPv4Candidates(adminIP string, dnsIPs, gatewayIPs []string) []string {
	candidates := make([]string, 0, 1+len(dnsIPs)+len(gatewayIPs))
	if adminIP != "" && adminIP != "127.0.0.1" {
		candidates = append(candidates, adminIP)
	}
	candidates = append(candidates, dnsIPs...)
	candidates = append(candidates, gatewayIPs...)
	ipv4, _ := canonicalWhitelistCandidates(candidates...)
	return ipv4
}

func applyWhitelistInfraChanges(added, retiredLegacyMetadata bool, applyPolicies func() error) error {
	if added || retiredLegacyMetadata {
		return applyPolicies()
	}
	fmt.Println("[SUCCESS] All critical IPs are already whitelisted.")
	return nil
}

// CheckIP performs a global diagnostic on an IP
func CheckIP(ip string) {
	target, err := parseCanonicalRecoveryListEntry(ip, false)
	if err != nil {
		fmt.Printf("[ERROR] Invalid IP address: %s\n", ip)
		return
	}

	fmt.Printf("\n=== SYSWARDEN Global Search: %s ===\n", ip)

	checkFile := func(filepath, name string) {
		fmt.Printf("[Storage] %-20s : ", name)
		content, err := os.ReadFile(filepath) // #nosec
		if err == nil && listContentContainsNetwork(content, target) {
			fmt.Println("PRESENT")
		} else {
			fmt.Println("Not Found")
		}
	}

	checkFile(WhitelistV4, "Global Whitelist (v4)")
	checkFile(WhitelistV6, "Global Whitelist (v6)")
	checkFile(SSHBypass, "SSH Bypass")
	checkFile(BlocklistV4, "Global Blocklist (v4)")
	checkFile(BlocklistV6, "Global Blocklist (v6)")

	fmt.Printf("[Kernel]  Active Nftables      : ")
	out, err := exec.Command("nft", "list", "ruleset").Output() // #nosec
	if err == nil && nftRulesetContainsExactNetwork(out, target) {
		fmt.Println("FOUND in active memory")
	} else {
		fmt.Println("Not found in active memory")
	}
	fmt.Println()
}

// ListIPs prints out all custom IP lists
func ListIPs() {
	fmt.Printf("\n=== SYSWARDEN Custom IP Registry (%s) ===\n", system.Version)

	printFile := func(filepath, title string) {
		fmt.Printf("\n[ %s ]\n", title)
		content, err := os.ReadFile(filepath) // #nosec
		if err != nil || len(strings.TrimSpace(string(content))) == 0 {
			fmt.Println("  None")
			return
		}
		lines := strings.Split(string(content), "\n")
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				fmt.Printf("  -> %s\n", l)
			}
		}
	}

	printFile(WhitelistV4, "Global Whitelisted IPv4")
	printFile(WhitelistV6, "Global Whitelisted IPv6")
	printFile(SSHBypass, "SSH-Only Bypass")
	printFile(BlocklistV4, "Manually Blocked IPv4")
	printFile(BlocklistV6, "Manually Blocked IPv6")
	fmt.Println()
}

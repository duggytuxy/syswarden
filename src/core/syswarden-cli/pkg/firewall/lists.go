package firewall

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"syswarden-cli/pkg/network"
	"syswarden-cli/pkg/system"
)

type approvedListFile struct {
	directory string
	name      string
}

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
	for _, existing := range lines {
		if strings.TrimSpace(existing) != "" && strings.TrimSpace(existing) != line {
			newLines = append(newLines, existing)
		}
	}
	return writeListFileInDirectoryFromSnapshot(directory, target, []byte(strings.Join(newLines, "\n")+"\n"), content)
}

func addToListFileAt(target approvedListFile, line string) error {
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
		if strings.TrimSpace(existing) == line {
			return nil
		}
	}
	return appendListFileInDirectory(directory, target, []byte(line+"\n"))
}

func removeIPFromListFileAt(target approvedListFile, ip string) (bool, error) {
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
	newContent, found := removeListEntriesForIP(content, ip)
	if !found {
		return false, nil
	}
	if err := writeListFileInDirectoryFromSnapshot(directory, target, newContent, content); err != nil {
		return false, err
	}
	return true, nil
}

const (
	WhitelistV4 = "/etc/syswarden/lists/syswarden_whitelist.ipv4"
	WhitelistV6 = "/etc/syswarden/lists/syswarden_whitelist.ipv6"
	BlocklistV4 = "/etc/syswarden/lists/syswarden_blacklist.ipv4"
	BlocklistV6 = "/etc/syswarden/lists/syswarden_blacklist.ipv6"
	SSHBypass   = "/etc/syswarden/ssh_whitelist.txt" // #nosec
)

// IsValidIP checks if a string is a valid IPv4 or IPv6 or a valid CIDR subnet
func IsValidIP(ip string) (bool, bool) {
	// 1. Check if it's a standard single IP
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		return true, parsedIP.To4() != nil
	}

	// 2. Check if it's a CIDR block (ex: 10.0.0.0/24)
	parsedIP, _, err := net.ParseCIDR(ip)
	if err == nil && parsedIP != nil {
		return true, parsedIP.To4() != nil
	}

	return false, false
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
	valid, isIPv4 := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	entry := formatListEntry(ip, port)

	// Remove from blocklist just in case
	fileToRemove := BlocklistV6
	if isIPv4 {
		fileToRemove = BlocklistV4
	}
	if err := removeFromFile(fileToRemove, ip); err != nil {
		return fmt.Errorf("remove IP from blocklist before whitelisting: %w", err)
	}

	file := WhitelistV6
	if isIPv4 {
		file = WhitelistV4
	}

	if err := addToFile(file, entry); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s safely whitelisted.\n", entry)
	return ApplyPolicies()
}

// RemoveFromWhitelist removes an IP from the whitelist
func RemoveFromWhitelist(ip string) error {
	valid, isIPv4 := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	file := WhitelistV6
	if isIPv4 {
		file = WhitelistV4
	}
	// Note: We might need to iterate and remove even if it has a port.
	// For simplicity, we'll try to remove exact IP, but we should handle IP:PORT stripping.
	target, err := approvedListFileForPath(file)
	if err != nil {
		return err
	}
	found, err := removeIPFromListFileAt(target, ip)
	if err != nil {
		return fmt.Errorf("remove IP from whitelist: %w", err)
	}
	if found {
		fmt.Printf("[SUCCESS] IP %s removed from whitelist.\n", ip)
		return ApplyPolicies()
	}
	fmt.Printf("[INFO] IP %s not found in whitelist.\n", ip)
	return nil
}

// AddToBlocklist appends an IP securely to the blocklist and reloads
func AddToBlocklist(ip string) error {
	valid, isIPv4 := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	file := BlocklistV6
	if isIPv4 {
		file = BlocklistV4
	}

	if err := addToFile(file, ip); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s safely blocklisted.\n", ip)

	if runtime.GOOS == "freebsd" {
		_ = exec.Command("pfctl", "-k", ip).Run() // #nosec
	}

	return ApplyPolicies()
}

// RemoveFromBlocklist removes an IP from the blocklist
func RemoveFromBlocklist(ip string) error {
	valid, isIPv4 := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	file := BlocklistV6
	if isIPv4 {
		file = BlocklistV4
	}

	if err := removeFromFile(file, ip); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s removed from blocklist.\n", ip)

	// Synchronize UNBAN to HA cluster
	_ = network.SyncHAUnban([]string{ip})

	return ApplyPolicies()
}

// AllowSSH adds an IP to the SSH bypass list
func AllowSSH(ip string, port string) error {
	valid, _ := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	entry := formatListEntry(ip, port)
	if err := addToFile(SSHBypass, entry); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] SSH Bypass granted for %s.\n", entry)
	return ApplyPolicies()
}

// RevokeSSH removes an IP from the SSH bypass list
func RevokeSSH(ip string) error {
	valid, _ := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	target, err := approvedListFileForPath(SSHBypass)
	if err != nil {
		return err
	}
	found, err := removeIPFromListFileAt(target, ip)
	if err != nil {
		return fmt.Errorf("remove IP from SSH bypass list: %w", err)
	}
	if found {
		fmt.Printf("[SUCCESS] SSH Bypass revoked for %s.\n", ip)
		return ApplyPolicies()
	}
	fmt.Printf("[INFO] IP %s not found in SSH bypass list.\n", ip)
	return nil
}

func listEntryIP(entry string) string {
	if host, _, err := net.SplitHostPort(entry); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(entry, "[]")
}

func formatListEntry(ip, port string) string {
	if port == "" {
		return ip
	}
	return net.JoinHostPort(ip, port)
}

func removeListEntriesForIP(content []byte, ip string) ([]byte, bool) {
	lines := strings.Split(string(content), "\n")
	newLines := make([]string, 0, len(lines))
	found := false
	for _, line := range lines {
		cleanLine := strings.TrimSpace(line)
		if listEntryIP(cleanLine) == ip {
			found = true
			continue
		}
		if cleanLine != "" {
			newLines = append(newLines, cleanLine)
		}
	}
	return []byte(strings.Join(newLines, "\n") + "\n"), found
}

func WhitelistInfra() error {
	fmt.Println("[INFO] SYSWARDEN Auto-Whitelist Infrastructure")
	ips := []string{}

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
	if adminIP != "" && adminIP != "127.0.0.1" {
		ips = append(ips, adminIP)
		fmt.Printf("[+] Auto-detected Admin SSH IP: %s\n", adminIP)
	}

	ips = append(ips, "169.254.169.254")

	// Read DNS
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil { // #nosec
		lines := strings.Split(string(b), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "nameserver ") {
				parts := strings.Fields(l)
				if len(parts) >= 2 {
					ips = append(ips, parts[1])
				}
			}
		}
	}

	// Read Gateway
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output() // #nosec
	if err == nil {
		fields := strings.Fields(string(out))
		for i, v := range fields {
			if v == "via" && i+1 < len(fields) {
				ips = append(ips, fields[i+1])
			}
		}
	}

	added := false
	for _, ip := range ips {
		valid, isIPv4 := IsValidIP(ip)
		if valid && isIPv4 {
			content, _ := os.ReadFile(WhitelistV4) // #nosec
			if !strings.Contains(string(content), ip+"\n") {
				_ = addToFile(WhitelistV4, ip)
				fmt.Printf("[+] Auto-whitelisted: %s\n", ip)
				added = true
			}
		}
	}

	if added {
		return ApplyPolicies()
	}
	fmt.Println("[SUCCESS] All critical IPs are already whitelisted.")
	return nil
}

// CheckIP performs a global diagnostic on an IP
func CheckIP(ip string) {
	valid, _ := IsValidIP(ip)
	if !valid {
		fmt.Printf("[ERROR] Invalid IP address: %s\n", ip)
		return
	}

	fmt.Printf("\n=== SYSWARDEN Global Search: %s ===\n", ip)

	checkFile := func(filepath, name string) {
		fmt.Printf("[Storage] %-20s : ", name)
		content, err := os.ReadFile(filepath) // #nosec
		if err == nil && strings.Contains(string(content), ip) {
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
	if err == nil && strings.Contains(string(out), ip) {
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

package network

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"syswarden-cli/pkg/system"
	"time"
)

const approvedFeedDirectory = "/etc/syswarden/lists"

var (
	approvedFeedBasename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*\.ipv[46]$`)
	approvedASN          = regexp.MustCompile(`^AS[0-9]{1,10}$`)
)

type feedFileTarget struct {
	directory string
	name      string
}

func approvedFeedFileForPath(path, suffix string) (feedFileTarget, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return feedFileTarget{}, fmt.Errorf("feed path must be absolute and canonical: %q", path)
	}
	if filepath.Dir(path) != approvedFeedDirectory {
		return feedFileTarget{}, fmt.Errorf("feed path must remain inside %s: %q", approvedFeedDirectory, path)
	}
	target := feedFileTarget{directory: approvedFeedDirectory, name: filepath.Base(path)}
	if err := validateFeedFileTarget(target, suffix); err != nil {
		return feedFileTarget{}, err
	}
	return target, nil
}

func validateFeedFileTarget(target feedFileTarget, suffix string) error {
	if suffix != ".ipv4" && suffix != ".ipv6" {
		return fmt.Errorf("unsupported feed suffix: %q", suffix)
	}
	if !filepath.IsAbs(target.directory) || filepath.Clean(target.directory) != target.directory {
		return fmt.Errorf("feed directory must be absolute and canonical: %q", target.directory)
	}
	for _, component := range strings.Split(filepath.ToSlash(target.directory), "/") {
		if component == "." || component == ".." {
			return fmt.Errorf("feed directory contains traversal: %q", target.directory)
		}
	}
	if filepath.Base(target.name) != target.name || strings.ContainsAny(target.name, `/\\`) ||
		!approvedFeedBasename.MatchString(target.name) || !strings.HasSuffix(target.name, suffix) {
		return fmt.Errorf("feed name is not an approved %s basename: %q", suffix, target.name)
	}
	return nil
}

func openFeedDirectory(target feedFileTarget, suffix string, create bool) (*os.Root, error) {
	if err := validateFeedFileTarget(target, suffix); err != nil {
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
				return nil, fmt.Errorf("create feed directory %s: %w", target.directory, mkdirErr)
			}
			info, statErr = currentRoot.Lstat(component)
		}
		if statErr != nil {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("inspect feed directory %s: %w", target.directory, statErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("feed directory component is not a real directory: %s", component)
		}
		nextRoot, err := currentRoot.OpenRoot(component)
		if err != nil {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("open feed directory component %s: %w", component, err)
		}
		openedInfo, err := nextRoot.Stat(".")
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = nextRoot.Close()
			_ = currentRoot.Close()
			return nil, fmt.Errorf("feed directory component changed while opening: %s", component)
		}
		_ = currentRoot.Close()
		currentRoot = nextRoot
	}
	return currentRoot, nil
}

func readFeedFileAt(target feedFileTarget, suffix string) ([]byte, error) {
	directory, err := openFeedDirectory(target, suffix, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	return readFeedFileInDirectory(directory, target)
}

func readFeedFileInDirectory(directory *os.Root, target feedFileTarget) ([]byte, error) {
	file, _, err := openFeedFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(file)
}

func lockFeedDirectory(directory *os.Root) (*os.File, error) {
	lockFile, err := directory.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open feed directory lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock feed directory: %w", err)
	}
	return lockFile, nil
}

func unlockFeedDirectory(lockFile *os.File) {
	_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	_ = lockFile.Close()
}

func openFeedFileInRoot(directory *os.Root, target feedFileTarget, flags int, create bool) (*os.File, bool, error) {
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
		return nil, false, fmt.Errorf("feed target is not a regular file: %s", target.name)
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
		return nil, false, fmt.Errorf("feed target changed while opening: %s", target.name)
	}
	return file, created, nil
}

type feedFileIdentity struct {
	info       fs.FileInfo
	digest     [sha256.Size]byte
	uid        int
	gid        int
	ownerKnown bool
}

func snapshotFeedFile(file *os.File) (fs.FileInfo, [sha256.Size]byte, error) {
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
		return nil, digest, fmt.Errorf("feed target changed while snapshotting")
	}
	copy(digest[:], hash.Sum(nil))
	return after, digest, nil
}

func sameFeedFileState(expected feedFileIdentity, actualInfo fs.FileInfo, actualDigest [sha256.Size]byte) bool {
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

func inspectFeedDestination(directory *os.Root, target feedFileTarget) (feedFileIdentity, bool, error) {
	pathInfo, err := directory.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return feedFileIdentity{}, false, nil
	}
	if err != nil {
		return feedFileIdentity{}, false, err
	}
	if !pathInfo.Mode().IsRegular() {
		return feedFileIdentity{}, false, fmt.Errorf("feed target is not a regular file: %s", target.name)
	}
	file, _, err := openFeedFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return feedFileIdentity{}, false, err
	}
	openedInfo, digest, statErr := snapshotFeedFile(file)
	closeErr := file.Close()
	if statErr != nil {
		return feedFileIdentity{}, false, statErr
	}
	if closeErr != nil {
		return feedFileIdentity{}, false, closeErr
	}
	identity := feedFileIdentity{info: openedInfo, digest: digest}
	if stat, ok := openedInfo.Sys().(*syscall.Stat_t); ok {
		identity.uid = int(stat.Uid)
		identity.gid = int(stat.Gid)
		identity.ownerKnown = true
	}
	return identity, true, nil
}

func createFeedStagingFile(directory *os.Root, target feedFileTarget) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate feed staging name: %w", err)
		}
		name := "." + target.name + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create feed staging file: %w", err)
		}
		return file, name, nil
	}
	return nil, "", fmt.Errorf("create feed staging file: too many name collisions")
}

func verifyFeedDestination(directory *os.Root, target feedFileTarget, identity feedFileIdentity, existed bool) error {
	current, err := directory.Lstat(target.name)
	if !existed {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("feed target appeared before publication: %s", target.name)
	}
	if err != nil {
		return fmt.Errorf("reinspect feed target %s: %w", target.name, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(identity.info, current) {
		return fmt.Errorf("feed target changed before publication: %s", target.name)
	}
	file, _, err := openFeedFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return fmt.Errorf("reopen feed target %s before publication: %w", target.name, err)
	}
	actualInfo, actualDigest, snapshotErr := snapshotFeedFile(file)
	closeErr := file.Close()
	if snapshotErr != nil {
		return fmt.Errorf("resnapshot feed target %s: %w", target.name, snapshotErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close feed target %s after resnapshot: %w", target.name, closeErr)
	}
	if !sameFeedFileState(identity, actualInfo, actualDigest) {
		return fmt.Errorf("feed target content or metadata changed before publication: %s", target.name)
	}
	return nil
}

func syncFeedDirectory(directory *os.Root) error {
	directoryFile, err := directory.Open(".")
	if err != nil {
		return fmt.Errorf("open feed directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync feed directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close feed directory: %w", err)
	}
	return nil
}

func writeFeedFileAt(target feedFileTarget, suffix string, content []byte) error {
	return writeFeedFileAtBeforeRename(target, suffix, content, nil)
}

func writeFeedFileAtBeforeRename(target feedFileTarget, suffix string, content []byte, beforeRename func() error) error {
	directory, err := openFeedDirectory(target, suffix, true)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockFeedDirectory(lockFile)
	return writeFeedFileInDirectoryBeforeRename(directory, target, content, beforeRename)
}

func writeFeedFileInDirectoryBeforeRename(directory *os.Root, target feedFileTarget, content []byte, beforeRename func() error) error {
	return writeFeedFileInDirectoryExpected(directory, target, content, nil, beforeRename)
}

func writeFeedFileInDirectoryFromSnapshot(directory *os.Root, target feedFileTarget, content, snapshot []byte) error {
	digest := sha256.Sum256(snapshot)
	return writeFeedFileInDirectoryExpected(directory, target, content, &digest, nil)
}

func writeFeedFileInDirectoryExpected(directory *os.Root, target feedFileTarget, content []byte, expectedDigest *[sha256.Size]byte, beforeRename func() error) error {
	identity, existed, err := inspectFeedDestination(directory, target)
	if err != nil {
		return fmt.Errorf("inspect feed target %s: %w", target.name, err)
	}
	if expectedDigest != nil && (!existed || identity.digest != *expectedDigest) {
		return fmt.Errorf("feed target changed after it was read: %s", target.name)
	}
	file, stagingName, err := createFeedStagingFile(directory, target)
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
			return fmt.Errorf("preserve feed target owner %s: %w", target.name, err)
		}
	}
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict feed staging file for %s: %w", target.name, err)
	}
	if written, err := file.Write(content); err != nil {
		return fmt.Errorf("write feed staging file for %s: %w", target.name, err)
	} else if written != len(content) {
		return fmt.Errorf("write feed staging file for %s: %w", target.name, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync feed staging file for %s: %w", target.name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close feed staging file for %s: %w", target.name, err)
	}
	file = nil
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return err
		}
	}
	if err := verifyFeedDestination(directory, target, identity, existed); err != nil {
		return err
	}
	if err := directory.Rename(stagingName, target.name); err != nil {
		return fmt.Errorf("publish feed target %s: %w", target.name, err)
	}
	stagingName = ""
	return syncFeedDirectory(directory)
}

func appendFeedFileAt(target feedFileTarget, suffix string, content []byte) (resultErr error) {
	directory, err := openFeedDirectory(target, suffix, true)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockFeedDirectory(lockFile)
	return appendFeedFileInDirectory(directory, target, content)
}

func appendFeedFileInDirectory(directory *os.Root, target feedFileTarget, content []byte) (resultErr error) {
	file, created, err := openFeedFileInRoot(directory, target, os.O_WRONLY|os.O_APPEND, true)
	if err != nil {
		return fmt.Errorf("open feed target %s for append: %w", target.name, err)
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil {
			resultErr = closeErr
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict feed target %s: %w", target.name, err)
	}
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("append feed target %s: %w", target.name, err)
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

// SecureDownloader downloads files with strict timeouts and resource limits
func SecureDownloader(ctx context.Context, url string, destPath string, expectedHash string) error {
	suffix := ".ipv4"
	if strings.HasSuffix(destPath, ".ipv6") {
		suffix = ".ipv6"
	}
	target, err := approvedFeedFileForPath(destPath, suffix)
	if err != nil {
		return err
	}
	var resp *http.Response
	client := &http.Client{Timeout: 30 * time.Second}

	for retries := 0; retries < 3; retries++ {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(2 * time.Second) // Wait before retry
	}

	if err != nil {
		return fmt.Errorf("download failed for %s after 3 retries: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code %d for %s after 3 retries", resp.StatusCode, url)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	if expectedHash != "" {
		hash := sha256.Sum256(bodyBytes)
		hashStr := hex.EncodeToString(hash[:])
		if !strings.EqualFold(hashStr, expectedHash) {
			return fmt.Errorf("SHA256 mismatch for %s: expected %s, got %s", url, expectedHash, hashStr)
		}
	}

	if err := writeFeedFileAt(target, suffix, bodyBytes); err != nil {
		return fmt.Errorf("failed to write destination file %s: %w", destPath, err)
	}

	if strings.HasSuffix(destPath, ".ipv6") {
		return CleanCIDRListV6(destPath)
	}
	return CleanCIDRList(destPath)
}

// CleanCIDRList ensures CWE-20 compliance by stripping any malformed IPs.
// Smart Parser: If IPv6 addresses are detected in an IPv4 list, they are automatically routed to the .ipv6 file.
func CleanCIDRList(filepath string) error {
	target, err := approvedFeedFileForPath(filepath, ".ipv4")
	if err != nil {
		return err
	}
	return cleanCIDRListAt(target)
}

func cleanCIDRListAt(target feedFileTarget) error {
	directory, err := openFeedDirectory(target, ".ipv4", false)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockFeedDirectory(lockFile)
	content, err := readFeedFileInDirectory(directory, target)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var validCIDRs []string
	var validCIDRsV6 []string
	seen := make(map[string]bool)
	seenV6 := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		isV6 := strings.Contains(line, ":")
		if !strings.Contains(line, "/") {
			if isV6 {
				line = line + "/128"
			} else {
				line = line + "/32"
			}
		}

		ip, _, err := net.ParseCIDR(line)
		if err == nil {
			if ip.To4() != nil {
				if !seen[line] {
					seen[line] = true
					validCIDRs = append(validCIDRs, line)
				}
			} else if ip.To16() != nil {
				if !seenV6[line] {
					seenV6[line] = true
					validCIDRsV6 = append(validCIDRsV6, line)
				}
			}
		}
	}

	var v6Target feedFileTarget
	if len(validCIDRsV6) > 0 {
		v6Target = feedFileTarget{
			directory: target.directory,
			name:      strings.TrimSuffix(target.name, ".ipv4") + ".ipv6",
		}
		if err := validateFeedFileTarget(v6Target, ".ipv6"); err != nil {
			return err
		}
		if _, _, err := inspectFeedDestination(directory, v6Target); err != nil {
			return fmt.Errorf("inspect routed IPv6 feed: %w", err)
		}
	}

	// Write IPv4 back to the original file
	if err := writeFeedFileInDirectoryFromSnapshot(directory, target, []byte(strings.Join(validCIDRs, "\n")+"\n"), content); err != nil {
		return err
	}

	// Smart Routing: Route extracted IPv6 to the corresponding .ipv6 file
	if len(validCIDRsV6) > 0 {
		if err := appendFeedFileInDirectory(directory, v6Target, []byte(strings.Join(validCIDRsV6, "\n")+"\n")); err != nil {
			return err
		}
	}
	return nil
}

// CleanCIDRListV6 ensures CWE-20 compliance for IPv6 lists.
// Smart Parser: If IPv4 addresses are detected in an IPv6 list, they are automatically routed to the .ipv4 file.
func CleanCIDRListV6(filepath string) error {
	target, err := approvedFeedFileForPath(filepath, ".ipv6")
	if err != nil {
		return err
	}
	return cleanCIDRListV6At(target)
}

func cleanCIDRListV6At(target feedFileTarget) error {
	directory, err := openFeedDirectory(target, ".ipv6", false)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockFeedDirectory(lockFile)
	content, err := readFeedFileInDirectory(directory, target)
	if err != nil {
		return err // file might not exist if no IPv6 routes were found, that's okay
	}

	lines := strings.Split(string(content), "\n")
	var validCIDRsV6 []string
	var validCIDRsV4 []string
	seenV6 := make(map[string]bool)
	seenV4 := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		isV6 := strings.Contains(line, ":")
		if !strings.Contains(line, "/") {
			if isV6 {
				line = line + "/128"
			} else {
				line = line + "/32"
			}
		}

		ip, _, err := net.ParseCIDR(line)
		if err == nil {
			if ip.To4() == nil && ip.To16() != nil {
				if !seenV6[line] {
					seenV6[line] = true
					validCIDRsV6 = append(validCIDRsV6, line)
				}
			} else if ip.To4() != nil {
				if !seenV4[line] {
					seenV4[line] = true
					validCIDRsV4 = append(validCIDRsV4, line)
				}
			}
		}
	}

	var v4Target feedFileTarget
	if len(validCIDRsV4) > 0 {
		v4Target = feedFileTarget{
			directory: target.directory,
			name:      strings.TrimSuffix(target.name, ".ipv6") + ".ipv4",
		}
		if err := validateFeedFileTarget(v4Target, ".ipv4"); err != nil {
			return err
		}
		if _, _, err := inspectFeedDestination(directory, v4Target); err != nil {
			return fmt.Errorf("inspect routed IPv4 feed: %w", err)
		}
	}

	// Write IPv6 back to the original file
	if err := writeFeedFileInDirectoryFromSnapshot(directory, target, []byte(strings.Join(validCIDRsV6, "\n")+"\n"), content); err != nil {
		return err
	}

	// Smart Routing: Route extracted IPv4 to the corresponding .ipv4 file
	if len(validCIDRsV4) > 0 {
		if err := appendFeedFileInDirectory(directory, v4Target, []byte(strings.Join(validCIDRsV4, "\n")+"\n")); err != nil {
			return err
		}
	}
	return nil
}

// DownloadFeeds manages the download of GeoIP, ASN, and OSINT feeds
func DownloadFeeds(mirrorURL, customURLIPv6, customHash, customHashIPv6, listChoice, geoCodes, asnList, geoAllowed, asnAllowed string, lanMode, useSpamhaus bool) error {
	fmt.Println("[INFO] Initializing Network Intelligence Feeds...")

	if lanMode {
		fmt.Println("[INFO] LAN Mode is ENABLED. Skipping public Data-Shield, GeoIP, ASN, and OSINT feeds to conserve local resources.")
		return nil
	}

	// Increased global context timeout to 15 minutes to allow full mirror failover rotation
	// without hitting "context deadline exceeded" prematurely.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if geoCodes != "" {
		codes := strings.Split(geoCodes, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" || code == "none" {
				continue
			}
			// Download IPv4
			url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(code))
			dest := fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP [%s] (IPv4)... ", code)
			if err := SecureDownloader(ctx, url, dest, ""); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}

			// Download IPv6
			urlV6 := fmt.Sprintf("https://www.ipdeny.com/ipv6/ipaddresses/blocks/%s.zone", strings.ToLower(code))
			destV6 := fmt.Sprintf("/etc/syswarden/lists/%s.ipv6", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP [%s] (IPv6)... ", code)
			if err := SecureDownloader(ctx, urlV6, destV6, ""); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
		}
	}

	// Build the deduplicated list of ASNs to drop
	asnSet := make(map[string]bool)
	var asnsToDrop []string

	if asnList != "" {
		asns := strings.Split(asnList, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn == "" || asn == "none" || asn == "auto" {
				continue
			}
			if !strings.HasPrefix(asn, "AS") {
				asn = "AS" + asn
			}
			asn = strings.ToUpper(asn)
			if !asnSet[asn] {
				asnSet[asn] = true
				asnsToDrop = append(asnsToDrop, asn)
			}
		}
	}

	if useSpamhaus {
		fmt.Printf("Fetching Spamhaus ASN-DROP list... ")
		spamhausASNs, err := FetchSpamhausASNs(ctx)
		if err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Printf("OK (%d ASNs found)\n", len(spamhausASNs))
			for _, asn := range spamhausASNs {
				asn = strings.ToUpper(asn)
				if !asnSet[asn] {
					asnSet[asn] = true
					asnsToDrop = append(asnsToDrop, asn)
				}
			}
		}
	}

	for i, asn := range asnsToDrop {
		dest := fmt.Sprintf("/etc/syswarden/lists/%s", asn)
		fmt.Printf("Downloading ASN [%s]... ", asn)
		if err := FetchASNWhois(asn, dest); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
		// Rate limit RADB queries to prevent blacklisting
		if i < len(asnsToDrop)-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Download GeoIP ALLOW lists (Zero-Trust Mode)
	if geoAllowed != "" {
		codes := strings.Split(geoAllowed, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" || code == "none" {
				continue
			}
			// Download IPv4
			url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(code))
			dest := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP ALLOW [%s] (IPv4)... ", code)
			if err := SecureDownloader(ctx, url, dest, ""); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}

			// Download IPv6
			urlV6 := fmt.Sprintf("https://www.ipdeny.com/ipv6/ipaddresses/blocks/%s.zone", strings.ToLower(code))
			destV6 := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv6", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP ALLOW [%s] (IPv6)... ", code)
			if err := SecureDownloader(ctx, urlV6, destV6, ""); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
		}
	}

	// Download ASN ALLOW lists (Zero-Trust Mode)
	if asnAllowed != "" {
		asns := strings.Split(asnAllowed, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn == "" || asn == "none" || asn == "auto" {
				continue
			}
			if !strings.HasPrefix(asn, "AS") {
				asn = "AS" + asn
			}
			dest := fmt.Sprintf("/etc/syswarden/lists/allowed_%s", strings.ToUpper(asn))
			fmt.Printf("Downloading ASN ALLOW [%s]... ", asn)
			if err := FetchASNWhois(asn, dest); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
			time.Sleep(500 * time.Millisecond) // Parity: Prevent RADB rate limiting
		}
	}

	// Download IPv6 Custom Blocklist if configured
	if listChoice == "3" && customURLIPv6 != "" {
		fmt.Printf("Downloading Custom IPv6 Blocklist... ")
		if err := SecureDownloader(ctx, customURLIPv6, "/etc/syswarden/lists/syswarden_threatintel.ipv6", customHashIPv6); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
	}

	// Download Threat Intel Blocklist
	switch listChoice {
	case "4":
		fmt.Println("Downloading Threat Intel IPv4 Blocklist... SKIPPED (Option 4 'none')")
		// Clean up existing threat intel files to ensure Zero-Trust or 'none' posture is strictly enforced
		_ = os.Remove("/etc/syswarden/lists/syswarden_threatintel.ipv4")
		_ = os.Remove("/etc/syswarden/lists/syswarden_threatintel.ipv6")
	case "3":
		fmt.Printf("Downloading Custom Threat Intel IPv4 Blocklist... ")
		dataShieldUrl := strings.TrimRight(mirrorURL, "/")
		if err := SecureDownloader(ctx, dataShieldUrl, "/etc/syswarden/lists/syswarden_threatintel.ipv4", customHash); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
	default:
		fmt.Printf("Downloading Threat Intel IPv4 Blocklist... ")
		var success bool
		mirrors := system.SelectFastestThreatIntelMirror(listChoice)

		var lastErr error
		for _, url := range mirrors {
			if err := SecureDownloader(ctx, url, "/etc/syswarden/lists/syswarden_threatintel.ipv4", ""); err == nil {
				fmt.Println("OK")
				success = true
				break
			} else {
				lastErr = err
			}
		}
		if !success {
			fmt.Printf("FAILED (%v)\n", lastErr)
		}
	}

	// Download OSINT Feeds (CINS Army & Blocklist.de)
	switch listChoice {
	case "4", "3":
		fmt.Println("Downloading Free OSINT Feeds (CINS & Blocklist.de)... SKIPPED")
	default:
		fmt.Printf("Downloading Free OSINT Feeds (CINS & Blocklist.de)... ")
		if err := DownloadOSINT(ctx, "/etc/syswarden/lists/syswarden_threatintel"); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
	}

	return nil
}

// DownloadOSINT downloads free OSINT threat feeds and appends them to the destination files
func DownloadOSINT(ctx context.Context, destBase string) error {
	v4Target, err := approvedFeedFileForPath(destBase+".ipv4", ".ipv4")
	if err != nil {
		return err
	}
	v6Target, err := approvedFeedFileForPath(destBase+".ipv6", ".ipv6")
	if err != nil {
		return err
	}
	urls := []string{
		"https://cinsscore.com/list/ci-badguys.txt",
		"https://lists.blocklist.de/lists/all.txt",
	}

	var ipv4Lines []string
	var ipv6Lines []string

	for _, url := range urls {
		client := &http.Client{Timeout: 30 * time.Second}
		var resp *http.Response
		for retries := 0; retries < 3; retries++ {
			req, reqErr := http.NewRequestWithContext(ctx, "GET", url, nil)
			if reqErr != nil {
				continue
			}
			resp, err = client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				break
			}
			if resp != nil {
				_ = resp.Body.Close()
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			return fmt.Errorf("download OSINT feed %s: %w", url, err)
		}
		if resp == nil {
			return fmt.Errorf("download OSINT feed %s returned no response", url)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download OSINT feed %s returned status %d", url, resp.StatusCode)
		}
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, ":") {
				ipv6Lines = append(ipv6Lines, line)
			} else {
				ipv4Lines = append(ipv4Lines, line)
			}
		}
		scanErr := scanner.Err()
		closeErr := resp.Body.Close()
		if scanErr != nil {
			return fmt.Errorf("scan OSINT response: %w", scanErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close OSINT response: %w", closeErr)
		}
	}

	if len(ipv4Lines) > 0 {
		if err := appendFeedFileAt(v4Target, ".ipv4", []byte(strings.Join(ipv4Lines, "\n")+"\n")); err != nil {
			return err
		}
	}
	if len(ipv6Lines) > 0 {
		if err := appendFeedFileAt(v6Target, ".ipv6", []byte(strings.Join(ipv6Lines, "\n")+"\n")); err != nil {
			return err
		}
	}
	if _, err := readFeedFileAt(v6Target, ".ipv6"); err == nil {
		if err := cleanCIDRListV6At(v6Target); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, err := readFeedFileAt(v4Target, ".ipv4"); err == nil {
		return cleanCIDRListAt(v4Target)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// SetupFeedsCron configures a root cron job to update feeds hourly at a random minute
func SetupFeedsCron() error {
	fmt.Println("[INFO] Setting up automatic hourly updates for Threat Intelligence...")

	// Generate a random minute (1-59) to prevent "Thundering Herd" API collisions
	randomMinute := rand.Intn(59) + 1 // #nosec

	cronJob := fmt.Sprintf("%d * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1", randomMinute)

	// Add to crontab natively
	out, _ := exec.Command("crontab", "-l").Output() // #nosec
	lines := strings.Split(string(out), "\n")
	var newLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "syswarden-cli update-feeds") {
			newLines = append(newLines, line)
		}
	}
	newLines = append(newLines, cronJob)

	newCron := strings.Join(newLines, "\n") + "\n"
	cmd := exec.Command("crontab", "-") // #nosec
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to inject feeds cron job: %w", err)
	}
	fmt.Printf("[+] Background Threat Feeds updater injected successfully (Hourly at minute %d).\n", randomMinute)

	return nil
}

// FetchASNWhois retrieves IPv4 and IPv6 prefixes for an ASN natively via TCP WHOIS
func FetchASNWhois(asn, destBase string) error {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	if !approvedASN.MatchString(asn) {
		return fmt.Errorf("invalid ASN %q", asn)
	}
	v4Target, err := approvedFeedFileForPath(destBase+".ipv4", ".ipv4")
	if err != nil {
		return err
	}
	v6Target, err := approvedFeedFileForPath(destBase+".ipv6", ".ipv6")
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp4", "whois.radb.net:43", 5*time.Second)
	if err != nil {
		conn, err = net.DialTimeout("tcp6", "whois.radb.net:43", 5*time.Second)
		if err != nil {
			return fmt.Errorf("whois connection failed: %w", err)
		}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	query := fmt.Sprintf("-i origin %s\r\n", asn)
	if _, err := conn.Write([]byte(query)); err != nil {
		return fmt.Errorf("whois query failed: %w", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("whois read failed: %w", err)
	}

	// Extract IPv4 and IPv6 routes
	reV4 := regexp.MustCompile(`(?m)^route:\s+([0-9]{1,3}\.([0-9]{1,3}\.){2}[0-9]{1,3}/[0-9]{1,2})`)
	reV6 := regexp.MustCompile(`(?m)^route6:\s+([0-9a-fA-F:]+/[0-9]{1,3})`)

	matchesV4 := reV4.FindAllStringSubmatch(string(data), -1)
	matchesV6 := reV6.FindAllStringSubmatch(string(data), -1)

	var cidrsV4 []string
	for _, m := range matchesV4 {
		if len(m) > 1 {
			cidrsV4 = append(cidrsV4, m[1])
		}
	}

	var cidrsV6 []string
	for _, m := range matchesV6 {
		if len(m) > 1 {
			cidrsV6 = append(cidrsV6, m[1])
		}
	}

	outV4 := strings.Join(cidrsV4, "\n") + "\n"
	if err := writeFeedFileAt(v4Target, ".ipv4", []byte(outV4)); err != nil {
		return err
	}

	if len(cidrsV6) > 0 {
		outV6 := strings.Join(cidrsV6, "\n") + "\n"
		if err := writeFeedFileAt(v6Target, ".ipv6", []byte(outV6)); err != nil {
			return err
		}
		if err := cleanCIDRListV6At(v6Target); err != nil {
			return err
		}
	}

	return cleanCIDRListAt(v4Target)
}

// FetchSpamhausASNs retrieves the latest ASNs from the Spamhaus DROP JSON list
func FetchSpamhausASNs(ctx context.Context) ([]string, error) {
	url := "https://www.spamhaus.org/drop/asndrop.json"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var resp *http.Response
	for retries := 0; retries < 3; retries++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()

	var asns []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		var record struct {
			ASN int `json:"asn"`
		}
		if err := json.Unmarshal([]byte(line), &record); err == nil && record.ASN > 0 {
			asns = append(asns, fmt.Sprintf("AS%d", record.ASN))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	return asns, nil
}

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
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/pkg/cronstate"
	"syswarden-cli/pkg/system"
	"time"
)

const approvedFeedDirectory = "/etc/syswarden/lists"

const (
	maximumCIDRFeedBytes        = 16 << 20
	maximumPublishedBytes       = 32 << 20
	maximumWHOISBytes           = 8 << 20
	maximumJSONFeedBytes        = 8 << 20
	maximumCanonicalFeedEntries = 250000
	feedHTTPTimeout             = 30 * time.Second
)

var (
	approvedFeedBasename      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*\.ipv[46]$`)
	approvedASN               = regexp.MustCompile(`^AS[0-9]{1,10}$`)
	approvedCountryCode       = regexp.MustCompile(`^[A-Za-z]{2}$`)
	approvedSHA256            = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	errFeedRedirect           = errors.New("feed redirects are disabled")
	errUnauthenticatedASNFeed = errors.New("unauthenticated RADB WHOIS data is non-authoritative for firewall policy")
	errNonPublicFeedPrefix    = errors.New("non-public or special-use prefix")
	reservedFeedPrefixes      = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.31.196.0/24"),
		netip.MustParsePrefix("192.52.193.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("192.175.48.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("::ffff:0:0/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("100:0:0:1::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2620:4f:8000::/48"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fec0::/10"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

type cidrFeedPolicy struct {
	expectedFamily         int
	minimumEntries         int
	minimumIPv4PrefixBits  int
	minimumIPv6PrefixBits  int
	requireHostPrefixes    bool
	requirePublicAddresses bool
	skipNonPublicEntries   bool
}

type feedPublicationPolicy struct {
	verified                    bool
	allowList                   bool
	mergePrevious               bool
	minimumRetentionPercent     int
	maximumGrowthPercent        int
	minimumUnverifiedOverlap    int
	plausibilityBaselineEntries int
}

type canonicalCIDRFeed struct {
	content                 []byte
	prefixes                []netip.Prefix
	ignoredNonPublicEntries int
}

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
	return readFeedFileInDirectoryBounded(directory, target, maximumPublishedBytes)
}

func readFeedFileSnapshotInDirectory(directory *os.Root, target feedFileTarget) ([]byte, feedFileIdentity, error) {
	identity, exists, err := inspectFeedDestination(directory, target)
	if err != nil {
		return nil, feedFileIdentity{}, err
	}
	if !exists {
		return nil, feedFileIdentity{}, fs.ErrNotExist
	}
	content, err := readFeedFileInDirectoryBounded(directory, target, maximumPublishedBytes)
	if err != nil {
		return nil, feedFileIdentity{}, err
	}
	if sha256.Sum256(content) != identity.digest {
		return nil, feedFileIdentity{}, fmt.Errorf("feed target changed while reading: %s", target.name)
	}
	if err := verifyFeedDestination(directory, target, identity, true); err != nil {
		return nil, feedFileIdentity{}, err
	}
	return content, identity, nil
}

func readFeedFileInDirectoryBounded(directory *os.Root, target feedFileTarget, maximumBytes int64) ([]byte, error) {
	file, _, err := openFeedFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	return readAllBounded(file, info.Size(), maximumBytes)
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
	if before.Size() < 0 || before.Size() > maximumPublishedBytes {
		return nil, digest, fmt.Errorf("feed target exceeds %d bytes", maximumPublishedBytes)
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

func writeFeedFileInDirectoryFromIdentity(directory *os.Root, target feedFileTarget, content []byte, expected feedFileIdentity) error {
	return writeFeedFileInDirectoryExpected(directory, target, content, &expected, nil)
}

func writeFeedFileInDirectoryExpected(directory *os.Root, target feedFileTarget, content []byte, expectedIdentity *feedFileIdentity, beforeRename func() error) error {
	identity, existed, err := inspectFeedDestination(directory, target)
	if err != nil {
		return fmt.Errorf("inspect feed target %s: %w", target.name, err)
	}
	if expectedIdentity != nil && (!existed || !sameFeedFileState(*expectedIdentity, identity.info, identity.digest)) {
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

func removeFeedTargets(targets ...feedFileTarget) error {
	if len(targets) == 0 {
		return nil
	}
	directoryPath := targets[0].directory
	for _, target := range targets {
		suffix := ".ipv4"
		if strings.HasSuffix(target.name, ".ipv6") {
			suffix = ".ipv6"
		}
		if target.directory != directoryPath {
			return fmt.Errorf("feed removal targets must share one directory")
		}
		if err := validateFeedFileTarget(target, suffix); err != nil {
			return err
		}
	}
	firstSuffix := ".ipv4"
	if strings.HasSuffix(targets[0].name, ".ipv6") {
		firstSuffix = ".ipv6"
	}
	directory, err := openFeedDirectory(targets[0], firstSuffix, false)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockFeedDirectory(lockFile)
	for _, target := range targets {
		if _, exists, err := inspectFeedDestination(directory, target); err != nil {
			return fmt.Errorf("inspect feed target before removal %s: %w", target.name, err)
		} else if !exists {
			continue
		}
		if err := directory.Remove(target.name); err != nil {
			return fmt.Errorf("remove feed target %s: %w", target.name, err)
		}
	}
	return syncFeedDirectory(directory)
}

func validateSHA256Digest(digest string) error {
	_, err := canonicalSHA256Digest(digest)
	return err
}

func canonicalSHA256Digest(digest string) (string, error) {
	if strings.TrimSpace(digest) != digest {
		return "", fmt.Errorf("SHA-256 digest must not contain surrounding whitespace")
	}
	digest = strings.TrimPrefix(digest, "sha256:")
	if !approvedSHA256.MatchString(digest) {
		return "", fmt.Errorf("SHA-256 digest must contain exactly 64 hexadecimal characters")
	}
	return strings.ToLower(digest), nil
}

func strictFeedHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{Timeout: feedHTTPTimeout}
	}
	client := *base
	if client.Timeout <= 0 || client.Timeout > feedHTTPTimeout {
		client.Timeout = feedHTTPTimeout
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errFeedRedirect
	}
	return &client
}

func validateHTTPSFeedURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse feed URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("feed URL must be an absolute HTTPS URL without credentials or a fragment")
	}
	return parsed, nil
}

func readAllBounded(reader io.Reader, declaredLength, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("invalid body size limit")
	}
	if declaredLength > limit {
		return nil, fmt.Errorf("response body exceeds the %d-byte limit", limit)
	}
	limited := io.LimitReader(reader, limit+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("response body exceeds the %d-byte limit", limit)
	}
	return content, nil
}

func acceptableCIDRContentType(value string) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	switch strings.ToLower(mediaType) {
	case "text/plain", "application/octet-stream", "binary/octet-stream":
		return true
	default:
		return false
	}
}

func acceptableJSONFeedContentType(value string) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	switch strings.ToLower(mediaType) {
	case "application/json", "application/x-ndjson", "application/jsonl", "text/plain":
		return true
	default:
		return false
	}
}

func fetchHTTPSBody(ctx context.Context, baseClient *http.Client, rawURL string, maximumBytes int64, contentTypeAllowed func(string) bool) ([]byte, error) {
	if _, err := validateHTTPSFeedURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create feed request: %w", err)
	}
	req.Header.Set("Accept", "text/plain, application/octet-stream;q=0.9")
	resp, err := strictFeedHTTPClient(baseClient).Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		requestErr := err
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			requestErr = urlErr.Err
		}
		return nil, fmt.Errorf("request feed: %w", requestErr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned HTTP status %d", resp.StatusCode)
	}
	if contentTypeAllowed != nil && !contentTypeAllowed(resp.Header.Get("Content-Type")) {
		return nil, fmt.Errorf("feed returned an unsupported Content-Type")
	}
	content, err := readAllBounded(resp.Body, resp.ContentLength, maximumBytes)
	if err != nil {
		return nil, fmt.Errorf("read feed body: %w", err)
	}
	return content, nil
}

func fetchHTTPSBodyWithRetry(ctx context.Context, client *http.Client, rawURL string, maximumBytes int64, contentTypeAllowed func(string) bool) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		content, err := fetchHTTPSBody(ctx, client, rawURL, maximumBytes, contentTypeAllowed)
		if err == nil {
			return content, nil
		}
		lastErr = err
		if errors.Is(err, errFeedRedirect) || ctx.Err() != nil {
			break
		}
		if attempt < 2 {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil, fmt.Errorf("download failed: %w", lastErr)
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() &&
		(left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func isPublicFeedPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if !address.IsValid() || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, reserved := range reservedFeedPrefixes {
		if prefixesOverlap(prefix, reserved) {
			return false
		}
	}
	return true
}

func parseCanonicalFeedPrefix(line string, policy cidrFeedPolicy) (netip.Prefix, error) {
	var prefix netip.Prefix
	if strings.Contains(line, "/") {
		parsed, err := netip.ParsePrefix(line)
		if err != nil {
			return prefix, err
		}
		prefix = parsed
	} else {
		address, err := netip.ParseAddr(line)
		if err != nil {
			return prefix, err
		}
		if address.Is4In6() {
			return prefix, fmt.Errorf("IPv4-mapped IPv6 addresses are not accepted")
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("ambiguous or zoned address")
	}
	prefix = prefix.Masked()
	family := 6
	minimumBits := policy.minimumIPv6PrefixBits
	if prefix.Addr().Is4() {
		family = 4
		minimumBits = policy.minimumIPv4PrefixBits
	}
	if policy.expectedFamily != 0 && policy.expectedFamily != family {
		return netip.Prefix{}, fmt.Errorf("address family does not match the destination")
	}
	if minimumBits > 0 && prefix.Bits() < minimumBits {
		return netip.Prefix{}, fmt.Errorf("prefix is broader than the configured safety floor")
	}
	if policy.requireHostPrefixes && prefix.Bits() != prefix.Addr().BitLen() {
		return netip.Prefix{}, fmt.Errorf("source must contain host prefixes only")
	}
	if policy.requirePublicAddresses && !isPublicFeedPrefix(prefix) {
		return netip.Prefix{}, errNonPublicFeedPrefix
	}
	return prefix, nil
}

func canonicalFeedFromPrefixes(prefixes []netip.Prefix) canonicalCIDRFeed {
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	canonical := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		canonical = append(canonical, prefix)
	}
	sort.Slice(canonical, func(i, j int) bool {
		if comparison := canonical[i].Addr().Compare(canonical[j].Addr()); comparison != 0 {
			return comparison < 0
		}
		return canonical[i].Bits() < canonical[j].Bits()
	})
	var builder strings.Builder
	for _, prefix := range canonical {
		builder.WriteString(prefix.String())
		builder.WriteByte('\n')
	}
	return canonicalCIDRFeed{content: []byte(builder.String()), prefixes: canonical}
}

func canonicalizeCIDRFeed(content []byte, policy cidrFeedPolicy) (canonicalCIDRFeed, error) {
	if len(content) == 0 {
		return canonicalCIDRFeed{}, fmt.Errorf("feed is empty")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 1024), 4096)
	prefixes := make([]netip.Prefix, 0)
	ignoredNonPublicEntries := 0
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		prefix, err := parseCanonicalFeedPrefix(line, policy)
		if err != nil {
			if policy.skipNonPublicEntries && errors.Is(err, errNonPublicFeedPrefix) {
				ignoredNonPublicEntries++
				continue
			}
			return canonicalCIDRFeed{}, fmt.Errorf("invalid CIDR at line %d: %w", lineNumber, err)
		}
		prefixes = append(prefixes, prefix)
		if len(prefixes) > maximumCanonicalFeedEntries {
			return canonicalCIDRFeed{}, fmt.Errorf("feed exceeds the %d-entry canonicalization limit", maximumCanonicalFeedEntries)
		}
	}
	if err := scanner.Err(); err != nil {
		return canonicalCIDRFeed{}, fmt.Errorf("scan CIDR feed: %w", err)
	}
	feed := canonicalFeedFromPrefixes(prefixes)
	if len(feed.prefixes) > maximumCanonicalFeedEntries {
		return canonicalCIDRFeed{}, fmt.Errorf("feed exceeds the %d-entry canonicalization limit", maximumCanonicalFeedEntries)
	}
	if len(feed.prefixes) < policy.minimumEntries {
		if ignoredNonPublicEntries > 0 {
			return canonicalCIDRFeed{}, fmt.Errorf("feed contains %d canonical entries after ignoring %d non-public or special-use entries, minimum is %d", len(feed.prefixes), ignoredNonPublicEntries, policy.minimumEntries)
		}
		return canonicalCIDRFeed{}, fmt.Errorf("feed contains %d canonical entries, minimum is %d", len(feed.prefixes), policy.minimumEntries)
	}
	if len(feed.prefixes) == 0 {
		return canonicalCIDRFeed{}, fmt.Errorf("feed contains no canonical CIDR entries")
	}
	feed.ignoredNonPublicEntries = ignoredNonPublicEntries
	return feed, nil
}

func canonicalPrefixSet(prefixes []netip.Prefix) map[netip.Prefix]struct{} {
	set := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		set[prefix.Masked()] = struct{}{}
	}
	return set
}

func feedPrefixContainedBySet(prefix netip.Prefix, candidates map[netip.Prefix]struct{}) bool {
	for bits := prefix.Bits(); bits >= 0; bits-- {
		candidate := netip.PrefixFrom(prefix.Addr(), bits).Masked()
		if _, exists := candidates[candidate]; exists {
			return true
		}
	}
	return false
}

func validateFeedReplacement(candidate, previous canonicalCIDRFeed, previousExists bool, policy feedPublicationPolicy) error {
	if !previousExists {
		if policy.allowList && !policy.verified {
			return fmt.Errorf("an unverified allow-list feed cannot create a new access grant")
		}
		return nil
	}
	baseline := policy.plausibilityBaselineEntries
	if baseline <= 0 {
		baseline = 10
	}
	if len(previous.prefixes) >= baseline {
		if policy.minimumRetentionPercent > 0 && len(candidate.prefixes)*100 < len(previous.prefixes)*policy.minimumRetentionPercent {
			return fmt.Errorf("candidate collapsed from %d to %d entries", len(previous.prefixes), len(candidate.prefixes))
		}
		if policy.maximumGrowthPercent > 0 && len(candidate.prefixes)*100 > len(previous.prefixes)*policy.maximumGrowthPercent {
			return fmt.Errorf("candidate grew implausibly from %d to %d entries", len(previous.prefixes), len(candidate.prefixes))
		}
	}
	previousSet := canonicalPrefixSet(previous.prefixes)
	if policy.allowList && !policy.verified {
		for _, prefix := range candidate.prefixes {
			if !feedPrefixContainedBySet(prefix, previousSet) {
				return fmt.Errorf("an unverified allow-list feed would widen access")
			}
		}
	}
	if !policy.verified && !policy.allowList && policy.minimumUnverifiedOverlap > 0 && len(previous.prefixes) >= baseline {
		overlap := 0
		for _, prefix := range candidate.prefixes {
			if _, exists := previousSet[prefix]; exists {
				overlap++
			}
		}
		denominator := len(candidate.prefixes)
		if len(previous.prefixes) < denominator {
			denominator = len(previous.prefixes)
		}
		if denominator > 0 && overlap*100 < denominator*policy.minimumUnverifiedOverlap {
			return fmt.Errorf("unverified candidate overlaps only %d of %d comparable entries", overlap, denominator)
		}
	}
	return nil
}

func publishCanonicalFeedAt(target feedFileTarget, suffix string, candidate canonicalCIDRFeed, validation cidrFeedPolicy, policy feedPublicationPolicy) error {
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

	var previous canonicalCIDRFeed
	previousExists := false
	destinationExists := false
	previousContent, previousIdentity, readErr := readFeedFileSnapshotInDirectory(directory, target)
	if readErr == nil {
		destinationExists = true
		previousExists = true
		previousPolicy := validation
		previousPolicy.minimumEntries = 1
		previous, err = canonicalizeCIDRFeed(previousContent, previousPolicy)
		if err != nil && !policy.verified {
			return fmt.Errorf("preserve unparseable last-known-good feed: %w", err)
		}
		if err != nil {
			previous = canonicalCIDRFeed{}
			previousExists = false
		}
	} else if !errors.Is(readErr, fs.ErrNotExist) {
		return fmt.Errorf("read last-known-good feed: %w", readErr)
	}

	if policy.mergePrevious && previousExists {
		merged := append(append([]netip.Prefix{}, previous.prefixes...), candidate.prefixes...)
		candidate = canonicalFeedFromPrefixes(merged)
	}
	if len(candidate.prefixes) > maximumCanonicalFeedEntries {
		return fmt.Errorf("canonical feed exceeds the %d-entry publication limit", maximumCanonicalFeedEntries)
	}
	if len(candidate.content) > maximumPublishedBytes {
		return fmt.Errorf("canonical feed exceeds the %d-byte publication limit", maximumPublishedBytes)
	}
	if err := validateFeedReplacement(candidate, previous, previousExists, policy); err != nil {
		return err
	}
	if destinationExists {
		return writeFeedFileInDirectoryFromIdentity(directory, target, candidate.content, previousIdentity)
	}
	return writeFeedFileInDirectoryBeforeRename(directory, target, candidate.content, nil)
}

func downloadCanonicalCIDRFeed(ctx context.Context, client *http.Client, rawURL, expectedHash string, policy cidrFeedPolicy) (canonicalCIDRFeed, error) {
	canonicalExpectedHash := ""
	if expectedHash != "" {
		var err error
		canonicalExpectedHash, err = canonicalSHA256Digest(expectedHash)
		if err != nil {
			return canonicalCIDRFeed{}, err
		}
	}
	content, err := fetchHTTPSBodyWithRetry(ctx, client, rawURL, maximumCIDRFeedBytes, acceptableCIDRContentType)
	if err != nil {
		return canonicalCIDRFeed{}, err
	}
	if expectedHash != "" {
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != canonicalExpectedHash {
			return canonicalCIDRFeed{}, fmt.Errorf("SHA-256 mismatch")
		}
	}
	return canonicalizeCIDRFeed(content, policy)
}

func secureDownloadWithClient(ctx context.Context, client *http.Client, rawURL string, target feedFileTarget, suffix, expectedHash string) error {
	family := 4
	if suffix == ".ipv6" {
		family = 6
	}
	validation := cidrFeedPolicy{
		expectedFamily:         family,
		minimumEntries:         1,
		minimumIPv4PrefixBits:  24,
		minimumIPv6PrefixBits:  64,
		requirePublicAddresses: true,
	}
	verified := strings.TrimSpace(expectedHash) != ""
	candidate, err := downloadCanonicalCIDRFeed(ctx, client, rawURL, expectedHash, validation)
	if err != nil {
		return err
	}
	allowList := strings.HasPrefix(strings.ToLower(target.name), "allowed_")
	if !verified && !allowList {
		return fmt.Errorf("unsigned single-origin feed is non-authoritative; last-known-good content was preserved")
	}
	publication := feedPublicationPolicy{
		verified:                    verified,
		allowList:                   allowList,
		minimumRetentionPercent:     20,
		maximumGrowthPercent:        500,
		minimumUnverifiedOverlap:    50,
		plausibilityBaselineEntries: 10,
	}
	return publishCanonicalFeedAt(target, suffix, candidate, validation, publication)
}

// SecureDownloader downloads files with strict timeouts and resource limits
func SecureDownloader(ctx context.Context, rawURL string, destPath string, expectedHash string) error {
	suffix := ".ipv4"
	if strings.HasSuffix(destPath, ".ipv6") {
		suffix = ".ipv6"
	}
	target, err := approvedFeedFileForPath(destPath, suffix)
	if err != nil {
		return err
	}
	if expectedHash == "" {
		fmt.Printf("[WARN] Feed %s has no operator-pinned digest and cannot authoritatively widen policy.\n", target.name)
	}
	if err := secureDownloadWithClient(ctx, &http.Client{Timeout: feedHTTPTimeout}, rawURL, target, suffix, expectedHash); err != nil {
		return fmt.Errorf("secure feed update for %s: %w", target.name, err)
	}
	return nil
}

type mirrorConsensusGroup struct {
	feed    canonicalCIDRFeed
	origins map[string]struct{}
}

func feedOrigin(rawURL string) (string, error) {
	parsed, err := validateHTTPSFeedURL(rawURL)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "raw.githubusercontent.com", "cdn.jsdelivr.net":
		return "github-backed-data-shield", nil
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Hostname()), nil
}

func reportNonAuthoritativeFeed(label string) {
	_, _ = fmt.Fprintf(os.Stderr, "[WARNING] %s is configured but has no authenticated authority; last-known-good files were preserved.\n", label)
}

func reportIgnoredOSINTEntries(writer io.Writer, origin string, count int) {
	if count <= 0 {
		return
	}
	entryLabel := "entries"
	if count == 1 {
		entryLabel = "entry"
	}
	_, _ = fmt.Fprintf(writer, "[WARNING] OSINT source %s ignored %d non-public or special-use CIDR %s.\n", origin, count, entryLabel)
}

func downloadMirrorQuorumWithClient(ctx context.Context, client *http.Client, mirrors []string, target feedFileTarget, suffix string, quorum int, validation cidrFeedPolicy, publication feedPublicationPolicy) error {
	if quorum < 2 {
		return fmt.Errorf("mirror quorum must require at least two independent origins")
	}
	groups := make(map[[sha256.Size]byte]*mirrorConsensusGroup)
	failures := 0
	for _, mirror := range mirrors {
		origin, err := feedOrigin(mirror)
		if err != nil {
			failures++
			continue
		}
		candidate, err := downloadCanonicalCIDRFeed(ctx, client, mirror, "", validation)
		if err != nil {
			failures++
			continue
		}
		digest := sha256.Sum256(candidate.content)
		group := groups[digest]
		if group == nil {
			group = &mirrorConsensusGroup{feed: candidate, origins: make(map[string]struct{})}
			groups[digest] = group
		}
		group.origins[origin] = struct{}{}
	}

	var selected *mirrorConsensusGroup
	selectedCount := 0
	tied := false
	for _, group := range groups {
		count := len(group.origins)
		if count > selectedCount {
			selected = group
			selectedCount = count
			tied = false
		} else if count == selectedCount && count > 0 {
			tied = true
		}
	}
	if selected == nil || selectedCount < quorum {
		return fmt.Errorf("feed mirror quorum not reached: best agreement %d/%d across %d responses and %d failures", selectedCount, quorum, len(mirrors)-failures, failures)
	}
	if tied {
		return fmt.Errorf("feed mirror quorum is ambiguous between equally supported canonical results")
	}
	publication.verified = true
	if err := publishCanonicalFeedAt(target, suffix, selected.feed, validation, publication); err != nil {
		return fmt.Errorf("publish quorum-verified feed: %w", err)
	}
	fmt.Printf("[INFO] Feed quorum verified by %d independent HTTPS origins.\n", selectedCount)
	return nil
}

func downloadDataShieldQuorum(ctx context.Context, listChoice string) error {
	target, err := approvedFeedFileForPath("/etc/syswarden/lists/syswarden_threatintel.ipv4", ".ipv4")
	if err != nil {
		return err
	}
	validation := cidrFeedPolicy{
		expectedFamily:         4,
		minimumEntries:         16,
		minimumIPv4PrefixBits:  24,
		minimumIPv6PrefixBits:  64,
		requirePublicAddresses: true,
	}
	publication := feedPublicationPolicy{
		minimumRetentionPercent:     20,
		maximumGrowthPercent:        500,
		plausibilityBaselineEntries: 16,
	}
	return downloadMirrorQuorumWithClient(
		ctx,
		&http.Client{Timeout: feedHTTPTimeout},
		system.ThreatIntelMirrors(listChoice),
		target,
		".ipv4",
		2,
		validation,
		publication,
	)
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
	content, sourceIdentity, err := readFeedFileSnapshotInDirectory(directory, target)
	if err != nil {
		return err
	}

	validation := cidrFeedPolicy{
		minimumIPv4PrefixBits:  24,
		minimumIPv6PrefixBits:  64,
		requirePublicAddresses: true,
	}
	var validCIDRs []netip.Prefix
	var validCIDRsV6 []netip.Prefix
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		prefix, parseErr := parseCanonicalFeedPrefix(line, validation)
		if parseErr != nil {
			continue
		}
		if prefix.Addr().Is4() {
			validCIDRs = append(validCIDRs, prefix)
		} else {
			validCIDRsV6 = append(validCIDRsV6, prefix)
		}
	}
	v4Feed := canonicalFeedFromPrefixes(validCIDRs)
	v6Feed := canonicalFeedFromPrefixes(validCIDRsV6)
	if len(v4Feed.prefixes) == 0 {
		return fmt.Errorf("CIDR cleaner found no safe IPv4 entries")
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
	if err := writeFeedFileInDirectoryFromIdentity(directory, target, v4Feed.content, sourceIdentity); err != nil {
		return err
	}

	// Smart Routing: Route extracted IPv6 to the corresponding .ipv6 file
	if len(validCIDRsV6) > 0 {
		if err := appendFeedFileInDirectory(directory, v6Target, v6Feed.content); err != nil {
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
	content, sourceIdentity, err := readFeedFileSnapshotInDirectory(directory, target)
	if err != nil {
		return err // file might not exist if no IPv6 routes were found, that's okay
	}

	validation := cidrFeedPolicy{
		minimumIPv4PrefixBits:  24,
		minimumIPv6PrefixBits:  64,
		requirePublicAddresses: true,
	}
	var validCIDRsV6 []netip.Prefix
	var validCIDRsV4 []netip.Prefix
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		prefix, parseErr := parseCanonicalFeedPrefix(line, validation)
		if parseErr != nil {
			continue
		}
		if prefix.Addr().Is4() {
			validCIDRsV4 = append(validCIDRsV4, prefix)
		} else {
			validCIDRsV6 = append(validCIDRsV6, prefix)
		}
	}
	v6Feed := canonicalFeedFromPrefixes(validCIDRsV6)
	v4Feed := canonicalFeedFromPrefixes(validCIDRsV4)
	if len(v6Feed.prefixes) == 0 {
		return fmt.Errorf("CIDR cleaner found no safe IPv6 entries")
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
	if err := writeFeedFileInDirectoryFromIdentity(directory, target, v6Feed.content, sourceIdentity); err != nil {
		return err
	}

	// Smart Routing: Route extracted IPv4 to the corresponding .ipv4 file
	if len(validCIDRsV4) > 0 {
		if err := appendFeedFileInDirectory(directory, v4Target, v4Feed.content); err != nil {
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
	var feedErrors []error

	if geoCodes != "" {
		codes := strings.Split(geoCodes, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" || code == "none" {
				continue
			}
			if !approvedCountryCode.MatchString(code) {
				feedErrors = append(feedErrors, fmt.Errorf("invalid GeoIP country code %q", code))
				continue
			}
			reportNonAuthoritativeFeed("GeoIP deny source " + strings.ToUpper(code))
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
		reportNonAuthoritativeFeed("Spamhaus ASN deny source")
	}

	for _, asn := range asnsToDrop {
		reportNonAuthoritativeFeed("RADB ASN deny source " + asn)
	}

	// Download GeoIP ALLOW lists (Zero-Trust Mode)
	if geoAllowed != "" {
		codes := strings.Split(geoAllowed, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" || code == "none" {
				continue
			}
			if !approvedCountryCode.MatchString(code) {
				feedErrors = append(feedErrors, fmt.Errorf("invalid GeoIP allow-list country code %q", code))
				continue
			}
			// Download IPv4
			url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(code))
			dest := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP ALLOW [%s] (IPv4)... ", code)
			if err := SecureDownloader(ctx, url, dest, ""); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
				feedErrors = append(feedErrors, fmt.Errorf("GeoIP allow-list %s IPv4: %w", code, err))
			} else {
				fmt.Println("OK")
			}

			// Download IPv6
			urlV6 := fmt.Sprintf("https://www.ipdeny.com/ipv6/ipaddresses/blocks/%s.zone", strings.ToLower(code))
			destV6 := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv6", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP ALLOW [%s] (IPv6)... ", code)
			if err := SecureDownloader(ctx, urlV6, destV6, ""); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
				feedErrors = append(feedErrors, fmt.Errorf("GeoIP allow-list %s IPv6: %w", code, err))
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
			reportNonAuthoritativeFeed("RADB ASN allow source " + strings.ToUpper(asn))
		}
	}

	// Download IPv6 Custom Blocklist if configured
	if listChoice == "3" && customURLIPv6 != "" {
		fmt.Printf("Downloading Custom IPv6 Blocklist... ")
		err := validateSHA256Digest(customHashIPv6)
		if err == nil {
			err = SecureDownloader(ctx, customURLIPv6, "/etc/syswarden/lists/syswarden_threatintel.ipv6", customHashIPv6)
		}
		if err != nil {
			fmt.Printf("FAILED (%v)\n", err)
			feedErrors = append(feedErrors, fmt.Errorf("custom IPv6 blocklist: %w", err))
		} else {
			fmt.Println("OK")
		}
	}

	// Download Threat Intel Blocklist
	switch listChoice {
	case "4":
		fmt.Println("Downloading Threat Intel IPv4 Blocklist... SKIPPED (Option 4 'none')")
		if err := removeFeedTargets(
			feedFileTarget{directory: approvedFeedDirectory, name: "syswarden_threatintel.ipv4"},
			feedFileTarget{directory: approvedFeedDirectory, name: "syswarden_threatintel.ipv6"},
		); err != nil {
			feedErrors = append(feedErrors, fmt.Errorf("remove disabled threat intelligence files: %w", err))
		}
	case "3":
		if strings.TrimSpace(mirrorURL) == "" {
			fmt.Println("Downloading Custom Threat Intel IPv4 Blocklist... SKIPPED (not configured)")
		} else {
			fmt.Printf("Downloading Custom Threat Intel IPv4 Blocklist... ")
			customURL := strings.TrimRight(mirrorURL, "/")
			err := validateSHA256Digest(customHash)
			if err == nil {
				err = SecureDownloader(ctx, customURL, "/etc/syswarden/lists/syswarden_threatintel.ipv4", customHash)
			}
			if err != nil {
				fmt.Printf("FAILED (%v)\n", err)
				feedErrors = append(feedErrors, fmt.Errorf("custom IPv4 blocklist: %w", err))
			} else {
				fmt.Println("OK")
			}
		}
	default:
		fmt.Printf("Downloading Threat Intel IPv4 Blocklist... ")
		if err := downloadDataShieldQuorum(ctx, listChoice); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
			feedErrors = append(feedErrors, fmt.Errorf("Data-Shield mirror quorum: %w", err))
		} else {
			fmt.Println("OK")
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
			feedErrors = append(feedErrors, fmt.Errorf("OSINT feeds: %w", err))
		} else {
			fmt.Println("OK")
		}
	}

	return errors.Join(feedErrors...)
}

// DownloadOSINT publishes only entries independently present at every configured OSINT origin.
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
	return downloadOSINTWithClient(ctx, &http.Client{Timeout: feedHTTPTimeout}, urls, v4Target, v6Target, 4)
}

func downloadOSINTWithClient(ctx context.Context, client *http.Client, urls []string, v4Target, v6Target feedFileTarget, minimumIntersectionEntries int) error {
	if len(urls) < 2 {
		return fmt.Errorf("OSINT publication requires at least two independent origins")
	}
	sourceValidation := cidrFeedPolicy{
		minimumEntries:         minimumIntersectionEntries,
		minimumIPv4PrefixBits:  32,
		minimumIPv6PrefixBits:  128,
		requireHostPrefixes:    true,
		requirePublicAddresses: true,
		skipNonPublicEntries:   true,
	}
	origins := make(map[string]struct{}, len(urls))
	presence := make(map[netip.Prefix]int)
	for _, rawURL := range urls {
		origin, err := feedOrigin(rawURL)
		if err != nil {
			return err
		}
		if _, duplicate := origins[origin]; duplicate {
			return fmt.Errorf("OSINT sources must use distinct HTTPS origins")
		}
		origins[origin] = struct{}{}
		candidate, err := downloadCanonicalCIDRFeed(ctx, client, rawURL, "", sourceValidation)
		if err != nil {
			return fmt.Errorf("validate OSINT source: %w", err)
		}
		reportIgnoredOSINTEntries(os.Stderr, origin, candidate.ignoredNonPublicEntries)
		for _, prefix := range candidate.prefixes {
			presence[prefix]++
		}
	}
	intersection := make([]netip.Prefix, 0)
	for prefix, count := range presence {
		if count == len(origins) {
			intersection = append(intersection, prefix)
		}
	}
	if len(intersection) < minimumIntersectionEntries {
		return fmt.Errorf("OSINT canonical intersection has %d entries, minimum is %d", len(intersection), minimumIntersectionEntries)
	}
	var ipv4Prefixes []netip.Prefix
	var ipv6Prefixes []netip.Prefix
	for _, prefix := range intersection {
		if prefix.Addr().Is4() {
			ipv4Prefixes = append(ipv4Prefixes, prefix)
		} else {
			ipv6Prefixes = append(ipv6Prefixes, prefix)
		}
	}
	publication := feedPublicationPolicy{
		mergePrevious:               true,
		minimumRetentionPercent:     100,
		maximumGrowthPercent:        500,
		minimumUnverifiedOverlap:    50,
		plausibilityBaselineEntries: 10,
	}
	if len(ipv4Prefixes) > 0 {
		validation := cidrFeedPolicy{
			expectedFamily:         4,
			minimumEntries:         1,
			minimumIPv4PrefixBits:  24,
			minimumIPv6PrefixBits:  64,
			requirePublicAddresses: true,
		}
		if err := publishCanonicalFeedAt(v4Target, ".ipv4", canonicalFeedFromPrefixes(ipv4Prefixes), validation, publication); err != nil {
			return fmt.Errorf("publish OSINT IPv4 feed: %w", err)
		}
	}
	if len(ipv6Prefixes) > 0 {
		validation := cidrFeedPolicy{
			expectedFamily:         6,
			minimumEntries:         1,
			minimumIPv4PrefixBits:  24,
			minimumIPv6PrefixBits:  64,
			requirePublicAddresses: true,
		}
		if err := publishCanonicalFeedAt(v6Target, ".ipv6", canonicalFeedFromPrefixes(ipv6Prefixes), validation, publication); err != nil {
			return fmt.Errorf("publish OSINT IPv6 feed: %w", err)
		}
	}
	return nil
}

// SetupFeedsCron configures the owned system cron file to update feeds hourly.
func SetupFeedsCron() error {
	fmt.Println("[INFO] Setting up automatic hourly updates for Threat Intelligence...")
	options := cronstate.DefaultOptions(system.ReadOnlyRootCrontabEvidence)
	options.AttestCronDProvider = system.AttestRuntimeCronDProvider
	options.RandomMinute = func() (int, error) {
		return rand.Intn(59) + 1, nil // #nosec G404 -- scheduling jitter is non-security-sensitive
	}
	result, err := cronstate.ReconcileFeed(options)
	if err != nil {
		return fmt.Errorf("failed to reconcile owned feeds cron job: %w", err)
	}
	source := "owned cron file"
	if result.Legacy {
		source = "read-only legacy root crontab"
	}
	fmt.Printf("[+] Background Threat Feeds updater verified (Hourly at minute %d, %s).\n", result.Minute, source)
	return nil
}

// FetchASNWhois validates a bounded RADB response but refuses to publish data received over unauthenticated WHOIS.
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
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set WHOIS deadline: %w", err)
	}

	query := fmt.Sprintf("-i origin %s\r\n", asn)
	if _, err := conn.Write([]byte(query)); err != nil {
		return fmt.Errorf("whois query failed: %w", err)
	}

	data, err := readAllBounded(conn, -1, maximumWHOISBytes)
	if err != nil {
		return fmt.Errorf("whois read failed: %w", err)
	}
	return rejectUnauthenticatedASNFeed(data, v4Target, v6Target)
}

func rejectUnauthenticatedASNFeed(data []byte, v4Target, v6Target feedFileTarget) error {
	if err := validateFeedFileTarget(v4Target, ".ipv4"); err != nil {
		return err
	}
	if err := validateFeedFileTarget(v6Target, ".ipv6"); err != nil {
		return err
	}
	var cidrsV4 []string
	var cidrsV6 []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		var destination *[]string
		var value string
		switch {
		case strings.HasPrefix(lower, "route:"):
			destination = &cidrsV4
			value = strings.TrimSpace(line[len("route:"):])
		case strings.HasPrefix(lower, "route6:"):
			destination = &cidrsV6
			value = strings.TrimSpace(line[len("route6:"):])
		default:
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return fmt.Errorf("WHOIS route field is empty")
		}
		*destination = append(*destination, fields[0])
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan WHOIS response: %w", err)
	}
	if len(cidrsV4)+len(cidrsV6) == 0 {
		return fmt.Errorf("WHOIS response contains no route prefixes; last-known-good content was preserved")
	}

	v4Validation := cidrFeedPolicy{
		expectedFamily:         4,
		minimumEntries:         1,
		minimumIPv4PrefixBits:  24,
		minimumIPv6PrefixBits:  64,
		requirePublicAddresses: true,
	}
	v6Validation := v4Validation
	v6Validation.expectedFamily = 6
	if len(cidrsV4) > 0 {
		_, err := canonicalizeCIDRFeed([]byte(strings.Join(cidrsV4, "\n")+"\n"), v4Validation)
		if err != nil {
			return fmt.Errorf("validate WHOIS IPv4 routes: %w", err)
		}
	}
	if len(cidrsV6) > 0 {
		_, err := canonicalizeCIDRFeed([]byte(strings.Join(cidrsV6, "\n")+"\n"), v6Validation)
		if err != nil {
			return fmt.Errorf("validate WHOIS IPv6 routes: %w", err)
		}
	}
	return fmt.Errorf("%w; last-known-good ASN files were preserved", errUnauthenticatedASNFeed)
}

// FetchSpamhausASNs validates the bounded official feed but refuses to authorize unsigned single-origin data.
func FetchSpamhausASNs(ctx context.Context) ([]string, error) {
	rawURL := "https://www.spamhaus.org/drop/asndrop.json"
	content, err := fetchHTTPSBodyWithRetry(ctx, &http.Client{Timeout: feedHTTPTimeout}, rawURL, maximumJSONFeedBytes, acceptableJSONFeedContentType)
	if err != nil {
		return nil, fmt.Errorf("download Spamhaus ASN feed: %w", err)
	}

	var asns []string
	seen := make(map[int]struct{})
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		var record struct {
			ASN int `json:"asn"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("invalid Spamhaus JSON record at line %d: %w", lineNumber, err)
		}
		if record.ASN <= 0 {
			return nil, fmt.Errorf("invalid Spamhaus ASN at line %d", lineNumber)
		}
		if _, exists := seen[record.ASN]; !exists {
			seen[record.ASN] = struct{}{}
			asns = append(asns, fmt.Sprintf("AS%d", record.ASN))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	if len(asns) == 0 {
		return nil, fmt.Errorf("Spamhaus ASN feed contains no records")
	}
	// No pinned digest or independent mirror is configured for this source, so its records cannot authorize firewall policy.
	return nil, fmt.Errorf("unsigned single-origin Spamhaus data is non-authoritative for firewall policy")
}

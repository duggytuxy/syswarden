//go:build linux

// Package cronstate owns the SysWarden system cron file without modifying the
// operator-controlled root crontab.
package cronstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"syswarden-cli/pkg/platformpaths"
)

const (
	DefaultRootPath       = "/"
	DefaultDirectoryPath  = "etc/cron.d"
	DefaultFileName       = "syswarden"
	maximumCronBytes      = 1 << 20
	maximumOwnedCronBytes = 4096
	maximumJournalBytes   = 8192
	ownedCronHeader       = "# Managed by SysWarden. Do not edit.\n"
	pendingFileName       = ".syswarden.pending-v1"
	retiredFileName       = ".syswarden.retired-v2"
	transactionFileName   = ".syswarden.transaction-v2"
	transactionRetired    = ".syswarden.transaction-retired-v2"
	commitFileName        = ".syswarden.commit-v2"
	commitRetired         = ".syswarden.commit-retired-v2"
	transactionVersion    = 2
	transactionPrepared   = "prepared"
	transactionCommitted  = "committed"
	operationCreate       = "create"
	operationUpdate       = "update"
	operationDelete       = "delete"
)

// RootCrontabReader returns the exact root crontab bytes and whether a root
// crontab exists. It must never modify the crontab.
type RootCrontabReader func() (content string, present bool, err error)

// Options defines one protected cron filesystem and its read-only legacy
// evidence source. RootPath and DirectoryPath are separate so tests can use a
// private filesystem root without weakening production parent validation.
type Options struct {
	RootPath            string
	DirectoryPath       string
	FileName            string
	CLIPath             string
	DirectoryOwnerUID   int
	DirectoryOwnerGID   int
	FileOwnerUID        int
	FileOwnerGID        int
	ReadRootCrontab     RootCrontabReader
	RandomMinute        func() (int, error)
	AttestCronDProvider func() error

	beforeMutation func()
	beforeReplace  func()
	faultPoint     func(string)
	renameat2      func(int, string, int, string, uint) error
	unlinkat       func(int, string, int) error
	syncDirectory  func(*os.File) error
	mutationGuard  func() error
}

// Inspection is the fully attested scheduling state.
type Inspection struct {
	LegacyFeedCount int
	LegacyHACount   int
	OwnedFeed       bool
	OwnedHA         bool
	FeedMinute      int
}

// FeedResult identifies the effective feed schedule after reconciliation.
type FeedResult struct {
	Minute int
	Legacy bool
}

type ownedState struct {
	feed       bool
	feedMinute int
	ha         bool
}

type legacyState struct {
	content    string
	present    bool
	feedCount  int
	feedMinute int
	haCount    int
}

type unixIdentity struct {
	device uint64
	inode  uint64
}

type fileIdentity struct {
	unixIdentity
	mode   fs.FileMode
	size   int64
	uid    uint32
	gid    uint32
	links  uint64
	digest [sha256.Size]byte
}

type journalIdentity struct {
	Present bool   `json:"present"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Mode    uint32 `json:"mode"`
	Size    int64  `json:"size"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Links   uint64 `json:"links"`
	SHA256  string `json:"sha256"`
}

type transactionRecord struct {
	Version       int             `json:"version"`
	Phase         string          `json:"phase"`
	Operation     string          `json:"operation"`
	LegacyPresent bool            `json:"legacy_present"`
	LegacySize    int             `json:"legacy_size"`
	LegacySHA256  string          `json:"legacy_sha256"`
	Old           journalIdentity `json:"old"`
	New           journalIdentity `json:"new"`
}

type transactionFiles struct {
	record         transactionRecord
	journal        fileIdentity
	journalPresent bool
	journalName    string
	commit         fileIdentity
	commitPresent  bool
	commitName     string
}

type openedDirectory struct {
	root     *os.Root
	identity unixIdentity
}

type namedPublicationError struct {
	cause error
}

func (failure *namedPublicationError) Error() string {
	return failure.cause.Error()
}

func (failure *namedPublicationError) Unwrap() error {
	return failure.cause
}

func namedPublicationMayExist(err error) bool {
	var failure *namedPublicationError
	return errors.As(err, &failure)
}

// DefaultOptions returns the production ownership and path contract.
func DefaultOptions(reader RootCrontabReader) Options {
	return Options{
		RootPath:          DefaultRootPath,
		DirectoryPath:     DefaultDirectoryPath,
		FileName:          DefaultFileName,
		CLIPath:           platformpaths.CLI,
		DirectoryOwnerUID: 0,
		DirectoryOwnerGID: 0,
		FileOwnerUID:      0,
		FileOwnerGID:      0,
		ReadRootCrontab:   reader,
		renameat2:         unix.Renameat2,
		unlinkat:          unix.Unlinkat,
		syncDirectory:     syncPinnedDirectory,
		mutationGuard:     func() error { return nil },
	}
}

func normalizeOptions(options Options) Options {
	if options.renameat2 == nil {
		options.renameat2 = unix.Renameat2
	}
	if options.unlinkat == nil {
		options.unlinkat = unix.Unlinkat
	}
	if options.syncDirectory == nil {
		options.syncDirectory = syncPinnedDirectory
	}
	if options.mutationGuard == nil {
		options.mutationGuard = func() error { return nil }
	}
	if options.faultPoint == nil {
		options.faultPoint = func(string) {}
	}
	return options
}

func validateOptions(options Options) error {
	if !filepath.IsAbs(options.RootPath) || filepath.Clean(options.RootPath) != options.RootPath {
		return fmt.Errorf("cron filesystem root must be absolute and canonical")
	}
	if options.DirectoryPath == "" || filepath.IsAbs(options.DirectoryPath) || filepath.Clean(options.DirectoryPath) != options.DirectoryPath {
		return fmt.Errorf("cron directory must be a canonical relative path")
	}
	for _, component := range strings.Split(filepath.ToSlash(options.DirectoryPath), "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("cron directory contains an unsafe component")
		}
	}
	if options.FileName != DefaultFileName || filepath.Base(options.FileName) != options.FileName {
		return fmt.Errorf("cron filename must be %q", DefaultFileName)
	}
	if options.CLIPath != platformpaths.CLI {
		return fmt.Errorf("cron CLI path must be %q", platformpaths.CLI)
	}
	validOwnershipID := func(value int) bool {
		return value >= 0 && int64(value) <= int64(^uint32(0))
	}
	if !validOwnershipID(options.DirectoryOwnerUID) || !validOwnershipID(options.DirectoryOwnerGID) ||
		!validOwnershipID(options.FileOwnerUID) || !validOwnershipID(options.FileOwnerGID) {
		return fmt.Errorf("cron ownership identifiers must fit the Linux uint32 identity domain")
	}
	if options.ReadRootCrontab == nil {
		return fmt.Errorf("root crontab reader is required")
	}
	if options.renameat2 == nil || options.unlinkat == nil || options.syncDirectory == nil ||
		options.mutationGuard == nil || options.faultPoint == nil {
		return fmt.Errorf("cron mutation primitives are required")
	}
	return nil
}

func unixStat(info fs.FileInfo) (*syscall.Stat_t, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return nil, fmt.Errorf("cron path lacks Unix identity metadata")
	}
	return stat, nil
}

func identityFromInfo(info fs.FileInfo) (unixIdentity, error) {
	stat, err := unixStat(info)
	if err != nil {
		return unixIdentity{}, err
	}
	return unixIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func validateProtectedDirectory(info fs.FileInfo, uid, gid int, label string) (unixIdentity, error) {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return unixIdentity{}, fmt.Errorf("%s is not a real directory", label)
	}
	stat, err := unixStat(info)
	if err != nil {
		return unixIdentity{}, fmt.Errorf("inspect %s ownership: %w", label, err)
	}
	if int64(stat.Uid) != int64(uid) || int64(stat.Gid) != int64(gid) {
		return unixIdentity{}, fmt.Errorf("%s is not owned by the expected account", label)
	}
	if info.Mode().Perm()&0022 != 0 {
		return unixIdentity{}, fmt.Errorf("%s is group-writable or world-writable", label)
	}
	return unixIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func openProtectedDirectory(options Options) (openedDirectory, error) {
	anchor, err := os.OpenRoot(options.RootPath)
	if err != nil {
		return openedDirectory{}, fmt.Errorf("open cron filesystem root: %w", err)
	}
	anchorInfo, err := anchor.Stat(".")
	if err != nil {
		_ = anchor.Close()
		return openedDirectory{}, fmt.Errorf("inspect cron filesystem root: %w", err)
	}
	if _, err := validateProtectedDirectory(anchorInfo, options.DirectoryOwnerUID, options.DirectoryOwnerGID, "cron filesystem root"); err != nil {
		_ = anchor.Close()
		return openedDirectory{}, err
	}

	current := anchor
	for _, component := range strings.Split(filepath.ToSlash(options.DirectoryPath), "/") {
		before, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return openedDirectory{}, fmt.Errorf("inspect cron directory component %s: %w", component, err)
		}
		beforeIdentity, err := validateProtectedDirectory(before, options.DirectoryOwnerUID, options.DirectoryOwnerGID, "cron directory component "+component)
		if err != nil {
			_ = current.Close()
			return openedDirectory{}, err
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return openedDirectory{}, fmt.Errorf("open cron directory component %s: %w", component, err)
		}
		after, err := next.Stat(".")
		if err != nil {
			_ = next.Close()
			_ = current.Close()
			return openedDirectory{}, fmt.Errorf("reattest cron directory component %s: %w", component, err)
		}
		afterIdentity, err := identityFromInfo(after)
		if err != nil || beforeIdentity != afterIdentity {
			_ = next.Close()
			_ = current.Close()
			return openedDirectory{}, fmt.Errorf("cron directory component %s changed while opening", component)
		}
		_ = current.Close()
		current = next
	}
	finalInfo, err := current.Stat(".")
	if err != nil {
		_ = current.Close()
		return openedDirectory{}, fmt.Errorf("inspect opened cron directory: %w", err)
	}
	identity, err := identityFromInfo(finalInfo)
	if err != nil {
		_ = current.Close()
		return openedDirectory{}, err
	}
	return openedDirectory{root: current, identity: identity}, nil
}

func reattestDirectoryPath(options Options, expected unixIdentity) error {
	opened, err := openProtectedDirectory(options)
	if err != nil {
		return err
	}
	defer func() { _ = opened.root.Close() }()
	if opened.identity != expected {
		return fmt.Errorf("cron directory path changed before mutation")
	}
	return nil
}

func reattestPinnedDirectoryPath(directory *os.Root, options Options) error {
	info, err := directory.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect pinned cron directory: %w", err)
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return err
	}
	return reattestDirectoryPath(options, identity)
}

func lockDirectory(directory *os.Root) (*os.File, error) {
	file, err := directory.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open cron directory lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock cron directory: %w", err)
	}
	return file, nil
}

func unlockDirectory(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func readBounded(file *os.File, declared int64) ([]byte, error) {
	if declared < 0 || declared > maximumCronBytes {
		return nil, fmt.Errorf("cron file exceeds %d bytes", maximumCronBytes)
	}
	limited := io.LimitReader(file, maximumCronBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(content) > maximumCronBytes {
		return nil, fmt.Errorf("cron file exceeds %d bytes", maximumCronBytes)
	}
	return content, nil
}

func inspectFile(directory *os.Root, name string, uid, gid int, allowedModes ...fs.FileMode) (fileIdentity, []byte, bool, error) {
	info, err := directory.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return fileIdentity{}, nil, false, nil
	}
	if err != nil {
		return fileIdentity{}, nil, false, fmt.Errorf("inspect cron file %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fileIdentity{}, nil, false, fmt.Errorf("cron file %s is not a regular file", name)
	}
	modeAllowed := false
	for _, mode := range allowedModes {
		if info.Mode().Perm() == mode {
			modeAllowed = true
			break
		}
	}
	if !modeAllowed {
		return fileIdentity{}, nil, false, fmt.Errorf("cron file %s has mode %04o", name, info.Mode().Perm())
	}
	stat, err := unixStat(info)
	if err != nil {
		return fileIdentity{}, nil, false, err
	}
	if int64(stat.Uid) != int64(uid) || int64(stat.Gid) != int64(gid) || stat.Nlink != 1 {
		return fileIdentity{}, nil, false, fmt.Errorf("cron file %s has unsafe ownership or link count", name)
	}
	file, err := directory.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fileIdentity{}, nil, false, fmt.Errorf("open cron file %s: %w", name, err)
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil {
		return fileIdentity{}, nil, false, fmt.Errorf("inspect opened cron file %s: %w", name, err)
	}
	openedStat, err := unixStat(openedInfo)
	if err != nil || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return fileIdentity{}, nil, false, fmt.Errorf("cron file %s changed while opening", name)
	}
	content, err := readBounded(file, openedInfo.Size())
	if err != nil {
		return fileIdentity{}, nil, false, fmt.Errorf("read cron file %s: %w", name, err)
	}
	identity := fileIdentity{
		unixIdentity: unixIdentity{device: uint64(stat.Dev), inode: stat.Ino},
		mode:         info.Mode().Perm(),
		size:         info.Size(),
		uid:          stat.Uid,
		gid:          stat.Gid,
		links:        uint64(stat.Nlink),
		digest:       sha256.Sum256(content),
	}
	return identity, content, true, nil
}

func sameFileIdentity(left, right fileIdentity) bool {
	return left == right
}

func journalIdentityFromFile(identity fileIdentity, present bool) journalIdentity {
	if !present {
		return journalIdentity{}
	}
	return journalIdentity{
		Present: true,
		Device:  identity.device,
		Inode:   identity.inode,
		Mode:    uint32(identity.mode.Perm()),
		Size:    identity.size,
		UID:     identity.uid,
		GID:     identity.gid,
		Links:   identity.links,
		SHA256:  hex.EncodeToString(identity.digest[:]),
	}
}

func journalIdentityMatches(expected journalIdentity, actual fileIdentity, present bool) bool {
	return expected == journalIdentityFromFile(actual, present)
}

func sameTransaction(left, right transactionRecord) bool {
	left.Phase = ""
	right.Phase = ""
	return left == right
}

func validateTransactionRecord(record transactionRecord, options Options) error {
	if record.Version != transactionVersion ||
		(record.Phase != transactionPrepared && record.Phase != transactionCommitted) {
		return fmt.Errorf("cron transaction has an unsupported version or phase")
	}
	if record.LegacySize < 0 || record.LegacySize > maximumCronBytes {
		return fmt.Errorf("cron transaction has an invalid root crontab size")
	}
	legacyDigest, err := hex.DecodeString(record.LegacySHA256)
	if err != nil || len(legacyDigest) != sha256.Size {
		return fmt.Errorf("cron transaction has an invalid root crontab digest")
	}
	validateIdentity := func(label string, identity journalIdentity) error {
		if !identity.Present {
			if identity != (journalIdentity{}) {
				return fmt.Errorf("cron transaction %s absence contains identity data", label)
			}
			return nil
		}
		if identity.Device == 0 || identity.Inode == 0 || identity.Mode != 0644 ||
			identity.Size <= 0 || identity.Size > maximumOwnedCronBytes ||
			int64(identity.UID) != int64(options.FileOwnerUID) || int64(identity.GID) != int64(options.FileOwnerGID) ||
			identity.Links != 1 {
			return fmt.Errorf("cron transaction %s identity violates the owned file contract", label)
		}
		digest, err := hex.DecodeString(identity.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("cron transaction %s digest is invalid", label)
		}
		return nil
	}
	if err := validateIdentity("old", record.Old); err != nil {
		return err
	}
	if err := validateIdentity("new", record.New); err != nil {
		return err
	}
	switch record.Operation {
	case operationCreate:
		if record.Old.Present || !record.New.Present {
			return fmt.Errorf("cron create transaction has inconsistent identities")
		}
	case operationUpdate:
		if !record.Old.Present || !record.New.Present || record.Old == record.New {
			return fmt.Errorf("cron update transaction has inconsistent identities")
		}
	case operationDelete:
		if !record.Old.Present || record.New.Present {
			return fmt.Errorf("cron delete transaction has inconsistent identities")
		}
	default:
		return fmt.Errorf("cron transaction operation is invalid")
	}
	return nil
}

func canonicalTransactionBytes(record transactionRecord, options Options) ([]byte, error) {
	if err := validateTransactionRecord(record, options); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode cron transaction: %w", err)
	}
	wire = append(wire, '\n')
	if len(wire) > maximumJournalBytes {
		return nil, fmt.Errorf("cron transaction exceeds %d bytes", maximumJournalBytes)
	}
	for _, value := range wire {
		if value > 0x7f {
			return nil, fmt.Errorf("cron transaction is not ASCII")
		}
	}
	return wire, nil
}

func decodeTransactionBytes(wire []byte, options Options) (transactionRecord, error) {
	if len(wire) == 0 || len(wire) > maximumJournalBytes {
		return transactionRecord{}, fmt.Errorf("cron transaction file is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var record transactionRecord
	if err := decoder.Decode(&record); err != nil {
		return transactionRecord{}, fmt.Errorf("decode cron transaction: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return transactionRecord{}, fmt.Errorf("cron transaction contains trailing data")
	}
	canonical, err := canonicalTransactionBytes(record, options)
	if err != nil {
		return transactionRecord{}, err
	}
	if !bytes.Equal(canonical, wire) {
		return transactionRecord{}, fmt.Errorf("cron transaction is not canonically encoded")
	}
	return record, nil
}

func legacySnapshotMatchesRecord(legacy legacyState, record transactionRecord) bool {
	digest := sha256.Sum256([]byte(legacy.content))
	return legacy.present == record.LegacyPresent && len(legacy.content) == record.LegacySize &&
		hex.EncodeToString(digest[:]) == record.LegacySHA256
}

func verifyFile(directory *os.Root, name string, expected fileIdentity, uid, gid int, allowedModes ...fs.FileMode) error {
	actual, _, exists, err := inspectFile(directory, name, uid, gid, allowedModes...)
	if err != nil {
		return err
	}
	if !exists || !sameFileIdentity(actual, expected) {
		return fmt.Errorf("cron file %s changed before mutation", name)
	}
	return nil
}

func verifyAbsent(directory *os.Root, name string, uid, gid int, allowedModes ...fs.FileMode) error {
	_, _, exists, err := inspectFile(directory, name, uid, gid, allowedModes...)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("cron file %s remains after removal", name)
	}
	return nil
}

func syncPinnedDirectory(directory *os.File) error {
	if directory == nil {
		return fmt.Errorf("cron directory handle is unavailable")
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync cron directory: %w", err)
	}
	return nil
}

func ensureReservedAbsent(directory *os.Root, options Options, name string, modes ...fs.FileMode) error {
	_, _, exists, err := inspectFile(directory, name, options.FileOwnerUID, options.FileOwnerGID, modes...)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("reserved cron path %s is occupied", name)
	}
	return nil
}

func guardFilesystemMutation(options Options, operation string) error {
	if err := options.mutationGuard(); err != nil {
		return fmt.Errorf("refuse cron filesystem mutation %s: %w", operation, err)
	}
	return nil
}

func conditionalMove(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	source string,
	destination string,
	expected fileIdentity,
	modes ...fs.FileMode,
) error {
	_, err := conditionalMoveStatus(
		directory, directoryFile, options,
		source, destination, expected, modes...,
	)
	return err
}

func conditionalMoveStatus(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	source string,
	destination string,
	expected fileIdentity,
	modes ...fs.FileMode,
) (bool, error) {
	if err := ensureReservedAbsent(directory, options, destination, modes...); err != nil {
		return false, err
	}
	if err := reattestPinnedDirectoryPath(directory, options); err != nil {
		return false, err
	}
	if err := guardFilesystemMutation(options, "move "+source+" to "+destination); err != nil {
		return false, err
	}
	if err := options.renameat2(
		int(directoryFile.Fd()), source,
		int(directoryFile.Fd()), destination,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return false, fmt.Errorf("conditionally move cron path %s to %s: %w", source, destination, err)
	}
	moved, _, exists, inspectErr := inspectFile(
		directory, destination, options.FileOwnerUID, options.FileOwnerGID, modes...,
	)
	if inspectErr != nil || !exists || !sameFileIdentity(moved, expected) {
		pathErr := reattestPinnedDirectoryPath(directory, options)
		if pathErr != nil {
			return true, errors.Join(inspectErr, pathErr)
		}
		if guardErr := guardFilesystemMutation(options, "restore "+destination+" to "+source); guardErr != nil {
			return true, errors.Join(inspectErr, guardErr)
		}
		restoreErr := options.renameat2(
			int(directoryFile.Fd()), destination,
			int(directoryFile.Fd()), source,
			unix.RENAME_NOREPLACE,
		)
		syncErr := options.syncDirectory(directoryFile)
		if inspectErr == nil {
			inspectErr = fmt.Errorf("moved cron identity does not match the expected source")
		}
		return restoreErr != nil || syncErr != nil, errors.Join(inspectErr, restoreErr, syncErr)
	}
	if err := options.syncDirectory(directoryFile); err != nil {
		return true, err
	}
	return true, nil
}

func conditionalExchange(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	left string,
	right string,
	expectedLeft fileIdentity,
	expectedRight fileIdentity,
	modes ...fs.FileMode,
) error {
	_, err := conditionalExchangeStatus(
		directory, directoryFile, options,
		left, right, expectedLeft, expectedRight, modes...,
	)
	return err
}

func conditionalExchangeStatus(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	left string,
	right string,
	expectedLeft fileIdentity,
	expectedRight fileIdentity,
	modes ...fs.FileMode,
) (bool, error) {
	if err := reattestPinnedDirectoryPath(directory, options); err != nil {
		return false, err
	}
	if err := guardFilesystemMutation(options, "exchange "+left+" and "+right); err != nil {
		return false, err
	}
	if err := options.renameat2(
		int(directoryFile.Fd()), left,
		int(directoryFile.Fd()), right,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return false, fmt.Errorf("conditionally exchange cron paths %s and %s: %w", left, right, err)
	}
	actualLeft, _, leftExists, leftErr := inspectFile(
		directory, left, options.FileOwnerUID, options.FileOwnerGID, modes...,
	)
	actualRight, _, rightExists, rightErr := inspectFile(
		directory, right, options.FileOwnerUID, options.FileOwnerGID, modes...,
	)
	if leftErr != nil || rightErr != nil || !leftExists || !rightExists ||
		!sameFileIdentity(actualLeft, expectedRight) || !sameFileIdentity(actualRight, expectedLeft) {
		pathErr := reattestPinnedDirectoryPath(directory, options)
		if pathErr != nil {
			return true, errors.Join(leftErr, rightErr, pathErr)
		}
		if guardErr := guardFilesystemMutation(options, "restore exchange "+left+" and "+right); guardErr != nil {
			return true, errors.Join(leftErr, rightErr, guardErr)
		}
		restoreErr := options.renameat2(
			int(directoryFile.Fd()), left,
			int(directoryFile.Fd()), right,
			unix.RENAME_EXCHANGE,
		)
		syncErr := options.syncDirectory(directoryFile)
		return restoreErr != nil || syncErr != nil, errors.Join(
			fmt.Errorf("cron exchange detected an external source mutation"),
			leftErr,
			rightErr,
			restoreErr,
			syncErr,
		)
	}
	if err := options.syncDirectory(directoryFile); err != nil {
		return true, err
	}
	return true, nil
}

func conditionalRemove(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	source string,
	quarantine string,
	expected fileIdentity,
	modes ...fs.FileMode,
) error {
	if err := conditionalMove(
		directory, directoryFile, options, source, quarantine, expected, modes...,
	); err != nil {
		return err
	}
	options.faultPoint("cron-remove-quarantined:" + source)
	if err := verifyFile(
		directory, quarantine, expected,
		options.FileOwnerUID, options.FileOwnerGID, modes...,
	); err != nil {
		return fmt.Errorf("reattest quarantined cron path %s: %w", source, err)
	}
	if err := reattestPinnedDirectoryPath(directory, options); err != nil {
		return err
	}
	if err := guardFilesystemMutation(options, "unlink "+quarantine); err != nil {
		return err
	}
	if err := options.unlinkat(int(directoryFile.Fd()), quarantine, 0); err != nil {
		return fmt.Errorf("unlink quarantined cron path %s: %w", source, err)
	}
	if err := options.syncDirectory(directoryFile); err != nil {
		return err
	}
	options.faultPoint("cron-remove-unlinked:" + source)
	return verifyAbsent(directory, quarantine, options.FileOwnerUID, options.FileOwnerGID, modes...)
}

func finishExpectedRemoval(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	source string,
	quarantine string,
	expected fileIdentity,
	modes ...fs.FileMode,
) error {
	sourceIdentity, _, sourceExists, sourceErr := inspectFile(
		directory, source, options.FileOwnerUID, options.FileOwnerGID, modes...,
	)
	if sourceErr != nil {
		return sourceErr
	}
	quarantineIdentity, _, quarantineExists, quarantineErr := inspectFile(
		directory, quarantine, options.FileOwnerUID, options.FileOwnerGID, modes...,
	)
	if quarantineErr != nil {
		return quarantineErr
	}
	if sourceExists && quarantineExists {
		return fmt.Errorf("both active and quarantined cron paths exist for %s", source)
	}
	if quarantineExists {
		if !sameFileIdentity(quarantineIdentity, expected) {
			return fmt.Errorf("quarantined cron path %s changed identity", source)
		}
		options.faultPoint("cron-remove-resume:" + source)
		if err := verifyFile(
			directory, quarantine, expected,
			options.FileOwnerUID, options.FileOwnerGID, modes...,
		); err != nil {
			return err
		}
		if err := reattestPinnedDirectoryPath(directory, options); err != nil {
			return err
		}
		if err := guardFilesystemMutation(options, "unlink "+quarantine); err != nil {
			return err
		}
		if err := options.unlinkat(int(directoryFile.Fd()), quarantine, 0); err != nil {
			return fmt.Errorf("finish removal of quarantined cron path %s: %w", source, err)
		}
		if err := options.syncDirectory(directoryFile); err != nil {
			return err
		}
		return verifyAbsent(directory, quarantine, options.FileOwnerUID, options.FileOwnerGID, modes...)
	}
	if !sourceExists {
		return nil
	}
	if !sameFileIdentity(sourceIdentity, expected) {
		return fmt.Errorf("cron path %s changed identity before removal", source)
	}
	return conditionalRemove(
		directory, directoryFile, options,
		source, quarantine, expected, modes...,
	)
}

func readLegacy(reader RootCrontabReader) (legacyState, error) {
	content, present, err := reader()
	if err != nil {
		return legacyState{}, fmt.Errorf("read root crontab evidence: %w", err)
	}
	if !present && content != "" {
		return legacyState{}, fmt.Errorf("absent root crontab evidence contains unexpected bytes")
	}
	if len(content) > maximumCronBytes {
		return legacyState{}, fmt.Errorf("root crontab exceeds %d bytes", maximumCronBytes)
	}
	state := legacyState{content: content, present: present}
	for len(content) > 0 {
		line := content
		if end := strings.IndexByte(content, '\n'); end >= 0 {
			line = content[:end]
			content = content[end+1:]
		} else {
			content = ""
		}
		if minute, exact := platformpaths.ManagedFeedCronMinute(line); exact {
			state.feedCount++
			state.feedMinute = minute
		}
		if platformpaths.IsManagedHACronLine(line) {
			state.haCount++
		}
		if !platformpaths.IsManagedCronLine(line) && legacyCronLookalike(line) {
			return legacyState{}, fmt.Errorf("root crontab contains a noncanonical SysWarden scheduling record")
		}
	}
	if state.feedCount > 1 {
		return legacyState{}, fmt.Errorf("root crontab contains %d canonical legacy feed records", state.feedCount)
	}
	if state.haCount > 1 {
		return legacyState{}, fmt.Errorf("root crontab contains %d canonical legacy HA records", state.haCount)
	}
	return state, nil
}

func legacyCronLookalike(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	if strings.Contains(trimmed, platformpaths.CLI) &&
		(strings.Contains(trimmed, "update-feeds") || strings.Contains(trimmed, "ha-sync")) {
		return true
	}
	fields := strings.Fields(line)
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == platformpaths.CLI &&
			(fields[index+1] == "update-feeds" || fields[index+1] == "ha-sync") {
			return true
		}
	}
	return false
}

func sameLegacySnapshot(left, right legacyState) bool {
	return left.present == right.present && left.content == right.content
}

func reattestLegacy(options Options, expected legacyState) error {
	actual, err := readLegacy(options.ReadRootCrontab)
	if err != nil {
		return err
	}
	if !sameLegacySnapshot(actual, expected) {
		return fmt.Errorf("root crontab changed before owned cron mutation")
	}
	return nil
}

func ownedFeedLine(cli string, minute int) string {
	return fmt.Sprintf("%d * * * * root %s update-feeds >/dev/null 2>&1", minute, cli)
}

func ownedHALine(cli string) string {
	return "*/30 * * * * root " + cli + " ha-sync >/dev/null 2>&1"
}

func renderOwned(state ownedState, cli string) ([]byte, error) {
	if !state.feed && !state.ha {
		return nil, nil
	}
	if state.feed && (state.feedMinute < 1 || state.feedMinute > 59) {
		return nil, fmt.Errorf("owned feed minute is outside 1 through 59")
	}
	var builder strings.Builder
	builder.WriteString(ownedCronHeader)
	if state.feed {
		builder.WriteString(ownedFeedLine(cli, state.feedMinute))
		builder.WriteByte('\n')
	}
	if state.ha {
		builder.WriteString(ownedHALine(cli))
		builder.WriteByte('\n')
	}
	content := []byte(builder.String())
	for _, value := range content {
		if value > 0x7f {
			return nil, fmt.Errorf("owned cron content is not ASCII")
		}
	}
	return content, nil
}

func parseOwned(content []byte, cli string) (ownedState, error) {
	if len(content) == 0 || len(content) > maximumOwnedCronBytes {
		return ownedState{}, fmt.Errorf("owned cron file is empty or oversized")
	}
	for _, value := range content {
		if value > 0x7f {
			return ownedState{}, fmt.Errorf("owned cron file is not ASCII")
		}
	}
	contentString := string(content)
	for minute := 1; minute <= 59; minute++ {
		for _, ha := range []bool{false, true} {
			candidate := ownedState{feed: true, feedMinute: minute, ha: ha}
			wire, err := renderOwned(candidate, cli)
			if err == nil && string(wire) == contentString {
				return candidate, nil
			}
		}
	}
	haOnly := ownedState{ha: true}
	wire, err := renderOwned(haOnly, cli)
	if err == nil && string(wire) == contentString {
		return haOnly, nil
	}
	return ownedState{}, fmt.Errorf("owned cron file does not match the canonical SysWarden grammar")
}

func inspectOwned(directory *os.Root, options Options) (ownedState, fileIdentity, bool, error) {
	identity, content, exists, err := inspectFile(directory, options.FileName, options.FileOwnerUID, options.FileOwnerGID, 0644)
	if err != nil || !exists {
		return ownedState{}, identity, exists, err
	}
	state, err := parseOwned(content, options.CLIPath)
	if err != nil {
		return ownedState{}, fileIdentity{}, false, err
	}
	return state, identity, true, nil
}

func validatePendingContent(identity fileIdentity, content []byte, cli string) error {
	if len(content) > maximumOwnedCronBytes {
		return fmt.Errorf("cron staging file is oversized")
	}
	if identity.mode == 0644 {
		if _, err := parseOwned(content, cli); err != nil {
			return fmt.Errorf("completed cron staging file is not canonical: %w", err)
		}
		return nil
	}
	if identity.mode != 0600 {
		return fmt.Errorf("cron staging file has unsupported mode %04o", identity.mode)
	}
	contentString := string(content)
	for minute := 1; minute <= 59; minute++ {
		for _, ha := range []bool{false, true} {
			candidate, err := renderOwned(ownedState{feed: true, feedMinute: minute, ha: ha}, cli)
			if err == nil && strings.HasPrefix(string(candidate), contentString) {
				return nil
			}
		}
	}
	candidate, err := renderOwned(ownedState{ha: true}, cli)
	if err == nil && strings.HasPrefix(string(candidate), contentString) {
		return nil
	}
	return fmt.Errorf("incomplete cron staging file is not a canonical publication prefix")
}

func inspectPending(directory *os.Root, options Options) (fileIdentity, bool, error) {
	identity, content, exists, err := inspectFile(
		directory,
		pendingFileName,
		options.FileOwnerUID,
		options.FileOwnerGID,
		0600,
		0644,
	)
	if err != nil || !exists {
		return identity, exists, err
	}
	if err := validatePendingContent(identity, content, options.CLIPath); err != nil {
		return fileIdentity{}, false, err
	}
	return identity, true, nil
}

func inspectTransactionRecord(
	directory *os.Root,
	options Options,
	name string,
	expectedPhase string,
) (transactionRecord, fileIdentity, bool, error) {
	identity, content, exists, err := inspectFile(
		directory, name, options.FileOwnerUID, options.FileOwnerGID, 0600,
	)
	if err != nil || !exists {
		return transactionRecord{}, identity, exists, err
	}
	if len(content) > maximumJournalBytes {
		return transactionRecord{}, fileIdentity{}, false, fmt.Errorf("cron transaction file %s is oversized", name)
	}
	record, err := decodeTransactionBytes(content, options)
	if err != nil {
		return transactionRecord{}, fileIdentity{}, false, fmt.Errorf("validate cron transaction file %s: %w", name, err)
	}
	if record.Phase != expectedPhase {
		return transactionRecord{}, fileIdentity{}, false, fmt.Errorf("cron transaction file %s has phase %q", name, record.Phase)
	}
	return record, identity, true, nil
}

func inspectTransactionFiles(directory *os.Root, options Options) (transactionFiles, error) {
	prepared, journal, journalPresent, err := inspectTransactionRecord(
		directory, options, transactionFileName, transactionPrepared,
	)
	if err != nil {
		return transactionFiles{}, err
	}
	retiredPrepared, retiredJournal, retiredJournalPresent, err := inspectTransactionRecord(
		directory, options, transactionRetired, transactionPrepared,
	)
	if err != nil {
		return transactionFiles{}, err
	}
	if journalPresent && retiredJournalPresent {
		return transactionFiles{}, fmt.Errorf("both active and retired prepared cron journals exist")
	}
	journalName := transactionFileName
	if retiredJournalPresent {
		prepared = retiredPrepared
		journal = retiredJournal
		journalPresent = true
		journalName = transactionRetired
	}
	committed, commit, commitPresent, err := inspectTransactionRecord(
		directory, options, commitFileName, transactionCommitted,
	)
	if err != nil {
		return transactionFiles{}, err
	}
	retiredCommitted, retiredCommit, retiredCommitPresent, err := inspectTransactionRecord(
		directory, options, commitRetired, transactionCommitted,
	)
	if err != nil {
		return transactionFiles{}, err
	}
	if commitPresent && retiredCommitPresent {
		return transactionFiles{}, fmt.Errorf("both active and retired committed cron journals exist")
	}
	commitName := commitFileName
	if retiredCommitPresent {
		committed = retiredCommitted
		commit = retiredCommit
		commitPresent = true
		commitName = commitRetired
	}
	files := transactionFiles{
		journal:        journal,
		journalPresent: journalPresent,
		journalName:    journalName,
		commit:         commit,
		commitPresent:  commitPresent,
		commitName:     commitName,
	}
	switch {
	case journalPresent && commitPresent:
		if !sameTransaction(prepared, committed) {
			return transactionFiles{}, fmt.Errorf("prepared and committed cron transaction records disagree")
		}
		files.record = committed
	case commitPresent:
		files.record = committed
	case journalPresent:
		files.record = prepared
	}
	return files, nil
}

func inspectRetired(
	directory *os.Root,
	options Options,
	name string,
	modes ...fs.FileMode,
) (fileIdentity, bool, error) {
	identity, _, exists, err := inspectFile(
		directory, name, options.FileOwnerUID, options.FileOwnerGID, modes...,
	)
	return identity, exists, err
}

func validateCombinedState(legacy legacyState, owned ownedState) error {
	if legacy.feedCount == 1 && owned.feed {
		return fmt.Errorf("feed scheduling coexists in the root crontab and owned cron file")
	}
	if legacy.haCount == 1 && owned.ha {
		return fmt.Errorf("HA scheduling coexists in the root crontab and owned cron file")
	}
	return nil
}

func recoverPending(
	directory openedDirectory,
	directoryFile *os.File,
	options Options,
	legacy legacyState,
	requireProvider bool,
) (legacyState, error) {
	identity, exists, err := inspectPending(directory.root, options)
	if err != nil || !exists {
		return legacy, err
	}
	confirmed, err := readLegacy(options.ReadRootCrontab)
	if err != nil {
		return legacyState{}, err
	}
	if !sameLegacySnapshot(legacy, confirmed) {
		return legacyState{}, fmt.Errorf("root crontab changed while recovering an interrupted cron publication")
	}
	if err := verifyRecoveryEnvironment(directory, options, confirmed, requireProvider); err != nil {
		return legacyState{}, err
	}
	if err := conditionalRemove(
		directory.root, directoryFile, options,
		pendingFileName, retiredFileName, identity, 0600, 0644,
	); err != nil {
		return legacyState{}, fmt.Errorf("abort interrupted cron publication: %w", err)
	}
	if err := verifyAbsent(directory.root, pendingFileName, options.FileOwnerUID, options.FileOwnerGID, 0600, 0644); err != nil {
		return legacyState{}, err
	}
	if err := verifyRecoveryEnvironment(directory, options, confirmed, requireProvider); err != nil {
		return legacyState{}, err
	}
	return confirmed, nil
}

func createNamed(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	name string,
	content []byte,
	finalMode fs.FileMode,
) (fileIdentity, error) {
	if err := ensureReservedAbsent(directory, options, name, 0600, 0644); err != nil {
		return fileIdentity{}, err
	}
	fd, err := unix.Openat(
		int(directoryFile.Fd()), ".",
		unix.O_WRONLY|unix.O_TMPFILE|unix.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return fileIdentity{}, fmt.Errorf("create anonymous reserved cron inode for %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), "cronstate-anonymous")
	if file == nil {
		_ = unix.Close(fd)
		return fileIdentity{}, fmt.Errorf("adopt anonymous reserved cron inode for %s", name)
	}
	closeWithError := func(current error) error {
		if closeErr := file.Close(); closeErr != nil {
			return errors.Join(current, closeErr)
		}
		return current
	}
	info, err := file.Stat()
	if err != nil {
		return fileIdentity{}, closeWithError(err)
	}
	stat, err := unixStat(info)
	if err != nil {
		return fileIdentity{}, closeWithError(err)
	}
	if int64(stat.Uid) != int64(options.FileOwnerUID) || int64(stat.Gid) != int64(options.FileOwnerGID) {
		if err := file.Chown(options.FileOwnerUID, options.FileOwnerGID); err != nil {
			return fileIdentity{}, closeWithError(fmt.Errorf("set cron staging ownership: %w", err))
		}
	}
	written, err := file.Write(content)
	if err != nil {
		return fileIdentity{}, closeWithError(fmt.Errorf("write cron staging file: %w", err))
	}
	if written != len(content) {
		return fileIdentity{}, closeWithError(fmt.Errorf("write reserved cron file %s: short write", name))
	}
	if err := file.Sync(); err != nil {
		return fileIdentity{}, closeWithError(fmt.Errorf("sync reserved cron file %s content: %w", name, err))
	}
	if err := file.Chmod(finalMode); err != nil {
		return fileIdentity{}, closeWithError(fmt.Errorf("set reserved cron file %s mode: %w", name, err))
	}
	if err := file.Sync(); err != nil {
		return fileIdentity{}, closeWithError(fmt.Errorf("sync reserved cron file %s metadata: %w", name, err))
	}
	if err := reattestPinnedDirectoryPath(directory, options); err != nil {
		return fileIdentity{}, closeWithError(err)
	}
	if err := guardFilesystemMutation(options, "link "+name); err != nil {
		return fileIdentity{}, closeWithError(err)
	}
	if err := unix.Linkat(
		int(file.Fd()), "",
		int(directoryFile.Fd()), name,
		unix.AT_EMPTY_PATH,
	); err != nil {
		return fileIdentity{}, closeWithError(fmt.Errorf("publish reserved cron file %s without replacement: %w", name, err))
	}
	closeErr := file.Close()
	directorySyncErr := options.syncDirectory(directoryFile)
	identity, staged, exists, inspectErr := inspectFile(
		directory, name, options.FileOwnerUID, options.FileOwnerGID, finalMode,
	)
	if inspectErr == nil && (!exists || !bytes.Equal(staged, content)) {
		inspectErr = fmt.Errorf("reserved cron file %s failed content verification", name)
	}
	if closeErr != nil || directorySyncErr != nil || inspectErr != nil {
		return identity, &namedPublicationError{cause: errors.Join(
			fmt.Errorf("durably publish reserved cron file %s", name),
			closeErr,
			directorySyncErr,
			inspectErr,
		)}
	}
	return identity, nil
}

func createPending(directory *os.Root, directoryFile *os.File, options Options, content []byte) (fileIdentity, error) {
	return createNamed(directory, directoryFile, options, pendingFileName, content, 0644)
}

func fileIdentityFromJournal(identity journalIdentity) (fileIdentity, error) {
	if !identity.Present {
		return fileIdentity{}, nil
	}
	digest, err := hex.DecodeString(identity.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return fileIdentity{}, fmt.Errorf("decode journal file identity digest")
	}
	var sum [sha256.Size]byte
	copy(sum[:], digest)
	return fileIdentity{
		unixIdentity: unixIdentity{device: identity.Device, inode: identity.Inode},
		mode:         fs.FileMode(identity.Mode),
		size:         identity.Size,
		uid:          identity.UID,
		gid:          identity.GID,
		links:        identity.Links,
		digest:       sum,
	}, nil
}

func buildTransactionRecord(
	legacy legacyState,
	operation string,
	oldIdentity fileIdentity,
	oldPresent bool,
	newIdentity fileIdentity,
	newPresent bool,
) transactionRecord {
	legacyDigest := sha256.Sum256([]byte(legacy.content))
	return transactionRecord{
		Version:       transactionVersion,
		Phase:         transactionPrepared,
		Operation:     operation,
		LegacyPresent: legacy.present,
		LegacySize:    len(legacy.content),
		LegacySHA256:  hex.EncodeToString(legacyDigest[:]),
		Old:           journalIdentityFromFile(oldIdentity, oldPresent),
		New:           journalIdentityFromFile(newIdentity, newPresent),
	}
}

func createTransactionRecordFile(
	directory *os.Root,
	directoryFile *os.File,
	options Options,
	name string,
	record transactionRecord,
) (fileIdentity, error) {
	wire, err := canonicalTransactionBytes(record, options)
	if err != nil {
		return fileIdentity{}, err
	}
	identity, err := createNamed(directory, directoryFile, options, name, wire, 0600)
	if err != nil {
		return identity, err
	}
	actual, actualIdentity, exists, err := inspectTransactionRecord(
		directory, options, name, record.Phase,
	)
	if err != nil || !exists || actual != record || !sameFileIdentity(actualIdentity, identity) {
		if err == nil {
			err = fmt.Errorf("published cron transaction record changed identity")
		}
		return identity, &namedPublicationError{cause: err}
	}
	return identity, nil
}

func inspectOwnedIdentity(
	directory *os.Root,
	options Options,
	name string,
) (fileIdentity, bool, error) {
	identity, content, exists, err := inspectFile(
		directory, name, options.FileOwnerUID, options.FileOwnerGID, 0644,
	)
	if err != nil || !exists {
		return identity, exists, err
	}
	if _, err := parseOwned(content, options.CLIPath); err != nil {
		return fileIdentity{}, false, err
	}
	return identity, true, nil
}

func verifyExpectedOwned(
	directory *os.Root,
	options Options,
	expected journalIdentity,
) error {
	actual, exists, err := inspectOwnedIdentity(directory, options, options.FileName)
	if err != nil {
		return err
	}
	if !journalIdentityMatches(expected, actual, exists) {
		return fmt.Errorf("owned cron destination does not match the transaction record")
	}
	return nil
}

func verifyTransactionEvidence(
	directory openedDirectory,
	options Options,
	legacy legacyState,
	expected journalIdentity,
	requireProvider bool,
) error {
	if requireProvider {
		if options.AttestCronDProvider == nil {
			return fmt.Errorf("cron.d provider attestation is required")
		}
		if err := options.AttestCronDProvider(); err != nil {
			return fmt.Errorf("attest cron.d provider: %w", err)
		}
	}
	if err := reattestLegacy(options, legacy); err != nil {
		return err
	}
	if err := reattestDirectoryPath(options, directory.identity); err != nil {
		return err
	}
	if err := verifyExpectedOwned(directory.root, options, expected); err != nil {
		return err
	}
	if requireProvider {
		if err := options.AttestCronDProvider(); err != nil {
			return fmt.Errorf("reattest cron.d provider: %w", err)
		}
	}
	if err := reattestLegacy(options, legacy); err != nil {
		return err
	}
	if err := verifyExpectedOwned(directory.root, options, expected); err != nil {
		return err
	}
	return reattestDirectoryPath(options, directory.identity)
}

func verifyRecoveryEnvironment(
	directory openedDirectory,
	options Options,
	legacy legacyState,
	requireProvider bool,
) error {
	if requireProvider {
		if options.AttestCronDProvider == nil {
			return fmt.Errorf("cron.d provider attestation is required for transaction recovery")
		}
		if err := options.AttestCronDProvider(); err != nil {
			return fmt.Errorf("attest cron.d provider before transaction recovery: %w", err)
		}
	}
	if err := reattestLegacy(options, legacy); err != nil {
		return err
	}
	if err := reattestDirectoryPath(options, directory.identity); err != nil {
		return err
	}
	if requireProvider {
		if err := options.AttestCronDProvider(); err != nil {
			return fmt.Errorf("reattest cron.d provider during transaction recovery: %w", err)
		}
	}
	if err := reattestLegacy(options, legacy); err != nil {
		return err
	}
	return reattestDirectoryPath(options, directory.identity)
}

func bindMutationGuard(
	options Options,
	directory openedDirectory,
	legacy legacyState,
	requireProvider bool,
) Options {
	base := options
	options.mutationGuard = func() error {
		return verifyRecoveryEnvironment(directory, base, legacy, requireProvider)
	}
	return options
}

func inspectTransactionArtifacts(
	directory *os.Root,
	options Options,
) (target fileIdentity, targetPresent bool, pending fileIdentity, pendingPresent bool, retired fileIdentity, retiredPresent bool, err error) {
	target, targetPresent, err = inspectOwnedIdentity(directory, options, options.FileName)
	if err != nil {
		return
	}
	pending, pendingPresent, err = inspectOwnedIdentity(directory, options, pendingFileName)
	if err != nil {
		return
	}
	retired, retiredPresent, err = inspectOwnedIdentity(directory, options, retiredFileName)
	return
}

func rollbackPreparedTransaction(
	directory openedDirectory,
	directoryFile *os.File,
	options Options,
	record transactionRecord,
) error {
	oldIdentity, err := fileIdentityFromJournal(record.Old)
	if err != nil {
		return err
	}
	newIdentity, err := fileIdentityFromJournal(record.New)
	if err != nil {
		return err
	}
	target, targetPresent, pending, pendingPresent, retired, retiredPresent, err :=
		inspectTransactionArtifacts(directory.root, options)
	if err != nil {
		return err
	}
	if retiredPresent && !sameFileIdentity(retired, newIdentity) {
		return fmt.Errorf("prepared cron transaction has unexpected retired state")
	}
	switch record.Operation {
	case operationCreate:
		switch {
		case targetPresent && journalIdentityMatches(record.New, target, true) && !pendingPresent && !retiredPresent:
			if err := conditionalMove(
				directory.root, directoryFile, options,
				options.FileName, pendingFileName, newIdentity, 0644,
			); err != nil {
				return err
			}
		case !targetPresent && pendingPresent && sameFileIdentity(pending, newIdentity) && !retiredPresent:
		case !targetPresent && !pendingPresent && retiredPresent:
		default:
			return fmt.Errorf("cannot safely roll back interrupted cron creation")
		}
		return finishExpectedRemoval(
			directory.root, directoryFile, options,
			pendingFileName, retiredFileName, newIdentity, 0644,
		)
	case operationUpdate:
		switch {
		case targetPresent && sameFileIdentity(target, oldIdentity) && pendingPresent && sameFileIdentity(pending, newIdentity) && !retiredPresent:
		case targetPresent && sameFileIdentity(target, newIdentity) && pendingPresent && sameFileIdentity(pending, oldIdentity) && !retiredPresent:
			if err := conditionalExchange(
				directory.root, directoryFile, options,
				pendingFileName, options.FileName, oldIdentity, newIdentity, 0644,
			); err != nil {
				return err
			}
		case targetPresent && sameFileIdentity(target, oldIdentity) && !pendingPresent && retiredPresent && sameFileIdentity(retired, newIdentity):
		default:
			return fmt.Errorf("cannot safely roll back interrupted cron update")
		}
		return finishExpectedRemoval(
			directory.root, directoryFile, options,
			pendingFileName, retiredFileName, newIdentity, 0644,
		)
	case operationDelete:
		switch {
		case targetPresent && sameFileIdentity(target, oldIdentity) && !pendingPresent && !retiredPresent:
			return nil
		case !targetPresent && pendingPresent && sameFileIdentity(pending, oldIdentity) && !retiredPresent:
			return conditionalMove(
				directory.root, directoryFile, options,
				pendingFileName, options.FileName, oldIdentity, 0644,
			)
		default:
			return fmt.Errorf("cannot safely roll back interrupted cron deletion")
		}
	default:
		return fmt.Errorf("cannot roll back unknown cron transaction operation")
	}
}

func completeCommittedTransaction(
	directory openedDirectory,
	directoryFile *os.File,
	options Options,
	record transactionRecord,
) error {
	oldIdentity, err := fileIdentityFromJournal(record.Old)
	if err != nil {
		return err
	}
	newIdentity, err := fileIdentityFromJournal(record.New)
	if err != nil {
		return err
	}
	if err := verifyExpectedOwned(directory.root, options, record.New); err != nil {
		return fmt.Errorf("committed cron transaction destination: %w", err)
	}
	_, pendingPresent, err := inspectOwnedIdentity(directory.root, options, pendingFileName)
	if err != nil {
		return err
	}
	_, retiredPresent, err := inspectOwnedIdentity(directory.root, options, retiredFileName)
	if err != nil {
		return err
	}
	switch record.Operation {
	case operationCreate:
		if pendingPresent || retiredPresent {
			return fmt.Errorf("committed cron creation has unexpected prior state")
		}
	case operationUpdate, operationDelete:
		if !pendingPresent && !retiredPresent {
			return nil
		}
		return finishExpectedRemoval(
			directory.root, directoryFile, options,
			pendingFileName, retiredFileName, oldIdentity, 0644,
		)
	default:
		return fmt.Errorf("cannot complete unknown cron transaction operation")
	}
	_ = newIdentity
	return nil
}

func removeTransactionRecords(
	directory openedDirectory,
	directoryFile *os.File,
	options Options,
	files transactionFiles,
) error {
	if files.journalPresent {
		if err := finishExpectedRemoval(
			directory.root, directoryFile, options,
			transactionFileName, transactionRetired, files.journal, 0600,
		); err != nil {
			return err
		}
	}
	if files.commitPresent {
		if err := finishExpectedRemoval(
			directory.root, directoryFile, options,
			commitFileName, commitRetired, files.commit, 0600,
		); err != nil {
			return err
		}
	}
	return nil
}

func recoverTransaction(
	directory openedDirectory,
	directoryFile *os.File,
	options Options,
	legacy legacyState,
	requireProvider bool,
) (legacyState, error) {
	files, err := inspectTransactionFiles(directory.root, options)
	if err != nil {
		return legacyState{}, err
	}
	if !files.journalPresent && !files.commitPresent {
		if _, _, _, err := inspectOwned(directory.root, options); err != nil {
			return legacyState{}, err
		}
		retiredIdentity, retiredContent, retiredPresent, err := inspectFile(
			directory.root, retiredFileName,
			options.FileOwnerUID, options.FileOwnerGID, 0600, 0644,
		)
		if err != nil {
			return legacyState{}, err
		}
		if retiredPresent {
			if err := validatePendingContent(retiredIdentity, retiredContent, options.CLIPath); err != nil {
				return legacyState{}, fmt.Errorf("validate interrupted cron retirement: %w", err)
			}
			if err := verifyRecoveryEnvironment(directory, options, legacy, requireProvider); err != nil {
				return legacyState{}, err
			}
			if err := finishExpectedRemoval(
				directory.root, directoryFile, options,
				pendingFileName, retiredFileName, retiredIdentity, 0600, 0644,
			); err != nil {
				return legacyState{}, err
			}
			if err := verifyRecoveryEnvironment(directory, options, legacy, requireProvider); err != nil {
				return legacyState{}, err
			}
		}
		return recoverPending(directory, directoryFile, options, legacy, requireProvider)
	}
	if !legacySnapshotMatchesRecord(legacy, files.record) {
		return legacyState{}, fmt.Errorf("root crontab changed while a durable cron transaction was incomplete")
	}
	if err := verifyRecoveryEnvironment(directory, options, legacy, requireProvider); err != nil {
		return legacyState{}, err
	}
	if files.commitPresent {
		if err := completeCommittedTransaction(directory, directoryFile, options, files.record); err != nil {
			return legacyState{}, err
		}
	} else if err := rollbackPreparedTransaction(directory, directoryFile, options, files.record); err != nil {
		return legacyState{}, err
	}
	if err := verifyRecoveryEnvironment(directory, options, legacy, requireProvider); err != nil {
		return legacyState{}, err
	}
	if err := removeTransactionRecords(directory, directoryFile, options, files); err != nil {
		return legacyState{}, err
	}
	if err := verifyRecoveryEnvironment(directory, options, legacy, requireProvider); err != nil {
		return legacyState{}, err
	}
	options.faultPoint("cron-transaction-recovered")
	return legacy, nil
}

func abortPreparedTransaction(
	directory openedDirectory,
	directoryFile *os.File,
	options Options,
	record transactionRecord,
	journal fileIdentity,
	commit fileIdentity,
	commitPresent bool,
) error {
	if commitPresent {
		if err := finishExpectedRemoval(
			directory.root, directoryFile, options,
			commitFileName, commitRetired, commit, 0600,
		); err != nil {
			return fmt.Errorf("withdraw committed cron marker before rollback: %w", err)
		}
	}
	if err := rollbackPreparedTransaction(directory, directoryFile, options, record); err != nil {
		return fmt.Errorf("roll back prepared cron transaction: %w", err)
	}
	if err := finishExpectedRemoval(
		directory.root, directoryFile, options,
		transactionFileName, transactionRetired, journal, 0600,
	); err != nil {
		return fmt.Errorf("retire rolled-back cron transaction: %w", err)
	}
	return nil
}

func applyOwnedTransaction(
	directory openedDirectory,
	directoryFile *os.File,
	options Options,
	legacy legacyState,
	oldIdentity fileIdentity,
	oldPresent bool,
	content []byte,
	requireProvider bool,
) (result error) {
	newPresent := len(content) > 0
	var operation string
	switch {
	case !oldPresent && newPresent:
		operation = operationCreate
	case oldPresent && !newPresent:
		operation = operationDelete
	case oldPresent && newPresent:
		operation = operationUpdate
	default:
		return nil
	}
	if options.beforeMutation != nil {
		options.beforeMutation()
	}
	if err := verifyTransactionEvidence(
		directory, options, legacy,
		journalIdentityFromFile(oldIdentity, oldPresent), requireProvider,
	); err != nil {
		return err
	}

	var newIdentity fileIdentity
	var err error
	if newPresent {
		newIdentity, err = createPending(directory.root, directoryFile, options, content)
		if err != nil {
			return err
		}
	}
	record := buildTransactionRecord(
		legacy, operation, oldIdentity, oldPresent, newIdentity, newPresent,
	)
	journal, err := createTransactionRecordFile(
		directory.root, directoryFile, options, transactionFileName, record,
	)
	if err != nil {
		if namedPublicationMayExist(err) {
			return err
		}
		if newPresent {
			result = finishExpectedRemoval(
				directory.root, directoryFile, options,
				pendingFileName, retiredFileName, newIdentity, 0644,
			)
		}
		return errors.Join(err, result)
	}
	options.faultPoint("cron-transaction-prepared")

	abort := func(cause error, commit fileIdentity, commitPresent bool, mutated bool) error {
		cleanupOptions := options
		cleanupOptions.mutationGuard = func() error {
			return reattestDirectoryPath(options, directory.identity)
		}
		if !mutated {
			var cleanupErr error
			if newPresent {
				cleanupErr = finishExpectedRemoval(
					directory.root, directoryFile, cleanupOptions,
					pendingFileName, retiredFileName, newIdentity, 0644,
				)
			}
			if cleanupErr != nil {
				return errors.Join(cause, cleanupErr)
			}
			journalErr := finishExpectedRemoval(
				directory.root, directoryFile, cleanupOptions,
				transactionFileName, transactionRetired, journal, 0600,
			)
			return errors.Join(cause, cleanupErr, journalErr)
		}
		rollbackErr := abortPreparedTransaction(
			directory, directoryFile, cleanupOptions, record, journal, commit, commitPresent,
		)
		return errors.Join(cause, rollbackErr)
	}
	if options.beforeReplace != nil {
		options.beforeReplace()
	}
	if err := verifyTransactionEvidence(
		directory, options, legacy, record.Old, requireProvider,
	); err != nil {
		return abort(err, fileIdentity{}, false, false)
	}
	if err := verifyFile(
		directory.root, transactionFileName, journal,
		options.FileOwnerUID, options.FileOwnerGID, 0600,
	); err != nil {
		return abort(err, fileIdentity{}, false, false)
	}
	if newPresent {
		if err := verifyFile(
			directory.root, pendingFileName, newIdentity,
			options.FileOwnerUID, options.FileOwnerGID, 0644,
		); err != nil {
			return abort(err, fileIdentity{}, false, false)
		}
	}

	mutated := false
	switch operation {
	case operationCreate:
		mutated, err = conditionalMoveStatus(
			directory.root, directoryFile, options,
			pendingFileName, options.FileName, newIdentity, 0644,
		)
	case operationUpdate:
		mutated, err = conditionalExchangeStatus(
			directory.root, directoryFile, options,
			pendingFileName, options.FileName, newIdentity, oldIdentity, 0644,
		)
	case operationDelete:
		mutated, err = conditionalMoveStatus(
			directory.root, directoryFile, options,
			options.FileName, pendingFileName, oldIdentity, 0644,
		)
	}
	if err != nil {
		return abort(err, fileIdentity{}, false, mutated)
	}
	options.faultPoint("cron-transaction-mutated:" + operation)
	if err := verifyTransactionEvidence(directory, options, legacy, record.New, requireProvider); err != nil {
		return abort(err, fileIdentity{}, false, true)
	}

	committed := record
	committed.Phase = transactionCommitted
	commit, err := createTransactionRecordFile(
		directory.root, directoryFile, options, commitFileName, committed,
	)
	if err != nil {
		if namedPublicationMayExist(err) {
			return err
		}
		return abort(err, fileIdentity{}, false, true)
	}
	options.faultPoint("cron-transaction-committed")
	if err := verifyTransactionEvidence(directory, options, legacy, record.New, requireProvider); err != nil {
		return abort(err, commit, true, true)
	}
	files := transactionFiles{
		record:         committed,
		journal:        journal,
		journalPresent: true,
		journalName:    transactionFileName,
		commit:         commit,
		commitPresent:  true,
		commitName:     commitFileName,
	}
	if err := completeCommittedTransaction(directory, directoryFile, options, committed); err != nil {
		return err
	}
	options.faultPoint("cron-transaction-prior-state-retired")
	if err := verifyTransactionEvidence(directory, options, legacy, record.New, requireProvider); err != nil {
		return err
	}
	if err := removeTransactionRecords(directory, directoryFile, options, files); err != nil {
		return err
	}
	options.faultPoint("cron-transaction-finished")
	return verifyTransactionEvidence(directory, options, legacy, record.New, requireProvider)
}

func withState(options Options, mutate func(legacyState, ownedState) (ownedState, any, error)) (any, error) {
	options = normalizeOptions(options)
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	if options.AttestCronDProvider == nil {
		return nil, fmt.Errorf("cron.d provider attestation is required for scheduling reconciliation")
	}
	if err := options.AttestCronDProvider(); err != nil {
		return nil, fmt.Errorf("attest cron.d provider before scheduling reconciliation: %w", err)
	}
	legacy, err := readLegacy(options.ReadRootCrontab)
	if err != nil {
		return nil, err
	}
	directory, err := openProtectedDirectory(options)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.root.Close() }()
	lock, err := lockDirectory(directory.root)
	if err != nil {
		return nil, err
	}
	defer unlockDirectory(lock)
	options = bindMutationGuard(options, directory, legacy, true)
	legacy, err = recoverTransaction(directory, lock, options, legacy, true)
	if err != nil {
		return nil, err
	}
	owned, identity, exists, err := inspectOwned(directory.root, options)
	if err != nil {
		return nil, err
	}
	if err := validateCombinedState(legacy, owned); err != nil {
		return nil, err
	}
	desired, value, err := mutate(legacy, owned)
	if err != nil {
		return nil, err
	}
	wire, err := renderOwned(desired, options.CLIPath)
	if err != nil {
		return nil, err
	}
	currentWire, err := renderOwned(owned, options.CLIPath)
	if err != nil {
		return nil, err
	}
	if string(wire) == string(currentWire) {
		if err := verifyTransactionEvidence(
			directory, options, legacy,
			journalIdentityFromFile(identity, exists), true,
		); err != nil {
			return nil, err
		}
		return value, nil
	}
	return value, applyOwnedTransaction(
		directory, lock, options, legacy, identity, exists, wire, true,
	)
}

// ReconcileFeed ensures one effective feed schedule. A canonical legacy root
// record remains authoritative and is never rewritten. The random source is
// used only when a new owned record must be created.
func ReconcileFeed(options Options) (FeedResult, error) {
	value, err := withState(options, func(legacy legacyState, owned ownedState) (ownedState, any, error) {
		if legacy.feedCount == 1 {
			return owned, FeedResult{Minute: legacy.feedMinute, Legacy: true}, nil
		}
		if owned.feed {
			return owned, FeedResult{Minute: owned.feedMinute}, nil
		}
		if options.RandomMinute == nil {
			return ownedState{}, nil, fmt.Errorf("random minute source is required for a fresh owned feed schedule")
		}
		minute, err := options.RandomMinute()
		if err != nil {
			return ownedState{}, nil, fmt.Errorf("select feed schedule minute: %w", err)
		}
		if minute < 1 || minute > 59 {
			return ownedState{}, nil, fmt.Errorf("selected feed minute is outside 1 through 59")
		}
		owned.feed = true
		owned.feedMinute = minute
		return owned, FeedResult{Minute: minute}, nil
	})
	if err != nil {
		return FeedResult{}, err
	}
	result, ok := value.(FeedResult)
	if !ok {
		return FeedResult{}, fmt.Errorf("invalid feed reconciliation result")
	}
	return result, nil
}

// ReconcileHA enables or disables only the owned HA record. A canonical legacy
// HA record satisfies enablement but makes disablement fail closed.
func ReconcileHA(options Options, enabled bool) error {
	_, err := withState(options, func(legacy legacyState, owned ownedState) (ownedState, any, error) {
		if legacy.haCount == 1 {
			if !enabled {
				return ownedState{}, nil, fmt.Errorf("cannot disable the canonical legacy HA record without modifying the root crontab")
			}
			return owned, nil, nil
		}
		owned.ha = enabled
		return owned, nil, nil
	})
	return err
}

// RemoveForUninstall removes only safely attested SysWarden cron.d state. The
// root crontab is read-only evidence and is never changed. Unsafe or
// noncanonical owned and staging files are preserved with an error.
func RemoveForUninstall(options Options) error {
	options = normalizeOptions(options)
	if err := validateOptions(options); err != nil {
		return err
	}
	legacy, err := readLegacy(options.ReadRootCrontab)
	if err != nil {
		return err
	}
	directory, err := openProtectedDirectory(options)
	if err != nil {
		return err
	}
	defer func() { _ = directory.root.Close() }()
	lock, err := lockDirectory(directory.root)
	if err != nil {
		return err
	}
	defer unlockDirectory(lock)
	options = bindMutationGuard(options, directory, legacy, false)
	legacy, err = recoverTransaction(directory, lock, options, legacy, false)
	if err != nil {
		return err
	}
	_, identity, exists, err := inspectOwned(directory.root, options)
	if err != nil {
		return err
	}
	if exists {
		return applyOwnedTransaction(
			directory, lock, options, legacy, identity, true, nil, false,
		)
	}
	return verifyTransactionEvidence(
		directory, options, legacy, journalIdentity{}, false,
	)
}

// Inspect reads and validates both scheduling stores without recovering or
// modifying either one.
func Inspect(options Options) (Inspection, error) {
	options = normalizeOptions(options)
	if err := validateOptions(options); err != nil {
		return Inspection{}, err
	}
	if options.AttestCronDProvider == nil {
		return Inspection{}, fmt.Errorf("cron.d provider attestation is required for scheduling inspection")
	}
	if err := options.AttestCronDProvider(); err != nil {
		return Inspection{}, fmt.Errorf("attest cron.d provider before scheduling inspection: %w", err)
	}
	legacy, err := readLegacy(options.ReadRootCrontab)
	if err != nil {
		return Inspection{}, err
	}
	directory, err := openProtectedDirectory(options)
	if err != nil {
		return Inspection{}, err
	}
	defer func() { _ = directory.root.Close() }()
	lock, err := lockDirectory(directory.root)
	if err != nil {
		return Inspection{}, err
	}
	defer unlockDirectory(lock)
	transactions, err := inspectTransactionFiles(directory.root, options)
	if err != nil {
		return Inspection{}, err
	}
	if transactions.journalPresent || transactions.commitPresent {
		return Inspection{}, fmt.Errorf("a durable cron transaction requires recovery")
	}
	if _, pending, err := inspectPending(directory.root, options); err != nil {
		return Inspection{}, err
	} else if pending {
		return Inspection{}, fmt.Errorf("an interrupted cron publication requires recovery")
	}
	if _, retired, err := inspectRetired(directory.root, options, retiredFileName, 0600, 0644); err != nil {
		return Inspection{}, err
	} else if retired {
		return Inspection{}, fmt.Errorf("an interrupted cron retirement requires recovery")
	}
	owned, identity, exists, err := inspectOwned(directory.root, options)
	if err != nil {
		return Inspection{}, err
	}
	if err := validateCombinedState(legacy, owned); err != nil {
		return Inspection{}, err
	}
	if err := verifyTransactionEvidence(
		directory, options, legacy,
		journalIdentityFromFile(identity, exists), true,
	); err != nil {
		return Inspection{}, err
	}
	minute := owned.feedMinute
	if legacy.feedCount == 1 {
		minute = legacy.feedMinute
	}
	return Inspection{
		LegacyFeedCount: legacy.feedCount,
		LegacyHACount:   legacy.haCount,
		OwnedFeed:       owned.feed,
		OwnedHA:         owned.ha,
		FeedMinute:      minute,
	}, nil
}

// Preflight performs the read-only scheduling, collision, and provider checks
// required before an install or reload begins any mutable work.
func Preflight(options Options, haEnabled bool) (Inspection, error) {
	inspection, err := Inspect(options)
	if err != nil {
		return Inspection{}, err
	}
	if !haEnabled && (inspection.LegacyHACount == 1 || inspection.OwnedHA) {
		return Inspection{}, fmt.Errorf("HA synchronization remains scheduled while HA is disabled")
	}
	return inspection, nil
}

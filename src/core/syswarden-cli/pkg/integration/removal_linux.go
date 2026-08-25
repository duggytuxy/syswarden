//go:build linux

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/config"

	"golang.org/x/sys/unix"
)

const (
	legacyCompletionParentDirectory = "/etc"
	legacyCompletionDirectoryName   = "bash_completion.d"
	legacyCompletionName            = "syswarden"
	legacyCompletionSize            = 16339
	legacyCompletionSHA256          = "c23c9f6c54b91105e9ecd8ad4431a9a11ad26ba3437bcd20ec2cef1a96e51d21"
	rsyslogSIEMConfigName           = "99-syswarden-siem.conf"
	exactArtifactQuarantineSuffix   = ".syswarden-removal-v1"
	exactArtifactRecreationSuffix   = ".syswarden-recreation-v1"
)

type exactOwnedArtifactExpectation struct {
	label          string
	name           string
	content        []byte
	digest         [sha256.Size]byte
	size           int64
	permittedModes map[uint32]struct{}
}

type exactOwnedArtifactIdentity struct {
	exists          bool
	dev, ino, nlink uint64
	size            int64
	mode, uid, gid  uint32
	mtime, ctime    unix.Timespec
	digest          [sha256.Size]byte
}

type exactOwnedArtifactInspection struct {
	identity  exactOwnedArtifactIdentity
	exact     bool
	ambiguous string
	content   []byte
}

type ownedArtifactDirectoryAmbiguityError struct {
	cause error
}

func (failure *ownedArtifactDirectoryAmbiguityError) Error() string { return failure.cause.Error() }
func (failure *ownedArtifactDirectoryAmbiguityError) Unwrap() error { return failure.cause }

type exactOwnedArtifactRemovalOptions struct {
	renameat2      func(int, string, int, string, uint) error
	unlinkat       func(int, string, int) error
	syncDirectory  func(*os.File) error
	faultPoint     func(string)
	recreationStep func(string) error
	warn           func(string)
	beforeCommit   func() error
	afterRestore   func() error
}

func defaultExactOwnedArtifactRemovalOptions() exactOwnedArtifactRemovalOptions {
	return exactOwnedArtifactRemovalOptions{
		renameat2: unix.Renameat2,
		unlinkat:  unix.Unlinkat,
		syncDirectory: func(directory *os.File) error {
			return directory.Sync()
		},
		faultPoint:     func(string) {},
		recreationStep: func(string) error { return nil },
		warn: func(message string) {
			fmt.Fprintf(os.Stderr, "[WARN] %s\n", message)
		},
	}
}

func normalizeExactOwnedArtifactRemovalOptions(
	options exactOwnedArtifactRemovalOptions,
) exactOwnedArtifactRemovalOptions {
	defaults := defaultExactOwnedArtifactRemovalOptions()
	if options.renameat2 == nil {
		options.renameat2 = defaults.renameat2
	}
	if options.unlinkat == nil {
		options.unlinkat = defaults.unlinkat
	}
	if options.syncDirectory == nil {
		options.syncDirectory = defaults.syncDirectory
	}
	if options.faultPoint == nil {
		options.faultPoint = defaults.faultPoint
	}
	if options.recreationStep == nil {
		options.recreationStep = defaults.recreationStep
	}
	if options.warn == nil {
		options.warn = defaults.warn
	}
	return options
}

func exactContentExpectation(label, name string, content []byte, mode uint32) exactOwnedArtifactExpectation {
	ownedContent := append([]byte(nil), content...)
	return exactOwnedArtifactExpectation{
		label:          label,
		name:           name,
		content:        ownedContent,
		digest:         sha256.Sum256(ownedContent),
		size:           int64(len(ownedContent)),
		permittedModes: map[uint32]struct{}{mode: {}},
	}
}

func legacyCompletionExpectation() exactOwnedArtifactExpectation {
	raw, err := hex.DecodeString(legacyCompletionSHA256)
	if err != nil || len(raw) != sha256.Size {
		panic("invalid compiled-in legacy completion digest")
	}
	var digest [sha256.Size]byte
	copy(digest[:], raw)
	return exactOwnedArtifactExpectation{
		label:          "legacy SysWarden bash completion",
		name:           legacyCompletionName,
		digest:         digest,
		size:           legacyCompletionSize,
		permittedModes: map[uint32]struct{}{0644: {}},
	}
}

func validOwnedArtifactName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		filepath.Base(name) == name && !strings.ContainsRune(name, 0)
}

func validateOwnedArtifactDirectory(
	label string,
	stat *unix.Stat_t,
	uid, gid uint32,
) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Gid != gid || stat.Mode&0022 != 0 {
		return fmt.Errorf(
			"%s must be a real uid %d gid %d directory without group/world write access",
			label, uid, gid,
		)
	}
	return nil
}

func openExistingOwnedArtifactDirectoryAt(
	parentPath, directoryName string,
	uid, gid uint32,
) (*os.File, bool, error) {
	if !validOwnedArtifactName(directoryName) {
		return nil, false, fmt.Errorf("invalid owned-artifact directory name %q", directoryName)
	}
	parentFD, err := unix.Open(
		parentPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open anchored parent %s: %w", parentPath, err)
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err := unix.Fstat(parentFD, &stat); err != nil {
		return nil, false, fmt.Errorf("inspect anchored parent %s: %w", parentPath, err)
	}
	if err := validateOwnedArtifactDirectory("owned-artifact parent "+parentPath, &stat, uid, gid); err != nil {
		return nil, false, err
	}

	directoryFD, err := unix.Openat(
		parentFD,
		directoryName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return nil, false, &ownedArtifactDirectoryAmbiguityError{cause: fmt.Errorf(
			"open anchored directory %s without following symlinks: %w",
			filepath.Join(parentPath, directoryName), err,
		)}
	}
	if err != nil {
		return nil, false, fmt.Errorf(
			"open anchored directory %s without following symlinks: %w",
			filepath.Join(parentPath, directoryName), err,
		)
	}
	if err := unix.Fstat(directoryFD, &stat); err != nil {
		_ = unix.Close(directoryFD)
		return nil, false, fmt.Errorf("inspect anchored directory: %w", err)
	}
	if err := validateOwnedArtifactDirectory(
		"owned-artifact directory "+filepath.Join(parentPath, directoryName), &stat, uid, gid,
	); err != nil {
		_ = unix.Close(directoryFD)
		return nil, false, &ownedArtifactDirectoryAmbiguityError{cause: err}
	}
	directory := os.NewFile(uintptr(directoryFD), filepath.Join(parentPath, directoryName))
	if directory == nil {
		_ = unix.Close(directoryFD)
		return nil, false, fmt.Errorf("wrap anchored owned-artifact directory")
	}
	return directory, true, nil
}

func ownedArtifactIdentity(stat *unix.Stat_t, digest [sha256.Size]byte) exactOwnedArtifactIdentity {
	return exactOwnedArtifactIdentity{
		exists: true,
		dev:    uint64(stat.Dev),
		ino:    uint64(stat.Ino),
		nlink:  uint64(stat.Nlink),
		size:   stat.Size,
		mode:   stat.Mode,
		uid:    stat.Uid,
		gid:    stat.Gid,
		mtime:  stat.Mtim,
		ctime:  stat.Ctim,
		digest: digest,
	}
}

func sameOwnedArtifactStat(left, right *unix.Stat_t) bool {
	return uint64(left.Dev) == uint64(right.Dev) && uint64(left.Ino) == uint64(right.Ino) &&
		left.Nlink == right.Nlink && left.Size == right.Size && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid &&
		left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func sameOwnedArtifactIdentity(left, right exactOwnedArtifactIdentity) bool {
	return left == right
}

func sameMovedOwnedArtifactIdentity(left, right exactOwnedArtifactIdentity) bool {
	left.ctime = unix.Timespec{}
	right.ctime = unix.Timespec{}
	return left == right
}

func inspectExactOwnedArtifact(
	directory *os.File,
	name string,
	expectation exactOwnedArtifactExpectation,
	uid, gid uint32,
) (exactOwnedArtifactInspection, error) {
	if !validOwnedArtifactName(name) || expectation.size < 0 ||
		expectation.size > rsyslogArtifactContentLimit {
		return exactOwnedArtifactInspection{}, fmt.Errorf("invalid exact-artifact expectation")
	}
	var pathBefore unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &pathBefore, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return exactOwnedArtifactInspection{}, nil
	}
	if err != nil {
		return exactOwnedArtifactInspection{}, fmt.Errorf("inspect %s: %w", expectation.label, err)
	}
	identity := ownedArtifactIdentity(&pathBefore, [sha256.Size]byte{})
	ambiguous := ""
	switch {
	case pathBefore.Mode&unix.S_IFMT != unix.S_IFREG:
		ambiguous = "path is not a regular file"
	case pathBefore.Uid != uid || pathBefore.Gid != gid:
		ambiguous = fmt.Sprintf("owner is uid %d gid %d", pathBefore.Uid, pathBefore.Gid)
	case pathBefore.Nlink != 1:
		ambiguous = fmt.Sprintf("link count is %d, want 1", pathBefore.Nlink)
	case pathBefore.Size != expectation.size:
		ambiguous = fmt.Sprintf("size is %d, want %d", pathBefore.Size, expectation.size)
	default:
		if _, allowed := expectation.permittedModes[pathBefore.Mode&07777]; !allowed {
			ambiguous = fmt.Sprintf("mode is %04o", pathBefore.Mode&07777)
		}
	}
	if ambiguous != "" {
		return exactOwnedArtifactInspection{identity: identity, ambiguous: ambiguous}, nil
	}

	fd, err := unix.Openat(
		int(directory.Fd()), name,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return exactOwnedArtifactInspection{}, fmt.Errorf("open anchored %s: %w", expectation.label, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return exactOwnedArtifactInspection{}, fmt.Errorf("wrap %s descriptor", expectation.label)
	}
	var openedBefore, openedAfter, pathAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil || !sameOwnedArtifactStat(&pathBefore, &openedBefore) {
		_ = file.Close()
		return exactOwnedArtifactInspection{}, errors.Join(
			fmt.Errorf("%s changed while opening", expectation.label), err,
		)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, expectation.size+1))
	statErr := unix.Fstat(fd, &openedAfter)
	closeErr := file.Close()
	pathErr := unix.Fstatat(int(directory.Fd()), name, &pathAfter, unix.AT_SYMLINK_NOFOLLOW)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil ||
		!sameOwnedArtifactStat(&openedBefore, &openedAfter) ||
		!sameOwnedArtifactStat(&openedAfter, &pathAfter) || int64(len(content)) != expectation.size {
		return exactOwnedArtifactInspection{}, errors.Join(
			fmt.Errorf("%s changed while reading", expectation.label),
			readErr, statErr, closeErr, pathErr,
		)
	}
	digest := sha256.Sum256(content)
	inspection := exactOwnedArtifactInspection{
		identity: ownedArtifactIdentity(&pathAfter, digest),
		content:  append([]byte(nil), content...),
	}
	if digest != expectation.digest {
		inspection.ambiguous = "SHA-256 does not match the generated artifact"
		return inspection, nil
	}
	if expectation.content != nil && !bytes.Equal(content, expectation.content) {
		inspection.ambiguous = "bytes do not match the generated artifact"
		return inspection, nil
	}
	inspection.exact = true
	return inspection, nil
}

func exactArtifactQuarantineName(name string) string {
	return "." + name + exactArtifactQuarantineSuffix
}

func requireOwnedArtifactAbsent(directory *os.File, name, label string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify absence of %s: %w", label, err)
	}
	return fmt.Errorf("%s appeared concurrently", label)
}

func runExactOwnedArtifactRestoreHook(options exactOwnedArtifactRemovalOptions) error {
	if options.afterRestore == nil {
		return nil
	}
	return options.afterRestore()
}

func restoreExactOwnedArtifact(
	directory *os.File,
	expectation exactOwnedArtifactExpectation,
	quarantineName string,
	expected exactOwnedArtifactIdentity,
	uid, gid uint32,
	options exactOwnedArtifactRemovalOptions,
) error {
	quarantined, err := inspectExactOwnedArtifact(directory, quarantineName, expectation, uid, gid)
	if err != nil || !quarantined.exact ||
		!sameMovedOwnedArtifactIdentity(expected, quarantined.identity) {
		return errors.Join(fmt.Errorf("refusing changed quarantine for %s", expectation.label), err)
	}
	err = options.renameat2(
		int(directory.Fd()), quarantineName,
		int(directory.Fd()), expectation.name,
		unix.RENAME_NOREPLACE,
	)
	if errors.Is(err, unix.EEXIST) {
		options.warn(fmt.Sprintf(
			"Preserving both %s and its recovery quarantine because the canonical path reappeared.",
			expectation.label,
		))
		return fmt.Errorf("refusing to displace concurrent canonical %s", expectation.label)
	}
	if err != nil {
		return fmt.Errorf("restore %s without replacement: %w", expectation.label, err)
	}
	restored, inspectErr := inspectExactOwnedArtifact(directory, expectation.name, expectation, uid, gid)
	syncErr := options.syncDirectory(directory)
	if inspectErr != nil || !restored.exact ||
		!sameMovedOwnedArtifactIdentity(expected, restored.identity) || syncErr != nil {
		return errors.Join(fmt.Errorf("%s was not durably restored", expectation.label), inspectErr, syncErr)
	}
	return nil
}

func restoreExactOwnedArtifactAfterFailure(
	cause error,
	directory *os.File,
	expectation exactOwnedArtifactExpectation,
	quarantineName string,
	expected exactOwnedArtifactIdentity,
	uid, gid uint32,
	options exactOwnedArtifactRemovalOptions,
) error {
	restoreErr := restoreExactOwnedArtifact(
		directory, expectation, quarantineName, expected, uid, gid, options,
	)
	return errors.Join(cause, restoreErr, runExactOwnedArtifactRestoreHook(options))
}

func recreateExactOwnedArtifact(
	directory *os.File,
	expectation exactOwnedArtifactExpectation,
	content []byte,
	expected exactOwnedArtifactIdentity,
	uid, gid uint32,
	options exactOwnedArtifactRemovalOptions,
) (resultErr error) {
	if int64(len(content)) != expectation.size || sha256.Sum256(content) != expectation.digest {
		return fmt.Errorf("refusing unverified recreation of %s", expectation.label)
	}
	if err := requireOwnedArtifactAbsent(directory, expectation.name, expectation.label); err != nil {
		return fmt.Errorf("refusing to overwrite a concurrent %s: %w", expectation.label, err)
	}
	stagingName := "." + expectation.name + exactArtifactRecreationSuffix
	if err := options.recreationStep("open"); err != nil {
		return fmt.Errorf("prepare recreation staging for %s: %w", expectation.label, err)
	}
	fd, err := unix.Openat(
		int(directory.Fd()), stagingName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create hidden recreation staging for %s: %w", expectation.label, err)
	}
	file := os.NewFile(uintptr(fd), stagingName)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), stagingName, 0)
		return fmt.Errorf("wrap recreation staging for %s", expectation.label)
	}
	defer func() {
		if file != nil {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if stagingName != "" {
			unlinkErr := unix.Unlinkat(int(directory.Fd()), stagingName, 0)
			if errors.Is(unlinkErr, unix.ENOENT) {
				unlinkErr = nil
			}
			resultErr = errors.Join(resultErr, unlinkErr, options.syncDirectory(directory))
		}
	}()

	if err := options.recreationStep("fchmod"); err != nil {
		return fmt.Errorf("prepare recreation mode for %s: %w", expectation.label, err)
	}
	if err := unix.Fchmod(fd, expected.mode&07777); err != nil {
		return fmt.Errorf("set recreation mode for %s: %w", expectation.label, err)
	}
	if err := options.recreationStep("fchown"); err != nil {
		return fmt.Errorf("prepare recreation owner for %s: %w", expectation.label, err)
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return fmt.Errorf("set recreation owner for %s: %w", expectation.label, err)
	}
	if err := options.recreationStep("write"); err != nil {
		return fmt.Errorf("prepare recreation write for %s: %w", expectation.label, err)
	}
	written, err := file.Write(content)
	if err != nil || written != len(content) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return fmt.Errorf("write recreation staging for %s: %w", expectation.label, err)
	}
	if err := options.recreationStep("fsync"); err != nil {
		return fmt.Errorf("prepare recreation sync for %s: %w", expectation.label, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync recreation staging for %s: %w", expectation.label, err)
	}
	if err := options.recreationStep("close"); err != nil {
		return fmt.Errorf("prepare recreation close for %s: %w", expectation.label, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close recreation staging for %s: %w", expectation.label, err)
	}
	file = nil
	if err := options.recreationStep("reattest"); err != nil {
		return fmt.Errorf("prepare recreation re-attestation for %s: %w", expectation.label, err)
	}
	staged, err := inspectExactOwnedArtifact(directory, stagingName, expectation, uid, gid)
	if err != nil || !staged.exact {
		return errors.Join(fmt.Errorf("recreation staging for %s failed re-attestation", expectation.label), err)
	}
	if err := options.recreationStep("rename"); err != nil {
		return fmt.Errorf("prepare recreation publication for %s: %w", expectation.label, err)
	}
	if err := options.renameat2(
		int(directory.Fd()), stagingName,
		int(directory.Fd()), expectation.name,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("publish recreated %s without replacement: %w", expectation.label, err)
	}
	stagingName = ""
	restored, inspectErr := inspectExactOwnedArtifact(directory, expectation.name, expectation, uid, gid)
	if inspectErr != nil || !restored.exact {
		return errors.Join(fmt.Errorf("recreated %s failed canonical re-attestation", expectation.label), inspectErr)
	}
	if err := options.recreationStep("directory-sync"); err != nil {
		return fmt.Errorf("prepare recreated %s directory sync: %w", expectation.label, err)
	}
	if err := options.syncDirectory(directory); err != nil {
		return fmt.Errorf("sync recreated %s directory: %w", expectation.label, err)
	}
	return nil
}

func finishExactOwnedArtifactRemoval(
	directory *os.File,
	expectation exactOwnedArtifactExpectation,
	quarantineName string,
	quarantined exactOwnedArtifactInspection,
	uid, gid uint32,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	if err := requireOwnedArtifactAbsent(directory, expectation.name, expectation.label); err != nil {
		return false, err
	}
	options.faultPoint("before-unlink:" + expectation.name)
	current, err := inspectExactOwnedArtifact(directory, quarantineName, expectation, uid, gid)
	if err != nil || !current.exact || !sameOwnedArtifactIdentity(quarantined.identity, current.identity) {
		return false, errors.Join(fmt.Errorf("quarantined %s changed", expectation.label), err)
	}
	if err := requireOwnedArtifactAbsent(directory, expectation.name, expectation.label); err != nil {
		return false, err
	}
	if options.beforeCommit != nil {
		if err := options.beforeCommit(); err != nil {
			return false, restoreExactOwnedArtifactAfterFailure(
				fmt.Errorf("pre-commit validation for %s: %w", expectation.label, err),
				directory, expectation, quarantineName, current.identity, uid, gid, options,
			)
		}
	}
	current, err = inspectExactOwnedArtifact(directory, quarantineName, expectation, uid, gid)
	if err != nil || !current.exact || !sameOwnedArtifactIdentity(quarantined.identity, current.identity) {
		return false, errors.Join(
			fmt.Errorf("quarantined %s changed after pre-commit validation", expectation.label),
			err,
			runExactOwnedArtifactRestoreHook(options),
		)
	}
	if err := requireOwnedArtifactAbsent(directory, expectation.name, expectation.label); err != nil {
		return false, restoreExactOwnedArtifactAfterFailure(
			err, directory, expectation, quarantineName, current.identity, uid, gid, options,
		)
	}
	options.faultPoint("after-before-commit:" + expectation.name)
	if err := options.unlinkat(int(directory.Fd()), quarantineName, 0); err != nil {
		return false, restoreExactOwnedArtifactAfterFailure(
			fmt.Errorf("unlink quarantined %s: %w", expectation.label, err),
			directory, expectation, quarantineName, current.identity, uid, gid, options,
		)
	}
	if err := options.syncDirectory(directory); err != nil {
		restoreErr := recreateExactOwnedArtifact(
			directory, expectation, current.content, current.identity, uid, gid, options,
		)
		return false, errors.Join(
			fmt.Errorf("sync removal of quarantined %s: %w", expectation.label, err),
			restoreErr,
			runExactOwnedArtifactRestoreHook(options),
		)
	}
	options.faultPoint("after-unlink:" + expectation.name)
	if err := requireOwnedArtifactAbsent(directory, quarantineName, "quarantined "+expectation.label); err != nil {
		return false, errors.Join(err, runExactOwnedArtifactRestoreHook(options))
	}
	if err := requireOwnedArtifactAbsent(directory, expectation.name, expectation.label); err != nil {
		return false, errors.Join(err, runExactOwnedArtifactRestoreHook(options))
	}
	return true, nil
}

func removeExactOwnedArtifactAtUsing(
	parentPath, directoryName string,
	uid, gid uint32,
	expectation exactOwnedArtifactExpectation,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(
		parentPath, directoryName, uid, gid,
	)
	if err != nil || !exists {
		return false, err
	}
	defer directory.Close()
	return removeExactOwnedArtifactInDirectoryUsing(
		directory, uid, gid, expectation, options,
	)
}

func removeExactOwnedArtifactInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	expectation exactOwnedArtifactExpectation,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	if directory == nil {
		return false, fmt.Errorf("exact-artifact directory is unavailable")
	}
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	quarantineName := exactArtifactQuarantineName(expectation.name)
	quarantine, err := inspectExactOwnedArtifact(directory, quarantineName, expectation, uid, gid)
	if err != nil {
		return false, err
	}
	if quarantine.identity.exists {
		if !quarantine.exact {
			return false, errors.Join(
				fmt.Errorf(
					"refusing ambiguous recovery quarantine for %s: %s",
					expectation.label, quarantine.ambiguous,
				),
				runExactOwnedArtifactRestoreHook(options),
			)
		}
		canonical, inspectErr := inspectExactOwnedArtifact(
			directory, expectation.name, expectation, uid, gid,
		)
		if inspectErr != nil {
			return false, inspectErr
		}
		if canonical.identity.exists {
			return false, errors.Join(
				fmt.Errorf(
					"refusing recovery with both canonical %s and its quarantine present",
					expectation.label,
				),
				runExactOwnedArtifactRestoreHook(options),
			)
		}
		return finishExactOwnedArtifactRemoval(
			directory, expectation, quarantineName, quarantine, uid, gid, options,
		)
	}

	initial, err := inspectExactOwnedArtifact(directory, expectation.name, expectation, uid, gid)
	if err != nil || !initial.identity.exists {
		return false, err
	}
	if !initial.exact {
		options.warn(fmt.Sprintf("Preserving %s: %s.", expectation.label, initial.ambiguous))
		return false, nil
	}
	options.faultPoint("before-rename:" + expectation.name)
	current, err := inspectExactOwnedArtifact(directory, expectation.name, expectation, uid, gid)
	if err != nil || !current.exact || !sameOwnedArtifactIdentity(initial.identity, current.identity) {
		return false, errors.Join(fmt.Errorf("%s changed before quarantine", expectation.label), err)
	}
	if err := options.renameat2(
		int(directory.Fd()), expectation.name,
		int(directory.Fd()), quarantineName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return false, fmt.Errorf("quarantine %s without replacement: %w", expectation.label, err)
	}
	quarantined, inspectErr := inspectExactOwnedArtifact(
		directory, quarantineName, expectation, uid, gid,
	)
	syncErr := options.syncDirectory(directory)
	if inspectErr != nil || !quarantined.exact ||
		!sameMovedOwnedArtifactIdentity(current.identity, quarantined.identity) || syncErr != nil {
		return false, restoreExactOwnedArtifactAfterFailure(
			errors.Join(fmt.Errorf("quarantine %s was not durably reattested", expectation.label), inspectErr, syncErr),
			directory, expectation, quarantineName, current.identity, uid, gid, options,
		)
	}
	options.faultPoint("after-rename:" + expectation.name)
	return finishExactOwnedArtifactRemoval(
		directory, expectation, quarantineName, quarantined, uid, gid, options,
	)
}

func removeExactOwnedArtifactDirectAtUsing(
	parentPath, directoryName string,
	uid, gid uint32,
	expectation exactOwnedArtifactExpectation,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	directory, exists, err := openExistingOwnedArtifactDirectoryAt(
		parentPath, directoryName, uid, gid,
	)
	if err != nil || !exists {
		return false, err
	}
	defer directory.Close()
	return removeExactOwnedArtifactDirectInDirectoryUsing(
		directory, uid, gid, expectation, options,
	)
}

func removeExactOwnedArtifactDirectInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	expectation exactOwnedArtifactExpectation,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	if directory == nil {
		return false, fmt.Errorf("exact-artifact directory is unavailable")
	}
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	initial, err := inspectExactOwnedArtifact(directory, expectation.name, expectation, uid, gid)
	if err != nil || !initial.identity.exists {
		return false, err
	}
	if !initial.exact {
		options.warn(fmt.Sprintf("Preserving %s: %s.", expectation.label, initial.ambiguous))
		return false, nil
	}
	current, err := inspectExactOwnedArtifact(directory, expectation.name, expectation, uid, gid)
	if err != nil || !current.exact || !sameOwnedArtifactIdentity(initial.identity, current.identity) {
		return false, errors.Join(fmt.Errorf("%s changed before direct removal", expectation.label), err)
	}
	if err := options.unlinkat(int(directory.Fd()), expectation.name, 0); err != nil {
		return false, fmt.Errorf("remove exact %s: %w", expectation.label, err)
	}
	if err := options.syncDirectory(directory); err != nil {
		return false, fmt.Errorf("sync exact %s removal: %w", expectation.label, err)
	}
	return true, requireOwnedArtifactAbsent(directory, expectation.name, expectation.label)
}

// RemoveExactLegacyBashCompletion removes only the byte-exact historical
// completion. Modified or ambiguous operator paths are preserved with a warning.
func RemoveExactLegacyBashCompletion() error {
	_, err := removeExactLegacyBashCompletionAtUsing(
		legacyCompletionParentDirectory,
		0,
		0,
		defaultExactOwnedArtifactRemovalOptions(),
	)
	return err
}

func removeExactLegacyBashCompletionAtUsing(
	parentPath string,
	uid, gid uint32,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	removed, err := removeExactOwnedArtifactDirectAtUsing(
		parentPath, legacyCompletionDirectoryName, uid, gid,
		legacyCompletionExpectation(), options,
	)
	var ambiguity *ownedArtifactDirectoryAmbiguityError
	if errors.As(err, &ambiguity) {
		options = normalizeExactOwnedArtifactRemovalOptions(options)
		options.warn(fmt.Sprintf(
			"Preserving the optional legacy SysWarden bash completion: %v.",
			ambiguity,
		))
		return false, nil
	}
	return removed, err
}

func removeExpectedRsyslogArtifactAtUsing(
	parentPath string,
	uid, gid uint32,
	expectation exactOwnedArtifactExpectation,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	return removeExactOwnedArtifactAtUsing(
		parentPath, wafRsyslogDirectoryName, uid, gid, expectation, options,
	)
}

func removeExpectedRsyslogArtifactInDirectoryUsing(
	directory *os.File,
	uid, gid uint32,
	expectation exactOwnedArtifactExpectation,
	options exactOwnedArtifactRemovalOptions,
) (bool, error) {
	return removeExactOwnedArtifactInDirectoryUsing(
		directory, uid, gid, expectation, options,
	)
}

func exactOwnedArtifactStillExistsInDirectory(
	directory *os.File,
	uid, gid uint32,
	expectation exactOwnedArtifactExpectation,
) (bool, error) {
	if directory == nil {
		return false, fmt.Errorf("exact-artifact directory is unavailable")
	}
	inspection, err := inspectExactOwnedArtifact(
		directory, expectation.name, expectation, uid, gid,
	)
	if err != nil {
		return false, err
	}
	return inspection.identity.exists, nil
}

// RemoveOwnedGeneratedArtifactsForPackageRemoval removes only byte-exact
// generated integrations while the installed binary and configuration exist.
func RemoveOwnedGeneratedArtifactsForPackageRemoval() error {
	return removeOwnedGeneratedArtifactsForPackageRemovalAtUsing(
		config.GlobalConfig,
		wafRsyslogParentDirectory,
		0, 0,
		defaultExactOwnedArtifactRemovalOptions(),
		reconcileWAFRsyslogService,
	)
}

func removeOwnedGeneratedArtifactsForPackageRemovalAtUsing(
	activeConfig *config.Config,
	parentPath string,
	uid, gid uint32,
	options exactOwnedArtifactRemovalOptions,
	activateRsyslog func(bool) error,
) error {
	options = normalizeExactOwnedArtifactRemovalOptions(options)
	if activeConfig == nil || activateRsyslog == nil {
		return fmt.Errorf("configuration or rsyslog activation is unavailable")
	}
	if _, err := removeExactLegacyBashCompletionAtUsing(parentPath, uid, gid, options); err != nil {
		return err
	}
	directory, err := openWAFRsyslogDirectoryAt(parentPath, uid, gid)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock complete rsyslog removal transaction: %w", err)
	}
	defer func() { _ = unix.Flock(int(directory.Fd()), unix.LOCK_UN) }()
	provenance, err := readRsyslogProvenanceRegistryInDirectory(directory, uid, gid)
	if err != nil {
		return fmt.Errorf("verify rsyslog artifact provenance before removal: %w", err)
	}
	rsyslogOptions := options
	rsyslogOptions.beforeCommit = func() error {
		if err := activateRsyslog(true); err != nil {
			return fmt.Errorf("validate and reactivate rsyslog after exact removal: %w", err)
		}
		return nil
	}
	rsyslogOptions.afterRestore = func() error {
		if err := activateRsyslog(true); err != nil {
			return fmt.Errorf("reactivate rsyslog after rollback: %w", err)
		}
		return nil
	}
	preserveProvenance := false

	wafExpectation, hasWAFProvenance := exactOwnedArtifactExpectation{}, false
	if record, exists := provenance.records[wafRsyslogConfigName]; exists {
		wafExpectation = provenanceExpectation(
			"SysWarden WAF rsyslog bridge", wafRsyslogConfigName, record,
		)
		hasWAFProvenance = true
	}
	if !hasWAFProvenance {
		waf, _, renderErr := renderWAFRsyslogConfig(activeConfig.ModsecLogs)
		if renderErr != nil {
			options.warn(fmt.Sprintf("Preserving the WAF rsyslog bridge: cannot render expected bytes: %v", renderErr))
		} else {
			wafExpectation = exactContentExpectation(
				"SysWarden WAF rsyslog bridge", wafRsyslogConfigName, []byte(waf), 0600,
			)
			hasWAFProvenance = true
		}
	}
	if hasWAFProvenance {
		removed, err := removeExpectedRsyslogArtifactInDirectoryUsing(
			directory, uid, gid,
			wafExpectation,
			rsyslogOptions,
		)
		if err != nil {
			return err
		}
		if provenance.exists && !removed {
			present, err := exactOwnedArtifactStillExistsInDirectory(
				directory, uid, gid, wafExpectation,
			)
			if err != nil {
				return fmt.Errorf("verify preserved WAF rsyslog bridge: %w", err)
			}
			preserveProvenance = preserveProvenance || present
		}
	}

	siemExpectation, hasSIEMProvenance := exactOwnedArtifactExpectation{}, false
	if record, exists := provenance.records[rsyslogSIEMConfigName]; exists {
		siemExpectation = provenanceExpectation(
			"SysWarden SIEM rsyslog forwarder", rsyslogSIEMConfigName, record,
		)
		hasSIEMProvenance = true
	}
	if !hasSIEMProvenance && activeConfig.SiemEnabled {
		siem, renderErr := renderSIEMRsyslogConfig(
			activeConfig.SiemIP, activeConfig.SiemPort,
			activeConfig.SiemProto, activeConfig.SiemTLSCA,
		)
		if renderErr != nil {
			options.warn(fmt.Sprintf("Preserving the SIEM rsyslog forwarder: cannot render expected bytes: %v", renderErr))
		} else {
			siemExpectation = exactContentExpectation(
				"SysWarden SIEM rsyslog forwarder", rsyslogSIEMConfigName, []byte(siem), 0600,
			)
			hasSIEMProvenance = true
		}
	}
	if hasSIEMProvenance {
		removed, err := removeExpectedRsyslogArtifactInDirectoryUsing(
			directory, uid, gid, siemExpectation, rsyslogOptions,
		)
		if err != nil {
			return err
		}
		if provenance.exists && !removed {
			present, err := exactOwnedArtifactStillExistsInDirectory(
				directory, uid, gid, siemExpectation,
			)
			if err != nil {
				return fmt.Errorf("verify preserved SIEM rsyslog forwarder: %w", err)
			}
			preserveProvenance = preserveProvenance || present
		}
	}
	if !provenance.exists {
		return nil
	}
	if preserveProvenance {
		options.warn("Preserving the SysWarden rsyslog provenance registry because a tracked artifact was preserved.")
		return nil
	}
	_, err = removeExactOwnedArtifactDirectInDirectoryUsing(
		directory,
		uid,
		gid,
		exactContentExpectation(
			"SysWarden rsyslog provenance registry",
			rsyslogProvenanceName,
			provenance.content,
			0600,
		),
		options,
	)
	return err
}

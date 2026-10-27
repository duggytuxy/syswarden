//go:build linux

package cronstate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type activationDirectoryIdentity struct {
	Path   string
	Device uint64
	Inode  uint64
	Mode   uint32
	UID    uint32
	GID    uint32
}

// activationDirectoryEvidence walks every component from the caller's trusted
// filesystem root through no-follow directory descriptors. Production uses /.
func activationDirectoryEvidence(options Options) ([]activationDirectoryIdentity, error) {
	fd, err := unix.Open(options.RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var identities []activationDirectoryIdentity
	path := "."
	components := append([]string{""}, strings.Split(filepath.ToSlash(options.DirectoryPath), "/")...)
	for _, component := range components {
		if component != "" {
			next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return nil, fmt.Errorf("open activation cron directory %s: %w", component, err)
			}
			_ = unix.Close(fd)
			fd = next
			path = filepath.Join(path, component)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return nil, err
		}
		if int64(stat.Uid) != int64(options.DirectoryOwnerUID) || int64(stat.Gid) != int64(options.DirectoryOwnerGID) || stat.Mode&0022 != 0 {
			return nil, fmt.Errorf("activation cron directory %s has unsafe ownership or permissions", path)
		}
		identities = append(identities, activationDirectoryIdentity{path, uint64(stat.Dev), stat.Ino, stat.Mode, stat.Uid, stat.Gid})
	}
	return identities, nil
}

func lockDirectoryForActivation(directory *os.Root) (*os.File, error) {
	file, err := directory.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open activation cron directory lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("activation cron directory is busy or unavailable: %w", err)
	}
	return file, nil
}

// PreflightForActivation is read-only and never waits for another cron writer.
// The root-crontab reader must be command-free and read-only; provider attestation
// must be read-only. Its digest binds the protected directory ancestry, exact
// legacy bytes/absence and owned cron inode.
// A digest records evidence; it is not approval or proof of applied scheduling.
func PreflightForActivation(options Options, haEnabled bool) (Inspection, string, error) {
	options = normalizeOptions(options)
	if err := validateOptions(options); err != nil {
		return Inspection{}, "", err
	}
	before, err := activationDirectoryEvidence(options)
	if err != nil {
		return Inspection{}, "", err
	}
	var digest string
	inspection, err := inspectScheduling(options, lockDirectoryForActivation, func(directory openedDirectory, legacy legacyState, owned journalIdentity) error {
		after, err := activationDirectoryEvidence(options)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, after) {
			return fmt.Errorf("activation cron directory ancestry changed during inspection")
		}
		last := after[len(after)-1]
		if directory.identity != (unixIdentity{device: last.Device, inode: last.Inode}) {
			return fmt.Errorf("activation cron directory changed during inspection")
		}
		wire, err := json.Marshal(struct {
			Schema        string
			Root          string
			Directories   []activationDirectoryIdentity
			FileName      string
			CLIPath       string
			LegacyPresent bool
			LegacySHA256  string
			Owned         journalIdentity
		}{"syswarden-activation-cronstate-v1", options.RootPath, after, options.FileName, options.CLIPath, legacy.present, fmt.Sprintf("%x", sha256.Sum256([]byte(legacy.content))), owned})
		if err != nil {
			return err
		}
		digest = fmt.Sprintf("%x", sha256.Sum256(wire))
		return nil
	})
	if err != nil {
		return Inspection{}, "", err
	}
	if !haEnabled && (inspection.LegacyHACount == 1 || inspection.OwnedHA) {
		return Inspection{}, "", fmt.Errorf("HA synchronization remains scheduled while HA is disabled")
	}
	return inspection, digest, nil
}

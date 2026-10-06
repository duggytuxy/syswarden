//go:build linux

// Package fileorigin records the origin of newly created product files.
// It must never infer ownership from a filename or adopt an existing file.
package fileorigin

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const LogAttribute = "user.syswarden.log-origin-v1"
const CoreLog = "core"
const TelemetryLog = "telemetry"

func logRecord(file *os.File, kind string) ([]byte, error) {
	if file == nil || kind != CoreLog && kind != TelemetryLog {
		return nil, fmt.Errorf("invalid product log origin request")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Nlink != 1 ||
		int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) {
		return nil, fmt.Errorf("product log origin requires an exclusive private owned inode")
	}
	var birth unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &birth); err != nil {
		return nil, err
	}
	if birth.Mask&unix.STATX_BTIME == 0 || birth.Ino != stat.Ino {
		return nil, fmt.Errorf("stable product log creation identity is unavailable")
	}
	return []byte(fmt.Sprintf("SYSWARDEN_LOG_ORIGIN_V1\nkind=%s\ninode=%d\nbirth_sec=%d\nbirth_nsec=%d\n", kind, stat.Ino, birth.Btime.Sec, birth.Btime.Nsec)), nil
}

// MarkCreatedLog is called only with a newly created exclusive file, or a
// new compaction output whose input already carried valid log provenance.
// The marker survives rename and cannot be copied to another inode as proof.
// It describes append-only product log ownership, never configuration data.
func MarkCreatedLog(file *os.File, kind string) error {
	record, err := logRecord(file, kind)
	if err != nil {
		return err
	}
	if err := unix.Fsetxattr(int(file.Fd()), LogAttribute, record, unix.XATTR_CREATE); err != nil {
		return fmt.Errorf("record new product log origin: %w", err)
	}
	return file.Sync()
}

// HasLogOrigin is read-only. Absence never upgrades an existing log into an
// owned file. A malformed or copied marker is an error, not valid provenance.
func HasLogOrigin(file *os.File, kind string) (bool, error) {
	if file == nil || kind != CoreLog && kind != TelemetryLog {
		return false, fmt.Errorf("invalid product log origin request")
	}
	var record [256]byte
	size, err := unix.Fgetxattr(int(file.Fd()), LogAttribute, record[:])
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	expected, err := logRecord(file, kind)
	if err != nil {
		return false, err
	}
	if string(record[:size]) != string(expected) {
		return false, fmt.Errorf("product log origin does not bind this inode and kind")
	}
	return true, nil
}

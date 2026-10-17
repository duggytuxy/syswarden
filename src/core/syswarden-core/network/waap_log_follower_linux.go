//go:build linux

package network

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syswarden-core/config"
	"time"

	"golang.org/x/sys/unix"
)

const (
	defaultWAAPLogPollInterval = 100 * time.Millisecond
	waapLogReadBufferBytes     = 64 << 10
)

type waapLogRefresh uint8

const (
	waapLogUnchanged waapLogRefresh = iota
	waapLogRotated
	waapLogTruncated
)

// secureWAAPLogFollower pins every directory from the filesystem root and
// opens the final component with O_NOFOLLOW. A pathname is never reopened by
// os.Open, including after rotation.
type secureWAAPLogFollower struct {
	path         string
	dirFD        int
	name         string
	file         *os.File
	reader       *bufio.Reader
	identity     unix.Stat_t
	offset       int64
	pollInterval time.Duration
	expectedUID  int64
	producerUID  *uint32
}

func newSecureWAAPLogFollower(path string, startAtEnd bool) (*secureWAAPLogFollower, error) {
	return newSecureWAAPLogFollowerWithAccess(path, startAtEnd, config.TrustedLogAccess{AuthorityUID: int64(os.Geteuid())})
}

func newSecureWAAPLogFollowerWithAccess(path string, startAtEnd bool, access config.TrustedLogAccess) (*secureWAAPLogFollower, error) {
	dirFD, name, err := access.OpenParent(path)
	if err != nil {
		return nil, err
	}

	file, identity, err := openRegularWAAPLogWithAccess(dirFD, name, path, access)
	if err != nil {
		_ = unix.Close(dirFD)
		return nil, err
	}

	offset := int64(0)
	if startAtEnd {
		offset, err = file.Seek(0, io.SeekEnd)
		if err != nil {
			_ = file.Close()
			_ = unix.Close(dirFD)
			return nil, fmt.Errorf("seek WAAP log %q: %w", path, err)
		}
	}

	return &secureWAAPLogFollower{
		path:         path,
		dirFD:        dirFD,
		name:         name,
		file:         file,
		reader:       bufio.NewReaderSize(file, waapLogReadBufferBytes),
		identity:     identity,
		offset:       offset,
		pollInterval: defaultWAAPLogPollInterval,
		expectedUID:  access.AuthorityUID,
		producerUID:  access.ProducerUID,
	}, nil
}

func openRegularWAAPLogWithAccess(dirFD int, name, path string, access config.TrustedLogAccess) (*os.File, unix.Stat_t, error) {
	fd, identity, err := access.OpenFile(dirFD, name)
	if err != nil {
		return nil, unix.Stat_t{}, fmt.Errorf("open verified WAAP log %q: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), identity, nil
}

func sameWAAPLogIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func validateWAAPLogSecurity(identity unix.Stat_t, expectedUID int64) error {
	return (config.TrustedLogAccess{AuthorityUID: expectedUID}).ValidateFile(identity, false)
}

func (f *secureWAAPLogFollower) access() config.TrustedLogAccess {
	return config.TrustedLogAccess{AuthorityUID: f.expectedUID, ProducerUID: f.producerUID}
}

func (f *secureWAAPLogFollower) attestParent() error {
	fd, _, err := f.access().OpenParent(f.path)
	if err != nil {
		return fmt.Errorf("revalidate WAAP log ancestry: %w", err)
	}
	defer unix.Close(fd)
	var pinned, linked unix.Stat_t
	if err := unix.Fstat(f.dirFD, &pinned); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &linked); err != nil {
		return err
	}
	if !sameWAAPLogIdentity(pinned, linked) {
		return fmt.Errorf("WAAP log parent was replaced")
	}
	return nil
}

func (f *secureWAAPLogFollower) Next(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var pending strings.Builder
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		if err := f.attestOpenFile(); err != nil {
			return "", err
		}

		chunk, readErr := f.reader.ReadSlice('\n')
		f.offset += int64(len(chunk))
		if pending.Len()+len(chunk) > maxWAAPLogLineBytes {
			return "", fmt.Errorf("WAAP log %q contains a line larger than %d bytes", f.path, maxWAAPLogLineBytes)
		}
		_, _ = pending.Write(chunk)

		switch {
		case readErr == nil:
			return strings.TrimSuffix(strings.TrimSuffix(pending.String(), "\n"), "\r"), nil
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case !errors.Is(readErr, io.EOF):
			return "", fmt.Errorf("read WAAP log %q: %w", f.path, readErr)
		}

		refresh, err := f.refresh()
		if err != nil {
			return "", err
		}
		switch refresh {
		case waapLogRotated:
			if pending.Len() > 0 {
				return strings.TrimSuffix(pending.String(), "\r"), nil
			}
			continue
		case waapLogTruncated:
			pending.Reset()
			continue
		}

		timer := time.NewTimer(f.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return "", ctx.Err()
		case <-timer.C:
		}
	}
}

func (f *secureWAAPLogFollower) attestOpenFile() error {
	var opened unix.Stat_t
	if err := unix.Fstat(int(f.file.Fd()), &opened); err != nil {
		return fmt.Errorf("reinspect opened WAAP log %q: %w", f.path, err)
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || !sameWAAPLogIdentity(opened, f.identity) {
		return fmt.Errorf("opened WAAP log %q identity drifted", f.path)
	}
	if err := f.access().ValidateFile(opened, true); err != nil {
		return fmt.Errorf("opened WAAP log %q ownership or mode drifted: %w", f.path, err)
	}
	return nil
}

func (f *secureWAAPLogFollower) refresh() (waapLogRefresh, error) {
	if err := f.attestParent(); err != nil {
		return waapLogUnchanged, err
	}
	var linked unix.Stat_t
	err := unix.Fstatat(f.dirFD, f.name, &linked, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return waapLogUnchanged, nil
	}
	if err != nil {
		return waapLogUnchanged, fmt.Errorf("revalidate WAAP log %q: %w", f.path, err)
	}
	if linked.Mode&unix.S_IFMT != unix.S_IFREG {
		return waapLogUnchanged, fmt.Errorf("WAAP log %q was replaced by a non-regular file", f.path)
	}
	if err := f.access().ValidateFile(linked, false); err != nil {
		return waapLogUnchanged, fmt.Errorf("WAAP log %q ownership or mode drifted: %w", f.path, err)
	}

	if sameWAAPLogIdentity(f.identity, linked) {
		if linked.Size >= f.offset {
			return waapLogUnchanged, nil
		}
		if _, err := f.file.Seek(0, io.SeekStart); err != nil {
			return waapLogUnchanged, fmt.Errorf("rewind truncated WAAP log %q: %w", f.path, err)
		}
		f.reader.Reset(f.file)
		f.offset = 0
		f.identity = linked
		return waapLogTruncated, nil
	}

	next, identity, err := openRegularWAAPLogWithAccess(f.dirFD, f.name, f.path, f.access())
	if errors.Is(err, unix.ENOENT) {
		return waapLogUnchanged, nil
	}
	if err != nil {
		return waapLogUnchanged, err
	}
	previous := f.file
	f.file = next
	f.reader.Reset(next)
	f.identity = identity
	f.offset = 0
	if err := previous.Close(); err != nil {
		return waapLogRotated, fmt.Errorf("close rotated WAAP log %q: %w", f.path, err)
	}
	return waapLogRotated, nil
}

func (f *secureWAAPLogFollower) Close() error {
	var errs []error
	if f.file != nil {
		if err := f.file.Close(); err != nil {
			errs = append(errs, err)
		}
		f.file = nil
	}
	if f.dirFD >= 0 {
		if err := unix.Close(f.dirFD); err != nil {
			errs = append(errs, err)
		}
		f.dirFD = -1
	}
	return errors.Join(errs...)
}

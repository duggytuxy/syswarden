//go:build linux

package network

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

const (
	defaultWAAPLogPollInterval = 100 * time.Millisecond
	maxWAAPLogLineBytes        = 1 << 20
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
}

func newSecureWAAPLogFollower(path string, startAtEnd bool) (*secureWAAPLogFollower, error) {
	dirFD, name, err := openPinnedWAAPLogParent(path)
	if err != nil {
		return nil, err
	}

	file, identity, err := openRegularWAAPLogAt(dirFD, name, path)
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
	}, nil
}

func openPinnedWAAPLogParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return -1, "", fmt.Errorf("WAAP log %q is not an absolute canonical path", path)
	}

	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[len(components)-1] == "" {
		return -1, "", fmt.Errorf("WAAP log %q has no file component", path)
	}

	fd, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open filesystem root for WAAP log %q: %w", path, err)
	}

	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(fd, component, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = unix.Close(fd)
			return -1, "", fmt.Errorf("open pinned parent for WAAP log %q: %w", path, openErr)
		}
		if closeErr := unix.Close(fd); closeErr != nil {
			_ = unix.Close(nextFD)
			return -1, "", fmt.Errorf("close parent descriptor for WAAP log %q: %w", path, closeErr)
		}
		fd = nextFD
	}

	return fd, components[len(components)-1], nil
}

func openRegularWAAPLogAt(dirFD int, name, path string) (*os.File, unix.Stat_t, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, fmt.Errorf("open WAAP log %q without following links: %w", path, err)
	}

	closeOnError := func(openErr error) (*os.File, unix.Stat_t, error) {
		_ = unix.Close(fd)
		return nil, unix.Stat_t{}, openErr
	}

	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return closeOnError(fmt.Errorf("inspect opened WAAP log %q: %w", path, err))
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG {
		return closeOnError(fmt.Errorf("WAAP log %q is not a real regular file", path))
	}

	var linked unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return closeOnError(fmt.Errorf("revalidate WAAP log %q: %w", path, err))
	}
	if linked.Mode&unix.S_IFMT != unix.S_IFREG || !sameWAAPLogIdentity(opened, linked) {
		return closeOnError(fmt.Errorf("WAAP log %q changed while opening", path))
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		return closeOnError(fmt.Errorf("adopt descriptor for WAAP log %q", path))
	}
	return file, opened, nil
}

func sameWAAPLogIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
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

func (f *secureWAAPLogFollower) refresh() (waapLogRefresh, error) {
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

	next, identity, err := openRegularWAAPLogAt(f.dirFD, f.name, f.path)
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

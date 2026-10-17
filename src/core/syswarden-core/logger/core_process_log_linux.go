//go:build linux

package logger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"golang.org/x/sys/unix"
	"syswarden-core/fileorigin"
)

const coreProcessLogLimit int64 = 16 << 20
const coreTailInputAttribute = "user.syswarden.core-tail-input-v1"

// CoreProcessLog keeps a bounded process log without restarting a service.
// Only creation-attested product inodes may be replaced during retention.
// An uncertain write or filesystem transition disables this sink until reopen.
// The caller must keep its independent system journal sink available.
type CoreProcessLog struct {
	mu        sync.Mutex
	directory *os.File
	file      *os.File
	path      string
	name      string
	limit     int64
	failure   error
}

func OpenCoreProcessLog(path string) (*CoreProcessLog, error) {
	return openCoreProcessLogWithLimit(path, coreProcessLogLimit)
}

func openCoreProcessLogWithLimit(path string, limit int64) (*CoreProcessLog, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "/" || strings.IndexFunc(path, unicode.IsControl) >= 0 || limit <= 0 || limit > coreProcessLogLimit {
		return nil, fmt.Errorf("invalid bounded core log path or limit")
	}
	directory, err := pinCoreLogDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	writer := &CoreProcessLog{directory: directory, path: path, name: filepath.Base(path), limit: limit}
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("core log directory already has a writer or cannot be locked: %w", err)
	}
	if err := writer.prepare(); err != nil {
		_ = writer.Close()
		return nil, err
	}
	return writer, nil
}

func pinCoreLogDirectory(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := -1; i < len(parts); i++ {
		if i >= 0 && parts[i] != "" {
			next, openErr := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			_ = unix.Close(fd)
			if openErr != nil {
				return nil, openErr
			}
			fd = next
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		trusted := stat.Uid == 0 || int64(stat.Uid) == int64(os.Geteuid())
		stickyParent := i < len(parts)-1 && stat.Mode&unix.S_ISVTX != 0
		if !trusted || stat.Mode&0022 != 0 && !stickyParent {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("core log directory ancestry is not owner controlled")
		}
		if i == len(parts)-1 && (int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) || stat.Mode&07777 != 0700 && stat.Mode&07777 != 0750) {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("core log directory must be private and owned by the service")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (w *CoreProcessLog) attestDirectory() error {
	opened, err := w.directory.Stat()
	if err != nil {
		return err
	}
	linked, err := os.Lstat(filepath.Dir(w.path))
	if err != nil || !linked.IsDir() || !os.SameFile(opened, linked) {
		return fmt.Errorf("core log parent changed")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) || opened.Mode().Perm() != 0700 && opened.Mode().Perm() != 0750 || opened.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("core log parent permissions changed")
	}
	return nil
}

func (w *CoreProcessLog) open(name string, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(int(w.directory.Fd()), name, flags, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if _, err := w.attest(file, name, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	if create {
		if err := fileorigin.MarkCreatedLog(file, fileorigin.CoreLog); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("core log origin unavailable; preserve the new private inode: %w", err)
		}
	}
	return file, nil
}

func (w *CoreProcessLog) attest(file *os.File, name string, requireOrigin bool) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Nlink != 1 || int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) || info.Size() < 0 {
		return nil, fmt.Errorf("core log must be an exclusive private owned regular inode")
	}
	var linked unix.Stat_t
	if err := unix.Fstatat(int(w.directory.Fd()), name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if stat.Dev != uint64(linked.Dev) || stat.Ino != linked.Ino || stat.Mode != linked.Mode || stat.Uid != linked.Uid || stat.Gid != linked.Gid || stat.Nlink != linked.Nlink {
		return nil, fmt.Errorf("core log pathname changed")
	}
	owned, err := fileorigin.HasLogOrigin(file, fileorigin.CoreLog)
	if err != nil {
		return nil, err
	}
	if requireOrigin && !owned {
		return nil, fmt.Errorf("core log retention requires creation provenance; preserve this file for explicit recovery")
	}
	return info, nil
}

func (w *CoreProcessLog) stagingName() string { return "." + w.name + ".tail" }

func (w *CoreProcessLog) tailInput(source *os.File, name string) ([]byte, error) {
	info, err := w.attest(source, name, true)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("core tail source identity unavailable")
	}
	var origin [256]byte
	size, err := unix.Fgetxattr(int(source.Fd()), fileorigin.LogAttribute, origin[:])
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%s\n%d:%d:%d:%d:%d:%d:%d\n%s", name, stat.Dev, stat.Ino, stat.Size, stat.Mtim.Sec, stat.Mtim.Nsec, stat.Ctim.Sec, stat.Ctim.Nsec, origin[:size])), nil
}

func (w *CoreProcessLog) retireRedundantTail(stage *os.File) error {
	if _, err := w.attest(stage, w.stagingName(), true); err != nil {
		return err
	}
	var input [512]byte
	size, err := unix.Fgetxattr(int(stage.Fd()), coreTailInputAttribute, input[:])
	if err != nil {
		return fmt.Errorf("preserve core tail without exact source binding: %w", err)
	}
	name, _, found := strings.Cut(string(input[:size]), "\n")
	if !found || name != w.name && name != w.name+".1" {
		return fmt.Errorf("preserve core tail with invalid source binding")
	}
	source, err := w.open(name, false)
	if err != nil {
		return fmt.Errorf("preserve core tail while its source is unavailable: %w", err)
	}
	defer source.Close()
	expected, err := w.tailInput(source, name)
	if err != nil || !bytes.Equal(expected, input[:size]) {
		return fmt.Errorf("preserve core tail because its source changed")
	}
	if _, err := w.attest(stage, w.stagingName(), true); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(w.directory.Fd()), w.stagingName(), 0); err != nil {
		return err
	}
	return w.directory.Sync()
}

func (w *CoreProcessLog) prepare() error {
	if err := w.attestDirectory(); err != nil {
		return err
	}
	// A compaction publishes by rename over its still-present source. Retire a
	// staged tail only when its exact source identity and modification metadata remain unchanged.
	stage, err := w.open(w.stagingName(), false)
	if err == nil {
		retireErr := w.retireRedundantTail(stage)
		_ = stage.Close()
		if retireErr != nil {
			return retireErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, name := range []string{w.name + ".1", w.name} {
		file, err := w.open(name, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := w.attest(file, name, name != w.name)
		if err == nil && info.Size() > w.limit {
			err = w.compact(file, name, info)
		}
		_ = file.Close()
		if err != nil {
			return err
		}
	}
	w.file, err = w.open(w.name, false)
	if errors.Is(err, os.ErrNotExist) {
		w.file, err = w.open(w.name, true)
	}
	if err != nil {
		return err
	}
	return w.directory.Sync()
}

func (w *CoreProcessLog) compact(source *os.File, name string, before os.FileInfo) error {
	input, err := w.tailInput(source, name)
	if err != nil {
		return err
	}
	start := before.Size() - w.limit
	tail := make([]byte, int(w.limit))
	if _, err := io.ReadFull(io.NewSectionReader(source, start, w.limit), tail); err != nil {
		return err
	}
	var previous [1]byte
	if _, err := source.ReadAt(previous[:], start-1); err != nil {
		return err
	}
	if previous[0] != '\n' {
		boundary := bytes.IndexByte(tail, '\n')
		if boundary < 0 {
			tail = nil
		} else {
			tail = tail[boundary+1:]
		}
	}
	// Keep only complete records in a retained tail.
	if len(tail) > 0 && tail[len(tail)-1] != '\n' {
		boundary := bytes.LastIndexByte(tail, '\n')
		if boundary < 0 {
			tail = nil
		} else {
			tail = tail[:boundary+1]
		}
	}
	stage, err := w.open(w.stagingName(), true)
	if err != nil {
		return err
	}
	defer stage.Close()
	if err := unix.Fsetxattr(int(stage.Fd()), coreTailInputAttribute, input, unix.XATTR_CREATE); err != nil {
		return err
	}
	if n, err := stage.Write(tail); err != nil {
		return err
	} else if n != len(tail) {
		return io.ErrShortWrite
	}
	if err := stage.Sync(); err != nil {
		return err
	}
	after, err := w.attest(source, name, true)
	if err != nil {
		return err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return fmt.Errorf("core log changed during compaction")
	}
	currentInput, err := w.tailInput(source, name)
	if err != nil || !bytes.Equal(currentInput, input) {
		return fmt.Errorf("core log identity changed during compaction")
	}
	if _, err := w.attest(stage, w.stagingName(), true); err != nil {
		return err
	}
	if err := w.attestDirectory(); err != nil {
		return err
	}
	if err := unix.Renameat(int(w.directory.Fd()), w.stagingName(), int(w.directory.Fd()), name); err != nil {
		return err
	}
	return w.directory.Sync()
}

func (w *CoreProcessLog) rotate() error {
	if _, err := w.attest(w.file, w.name, true); err != nil {
		return err
	}
	retained, err := w.open(w.name+".1", false)
	if err == nil {
		_, err = w.attest(retained, w.name+".1", true)
		_ = retained.Close()
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat(int(w.directory.Fd()), w.name, int(w.directory.Fd()), w.name+".1"); err != nil {
		return err
	}
	if err := w.directory.Sync(); err != nil {
		return err
	}
	// A crash here leaves the complete last generation at .1. Reopen creates
	// a new active inode; no copytruncate window or service restart is needed.
	if err := w.file.Close(); err != nil {
		w.file = nil
		return err
	}
	w.file = nil
	w.file, err = w.open(w.name, true)
	if err != nil {
		return err
	}
	return w.directory.Sync()
}

func (w *CoreProcessLog) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.directory == nil {
		return 0, os.ErrClosed
	}
	if w.failure != nil {
		return 0, w.failure
	}
	fail := func(err error) (int, error) { w.failure = err; return 0, err }
	if int64(len(data)) > w.limit {
		return fail(fmt.Errorf("core log record exceeds the retention limit"))
	}
	if err := w.attestDirectory(); err != nil {
		return fail(err)
	}
	info, err := w.attest(w.file, w.name, false)
	if err != nil {
		return fail(err)
	}
	if info.Size() > w.limit {
		return fail(fmt.Errorf("core log grew outside the managed writer"))
	}
	if int64(len(data)) > w.limit-info.Size() {
		if err := w.rotate(); err != nil {
			return fail(err)
		}
	}
	n, err := w.file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.failure = err
	}
	return n, err
}

func (w *CoreProcessLog) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var errs []error
	if w.file != nil {
		errs = append(errs, w.file.Sync(), w.file.Close())
		w.file = nil
	}
	if w.directory != nil {
		errs = append(errs, w.directory.Close())
		w.directory = nil
	}
	return errors.Join(errs...)
}

// CoreProcessOutput preserves the independent journal write even when bounded
// file logging fails. A single direct diagnostic avoids recursive log writes.
func CoreProcessOutput(journal io.Writer, file *CoreProcessLog, diagnostics io.Writer) io.Writer {
	return &coreProcessOutput{journal: journal, file: file, diagnostics: diagnostics}
}

type coreProcessOutput struct {
	journal     io.Writer
	file        io.Writer
	diagnostics io.Writer
	once        sync.Once
}

func (w *coreProcessOutput) Write(data []byte) (int, error) {
	n, journalErr := w.journal.Write(data)
	if _, err := w.file.Write(data); err != nil {
		w.once.Do(func() {
			_, _ = fmt.Fprintf(w.diagnostics, "[SYSWARDEN-Core] File logging unavailable; system journal output continues. Inspect retained log evidence before recovery: %v\n", err)
		})
	}
	return n, journalErr
}

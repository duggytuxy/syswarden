package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const MaxAuthorityExecutableBytes = 64 << 20

var ErrAuthorityExecutable = errors.New("invalid protected authority executable")

const authorityImageSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

// SnapshotAuthorityExecutable copies one independently approved root-owned
// executable into a sealed anonymous file. It discovers no path or trust, grants
// no execution authority and starts no process. The caller retains source and
// owns the returned close-on-exec descriptor. Source offsets are unchanged.
func SnapshotAuthorityExecutable(source *os.File, expectedSHA256 string) (*os.File, error) {
	if source == nil || !validRecoveryApproval(expectedSHA256) {
		return nil, ErrAuthorityExecutable
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrAuthorityExecutable
	}
	var image *os.File
	var operation error
	err = raw.Control(func(fd uintptr) {
		image, operation = snapshotAuthorityExecutable(int(fd), expectedSHA256)
	})
	if err != nil || operation != nil {
		if image != nil {
			_ = image.Close()
		}
		return nil, ErrAuthorityExecutable
	}
	return image, nil
}

func snapshotAuthorityExecutable(source int, digest string) (_ *os.File, result error) {
	var before, after unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(source), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return nil, ErrAuthorityExecutable
	}
	if err := unix.Fstat(source, &before); err != nil || !validAuthorityExecutableStat(before) {
		return nil, ErrAuthorityExecutable
	}
	if !authorityImageMountAllowsExec(source, unix.Fstatfs) {
		return nil, ErrAuthorityExecutable
	}
	if err := noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(source, name, nil) }); err != nil {
		return nil, ErrAuthorityExecutable
	}
	_, err = unix.Fgetxattr(source, "security.capability", nil)
	if !(errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP)) {
		return nil, ErrAuthorityExecutable
	}
	fd, err := newAuthorityImage(unix.MemfdCreate)
	if err != nil {
		return nil, ErrAuthorityExecutable
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, unix.Close(fd))
		}
	}()
	read := func(b []byte, offset int64) (int, error) { return unix.Pread(source, b, offset) }
	write := func(b []byte, offset int64) (int, error) { return unix.Pwrite(fd, b, offset) }
	got, err := streamAuthorityImage(before.Size, read, write)
	if err != nil || got != digest {
		return nil, ErrAuthorityExecutable
	}
	if err := unix.Fstat(source, &after); err != nil || !sameStamp(before, after) || !authorityImageMountAllowsExec(source, unix.Fstatfs) {
		return nil, ErrAuthorityExecutable
	}
	if err := unix.Fchmod(fd, 0555); err != nil {
		return nil, ErrAuthorityExecutable
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, authorityImageSeals); err != nil {
		return nil, ErrAuthorityExecutable
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || seals&authorityImageSeals != authorityImageSeals {
		return nil, ErrAuthorityExecutable
	}
	flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return nil, ErrAuthorityExecutable
	}
	if err := unix.Fstat(fd, &after); err != nil || after.Size != before.Size || after.Mode&(unix.S_IFMT|07777) != unix.S_IFREG|0555 {
		return nil, ErrAuthorityExecutable
	}
	// Authenticate the actual sealed output, not just the source stream.
	got, err = streamAuthorityImage(before.Size, func(b []byte, offset int64) (int, error) { return unix.Pread(fd, b, offset) }, nil)
	if err != nil || got != digest {
		return nil, ErrAuthorityExecutable
	}
	return os.NewFile(uintptr(fd), "syswarden-authority-image"), nil
}

func validAuthorityExecutableStat(st unix.Stat_t) bool {
	return st.Mode&(unix.S_IFMT|07777) == unix.S_IFREG|0555 && st.Uid == 0 && st.Gid == 0 && st.Nlink == 1 && st.Size > 0 && st.Size <= MaxAuthorityExecutableBytes
}

func newAuthorityImage(create func(string, int) (int, error)) (int, error) {
	flags := unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING
	fd, err := create("syswarden-authority-image", flags|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		// Older kernels do not recognize MFD_EXEC. Only that feature-detection
		// error permits the legacy API; policy denials never trigger fallback.
		return create("syswarden-authority-image", flags)
	}
	return fd, err
}

// Fixed-size positional chunks bound memory and preserve descriptor offsets.
// Short reads/writes and any I/O error discard the entire candidate.
func streamAuthorityImage(size int64, read func([]byte, int64) (int, error), write func([]byte, int64) (int, error)) (string, error) {
	if size <= 0 || size > MaxAuthorityExecutableBytes || read == nil {
		return "", ErrAuthorityExecutable
	}
	buffer := make([]byte, 64<<10)
	hash := sha256.New()
	for offset := int64(0); offset < size; {
		amount := min(int64(len(buffer)), size-offset)
		chunk := buffer[:int(amount)]
		n, err := read(chunk, offset)
		if err != nil || n != len(chunk) {
			return "", ErrAuthorityExecutable
		}
		if write != nil {
			n, err = write(chunk, offset)
			if err != nil || n != len(chunk) {
				return "", ErrAuthorityExecutable
			}
		}
		_, _ = hash.Write(chunk)
		offset += amount
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Linux fstatfs uses ST_NOEXEC (0x8). Keep source mount policy instead of
// treating anonymous execution as permission to bypass a noexec source.
func authorityImageMountAllowsExec(fd int, inspect func(int, *unix.Statfs_t) error) bool {
	const statfsNoExec = 0x8
	var st unix.Statfs_t
	return inspect(fd, &st) == nil && st.Flags&statfsNoExec == 0
}

// VerifyAuthorityExecutableImage authenticates an inherited sealed snapshot.
// It never grants execution approval, changes descriptor flags or reads a path.
// The independently protected digest and trusted provisioning remain required.
func VerifyAuthorityExecutableImage(image *os.File, digest string) error {
	if image == nil || !validRecoveryApproval(digest) {
		return ErrAuthorityExecutable
	}
	raw, err := image.SyscallConn()
	if err != nil {
		return ErrAuthorityExecutable
	}
	operation := ErrAuthorityExecutable
	err = raw.Control(func(fd uintptr) {
		var st unix.Stat_t
		if unix.Fstat(int(fd), &st) != nil || st.Mode&(unix.S_IFMT|07777) != unix.S_IFREG|0555 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 0 || st.Size <= 0 || st.Size > MaxAuthorityExecutableBytes {
			return
		}
		seals, e := unix.FcntlInt(fd, unix.F_GET_SEALS, 0)
		if e != nil || seals&authorityImageSeals != authorityImageSeals {
			return
		}
		got, e := streamAuthorityImage(st.Size, func(b []byte, offset int64) (int, error) { return unix.Pread(int(fd), b, offset) }, nil)
		if e == nil && got == digest {
			operation = nil
		}
	})
	if err != nil || operation != nil {
		return ErrAuthorityExecutable
	}
	return nil
}

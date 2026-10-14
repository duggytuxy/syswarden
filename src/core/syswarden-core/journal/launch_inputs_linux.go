package journal

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var ErrAuthorityLaunchInputs = errors.New("invalid protected authority launch inputs")

// OpenAuthorityLaunchInputs acquires the fixed launch.json and syswarden-authority
// entries from an independently trusted root-owned 0700 directory. It validates
// the launch record and seals and inspects the executable using separate pinned
// digests. Both returned CLOEXEC handles are immutable snapshots. The caller
// retains directory and owns both returned handles.
// Every failure returns two nil handles and closes all intermediate resources.
// It never creates source files, starts a process or approves a dynamic loader.
// The caller must protect directory ancestry, mount namespace and digest origin;
// root ownership in an untrusted user namespace is not host-root provenance.
func OpenAuthorityLaunchInputs(directory *os.File, launchDigest, imageDigest string) (*os.File, *os.File, error) {
	if directory == nil || !validRecoveryApproval(launchDigest) || !validRecoveryApproval(imageDigest) {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	raw, err := directory.SyscallConn()
	if err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	var launch, image *os.File
	operation := ErrAuthorityLaunchInputs
	err = raw.Control(func(fd uintptr) {
		launch, image, operation = openAuthorityLaunchInputs(int(fd), launchDigest, imageDigest)
	})
	if err != nil || operation != nil {
		if launch != nil {
			_ = launch.Close()
		}
		if image != nil {
			_ = image.Close()
		}
		return nil, nil, ErrAuthorityLaunchInputs
	}
	return launch, image, nil
}

func openAuthorityLaunchInputs(directory int, launchDigest, imageDigest string) (_ *os.File, _ *os.File, result error) {
	before, err := attestAuthorityInputDirectory(directory)
	if err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	launch, launchStamp, err := openAuthorityInput(directory, "launch.json", false)
	if err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	defer func() { _ = launch.Close() }()
	var image *os.File
	defer func() {
		if result != nil {
			if image != nil {
				_ = image.Close()
			}
		}
	}()
	if _, err := LoadAuthorityLaunch(launch, launchDigest); err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	source, sourceStamp, err := openAuthorityInput(directory, "syswarden-authority", true)
	if err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	defer func() { _ = source.Close() }()
	image, err = SnapshotAuthorityExecutable(source, imageDigest)
	if err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	if _, err := InspectAuthorityExecutableImage(image, imageDigest); err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	after, err := attestAuthorityInputDirectory(directory)
	if err != nil || !sameStamp(before, after) ||
		!authorityInputStillBound(directory, "launch.json", launch, launchStamp) ||
		!authorityInputStillBound(directory, "syswarden-authority", source, sourceStamp) {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	// Recheck the launch bytes after image acquisition. This is a bounded
	// coherence check, not an atomic deployment transaction or a root trust model.
	frozen, err := SnapshotAuthorityLaunch(launch, launchDigest)
	if err != nil {
		return nil, nil, ErrAuthorityLaunchInputs
	}
	return frozen, image, nil
}

func attestAuthorityInputDirectory(fd int) (unix.Stat_t, error) {
	var st unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return st, ErrAuthorityLaunchInputs
	}
	if unix.Fstat(fd, &st) != nil || st.Mode&(unix.S_IFMT|07777) != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 || st.Nlink == 0 {
		return st, ErrAuthorityLaunchInputs
	}
	if noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) }) != nil {
		return st, ErrAuthorityLaunchInputs
	}
	return st, nil
}

func validAuthorityInputStat(st unix.Stat_t, executable bool) bool {
	if executable {
		return validAuthorityExecutableStat(st)
	}
	return st.Mode&(unix.S_IFMT|07777) == unix.S_IFREG|0400 && st.Uid == 0 && st.Gid == 0 && st.Nlink == 1 && st.Size > 0 && st.Size <= MaxAuthorityLaunchBytes
}

func openAuthorityInput(directory int, name string, executable bool) (*os.File, unix.Stat_t, error) {
	var before, after unix.Stat_t
	// Reject known devices and FIFOs before opening. The independently trusted
	// directory excludes ordinary-user substitution; this does not defend root.
	if unix.Fstatat(directory, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !validAuthorityInputStat(before, executable) {
		return nil, before, ErrAuthorityLaunchInputs
	}
	fd, err := openAuthorityInputFD(directory, name, unix.Openat2)
	if err != nil {
		return nil, before, ErrAuthorityLaunchInputs
	}
	file := os.NewFile(uintptr(fd), "authority-launch-input")
	if unix.Fstat(fd, &after) != nil || !sameStamp(before, after) {
		_ = file.Close()
		return nil, before, ErrAuthorityLaunchInputs
	}
	return file, after, nil
}

// These restrictions are mandatory. Unsupported kernels, mount crossings,
// policy denials and uncertain resolution fail without a weaker fallback.
func openAuthorityInputFD(directory int, name string, open func(int, string, *unix.OpenHow) (int, error)) (int, error) {
	if directory < 0 || (name != "launch.json" && name != "syswarden-authority") || open == nil {
		return -1, ErrAuthorityLaunchInputs
	}
	return open(directory, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func authorityInputStillBound(directory int, name string, file *os.File, stamp unix.Stat_t) bool {
	var entry, held unix.Stat_t
	return unix.Fstatat(directory, name, &entry, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		unix.Fstat(int(file.Fd()), &held) == nil && sameStamp(stamp, held) && sameStamp(held, entry)
}

package journal

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const authorityLaunchSeals = authorityImageSeals | unix.F_SEAL_EXEC

// A named source retains the original one-link contract. An unlinked source is
// accepted only with complete immutable data and executable-mode seals.
func validAuthorityLaunchLinks(fd int, links uint64) bool {
	if links == 1 {
		return true
	}
	if links != 0 {
		return false
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	return err == nil && seals&authorityLaunchSeals == authorityLaunchSeals
}

// SnapshotAuthorityLaunch copies exact authenticated canonical launch bytes into
// a root-owned 0400 anonymous file, with immutable data and executable-mode seals.
// The returned handle is read-only and CLOEXEC. Source and its offset are retained.
// Trusted procfs is required only to reopen this exact kernel-created descriptor
// read-only; identity, seals and bytes are then verified again. No path is supplied
// by the record. Unsupported no-exec sealing fails without a weaker fallback.
func SnapshotAuthorityLaunch(source *os.File, digest string) (*os.File, error) {
	data, err := readAuthorityLaunchBytes(source, digest)
	if err != nil {
		return nil, ErrAuthorityLaunch
	}
	if _, err := DecodeAuthorityLaunch(data); err != nil {
		return nil, ErrAuthorityLaunch
	}
	fd, err := newAuthorityLaunchSnapshot(unix.MemfdCreate)
	if err != nil {
		return nil, ErrAuthorityLaunch
	}
	defer func() { _ = unix.Close(fd) }()
	n, err := unix.Pwrite(fd, data, 0)
	if err != nil || n != len(data) || unix.Fchmod(fd, 0400) != nil {
		return nil, ErrAuthorityLaunch
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, authorityLaunchSeals); err != nil {
		return nil, ErrAuthorityLaunch
	}
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Nlink != 0 || !validAuthorityLaunchLinks(fd, 0) {
		return nil, ErrAuthorityLaunch
	}
	// Reopen the exact held object, never the original disk pathname. This
	// trusted procfs bridge reduces access mode instead of granting new access.
	readerFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrAuthorityLaunch
	}
	reader := os.NewFile(uintptr(readerFD), "syswarden-authority-launch-snapshot")
	fail := func() (*os.File, error) { _ = reader.Close(); return nil, ErrAuthorityLaunch }
	flags, err := unix.FcntlInt(uintptr(readerFD), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 || unix.Fstat(readerFD, &after) != nil || !sameStamp(before, after) {
		return fail()
	}
	if _, err := LoadAuthorityLaunch(reader, digest); err != nil {
		return fail()
	}
	return reader, nil
}

func newAuthorityLaunchSnapshot(create func(string, int) (int, error)) (int, error) {
	// MFD_NOEXEC_SEAL also installs F_SEAL_EXEC. Do not infer support from the
	// kernel version or change a namespace's security policy after denial.
	return create("syswarden-authority-launch", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_NOEXEC_SEAL)
}

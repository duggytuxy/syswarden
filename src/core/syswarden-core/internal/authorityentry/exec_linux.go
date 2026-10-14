package authorityentry

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"syswarden-core/journal"
)

// ExecSealed replaces this dedicated bootstrap with the independently approved
// authority image. The supervisor must already have dropped credentials and
// delivered descriptors 3..7. This is not an embeddable server API: it changes
// thread/process state and retains the OS thread lock even on failure. The
// caller must immediately exit if any error returns. It never forks or repairs.
func ExecSealed(launchDigest, imageDigest string) error {
	runtime.LockOSThread()
	files := [4]*os.File{os.NewFile(3, "launch"), os.NewFile(4, "state"), os.NewFile(5, "endpoint"), os.NewFile(6, "readiness")}
	image := os.NewFile(7, "image")
	launch, err := journal.LoadAuthorityLaunch(files[0], launchDigest)
	if err != nil {
		return err
	}
	if err := journal.VerifyAuthorityExecutableImage(image, imageDigest); err != nil {
		return err
	}
	// Only the exec thread needs this transition: successful exec destroys the
	// other bootstrap threads, and every new authority thread inherits the flag.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := confineStartup(files, launch); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	// Isolate the calling thread's descriptor table and mark every descriptor
	// beyond stdio close-on-exec, without disrupting the Go runtime's live fds.
	// Never fall back to a racy procfs inventory or a guessed numeric ceiling.
	if err := sealExecDescriptors(unix.CloseRange, unix.FcntlInt); err != nil {
		return err
	}
	err = unix.Exec("/proc/self/fd/7", []string{"syswarden-authority", "--launch-sha256", launchDigest}, []string{"GOMAXPROCS=2"})
	runtime.KeepAlive(files)
	runtime.KeepAlive(image)
	return err
}

func sealExecDescriptors(closeRange func(uint, uint, uint) error, fcntl func(uintptr, int, int) (int, error)) error {
	if err := closeRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_UNSHARE|unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err
	}
	for fd := uintptr(3); fd <= 6; fd++ {
		if _, err := fcntl(fd, unix.F_SETFD, 0); err != nil {
			return err
		}
		flags, err := fcntl(fd, unix.F_GETFD, 0)
		if err != nil {
			return err
		}
		if flags != 0 {
			return journal.ErrAuthorityExecutable
		}
	}
	flags, err := fcntl(7, unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	if flags&unix.FD_CLOEXEC == 0 {
		return journal.ErrAuthorityExecutable
	}
	return nil
}

//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const nativeOpenRCCorePath = "/opt/syswarden/bin/syswarden-core"

func observeNativeOpenRCCore(r *nativeOpenRCRead) (string, error) {
	return observeNativeOpenRCCoreWithPath(r, nativeOpenRCCorePath)
}

func observeNativeOpenRCCoreWithPath(r *nativeOpenRCRead, expectedPath string) (string, error) {
	before, err := os.Lstat("/proc")
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("native core procfs is unavailable")
	}
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return "", err
	}
	defer func() { _ = proc.Close() }()
	file, err := proc.Open(".")
	if err != nil {
		return "", err
	}
	opened, statErr := file.Stat()
	var fs unix.Statfs_t
	fsErr := unix.Fstatfs(int(file.Fd()), &fs)
	_ = file.Close()
	if statErr != nil || fsErr != nil || fs.Type != unix.PROC_SUPER_MAGIC || !os.SameFile(before, opened) {
		return "", errors.New("native core observation requires pinned procfs")
	}
	proof, err := observeNativeOpenRCCoreAtPath(r, proc, expectedPath)
	after, pathErr := os.Lstat("/proc")
	if pathErr != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("native core procfs changed")
	}
	return proof, err
}

// Synthetic procfs is accepted only through this internal test seam. Production
// always enters through the kernel filesystem check above.
func observeNativeOpenRCCoreAt(r *nativeOpenRCRead, proc *os.Root) (string, error) {
	return observeNativeOpenRCCoreAtPath(r, proc, nativeOpenRCCorePath)
}

func observeNativeOpenRCCoreAtPath(r *nativeOpenRCRead, proc *os.Root, expectedPath string) (string, error) {
	wire, err := r.file("run/syswarden-core.pid", 32)
	if err != nil {
		return "", errors.New("started OpenRC core has no readable PID identity")
	}
	text := strings.TrimSuffix(string(wire), "\n")
	pid, err := strconv.ParseInt(text, 10, 32)
	if err != nil || pid <= 1 || strconv.FormatInt(pid, 10) != text {
		return "", errors.New("OpenRC core PID is not canonical")
	}
	before, err := proc.Lstat(text)
	if err != nil || !r.trusted(before, true, false) {
		return "", errors.New("started OpenRC core has no trusted live process")
	}
	process, err := proc.OpenRoot(text)
	if err != nil {
		return "", err
	}
	defer func() { _ = process.Close() }()
	opened, err := process.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return "", errors.New("OpenRC core process changed while opening")
	}
	identity, err := nativeOpenRCCoreIdentity(process, text, expectedPath)
	if err != nil {
		return "", err
	}
	confirmed, err := nativeOpenRCCoreIdentity(process, text, expectedPath)
	after, pathErr := proc.Lstat(text)
	if err != nil || pathErr != nil || identity != confirmed || !os.SameFile(before, after) || !r.trusted(after, true, false) {
		return "", errors.New("OpenRC core process changed during observation")
	}
	return identity, nil
}

func nativeOpenRCCoreIdentity(process *os.Root, pid, expectedPath string) (string, error) {
	wire, err := readBoundedFirewallRemovalProcFile(process, "stat", 8192)
	if err != nil {
		return "", errors.New("OpenRC core process identity is unreadable")
	}
	text := string(wire)
	end := strings.LastIndex(text, ") ")
	if !strings.HasPrefix(text, pid+" (") || end < len(pid)+2 {
		return "", errors.New("OpenRC core process identity is malformed")
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 50 || len(fields[0]) != 1 || !strings.Contains("RSDI", fields[0]) {
		return "", errors.New("OpenRC core process is not live and running")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", errors.New("OpenRC core process lacks a start identity")
	}
	target, err := process.Readlink("exe")
	// Native replacement can unlink the old executable while its process remains
	// alive. The kernel's exact deleted-path suffix is permitted, not arbitrary
	// aliases or matching command-line names.
	if err != nil || target != expectedPath && target != expectedPath+" (deleted)" {
		return "", errors.New("OpenRC core PID belongs to a different executable")
	}
	return fmt.Sprintf("%s:%d:%s", pid, start, target), nil
}

//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type apkNativeProcess struct {
	PID        int                         `json:"pid"`
	ParentPID  int                         `json:"parent_pid"`
	Start      uint64                      `json:"start"`
	Executable nativeActivationRuntimeFile `json:"executable"`
}

func parseAPKNativeProcessStat(raw []byte, pid int) (int, uint64, error) {
	text := string(raw)
	end := strings.LastIndex(text, ") ")
	if pid <= 1 || len(raw) > 8192 || !strings.HasPrefix(text, strconv.Itoa(pid)+" (") || end < 0 {
		return 0, 0, errors.New("APK process stat is malformed")
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.Contains("RSDI", fields[0]) {
		return 0, 0, errors.New("APK process is not live")
	}
	parent, err := strconv.Atoi(fields[1])
	start, startErr := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startErr != nil || parent <= 0 || start == 0 {
		return 0, 0, errors.New("APK process ancestry is unavailable")
	}
	return parent, start, nil
}

// Kernel procfs and a live process start identity are required. The executable
// magic link is followed deliberately, then its actual inode and bytes are
// compared to independently retained expected evidence by the caller.
func observeAPKNativeProcess(ctx context.Context, pid int) (_ apkNativeProcess, result error) {
	var empty apkNativeProcess
	if ctx == nil || pid <= 1 {
		return empty, errors.New("APK process observation requires a live identity")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	proc, err := os.Open("/proc")
	if err != nil {
		return empty, err
	}
	defer func() { result = errors.Join(result, proc.Close()) }()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(proc.Fd()), &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return empty, errors.New("APK process observation requires real procfs")
	}
	process, err := os.OpenRoot(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return empty, err
	}
	defer func() { result = errors.Join(result, process.Close()) }()
	before, err := readBoundedFirewallRemovalProcFile(process, "stat", 8192)
	if err != nil {
		return empty, err
	}
	parent, start, err := parseAPKNativeProcessStat(before, pid)
	if err != nil {
		return empty, err
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return empty, err
	}
	defer func() { result = errors.Join(result, file.Close()) }() // #nosec G304 -- positive kernel PID, executable inode and bytes are independently checked
	info, err := file.Stat()
	if err != nil {
		return empty, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > maximumAPKExecutionHelperBytes || int64(st.Uid) != int64(os.Geteuid()) || int64(st.Gid) != int64(os.Getegid()) {
		return empty, errors.New("APK process executable is not protected")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumAPKExecutionHelperBytes+1))
	if err != nil || int64(len(data)) != info.Size() {
		return empty, errors.New("APK process executable read was incomplete")
	}
	final, err := file.Stat()
	if err != nil || apkTransitionStat(final.Sys().(*syscall.Stat_t)) != apkTransitionStat(st) {
		return empty, errors.New("APK process executable changed during observation")
	}
	after, err := readBoundedFirewallRemovalProcFile(process, "stat", 8192)
	if err != nil {
		return empty, err
	}
	afterParent, afterStart, err := parseAPKNativeProcessStat(after, pid)
	if err != nil || parent != afterParent || start != afterStart {
		return empty, errors.New("APK process identity changed during observation")
	}
	return apkNativeProcess{pid, parent, start, nativeActivationRuntimeFile{apkTransitionStat(st), apkTransitionDigest(data)}}, ctx.Err()
}

// APK can unlink the original installed coordinator executable during payload
// replacement. The live process remains bound to its original PID/start and
// inode/bytes. Only the resulting zero-link count and ctime change are allowed,
// and only after replacement; another process or executable is never adopted.
func sameAPKCoordinatorProcess(current, original apkNativeProcess, phase string) bool {
	if current == original {
		return true
	}
	if phase != "post-upgrade" && phase != "post-commit" {
		return false
	}
	if original.Executable.Identity.Links != 1 || current.Executable.Identity.Links != 0 {
		return false
	}
	adjusted := current
	adjusted.Executable.Identity.Links = original.Executable.Identity.Links
	adjusted.Executable.Identity.ChangedSec = original.Executable.Identity.ChangedSec
	adjusted.Executable.Identity.ChangedNS = original.Executable.Identity.ChangedNS
	return adjusted == original
}

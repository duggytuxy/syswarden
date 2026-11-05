//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// A rootless PID namespace may expose procfs with an unmapped mount owner.
// Require the kernel filesystem and a pinned real directory, not its UID.
func captureNFTOpenRCProcesses(host nftPersistenceFilesystem) (nftPersistenceRead, error) {
	var empty nftPersistenceRead
	parent, err := host.openDirectory("/")
	if err != nil {
		return empty, err
	}
	defer func() { _ = parent.Close() }()
	before, err := parent.Lstat("proc")
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return empty, fmt.Errorf("OpenRC process inventory is not a real directory")
	}
	proc, err := parent.OpenRoot("proc")
	if err != nil {
		return empty, err
	}
	defer func() { _ = proc.Close() }()
	file, err := proc.Open(".")
	if err != nil {
		return empty, err
	}
	opened, statErr := file.Stat()
	var filesystem unix.Statfs_t
	fsErr := unix.Fstatfs(int(file.Fd()), &filesystem)
	_ = file.Close()
	if statErr != nil || fsErr != nil || filesystem.Type != unix.PROC_SUPER_MAGIC || !os.SameFile(before, opened) {
		return empty, fmt.Errorf("OpenRC process inventory is not pinned procfs")
	}
	proof, err := captureNFTOpenRCProcessesAt(host, proc)
	after, pathErr := parent.Lstat("proc")
	if pathErr != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink != 0 {
		return empty, fmt.Errorf("OpenRC procfs mount changed during observation")
	}
	return proof, err
}

// This explicit helper permits synthetic proc fixtures. Production always
// enters through the procfs filesystem check above and has no fallback.
func captureNFTOpenRCProcessesAt(host nftPersistenceFilesystem, proc *os.Root) (nftPersistenceRead, error) {
	var proof nftPersistenceRead
	if proc == nil {
		return proof, fmt.Errorf("OpenRC process inventory is unavailable")
	}
	pids, err := nftOpenRCProcessIDs(proc)
	if err != nil || !slices.Contains(pids, "1") {
		return proof, fmt.Errorf("OpenRC process inventory lacks a readable PID 1")
	}
	for _, pid := range pids {
		observed, err := inspectNFTOpenRCProcess(host, proc, pid)
		if err != nil {
			// Do not expose command lines or process metadata in diagnostics.
			return nftPersistenceRead{}, fmt.Errorf("OpenRC process inventory is active, changing or unreadable: %w", err)
		}
		if pid == "1" {
			proof = observed
		}
	}
	confirmed, err := nftOpenRCProcessIDs(proc)
	if err != nil || !slices.Equal(pids, confirmed) {
		return nftPersistenceRead{}, fmt.Errorf("OpenRC process inventory changed during observation")
	}
	return proof, nil
}

func nftOpenRCProcessIDs(proc *os.Root) ([]string, error) {
	entries, err := nftOpenRCEntries(proc)
	if err != nil {
		return nil, err
	}
	var pids []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.Trim(name, "0123456789") != "" {
			continue
		}
		pid, err := strconv.ParseInt(name, 10, 32)
		if err != nil || pid <= 0 || strconv.FormatInt(pid, 10) != name || !entry.IsDir() {
			return nil, fmt.Errorf("OpenRC process inventory contains an invalid PID entry")
		}
		pids = append(pids, name)
	}
	slices.Sort(pids)
	return pids, nil
}

type nftOpenRCProcessIdentity struct {
	start  uint64
	comm   string
	kernel bool
	dead   bool
}

func decodeNFTOpenRCProcessIdentity(content []byte, pid string) (nftOpenRCProcessIdentity, error) {
	var empty nftOpenRCProcessIdentity
	prefix := pid + " ("
	text := string(content)
	end := strings.LastIndex(text, ") ")
	if !strings.HasPrefix(text, prefix) || end < len(prefix) {
		return empty, fmt.Errorf("OpenRC process identity is malformed")
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 50 || len(fields[0]) != 1 || !strings.Contains("RSDTtWPINZXx", fields[0]) {
		return empty, fmt.Errorf("OpenRC process state is unsupported")
	}
	start, startErr := strconv.ParseUint(fields[19], 10, 64)
	flags, flagErr := strconv.ParseUint(fields[6], 10, 64)
	if startErr != nil || flagErr != nil {
		return empty, fmt.Errorf("OpenRC process identity is incomplete")
	}
	// PF_KTHREAD distinguishes genuine kernel tasks with empty cmdline from
	// userspace processes whose arguments cannot establish a safe observation.
	return nftOpenRCProcessIdentity{start, text[len(prefix):end], flags&0x00200000 != 0, strings.Contains("ZXx", fields[0])}, nil
}

func inspectNFTOpenRCProcess(host nftPersistenceFilesystem, proc *os.Root, pid string) (nftPersistenceRead, error) {
	var proof nftPersistenceRead
	before, err := proc.Lstat(pid)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return proof, fmt.Errorf("process directory is unavailable")
	}
	process, err := proc.OpenRoot(pid)
	if err != nil {
		return proof, fmt.Errorf("process directory cannot be pinned")
	}
	defer func() { _ = process.Close() }()
	opened, err := process.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return proof, fmt.Errorf("process directory identity changed")
	}
	stat, err := readLegacyFail2banProcessFile(process, "stat", 8192)
	if err != nil {
		return proof, fmt.Errorf("process identity cannot be read")
	}
	identity, err := decodeNFTOpenRCProcessIdentity(stat, pid)
	if err != nil {
		return proof, err
	}
	arguments, err := readLegacyFail2banProcessFile(process, "cmdline", 65536)
	if err != nil {
		return proof, fmt.Errorf("process command line cannot be read")
	}
	if !identity.dead && !identity.kernel {
		if err := rejectNFTOpenRCProcessInvocation(identity.comm, arguments); err != nil {
			return proof, err
		}
	}
	if pid == "1" {
		proof, err = readNFTOpenRCRuntimeFile(host, process, "comm")
		if err != nil || identity.dead || identity.kernel ||
			(string(proof.content) != "init\n" && string(proof.content) != "openrc-init\n") ||
			strings.TrimSuffix(string(proof.content), "\n") != identity.comm {
			return nftPersistenceRead{}, fmt.Errorf("PID 1 is not coherent with OpenRC")
		}
	}
	if host.afterRead != nil {
		host.afterRead()
	}
	confirmedArguments, argsErr := readLegacyFail2banProcessFile(process, "cmdline", 65536)
	confirmedStat, statErr := readLegacyFail2banProcessFile(process, "stat", 8192)
	confirmed, decodeErr := decodeNFTOpenRCProcessIdentity(confirmedStat, pid)
	named, pathErr := proc.Lstat(pid)
	if argsErr != nil || statErr != nil || decodeErr != nil || pathErr != nil || identity != confirmed ||
		!bytes.Equal(arguments, confirmedArguments) || !os.SameFile(before, named) || named.Mode()&os.ModeSymlink != 0 {
		return nftPersistenceRead{}, fmt.Errorf("process identity or command line changed during observation")
	}
	return proof, nil
}

func rejectNFTOpenRCProcessInvocation(comm string, content []byte) error {
	if len(content) == 0 || content[len(content)-1] != 0 {
		return fmt.Errorf("live process command line is incomplete")
	}
	arguments := strings.Split(string(content[:len(content)-1]), "\x00")
	if len(arguments) > 4096 || arguments[0] == "" {
		return fmt.Errorf("live process arguments are ambiguous")
	}
	base := filepath.Base(arguments[0])
	manager := func(name string) bool {
		return name == "openrc-run" || name == "rc-service" || name == "service" || name == "openrc"
	}
	wrapper := func(name string) bool { return name == "openrc-run.sh" || name == "nftables" }
	isShell := func(name string) bool {
		return slices.Contains([]string{"sh", "ash", "bash", "dash", "ksh", "zsh"}, name)
	}
	shell := isShell(base) || isShell(comm) || (base == "busybox" || comm == "busybox") && len(arguments) > 1 && isShell(arguments[1])
	relevant := manager(base) || manager(comm) || wrapper(base) || wrapper(comm) || shell
	if !relevant {
		return nil
	}
	if base == "openrc" || comm == "openrc" {
		return fmt.Errorf("OpenRC manager is active")
	}
	if base == "nftables" || comm == "nftables" {
		return fmt.Errorf("OpenRC nftables service invocation is active")
	}
	for _, argument := range arguments[1:] {
		if filepath.Base(argument) == "nftables" || shell &&
			(strings.Contains(argument, "/etc/init.d/nftables") || strings.Contains(argument, "nftables") &&
				(strings.Contains(argument, "rc-service") || strings.Contains(argument, "openrc-run") || strings.Contains(argument, "service nftables"))) {
			return fmt.Errorf("OpenRC nftables service invocation is active")
		}
	}
	if len(arguments) < 2 && (manager(base) || manager(comm) || wrapper(base) || wrapper(comm)) {
		return fmt.Errorf("OpenRC invocation lacks a readable service argument")
	}
	return nil
}

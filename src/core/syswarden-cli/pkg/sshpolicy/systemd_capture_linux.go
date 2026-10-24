//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

// ObserveSystemdRuntime is an internal integration API, not a new CLI command or
// an activation adapter. Fixed protected paths and a root-only manager socket
// prevent environment hints, PATH and an unprivileged fake bus from choosing
// the observed manager. OpenRC and offline roots require their own adapters.
func ObserveSystemdRuntime() (summary SystemdSummary, err error) {
	defer func() {
		if err != nil {
			summary = SystemdSummary{}
		}
	}()
	if os.Geteuid() != 0 {
		return summary, fmt.Errorf("SSH service-manager observation requires root")
	}
	root, err := os.Open("/")
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	tool, err := openSSHSystemctl(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, tool.file.Close()) }()
	endpoint, err := readSSHSystemdEndpoint(root, 0)
	if err != nil {
		return summary, err
	}
	guard := func() error {
		current, err := readSSHSystemdEndpoint(root, 0)
		if err != nil || !reflect.DeepEqual(current, endpoint) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return tool.recheck(root, 0)
	}
	return observeSSHSystemd(context.Background(), tool.digest, tool.run, guard)
}

type sshSystemctl struct {
	file   *os.File
	state  inventoryStamp
	digest string
}

func openSSHSystemctl(root *os.File, uid int) (*sshSystemctl, error) {
	if root == nil {
		return nil, ErrInventoryUnsafe
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	directory, err := reader.openDirectory("/usr/bin")
	if err != nil || directory == nil {
		return nil, errors.Join(fmt.Errorf("trusted systemctl directory is unavailable"), err)
	}
	file, state, digest, err := readSSHExecutable(directory, "systemctl", uid)
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, errors.Join(err, closeErr)
	}
	return &sshSystemctl{file, state, digest}, nil
}

func (tool *sshSystemctl) recheck(root *os.File, uid int) error {
	current, err := openSSHSystemctl(root, uid)
	if err != nil {
		return err
	}
	defer current.file.Close()
	if current.state != tool.state || current.digest != tool.digest {
		return ErrInventoryChanged
	}
	return nil
}

// The manager's private socket is never created, connected or removed here.
// systemctl makes its own authenticated local system-manager query. Rechecking
// protected ancestors and endpoint identity bounds the ordinary-UID threat
// model; this cannot defend against a hostile root or a compromised manager.
func readSSHSystemdEndpoint(root *os.File, uid int) (inventorySnapshot, error) {
	if root == nil {
		return inventorySnapshot{}, ErrInventoryUnsafe
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	directory, err := reader.openDirectory("/run/systemd")
	if err != nil || directory == nil {
		return inventorySnapshot{}, errors.Join(fmt.Errorf("local systemd manager is unavailable; no offline or OpenRC fallback is inferred"), err)
	}
	defer directory.Close()
	var st unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), "private", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return inventorySnapshot{}, err
	}
	if int64(st.Uid) != int64(uid) || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&07077 != 0 || st.Nlink != 1 {
		return inventorySnapshot{}, ErrInventoryUnsafe
	}
	reader.state.nodes["/run/systemd/private"] = stamp(st)
	return sshEndpointAncestors(reader.state), nil
}

// Shared runtime directory membership changes during ordinary daemon reloads.
// Retain each protected ancestor's inode, device, type, permissions, owner and
// captured attributes, but do not bind its unrelated child count or timestamps.
// The endpoint socket retains its full stamp. Configuration inventories retain
// their stronger membership and timestamp checks; this is only a bus boundary.
func sshEndpointAncestors(snapshot inventorySnapshot) inventorySnapshot {
	for name, node := range snapshot.nodes {
		if node.exists && node.mode&unix.S_IFMT == unix.S_IFDIR {
			snapshot.nodes[name] = inventoryStamp{exists: true, dev: node.dev, ino: node.ino, mode: node.mode, uid: node.uid, gid: node.gid}
		}
	}
	return snapshot
}

// Do not embed bytes.Buffer: its promoted ReadFrom would bypass Write's limit
// when os/exec copies a pipe through io.Copy.
type sshSystemdOutput struct{ buffer bytes.Buffer }

func (output *sshSystemdOutput) Write(data []byte) (int, error) {
	if len(data) > maxSSHSystemdOutput-output.buffer.Len() {
		return 0, ErrInventoryBounds
	}
	return output.buffer.Write(data)
}

func (tool *sshSystemctl) command(ctx context.Context, unit string) (*exec.Cmd, error) {
	if tool == nil || tool.file == nil || ctx == nil {
		return nil, ErrInventoryUnsafe
	}
	// Executable descriptor, verbs, option names and unit names are fixed. No
	// observed property is interpolated into a command or a future action.
	var command *exec.Cmd
	switch unit {
	case "ssh.service":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--system", "--no-pager", "--no-ask-password", "show", "--all", "--property="+sshSystemdService, "ssh.service")
	case "sshd.service":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--system", "--no-pager", "--no-ask-password", "show", "--all", "--property="+sshSystemdService, "sshd.service")
	case "ssh.socket":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--system", "--no-pager", "--no-ask-password", "show", "--all", "--property="+sshSystemdSocket, "ssh.socket")
	case "sshd.socket":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--system", "--no-pager", "--no-ask-password", "show", "--all", "--property="+sshSystemdSocket, "sshd.socket")
	default:
		return nil, ErrInventoryUnsafe
	}
	command.ExtraFiles = []*os.File{tool.file}
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	return command, nil
}

func (tool *sshSystemctl) run(parent context.Context, unit string) ([]byte, error) {
	if parent == nil {
		return nil, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	command, err := tool.command(ctx, unit)
	if err != nil {
		return nil, err
	}
	var stdout, stderr sshSystemdOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil || stderr.buffer.Len() != 0 {
		return nil, fmt.Errorf("SSH system-manager query failed or exceeded its bounds")
	}
	return stdout.buffer.Bytes(), nil
}

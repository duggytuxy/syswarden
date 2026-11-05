//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

type sshBusctl struct {
	file   *os.File
	state  inventoryStamp
	digest string
}

func openSSHBusctl(root *os.File, uid int) (*sshBusctl, error) {
	if root == nil {
		return nil, ErrInventoryUnsafe
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	directory, err := reader.openDirectory("/usr/bin")
	if err != nil || directory == nil {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	file, state, digest, readErr := readSSHExecutable(directory, "busctl", uid)
	if err := errors.Join(readErr, directory.Close()); err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}
	return &sshBusctl{file, state, digest}, nil
}

func (tool *sshBusctl) recheck(root *os.File, uid int) error {
	current, err := openSSHBusctl(root, uid)
	if err != nil {
		return err
	}
	closeErr := current.file.Close()
	if current.state != tool.state || current.digest != tool.digest {
		return errors.Join(ErrInventoryChanged, closeErr)
	}
	return closeErr
}

func (tool *sshBusctl) command(ctx context.Context, unit string) (*exec.Cmd, error) {
	if ctx == nil || tool == nil || tool.file == nil {
		return nil, ErrInventoryUnsafe
	}
	// Descriptor and every bus argument are fixed. Query the same protected
	// system bus endpoint. Verify that systemd is owned by root PID 1. No user bus, shell,
	// auto-start, environment-selected transport or mutation method is permitted.
	var command *exec.Cmd
	switch unit {
	case "ssh.service":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/ssh_2eservice", "org.freedesktop.systemd1.Service", "ExecStartEx")
	case "sshd.service":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/sshd_2eservice", "org.freedesktop.systemd1.Service", "ExecStartEx")
	case "ssh.service/environment":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/ssh_2eservice", "org.freedesktop.systemd1.Service", "Environment")
	case "ssh.service/environment-files":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/ssh_2eservice", "org.freedesktop.systemd1.Service", "EnvironmentFiles")
	case "ssh.service/pam-name":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/ssh_2eservice", "org.freedesktop.systemd1.Service", "PAMName")
	case "sshd.service/environment":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/sshd_2eservice", "org.freedesktop.systemd1.Service", "Environment")
	case "sshd.service/environment-files":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/sshd_2eservice", "org.freedesktop.systemd1.Service", "EnvironmentFiles")
	case "sshd.service/pam-name":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/sshd_2eservice", "org.freedesktop.systemd1.Service", "PAMName")
	case "manager-pid":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID", "s", "org.freedesktop.systemd1")
	case "manager-uid":
		command = exec.CommandContext(ctx, "/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixUser", "s", "org.freedesktop.systemd1")
	default:
		return nil, ErrInventoryUnsafe
	}
	command.ExtraFiles = []*os.File{tool.file}
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	return command, nil
}

// A system bus is a broker, unlike the manager's peer-to-peer private socket.
// The broker identifies the well-known manager as root PID 1 on both sides of
// the property read. These queries cannot activate a service or set a property.
func querySSHStartupBus(ctx context.Context, unit string, execute sshStartupQuery) ([]byte, error) {
	if ctx == nil || execute == nil || !validSSHStartupQuery(unit) {
		return nil, ErrInventoryUnsafe
	}
	identity := func() error {
		for _, item := range []struct {
			key      string
			expected uint32
		}{{"manager-pid", 1}, {"manager-uid", 0}} {
			if err := ctx.Err(); err != nil {
				return err
			}
			wire, err := execute(ctx, item.key)
			if err != nil {
				return err
			}
			data, err := decodeSSHBusValue(wire, "u")
			if err != nil {
				return err
			}
			var values []json.RawMessage
			if json.Unmarshal(data, &values) != nil || len(values) != 1 || bytes.Equal(bytes.TrimSpace(values[0]), []byte("null")) {
				return ErrInventoryUnsafe
			}
			var got uint32
			if json.Unmarshal(values[0], &got) != nil || got != item.expected {
				return ErrInventoryUnsafe
			}
		}
		return ctx.Err()
	}
	if err := identity(); err != nil {
		return nil, err
	}
	wire, err := execute(ctx, unit)
	if err = errors.Join(err, identity(), ctx.Err()); err != nil {
		return nil, err
	}
	return wire, nil
}

func (tool *sshBusctl) run(parent context.Context, unit string) ([]byte, error) {
	if parent == nil {
		return nil, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	return querySSHStartupBus(ctx, unit, tool.execute)
}

func (tool *sshBusctl) execute(ctx context.Context, unit string) ([]byte, error) {
	command, err := tool.command(ctx, unit)
	if err != nil {
		return nil, err
	}
	var stdout, stderr sshSystemdOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := runSSHQueryProcess(ctx, command); err != nil || stderr.buffer.Len() != 0 {
		return nil, fmt.Errorf("SSH startup query failed or exceeded its bounds")
	}
	return stdout.buffer.Bytes(), nil
}

func readSSHSystemBusEndpoint(root *os.File, uid int) (snapshot inventorySnapshot, err error) {
	if root == nil {
		return inventorySnapshot{}, ErrInventoryUnsafe
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	directory, err := reader.openDirectory("/run/dbus")
	if err != nil || directory == nil {
		return inventorySnapshot{}, errors.Join(ErrInventoryUnsafe, err)
	}
	defer func() {
		err = errors.Join(err, directory.Close())
		if err != nil {
			snapshot = inventorySnapshot{}
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), "system_bus_socket", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return inventorySnapshot{}, err
	}
	// Connection permissions may be public. Protected ancestors, root ownership
	// and broker-reported manager credentials establish this read-only boundary.
	if int64(st.Uid) != int64(uid) || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&07000 != 0 || st.Nlink != 1 {
		return inventorySnapshot{}, ErrInventoryUnsafe
	}
	reader.state.nodes["/run/dbus/system_bus_socket"] = stamp(st)
	return sshEndpointAncestors(reader.state), nil
}

func validSSHStartupQuery(key string) bool {
	switch key {
	case "ssh.service", "sshd.service", "ssh.service/environment", "sshd.service/environment", "ssh.service/environment-files", "sshd.service/environment-files", "ssh.service/pam-name", "sshd.service/pam-name":
		return true
	default:
		return false
	}
}

//go:build freebsd

package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const freeBSDOwnedStateDirectory = "/var/db/syswarden"

func secureFreeBSDOwnedStateRoot() (*os.Root, error) {
	if err := os.MkdirAll(freeBSDOwnedStateDirectory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(freeBSDOwnedStateDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("unsafe FreeBSD owned-state directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return nil, fmt.Errorf("FreeBSD owned-state directory is not root-owned")
	}
	return os.OpenRoot(freeBSDOwnedStateDirectory)
}

func writeFreeBSDOwnedState(name string, value any) error {
	if !fs.ValidPath(name) || name == "." || strings.Contains(name, "/") {
		return fmt.Errorf("invalid owned-state name")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	root, err := secureFreeBSDOwnedStateRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	clean := false
	defer func() {
		_ = file.Close()
		if !clean {
			_ = root.Remove(name)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	clean = true
	return file.Close()
}

func readFreeBSDOwnedState(name string, maximum int64, value any) (bool, error) {
	root, err := secureFreeBSDOwnedStateRoot()
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0600 || info.Size() > maximum {
		return false, fmt.Errorf("unsafe FreeBSD owned-state file %s", name)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return false, fmt.Errorf("FreeBSD owned-state file %s is not root-owned", name)
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false, fmt.Errorf("FreeBSD owned-state file changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return false, fmt.Errorf("read bounded FreeBSD owned state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return false, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return false, fmt.Errorf("FreeBSD owned-state file has trailing data")
	}
	return true, nil
}

func removeFreeBSDOwnedState(name string) error {
	root, err := secureFreeBSDOwnedStateRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

type freeBSDRCValue struct {
	Present bool   `json:"present"`
	Value   string `json:"value"`
}

func freeBSDRCValues() (map[string]string, error) {
	output, err := exec.Command("sysrc", "-a").Output()
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return values, nil
}

func capturedFreeBSDRCValue(values map[string]string, name string) freeBSDRCValue {
	value, present := values[name]
	return freeBSDRCValue{Present: present, Value: value}
}

func validFreeBSDRCValue(value string) bool {
	return len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n")
}

func setFreeBSDRCValue(name string, state freeBSDRCValue) error {
	if !state.Present {
		var command *exec.Cmd
		switch name {
		case "syslogd_enable":
			command = exec.Command("sysrc", "-x", "syslogd_enable")
		case "rsyslogd_enable":
			command = exec.Command("sysrc", "-x", "rsyslogd_enable")
		case "rsyslogd_pidfile":
			command = exec.Command("sysrc", "-x", "rsyslogd_pidfile")
		case "gateway_enable":
			command = exec.Command("sysrc", "-x", "gateway_enable")
		case "wireguard_enable":
			command = exec.Command("sysrc", "-x", "wireguard_enable")
		case "wireguard_interfaces":
			command = exec.Command("sysrc", "-x", "wireguard_interfaces")
		default:
			return fmt.Errorf("unsupported rc variable %q", name)
		}
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("remove rc variable %s: %s: %w", name, strings.TrimSpace(string(output)), err)
		}
		return nil
	}
	if !validFreeBSDRCValue(state.Value) {
		return fmt.Errorf("unsafe rc value for %s", name)
	}
	var command *exec.Cmd
	switch name {
	case "syslogd_enable":
		command = exec.Command("/bin/sh", "-c", `exec sysrc "syslogd_enable=$SYSWARDEN_RC_VALUE"`)
	case "rsyslogd_enable":
		command = exec.Command("/bin/sh", "-c", `exec sysrc "rsyslogd_enable=$SYSWARDEN_RC_VALUE"`)
	case "rsyslogd_pidfile":
		command = exec.Command("/bin/sh", "-c", `exec sysrc "rsyslogd_pidfile=$SYSWARDEN_RC_VALUE"`)
	case "gateway_enable":
		command = exec.Command("/bin/sh", "-c", `exec sysrc "gateway_enable=$SYSWARDEN_RC_VALUE"`)
	case "wireguard_enable":
		command = exec.Command("/bin/sh", "-c", `exec sysrc "wireguard_enable=$SYSWARDEN_RC_VALUE"`)
	case "wireguard_interfaces":
		command = exec.Command("/bin/sh", "-c", `exec sysrc "wireguard_interfaces=$SYSWARDEN_RC_VALUE"`)
	default:
		return fmt.Errorf("unsupported rc variable %q", name)
	}
	command.Env = append(os.Environ(), "SYSWARDEN_RC_VALUE="+state.Value)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("restore rc variable %s: %s: %w", name, strings.TrimSpace(string(output)), err)
	}
	return nil
}

func exactFreeBSDRCValue(name, value string) error {
	return setFreeBSDRCValue(name, freeBSDRCValue{Present: true, Value: value})
}

func freeBSDServiceActive(name string) (bool, error) {
	var command *exec.Cmd
	switch name {
	case "syslogd":
		command = exec.Command("service", "syslogd", "onestatus")
	case "rsyslogd":
		command = exec.Command("service", "rsyslogd", "onestatus")
	case "wireguard":
		command = exec.Command("service", "wireguard", "onestatus")
	default:
		return false, fmt.Errorf("unsupported service %q", name)
	}
	err := command.Run()
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

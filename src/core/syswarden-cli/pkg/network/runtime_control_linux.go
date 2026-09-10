//go:build linux

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const runtimeControlSocketPath = "/run/syswarden-control.sock"

func PreflightRuntimeUnban(entry string) error {
	return requestRuntimeControl("preflight", entry)
}

// UnbanRuntime asks the authenticated core to change its authoritative model
// and native enforcement together. It never falls back to an unjournaled
// direct kernel removal when the daemon is unavailable.
func UnbanRuntime(entry string) error {
	return requestRuntimeControl("unban", entry)
}

func requestRuntimeControl(action, entry string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return requestRuntimeControlAt(ctx, runtimeControlSocketPath, 0, action, entry)
}

func canonicalRuntimeControlEntry(entry string) bool {
	if address, err := netip.ParseAddr(entry); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == entry
	}
	prefix, err := netip.ParsePrefix(entry)
	return err == nil && !prefix.Addr().Is4In6() && prefix.Masked().String() == entry
}

func requestRuntimeControlAt(ctx context.Context, path string, ownerUID int, action, entry string) error {
	if ctx == nil || ownerUID < 0 || action != "preflight" && action != "unban" || !canonicalRuntimeControlEntry(entry) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("invalid authoritative runtime control request")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	parentOwner, ownerErr := haFileOwnerUID(parentInfo)
	if ownerErr != nil || parentOwner != ownerUID || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("runtime control parent is not an owner-controlled real directory")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		return fmt.Errorf("runtime control parent changed while opening")
	}
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("authoritative runtime control is unavailable: %w", err)
	}
	owner, ownerErr := haFileOwnerUID(before)
	stat, statOK := before.Sys().(*syscall.Stat_t)
	if ownerErr != nil || owner != ownerUID || !statOK || stat.Nlink != 1 || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0600 {
		return fmt.Errorf("runtime control endpoint is not a private single-link owner-owned socket")
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("connect to authoritative runtime control: %w", err)
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("runtime control transport is not Unix")
	}
	deadline := time.Now().Add(10 * time.Second)
	if requested, present := ctx.Deadline(); present && requested.Before(deadline) {
		deadline = requested
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancellation()
	current, err := root.Lstat(name)
	currentParent, parentErr := os.Lstat(filepath.Dir(path))
	if err != nil || parentErr != nil || !os.SameFile(before, current) || !os.SameFile(parentInfo, currentParent) {
		return fmt.Errorf("runtime control endpoint changed while connecting")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return err
	}
	var credentials *syscall.Ucred
	var credentialErr error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, credentialErr = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credentialErr != nil || credentials == nil || int(credentials.Uid) != ownerUID {
		return fmt.Errorf("runtime control server peer identity is not authorized")
	}
	request := struct {
		Version int    `json:"version"`
		Action  string `json:"action"`
		Entry   string `json:"entry"`
	}{Version: 1, Action: action, Entry: entry}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return err
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return err
	}
	wire, err := io.ReadAll(io.LimitReader(connection, 2049))
	if err != nil {
		return fmt.Errorf("runtime operation response is ambiguous; inspect the core state before retrying: %w", err)
	}
	if len(wire) == 0 || len(wire) > 2048 {
		return fmt.Errorf("runtime operation response is empty or exceeds bounds")
	}
	if err := rejectDuplicateJSONNames(json.NewDecoder(bytes.NewReader(wire))); err != nil {
		return err
	}
	var response struct {
		Version int    `json:"version"`
		OK      *bool  `json:"ok"`
		Error   string `json:"error,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("runtime control response contains trailing data")
	}
	if response.Version != 1 || response.OK == nil || *response.OK && response.Error != "" {
		return fmt.Errorf("runtime control response is inconsistent")
	}
	if !*response.OK {
		if len(response.Error) > 1024 {
			return fmt.Errorf("runtime operation failed with an oversized response")
		}
		return fmt.Errorf("authoritative runtime operation refused: %s", response.Error)
	}
	return nil
}

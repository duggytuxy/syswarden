//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"syscall"
)

const approvedLXCServiceDropInPath = "/run/systemd/system/service.d/zzz-lxc-service.conf"

// Only the modern, non-privileged distrobuilder profile is reviewed here.
// This is a compatibility constraint, not package provenance or a claim that
// the container provides the same isolation as an independently managed host.
// Source: lxc/distrobuilder a81b4f5b59adcd5ca41265bbe2882df0254a124c.
const approvedLXCServiceDropInContent = `[Service]
ProcSubset=all
ProtectProc=default
ProtectControlGroups=no
ProtectKernelTunables=no
NoNewPrivileges=no
LoadCredential=
PrivateNetwork=no
ImportCredential=
`

func attestLXCServiceLoadedProfile(executor firewallManagerExecutor, systemctl, unit, dropIns string) error {
	for _, path := range strings.Split(dropIns, " ") {
		if path != approvedLXCServiceDropInPath {
			continue
		}
		value, err := queryCronProperty(executor, systemctl, unit, "NeedDaemonReload", false)
		if err != nil || value != "no" {
			return fmt.Errorf("LXC service compatibility requires current systemd unit metadata; inspect pending daemon reload")
		}
	}
	return nil
}

func attestLXCServiceDropIn(executor firewallManagerExecutor, path string) (string, error) {
	return attestLXCServiceDropInAt(executor, path, approvedLXCServiceDropInPath, "/", 0, 0)
}

func attestLXCServiceDropInAt(
	executor firewallManagerExecutor,
	path, expectedPath, trustedRoot string,
	uid, gid uint32,
) (string, error) {
	if path != expectedPath {
		return "", fmt.Errorf("LXC compatibility drop-in path is not approved")
	}
	if err := attestApprovedSystemdServiceDropInParents(path, trustedRoot, uid, gid); err != nil {
		return "", fmt.Errorf("LXC compatibility drop-in parents: %w", err)
	}
	first, err := readFirewallRemovalFileWithOwner(path, 0644, uid, gid)
	if err != nil {
		return "", fmt.Errorf("LXC compatibility drop-in metadata: %w", err)
	}
	if string(first.content) != approvedLXCServiceDropInContent {
		return "", fmt.Errorf("LXC compatibility drop-in differs from the reviewed non-privileged profile")
	}
	detector, err := resolveFirewallExecutable(executor, "systemd-detect-virt")
	if err != nil {
		return "", fmt.Errorf("resolve LXC context detector: %w", err)
	}
	for range 2 {
		context, err := executor.output(detector, "--container")
		if err != nil || !bytes.Equal(context, []byte("lxc\n")) {
			return "", fmt.Errorf("LXC compatibility drop-in requires verified LXC container context")
		}
		current, err := readFirewallRemovalFileWithOwner(path, 0644, uid, gid)
		if err != nil || !sameFirewallRemovalFileIdentity(first.identity, current.identity) ||
			!bytes.Equal(first.content, current.content) {
			return "", fmt.Errorf("LXC compatibility drop-in changed during context attestation")
		}
	}
	if err := attestApprovedSystemdServiceDropInParents(path, trustedRoot, uid, gid); err != nil {
		return "", fmt.Errorf("LXC compatibility drop-in parents changed: %w", err)
	}
	stat, ok := first.identity.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("LXC compatibility drop-in identity is unavailable")
	}
	// Include identity as well as bytes so the enclosing provider's repeated
	// capture also rejects a replacement with identical contents.
	return fmt.Sprintf("%s#%x#lxc-reviewed-profile#%d:%d:%d:%d", path,
		sha256.Sum256(first.content), stat.Dev, stat.Ino, stat.Ctim.Sec, stat.Ctim.Nsec), nil
}

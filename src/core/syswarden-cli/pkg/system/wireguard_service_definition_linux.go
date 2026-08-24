//go:build linux

package system

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- APK v2 Q1 records require SHA-1 compatibility attestation
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	maximumAPKInstalledDatabaseSize = 64 << 20
	maximumOpenRCWireGuardSize      = 1 << 20
)

type openRCWireGuardDefinitionPaths struct {
	root        string
	expectedUID uint32
	expectedGID uint32
}

type wireGuardDefinitionFile struct {
	identity os.FileInfo
	content  []byte
}

type wireGuardDefinitionLink struct {
	identity os.FileInfo
	target   string
}

func productionOpenRCWireGuardDefinitionPaths() openRCWireGuardDefinitionPaths {
	return openRCWireGuardDefinitionPaths{root: "/", expectedUID: 0, expectedGID: 0}
}

func (paths openRCWireGuardDefinitionPaths) hostPath(absolute string) (string, error) {
	if !filepath.IsAbs(paths.root) || filepath.Clean(paths.root) != paths.root {
		return "", fmt.Errorf("OpenRC attestation root is not clean and absolute")
	}
	if !filepath.IsAbs(absolute) || filepath.Clean(absolute) != absolute || absolute == "/" {
		return "", fmt.Errorf("OpenRC definition path %q is not clean and absolute", absolute)
	}
	return filepath.Join(paths.root, strings.TrimPrefix(absolute, "/")), nil
}

func sameWireGuardDefinitionIdentity(first, second os.FileInfo) bool {
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && os.SameFile(first, second) &&
		first.Mode() == second.Mode() && first.Size() == second.Size() &&
		first.ModTime() == second.ModTime() && firstStat.Uid == secondStat.Uid &&
		firstStat.Gid == secondStat.Gid && firstStat.Nlink == secondStat.Nlink &&
		firstStat.Ctim == secondStat.Ctim
}

func (paths openRCWireGuardDefinitionPaths) attestProtectedDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 ||
		stat.Uid != paths.expectedUID || stat.Gid != paths.expectedGID {
		return nil, fmt.Errorf("refusing unsafe OpenRC definition directory %s", path)
	}
	return info, nil
}

func (paths openRCWireGuardDefinitionPaths) attestProtectedParentChain(path string) error {
	rootInfo, err := paths.attestProtectedDirectory(paths.root)
	if err != nil {
		return fmt.Errorf("attest OpenRC definition root: %w", err)
	}
	_ = rootInfo
	relative, err := filepath.Rel(paths.root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("OpenRC definition path %s escapes its attestation root", path)
	}
	current := paths.root
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("invalid OpenRC definition directory component")
		}
		current = filepath.Join(current, component)
		if _, err := paths.attestProtectedDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func (paths openRCWireGuardDefinitionPaths) readFile(
	path string,
	maximumSize int64,
	exactMode *os.FileMode,
) (wireGuardDefinitionFile, error) {
	parent := filepath.Dir(path)
	if err := paths.attestProtectedParentChain(parent); err != nil {
		return wireGuardDefinitionFile{}, err
	}
	parentBefore, err := paths.attestProtectedDirectory(parent)
	if err != nil {
		return wireGuardDefinitionFile{}, err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return wireGuardDefinitionFile{}, fmt.Errorf("pin OpenRC definition directory %s: %w", parent, err)
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := root.Stat(".")
	if err != nil || !sameWireGuardDefinitionIdentity(parentBefore, rootInfo) {
		return wireGuardDefinitionFile{}, fmt.Errorf("OpenRC definition directory %s changed while pinning", parent)
	}
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return wireGuardDefinitionFile{}, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0022 != 0 || stat.Uid != paths.expectedUID ||
		stat.Gid != paths.expectedGID || stat.Nlink != 1 || before.Size() < 0 ||
		before.Size() > maximumSize {
		return wireGuardDefinitionFile{}, fmt.Errorf("refusing unsafe OpenRC definition file %s", path)
	}
	if exactMode != nil && before.Mode().Perm() != *exactMode {
		return wireGuardDefinitionFile{}, fmt.Errorf(
			"OpenRC definition file %s has mode %04o, want %04o",
			path, before.Mode().Perm(), *exactMode,
		)
	}
	file, err := root.Open(name)
	if err != nil {
		return wireGuardDefinitionFile{}, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximumSize+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil ||
		!sameWireGuardDefinitionIdentity(before, opened) || int64(len(content)) > maximumSize {
		return wireGuardDefinitionFile{}, fmt.Errorf("OpenRC definition file %s changed while reading", path)
	}
	after, err := root.Lstat(name)
	parentAfter, parentErr := os.Lstat(parent)
	if err != nil || parentErr != nil || !sameWireGuardDefinitionIdentity(opened, after) ||
		!sameWireGuardDefinitionIdentity(rootInfo, parentAfter) {
		return wireGuardDefinitionFile{}, fmt.Errorf("OpenRC definition file %s changed during attestation", path)
	}
	return wireGuardDefinitionFile{identity: after, content: content}, nil
}

func (paths openRCWireGuardDefinitionPaths) readLink(path, expectedTarget string) (wireGuardDefinitionLink, error) {
	parent := filepath.Dir(path)
	if err := paths.attestProtectedParentChain(parent); err != nil {
		return wireGuardDefinitionLink{}, err
	}
	parentBefore, err := paths.attestProtectedDirectory(parent)
	if err != nil {
		return wireGuardDefinitionLink{}, err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return wireGuardDefinitionLink{}, fmt.Errorf("pin OpenRC service directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := root.Stat(".")
	if err != nil || !sameWireGuardDefinitionIdentity(parentBefore, rootInfo) {
		return wireGuardDefinitionLink{}, fmt.Errorf("OpenRC service directory changed while pinning")
	}
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return wireGuardDefinitionLink{}, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != paths.expectedUID ||
		stat.Gid != paths.expectedGID || stat.Nlink != 1 {
		return wireGuardDefinitionLink{}, fmt.Errorf("refusing unsafe OpenRC WireGuard service link %s", path)
	}
	target, err := root.Readlink(name)
	if err != nil || target != expectedTarget {
		return wireGuardDefinitionLink{}, fmt.Errorf("refusing unexpected OpenRC WireGuard service target %q", target)
	}
	after, err := root.Lstat(name)
	parentAfter, parentErr := os.Lstat(parent)
	if err != nil || parentErr != nil || !sameWireGuardDefinitionIdentity(before, after) ||
		!sameWireGuardDefinitionIdentity(rootInfo, parentAfter) {
		return wireGuardDefinitionLink{}, fmt.Errorf("OpenRC WireGuard service link changed during attestation")
	}
	return wireGuardDefinitionLink{identity: after, target: target}, nil
}

func targetAPKPackageRecord(installed []byte) ([]string, error) {
	if bytes.IndexByte(installed, 0) >= 0 || bytes.IndexByte(installed, '\r') >= 0 {
		return nil, fmt.Errorf("APK installed database contains invalid control bytes")
	}
	var target []string
	matched := 0
	for _, rawRecord := range strings.Split(string(installed), "\n\n") {
		rawRecord = strings.Trim(rawRecord, "\n")
		if rawRecord == "" {
			continue
		}
		lines := strings.Split(rawRecord, "\n")
		packageFields := 0
		isTarget := false
		for _, line := range lines {
			if len(line) < 2 || line[1] != ':' {
				return nil, fmt.Errorf("APK installed database contains a malformed record")
			}
			if strings.HasPrefix(line, "P:") {
				packageFields++
				isTarget = line == "P:wireguard-tools-openrc"
			}
		}
		if packageFields != 1 {
			return nil, fmt.Errorf("APK installed database package record is ambiguous")
		}
		if isTarget {
			matched++
			target = lines
		}
	}
	if matched != 1 {
		return nil, fmt.Errorf("APK installed database contains %d wireguard-tools-openrc records, want 1", matched)
	}
	return target, nil
}

func apkOpenRCWireGuardChecksum(installed []byte) ([sha1.Size]byte, error) {
	var zero [sha1.Size]byte
	lines, err := targetAPKPackageRecord(installed)
	if err != nil {
		return zero, err
	}
	currentDirectory := ""
	matchingFiles := 0
	matchingFile := false
	mode := ""
	checksum := ""
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "F:"):
			currentDirectory = strings.TrimPrefix(line, "F:")
			matchingFile = false
		case strings.HasPrefix(line, "R:"):
			matchingFile = currentDirectory == "etc/init.d" && line == "R:wg-quick"
			if matchingFile {
				matchingFiles++
			}
		case matchingFile && strings.HasPrefix(line, "a:"):
			if mode != "" {
				return zero, fmt.Errorf("APK wg-quick ownership metadata is duplicated")
			}
			mode = strings.TrimPrefix(line, "a:")
		case matchingFile && strings.HasPrefix(line, "Z:"):
			if checksum != "" {
				return zero, fmt.Errorf("APK wg-quick checksum metadata is duplicated")
			}
			checksum = strings.TrimPrefix(line, "Z:")
		}
	}
	if matchingFiles != 1 || mode != "0:0:755" || !strings.HasPrefix(checksum, "Q1") {
		return zero, fmt.Errorf("APK wg-quick ownership tuple is missing or ambiguous")
	}
	encoded := strings.TrimPrefix(checksum, "Q1")
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != sha1.Size {
		return zero, fmt.Errorf("APK wg-quick Q1 checksum is not canonical SHA-1")
	}
	var expected [sha1.Size]byte
	copy(expected[:], decoded)
	return expected, nil
}

func attestOpenRCWireGuardDefinitionWith(paths openRCWireGuardDefinitionPaths) error {
	databasePath, err := paths.hostPath("/lib/apk/db/installed")
	if err != nil {
		return err
	}
	scriptPath, err := paths.hostPath("/etc/init.d/wg-quick")
	if err != nil {
		return err
	}
	linkPath, err := paths.hostPath("/etc/init.d/wg-quick.wg-syswarden")
	if err != nil {
		return err
	}
	database, err := paths.readFile(databasePath, maximumAPKInstalledDatabaseSize, nil)
	if err != nil {
		return fmt.Errorf("attest APK installed database: %w", err)
	}
	expectedChecksum, err := apkOpenRCWireGuardChecksum(database.content)
	if err != nil {
		return err
	}
	mode := os.FileMode(0755)
	script, err := paths.readFile(scriptPath, maximumOpenRCWireGuardSize, &mode)
	if err != nil {
		return fmt.Errorf("attest APK-owned OpenRC WireGuard script: %w", err)
	}
	actualChecksum := sha1.Sum(script.content) // #nosec G401 -- compare with APK v2 Q1 package evidence
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("OpenRC WireGuard script does not match its APK ownership checksum")
	}
	link, err := paths.readLink(linkPath, "/etc/init.d/wg-quick")
	if err != nil {
		return err
	}
	confirmedDatabase, err := paths.readFile(databasePath, maximumAPKInstalledDatabaseSize, nil)
	if err != nil || !sameWireGuardDefinitionIdentity(database.identity, confirmedDatabase.identity) ||
		!bytes.Equal(database.content, confirmedDatabase.content) {
		return fmt.Errorf("APK installed database changed during WireGuard service attestation")
	}
	confirmedScript, err := paths.readFile(scriptPath, maximumOpenRCWireGuardSize, &mode)
	if err != nil || !sameWireGuardDefinitionIdentity(script.identity, confirmedScript.identity) ||
		!bytes.Equal(script.content, confirmedScript.content) {
		return fmt.Errorf("OpenRC WireGuard script changed during service attestation")
	}
	confirmedLink, err := paths.readLink(linkPath, "/etc/init.d/wg-quick")
	if err != nil || !sameWireGuardDefinitionIdentity(link.identity, confirmedLink.identity) ||
		link.target != confirmedLink.target {
		return fmt.Errorf("OpenRC WireGuard service link changed during service attestation")
	}
	return nil
}

func attestOfflineSystemdWireGuardDefinition(host firewallRemovalPreparationHost) error {
	candidates := []string{
		"/usr/lib/systemd/system/wg-quick@.service",
		"/lib/systemd/system/wg-quick@.service",
	}
	var selected string
	var selectedInfo os.FileInfo
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect offline WireGuard service definition %s: %w", candidate, err)
		}
		if selected == "" {
			selected = candidate
			selectedInfo = info
			continue
		}
		if !os.SameFile(selectedInfo, info) {
			return fmt.Errorf("refusing ambiguous offline WireGuard service definitions")
		}
	}
	if selected == "" {
		return fmt.Errorf("offline WireGuard service definition is absent")
	}
	if _, err := host.resolveWireGuardExe(); err != nil {
		return fmt.Errorf("attest offline WireGuard executable: %w", err)
	}
	if err := host.attestSystemdUnit(selected); err != nil {
		return fmt.Errorf("attest offline WireGuard service definition: %w", err)
	}
	if _, err := host.resolveWireGuardExe(); err != nil {
		return fmt.Errorf("reattest offline WireGuard executable: %w", err)
	}
	return host.attestSystemdUnit(selected)
}

// AttestWireGuardServiceDefinition proves the exact service definition that
// can activate wg-syswarden. It performs no service-manager transition.
func AttestWireGuardServiceDefinition() error {
	host := productionFirewallRemovalPreparationHost()
	if host.effectiveUID != 0 {
		return fmt.Errorf("WireGuard service definition attestation must be executed as root")
	}
	state, err := host.classifyRuntime(host.alpine)
	if err != nil {
		return fmt.Errorf("attest service-manager runtime for WireGuard definition: %w", err)
	}
	switch state {
	case serviceManagerActive:
		manager, err := host.resolveManager()
		if err != nil {
			return err
		}
		service := firewallRemovalService{name: "wg-quick@wg-syswarden", wireGuard: true}
		if manager.alpine {
			return manager.attestOpenRCUnit(service)
		}
		return attestSystemdFirewallRemovalService(manager, service)
	case serviceManagerOffline:
		if host.alpine {
			return attestOpenRCWireGuardDefinitionWith(productionOpenRCWireGuardDefinitionPaths())
		}
		return attestOfflineSystemdWireGuardDefinition(host)
	default:
		return fmt.Errorf("refusing WireGuard definition attestation with manager state %s", state)
	}
}

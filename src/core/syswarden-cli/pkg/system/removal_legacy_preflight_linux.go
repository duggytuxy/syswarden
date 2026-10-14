//go:build linux

package system

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"syswarden-cli/pkg/platformpaths"
)

// This is a bounded discovery list, not an ownership allowlist. A present
// path is preserved for recovery even if its name resembles a generated file.
// Current manifest-owned services and cron.d entries have separate verified
// removal phases. Native payload files are removed by their package manager.
var historicalHostRemovalPaths = []string{
	"/etc/syswarden.conf",
	"/etc/aide/aide.conf.d/99_syswarden_exclusions",
	"/etc/profile.d/syswarden.sh",
	"/etc/rsyslog.d/10-syswarden.conf",
	"/etc/rsyslog.d/99-syswarden.conf",
	"/etc/sysctl.d/99-syswarden-vpn.conf",
	"/etc/systemd/system/syswarden-ipset.service",
	"/usr/share/fish/vendor_completions.d/syswarden.fish",
	"/usr/share/zsh/site-functions/_syswarden",
}

// These optional artifacts have existing exact cleanup phases. Inspect them
// only after those phases, so an exact file can be retired before absence is
// required. Modified artifacts must remain available for bounded recovery.
var historicalHostRemovalFinalPaths = []string{
	"/etc/systemd/journald.conf.d/99-syswarden.conf",
	"/etc/bash_completion.d/syswarden",
	"/etc/modprobe.d/syswarden-cis-fs.conf",
	"/etc/modprobe.d/syswarden-cis-net.conf",
	"/etc/security/limits.d/99-syswarden-cis.conf",
	"/etc/sysctl.d/99-syswarden-cis-level2.conf",
	"/etc/systemd/coredump.conf.d/99-syswarden.conf",
	"/etc/rsyslog.d/99-syswarden-antiforging.conf",
	"/etc/rsyslog.d/99-syswarden-siem.conf",
}

type historicalHostRemovalRemainder struct {
	path string
	kind string
}

// The caller supplies metadata-only inspection and a bounded root-crontab
// reader. Neither function may mutate the inspected configuration. Command
// contents and configuration bytes are never included in returned diagnostics.
func inspectHistoricalHostRemovalRemainders(final bool, present func(string) (bool, error), readCron func() (string, bool, error)) ([]historicalHostRemovalRemainder, error) {
	if present == nil || readCron == nil {
		return nil, fmt.Errorf("historical host removal inspection is incomplete")
	}
	var found []historicalHostRemovalRemainder
	paths := append([]string(nil), historicalHostRemovalPaths...)
	if final {
		paths = append(paths, historicalHostRemovalFinalPaths...)
	}
	for _, path := range paths {
		exists, err := present(path)
		if err != nil {
			return nil, fmt.Errorf("inspect historical removal candidate %s: %w", path, err)
		}
		if exists {
			found = append(found, historicalHostRemovalRemainder{path, "unresolved file ownership"})
		}
	}
	content, exists, err := readCron()
	if err != nil {
		return nil, fmt.Errorf("inspect root cron dependencies before complete removal: %w", err)
	}
	if len(content) > 1<<20 || !exists && content != "" || strings.ContainsRune(content, '\x00') {
		return nil, fmt.Errorf("root cron dependency evidence is inconsistent or exceeds its bound")
	}
	for index, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		kind := ""
		if platformpaths.IsManagedCronLine(line) {
			kind = "exact historical generated schedule"
		} else if strings.Contains(strings.ToLower(line), "syswarden") {
			kind = "unresolved scheduling dependency"
		}
		if kind != "" {
			found = append(found, historicalHostRemovalRemainder{fmt.Sprintf("root crontab line %d", index+1), kind})
		}
	}
	return found, nil
}

// Inspect each parent component without following symlinks. No file contents
// or directory trees are read, and absence is accepted only from a successful
// walk to the first missing component. A path substitution during the walk
// refuses cleanup instead of turning an unavailable path into absence.
func historicalRemovalCandidatePresent(root *os.Root, path string, uid, gid uint32, afterWalk func()) (bool, error) {
	if root == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, '\x00') {
		return false, fmt.Errorf("invalid historical removal candidate")
	}
	trustedDirectory := func(info os.FileInfo) bool {
		if info == nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Uid == uid && stat.Gid == gid
	}
	current, err := root.OpenRoot(".")
	if err != nil {
		return false, err
	}
	type binding struct {
		parent *os.Root
		name   string
		child  *os.Root
		info   os.FileInfo
	}
	var ancestry []binding
	openedRoots := []*os.Root{current}
	defer func() {
		for _, opened := range openedRoots {
			_ = opened.Close()
		}
	}()
	rootInfo, err := current.Stat(".")
	if err != nil || !trustedDirectory(rootInfo) {
		return false, fmt.Errorf("historical removal inspection root is unsafe")
	}
	exists := false
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, name := range parts {
		before, err := current.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			return false, err
		}
		if index == len(parts)-1 {
			// A final symlink is a retained candidate, never absence and never
			// authority to follow or remove its target.
			exists = true
			break
		}
		if !trustedDirectory(before) {
			return false, fmt.Errorf("historical removal candidate has an ambiguous parent")
		}
		next, err := current.OpenRoot(name)
		if err != nil {
			return false, err
		}
		openedRoots = append(openedRoots, next)
		opened, err := next.Stat(".")
		if err != nil || !trustedDirectory(opened) || !os.SameFile(before, opened) {
			return false, fmt.Errorf("historical removal candidate parent changed while opening")
		}
		ancestry = append(ancestry, binding{current, name, next, before})
		current = next
	}
	if afterWalk != nil {
		afterWalk()
	}
	// Keep and recheck the entire ancestry. Checking only the last directory
	// could accept absence in a tree detached from the active filesystem.
	for index := len(ancestry) - 1; index >= 0; index-- {
		link := ancestry[index]
		named, pathErr := link.parent.Lstat(link.name)
		opened, statErr := link.child.Stat(".")
		if pathErr != nil || statErr != nil || !trustedDirectory(named) || !trustedDirectory(opened) ||
			!os.SameFile(link.info, named) || !os.SameFile(link.info, opened) || link.info.Mode() != named.Mode() {
			return false, fmt.Errorf("historical removal candidate parent changed while inspecting")
		}
	}
	rootAfter, err := openedRoots[0].Stat(".")
	if err != nil || !trustedDirectory(rootAfter) || !os.SameFile(rootInfo, rootAfter) || rootInfo.Mode() != rootAfter.Mode() {
		return false, fmt.Errorf("historical removal inspection root changed")
	}
	// Recheck the complete path after ancestry attestation to reject a newly
	// appeared candidate or changed absence. This reads metadata only.
	_, err = root.Lstat(strings.TrimPrefix(path, "/"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if (err == nil) != exists {
		return false, fmt.Errorf("historical removal candidate presence changed while inspecting")
	}
	return exists, nil
}

func preflightHistoricalHostRemovalUsing(final bool, present func(string) (bool, error), readCron func() (string, bool, error)) error {
	found, err := inspectHistoricalHostRemovalRemainders(final, present, readCron)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return nil
	}
	var reasons []string
	legacyCron := false
	for _, item := range found {
		if item.kind == "exact historical generated schedule" {
			legacyCron = true
		}
		reasons = append(reasons, item.path+" ("+item.kind+")")
	}
	if legacyCron {
		reasons = append(reasons, "inspect exact root cron retirement with sudo syswarden recover-removal --retire-legacy-cron")
	}
	return fmt.Errorf("complete product removal requires verified retirement of retained historical artifacts; preserve these sources and the product executable for bounded recovery: %s", strings.Join(reasons, "; "))
}

// PreflightHistoricalHostRemoval prevents product deletion from reporting a
// complete uninstall while known historical candidates or scheduling records
// remain. This gate neither establishes ownership nor removes those sources.
func PreflightHistoricalHostRemoval() error {
	return inspectHistoricalHostRemoval(false)
}

// AttestHistoricalHostRemovalComplete also checks optional artifacts after
// their exact cleanup phases. It must run before deleting recovery resources.
func AttestHistoricalHostRemovalComplete() error {
	return inspectHistoricalHostRemoval(true)
}

func inspectHistoricalHostRemoval(final bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("historical host removal inspection requires root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return preflightHistoricalHostRemovalUsing(final, func(path string) (bool, error) {
		return historicalRemovalCandidatePresent(root, path, 0, 0, nil)
	}, ReadOnlyRootCrontabEvidence)
}

// Native package managers remove their own completion payload after the shared
// preparation returns. A standalone tail has no such later phase and must
// retain its executable if an unaccounted completion payload is still present.
func attestStandaloneCompletionPayloadAbsent() error {
	root, err := os.OpenRoot("/")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	const path = "/usr/share/bash-completion/completions/syswarden"
	present, err := historicalRemovalCandidatePresent(root, path, 0, 0, nil)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("standalone removal requires verified retirement of the retained completion payload %s; preserve the executable for recovery", path)
	}
	return nil
}

// RemoveUninstallCompletionPayload preserves the opt-in profile's RPM-owned
// completion. Standalone deletion still requires independently absent package
// registration, even if the profile changes between inspections.
func RemoveUninstallCompletionPayload(content string) error {
	return removeUninstallCompletionPayloadWith(content, attestInstalledRHELPackageOwnedProfileForRemoval, RemoveStandaloneCompletionPayload)
}

func removeUninstallCompletionPayloadWith(content string, attestProfile func() (bool, error), removeStandalone func(string) error) error {
	if attestProfile == nil || removeStandalone == nil {
		return fmt.Errorf("uninstall completion authority is unavailable")
	}
	present, err := attestProfile()
	if err != nil {
		return fmt.Errorf("attest completion payload authority: %w", err)
	}
	if present {
		return nil
	}
	return removeStandalone(content)
}

// RemoveStandaloneCompletionPayload retires only the exact current completion
// rendered by the running CLI. Package registration, a modified completion,
// unsafe metadata or another hard link prevents deletion. The pinned
// quarantine operation rechecks the bytes and identity after the rename.
func RemoveStandaloneCompletionPayload(content string) error {
	if content == "" || len(content) > 256<<10 {
		return fmt.Errorf("standalone completion renderer returned an invalid payload")
	}
	if err := PreflightStandaloneUninstall(); err != nil {
		return err
	}
	if err := RequireRemovalTombstone(); err != nil {
		return err
	}
	if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
		return err
	}
	if err := removePreparedExactServiceFile(
		"/usr/share/bash-completion/completions/syswarden", content, 0644,
	); err != nil {
		return fmt.Errorf("retire exact standalone completion payload: %w", err)
	}
	return RequireRemovalTombstone()
}

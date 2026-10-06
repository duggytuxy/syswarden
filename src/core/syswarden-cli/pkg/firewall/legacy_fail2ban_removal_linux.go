//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PreflightHistoricalFail2banRemoval prevents ordinary product deletion from
// discarding evidence while a historical producer is still configured. It is
// deliberately read-only: stopping a jail requires a separately bound runtime
// plan, and a suggestive name never authorizes deleting administrator files.
// Passing this check alone does not establish absence of orphaned kernel rules,
// nondefault service roots or persistent nftables sources.
func PreflightHistoricalFail2banRemoval() error {
	root, err := os.OpenRoot("/")
	if err != nil {
		return fmt.Errorf("open historical Fail2ban inspection root: %w", err)
	}
	defer func() { _ = root.Close() }()
	return preflightHistoricalFail2banRemoval(nftPersistenceFilesystem{root: root})
}

func preflightHistoricalFail2banRemoval(host nftPersistenceFilesystem) error {
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		return fmt.Errorf("inspect historical Fail2ban sources before product removal: %w", err)
	}
	var exact, ambiguous []string
	for _, source := range inventory.sources {
		if _, matches := matchLegacyFail2banTemplate(source.path, source.snapshot.content); matches {
			exact = append(exact, source.path)
			continue
		}
		// These are discovery hints only. A changed historical template or an
		// administrator's dependency on a product command needs explicit review.
		// Do not publish content, assume ownership, or move it based on a hint.
		candidate := strings.Contains(strings.ToLower(filepath.Base(source.path)), "syswarden")
		for _, reference := range []string{"/opt/syswarden/", "/etc/syswarden/", "/var/lib/syswarden/", "/usr/local/bin/syswarden", "syswarden_f2b", "syswarden-nft", "syswarden-persistence"} {
			candidate = candidate || bytes.Contains(source.snapshot.content, []byte(reference))
		}
		if candidate {
			ambiguous = append(ambiguous, source.path)
		}
	}
	if err := reattestLegacyFail2banPlanInventory(host, inventory); err != nil {
		return err
	}
	if len(exact) == 0 && len(ambiguous) == 0 {
		return nil
	}
	sort.Strings(exact)
	sort.Strings(ambiguous)
	// Show paths, not configuration bytes or expanded commands. In particular,
	// do not imply that successful package removal would retire these sources.
	return fmt.Errorf("historical Fail2ban recovery is incomplete; preserve the removal barrier and configuration for verified retirement; exact generated sources: %q; unresolved dependencies or modified sources: %q", exact, ambiguous)
}

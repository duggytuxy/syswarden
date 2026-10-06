//go:build linux

package firewall

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

var knownNFTPersistenceEntryPoints = []string{
	"/etc/nftables.conf",
	"/etc/nftables.nft",
	"/etc/sysconfig/nftables.conf",
}

// PreflightKnownNFTPersistenceRemoval discovers product references in common
// distribution entry points and their complete literal include graphs. Names
// are discovery hints, never ownership evidence or permission to edit a file.
// A clean result does not attest custom service entry points or other loaders.
func PreflightKnownNFTPersistenceRemoval() error {
	root, err := os.OpenRoot("/")
	if err != nil {
		return fmt.Errorf("open nftables persistence inspection root: %w", err)
	}
	defer func() { _ = root.Close() }()
	return preflightKnownNFTPersistenceRemoval(nftPersistenceFilesystem{root: root})
}

func preflightKnownNFTPersistenceRemoval(host nftPersistenceFilesystem) error {
	var present, absent []string
	for _, path := range knownNFTPersistenceEntryPoints {
		_, err := host.snapshot(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			absent = append(absent, path)
		case err != nil:
			return fmt.Errorf("inspect nftables persistence entry point %q: %w", path, err)
		default:
			present = append(present, path)
		}
	}
	var candidates []string
	if len(present) > 0 {
		graph, err := inspectNFTPersistenceGraph(present, host.reader())
		if err != nil {
			return fmt.Errorf("inspect nftables persistence before removal: %w", err)
		}
		for _, source := range graph.sources {
			content, err := host.read(source.path)
			if err != nil {
				return err
			}
			if sha256.Sum256(content) != source.sha256 {
				return fmt.Errorf("nftables persistence source changed during removal inspection: %q", source.path)
			}
			candidate := strings.HasPrefix(source.path, "/etc/syswarden/") || unresolvedNFTPersistentProductReference(host, source.path, content)
			if candidate {
				candidates = append(candidates, source.path)
			}
		}
		if err := verifyNFTPersistenceGraph(graph, host.reader()); err != nil {
			return err
		}
	}
	// A source absent at discovery must not appear unnoticed during graph
	// inspection. Missing files never bypass an unreadable or symlinked path.
	for _, path := range absent {
		if _, err := host.snapshot(path); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("nftables persistence entry point appeared or became ambiguous during removal inspection: %q", path)
		}
	}
	if len(candidates) > 0 {
		if err := preflightOwnedNFTPersistenceRemoval(host, present); err == nil {
			return nil
		}
		sort.Strings(candidates)
		return fmt.Errorf("persistent firewall recovery is incomplete; preserve the include graph and administrator rules for verified retirement before product removal; sources requiring ownership and dependency review: %q", candidates)
	}
	return nil
}

// Permit preparation for a writer-owned policy only when the proposed graph
// removes every product reference and preserves every administrator source.
// This is read-only permission to continue preparation, never a deletion grant.
func preflightOwnedNFTPersistenceRemoval(host nftPersistenceFilesystem, entries []string) error {
	origin, err := inspectNFTPolicyOwnership(host)
	if err != nil {
		return err
	}
	all := append(append([]string(nil), entries...), legacyNFTIncludePath)
	graph, err := inspectNFTPersistenceGraph(all, host.reader())
	if err != nil {
		return err
	}
	var retiring []nftPersistenceRetiredSource
	for _, source := range graph.sources {
		if source.path == legacyNFTIncludePath {
			if fmt.Sprintf("%x", source.sha256) != origin.source {
				return fmt.Errorf("writer source changed during read-only preparation")
			}
			retiring = append(retiring, nftPersistenceRetiredSource{source.path, source.sha256})
			continue
		}
		if unresolvedNFTPersistentProductReference(host, source.path, source.edit.content) {
			return fmt.Errorf("additional persistent product references require separate verified recovery")
		}
	}
	if err := verifyNFTPersistenceRetirementCoverageWithProductEntry(graph, retiring, true); err != nil {
		return err
	}
	if err := verifyNFTPersistenceGraph(graph, host.reader()); err != nil {
		return err
	}
	return origin.verify(host)
}

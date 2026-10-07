//go:build linux

package firewall

import (
	"crypto/sha256"
	"fmt"
)

type nftPersistenceRetiredSource struct {
	path   string
	sha256 [sha256.Size]byte
}

// verifyNFTPersistenceRetirementCoverage projects the include graph after
// proposed edits and source retirements. Every original source not explicitly
// retired must remain reachable. An exact generated include marker is not
// sufficient to detach a file that also brings in administrator configuration.
//
// The retired source digests must come from a separate ownership attestation.
// This pure dependency check cannot prove ownership from a filename or digest,
// and does not inspect service entry points or change files or runtime state.
// The original graph must still be reattested immediately before any mutation.
func verifyNFTPersistenceRetirementCoverage(graph nftPersistenceGraph, retiring []nftPersistenceRetiredSource) error {
	return verifyNFTPersistenceRetirementCoverageWithProductEntry(graph, retiring, false)
}

// A dedicated product entry point is allowed only with separate writer
// ownership and quiescent product-loader evidence. Shared service entry points
// remain non-retireable. The fixed path is a boundary, never that evidence.
func verifyNFTPersistenceRetirementCoverageWithProductEntry(graph nftPersistenceGraph, retiring []nftPersistenceRetiredSource, productEntry bool) error {
	if len(graph.entries) == 0 || len(graph.sources) == 0 || len(retiring) > maximumNFTPersistenceFiles {
		return fmt.Errorf("nftables retirement requires bounded source and entry-point evidence")
	}
	sources := make(map[string]nftPersistenceSource, len(graph.sources))
	for _, source := range graph.sources {
		if _, duplicate := sources[source.path]; duplicate || source.sha256 != source.edit.originalSHA256 {
			return fmt.Errorf("nftables retirement source evidence is duplicate or unbound")
		}
		sources[source.path] = source
	}
	retired := make(map[string]bool, len(retiring))
	for _, source := range retiring {
		expected, found := sources[source.path]
		if !found || retired[source.path] || source.sha256 != expected.sha256 {
			return fmt.Errorf("nftables retirement digest does not match an inspected source")
		}
		retired[source.path] = true
	}
	if productEntry && (len(retiring) != 1 || !retired[legacyNFTIncludePath]) {
		return fmt.Errorf("dedicated product entry retirement has unexpected source coverage")
	}
	var projectedEntries []string
	foundProductEntry := false
	for _, entry := range graph.entries {
		if retired[entry] {
			if productEntry && entry == legacyNFTIncludePath {
				foundProductEntry = true
				continue
			}
			return fmt.Errorf("nftables retirement would remove a configured entry point")
		}
		projectedEntries = append(projectedEntries, entry)
	}
	if productEntry && !foundProductEntry {
		return fmt.Errorf("dedicated product entry retirement lacks its exact entry point")
	}
	if len(projectedEntries) == 0 {
		if len(sources) != len(retired) {
			return fmt.Errorf("dedicated product entry retirement would detach retained administrator sources")
		}
		return nil
	}
	expansions := make(map[string][]string, len(graph.expansions))
	for _, expansion := range graph.expansions {
		if _, duplicate := expansions[expansion.pattern]; duplicate {
			return fmt.Errorf("nftables retirement has duplicate wildcard evidence")
		}
		paths := make([]string, 0, len(expansion.paths))
		for _, path := range expansion.paths {
			if !retired[path] {
				paths = append(paths, path)
			}
		}
		expansions[expansion.pattern] = paths
	}
	projected, err := inspectNFTPersistenceGraph(projectedEntries, nftPersistenceGraphReader{
		read: func(path string) (nftPersistenceRead, error) {
			source, found := sources[path]
			if !found || retired[path] {
				return nftPersistenceRead{}, fmt.Errorf("projected include refers to an unavailable source")
			}
			// The staged bytes are a proposal, not a filesystem identity.
			return nftPersistenceRead{content: source.edit.content}, nil
		},
		expand: func(pattern string) ([]string, error) {
			paths, found := expansions[pattern]
			if !found {
				return nil, fmt.Errorf("projected include has no inspected wildcard expansion")
			}
			return paths, nil
		},
	})
	if err != nil {
		return fmt.Errorf("nftables retirement would leave an unresolved include: %w", err)
	}
	reachable := make(map[string]bool, len(projected.sources))
	for _, source := range projected.sources {
		reachable[source.path] = true
	}
	for _, source := range graph.sources {
		if !retired[source.path] && !reachable[source.path] {
			return fmt.Errorf("nftables retirement would detach an unretired persistent source: %q", source.path)
		}
	}
	return nil
}

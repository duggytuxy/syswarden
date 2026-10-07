//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"slices"
)

// verifyNFTPersistenceGraph checks the same entry points again, including
// unchanged files and previously empty wildcard expansions. It does not lock
// out external editors or authorize mutation. A writer must also reattest its
// file and dependency observations at the mutation boundary.
func verifyNFTPersistenceGraph(expected nftPersistenceGraph, reader nftPersistenceGraphReader) error {
	if len(expected.entries) == 0 || len(expected.sources) == 0 {
		return fmt.Errorf("nftables persistence graph has no attested entry points or sources")
	}
	for _, source := range expected.sources {
		if source.identity == nil || source.edit.originalSHA256 != source.sha256 {
			return fmt.Errorf("nftables persistence graph lacks a bound file identity for %q", source.path)
		}
	}
	current, err := inspectNFTPersistenceGraph(expected.entries, reader)
	if err != nil {
		return fmt.Errorf("reattest nftables persistence graph: %w", err)
	}
	if !slices.Equal(expected.entries, current.entries) || len(expected.sources) != len(current.sources) ||
		len(expected.expansions) != len(current.expansions) {
		return fmt.Errorf("nftables persistence dependencies changed after inspection")
	}
	for index, source := range expected.sources {
		actual := current.sources[index]
		if source.path != actual.path || source.sha256 != actual.sha256 ||
			!sameNFTPersistenceIdentity(source.identity, actual.identity) {
			return fmt.Errorf("nftables persistence source changed after inspection: %q", source.path)
		}
		if !bytes.Equal(source.edit.content, actual.edit.content) || !slices.Equal(source.edit.removed, actual.edit.removed) {
			return fmt.Errorf("nftables persistence edit changed after inspection: %q", source.path)
		}
	}
	for index, expansion := range expected.expansions {
		actual := current.expansions[index]
		if expansion.pattern != actual.pattern || !slices.Equal(expansion.paths, actual.paths) {
			return fmt.Errorf("nftables persistence wildcard changed after inspection: %q", expansion.pattern)
		}
	}
	return nil
}

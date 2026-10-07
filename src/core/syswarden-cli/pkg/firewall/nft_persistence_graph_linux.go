//go:build linux

package firewall

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maximumNFTPersistenceFiles      = 128
	maximumNFTPersistenceGraphBytes = 32 << 20
	maximumNFTPersistenceIncludes   = 512
	maximumNFTPersistenceGraphDepth = 32
)

// File reads and wildcard expansion are supplied by an attested filesystem
// reader. This graph builder does not execute nftables or infer file ownership.
type nftPersistenceGraphReader struct {
	read   func(string) (nftPersistenceRead, error)
	expand func(string) ([]string, error)
}

type nftPersistenceRead struct {
	content        []byte
	identity       os.FileInfo
	filesystemUUID string
}

type nftPersistenceSource struct {
	path     string
	sha256   [sha256.Size]byte
	identity os.FileInfo
	document nftPersistenceDocument
	edit     nftPersistenceEdit
}

type nftPersistenceExpansion struct {
	pattern string
	paths   []string
}

type nftPersistenceGraph struct {
	entries    []string
	sources    []nftPersistenceSource
	expansions []nftPersistenceExpansion
}

func canonicalNFTPersistencePath(path string, allowWildcard bool) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		strings.ContainsAny(path, "\\\n\r\t\x00$") {
		return false
	}
	// Wildcards in directory components make the search boundary ambiguous.
	if strings.ContainsAny(filepath.Dir(path), "*?[") {
		return false
	}
	return allowWildcard || !strings.ContainsAny(path, "*?[")
}

func matchNFTPersistenceWildcard(pattern, path string) (bool, error) {
	// Only star patterns are resolved automatically. Character classes and
	// single-character matches have libc/locale semantics that filepath.Match
	// cannot attest. They require separate reviewed resolution.
	if strings.ContainsAny(pattern, "?[") {
		return false, fmt.Errorf("nftables persistence wildcard requires reviewed pattern resolution")
	}
	// nftables uses shell include expansion. A star does not implicitly match
	// a leading dot, unlike filepath.Match. See the upstream nft(8) include
	// documentation: https://netfilter.org/projects/nftables/manpage.html
	if strings.HasPrefix(filepath.Base(path), ".") && !strings.HasPrefix(filepath.Base(pattern), ".") {
		return false, nil
	}
	return filepath.Match(pattern, path)
}

// inspectNFTPersistenceGraph follows a bounded, literal include graph. It
// retains every source digest and wildcard result for later reattestation.
// Unsupported or unreadable input returns no partial plan. A successful result
// is an inventory, not proof that the host uses only these entry points.
func inspectNFTPersistenceGraph(entries []string, reader nftPersistenceGraphReader) (nftPersistenceGraph, error) {
	if len(entries) == 0 || len(entries) > maximumNFTPersistenceFiles || reader.read == nil || reader.expand == nil {
		return nftPersistenceGraph{}, fmt.Errorf("nftables persistence graph requires bounded entry points and a complete reader")
	}
	graph := nftPersistenceGraph{entries: append([]string(nil), entries...)}
	sort.Strings(graph.entries)
	for index := 1; index < len(graph.entries); index++ {
		if graph.entries[index] == graph.entries[index-1] {
			return nftPersistenceGraph{}, fmt.Errorf("nftables persistence entry points contain a duplicate")
		}
	}
	state := make(map[string]uint8)
	expanded := make(map[string][]string)
	totalBytes, includeCount := 0, 0
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		if !canonicalNFTPersistencePath(path, false) {
			return fmt.Errorf("nftables persistence path is not canonical and absolute: %q", path)
		}
		if depth > maximumNFTPersistenceGraphDepth {
			return fmt.Errorf("nftables persistence include graph exceeds the depth limit")
		}
		switch state[path] {
		case 1:
			return fmt.Errorf("nftables persistence include graph contains a cycle at %q", path)
		case 2:
			return nil
		}
		if len(state) == maximumNFTPersistenceFiles {
			return fmt.Errorf("nftables persistence include graph exceeds the file limit")
		}
		state[path] = 1
		input, err := reader.read(path)
		if err != nil {
			return fmt.Errorf("read nftables persistence source %q: %w", path, err)
		}
		content := input.content
		if len(content) > maximumNFTPersistenceGraphBytes-totalBytes {
			return fmt.Errorf("nftables persistence include graph exceeds the total byte limit")
		}
		totalBytes += len(content)
		document, err := inspectNFTPersistence(content)
		if err != nil {
			return fmt.Errorf("inspect nftables persistence source %q: %w", path, err)
		}
		edit, err := planLegacyNFTIncludeRetirement(content)
		if err != nil {
			return fmt.Errorf("plan nftables persistence source %q: %w", path, err)
		}
		graph.sources = append(graph.sources, nftPersistenceSource{
			path: path, sha256: sha256.Sum256(content), identity: input.identity, document: document, edit: edit,
		})
		for _, include := range document.includes {
			includeCount++
			if includeCount > maximumNFTPersistenceIncludes {
				return fmt.Errorf("nftables persistence include graph exceeds the edge limit")
			}
			if !canonicalNFTPersistencePath(include.path, true) {
				return fmt.Errorf("nftables persistence include requires reviewed path resolution: %q", include.path)
			}
			matches := []string{include.path}
			if strings.ContainsAny(include.path, "*?[") {
				if _, err := matchNFTPersistenceWildcard(include.path, ""); err != nil {
					return err
				}
				var known bool
				matches, known = expanded[include.path]
				if !known {
					matches, err = reader.expand(include.path)
					if err != nil {
						return fmt.Errorf("expand nftables persistence include %q: %w", include.path, err)
					}
					if len(matches) > maximumNFTPersistenceFiles {
						return fmt.Errorf("nftables persistence wildcard exceeds the file limit")
					}
					matches = append([]string(nil), matches...)
					sort.Strings(matches)
					for index, match := range matches {
						matched, matchErr := matchNFTPersistenceWildcard(include.path, match)
						if !canonicalNFTPersistencePath(match, false) || !matched || matchErr != nil ||
							index > 0 && matches[index-1] == match {
							return fmt.Errorf("nftables persistence wildcard returned an invalid or duplicate path")
						}
					}
					expanded[include.path] = matches
					graph.expansions = append(graph.expansions, nftPersistenceExpansion{include.path, matches})
				}
			}
			for _, match := range matches {
				if err := visit(match, depth+1); err != nil {
					return err
				}
			}
		}
		state[path] = 2
		return nil
	}
	for _, path := range entries {
		if err := visit(path, 0); err != nil {
			return nftPersistenceGraph{}, err
		}
	}
	sort.Slice(graph.sources, func(left, right int) bool { return graph.sources[left].path < graph.sources[right].path })
	sort.Slice(graph.expansions, func(left, right int) bool { return graph.expansions[left].pattern < graph.expansions[right].pattern })
	return graph, nil
}

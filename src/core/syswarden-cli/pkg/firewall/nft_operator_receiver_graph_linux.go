//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
)

// A receiving policy must be reached exactly once by the actual shared loader.
// This bounded projection also refuses other sources that could replace it.
// Loader identity, boot enablement, source metadata and kernel observations are
// separate mandatory proofs. Passing this pure check alone authorizes no action.
func verifyNFTOperatorReceiverGraph(model nftOperatorReceiverModel, path string, graph nftPersistenceGraph, read func(string) ([]byte, error)) error {
	if !canonicalNFTPersistencePath(path, false) || !strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/etc/syswarden/") || len(graph.entries) != 1 || read == nil {
		return fmt.Errorf("operator receiver requires one independent shared-loader entry point")
	}
	sources := make(map[string]nftPersistenceSource, len(graph.sources))
	expansions := make(map[string][]string, len(graph.expansions))
	found := false
	for _, source := range graph.sources {
		if _, duplicate := sources[source.path]; duplicate {
			return fmt.Errorf("receiver graph contains duplicate source identities")
		}
		content, err := read(source.path)
		if err != nil || sha256.Sum256(content) != source.sha256 {
			return fmt.Errorf("receiver persistence graph changed during inspection")
		}
		if source.path == path {
			if !bytes.Equal(content, model.source) || len(source.document.tables) != 1 || len(source.document.includes) != 0 {
				return fmt.Errorf("receiver source differs from its independently compiled policy")
			}
			found = true
		} else if err := verifyNFTOperatorReceiverNeighbor(content, source, graph.entries[0], model.table); err != nil {
			return err
		}
		for _, include := range source.document.includes {
			if include.depth != 0 {
				return fmt.Errorf("receiver graph contains a nested include")
			}
		}
		sources[source.path] = source
	}
	if !found {
		return fmt.Errorf("operator receiver is not consumed by the shared loader")
	}
	for _, expanded := range graph.expansions {
		if _, duplicate := expansions[expanded.pattern]; duplicate {
			return fmt.Errorf("receiver graph contains duplicate wildcard evidence")
		}
		expansions[expanded.pattern] = expanded.paths
	}
	visits, occurrences := 0, 0
	stack := map[string]bool{}
	var visit func(string, int) error
	visit = func(current string, depth int) error {
		visits++
		if depth > maximumNFTPersistenceGraphDepth || visits > maximumNFTPersistenceIncludes || stack[current] {
			return fmt.Errorf("receiver reachability is cyclic or exceeds its bound")
		}
		source, ok := sources[current]
		if !ok {
			return fmt.Errorf("receiver graph references an unobserved source")
		}
		if current == path {
			occurrences++
			if occurrences > 1 {
				return fmt.Errorf("shared loader would evaluate the receiver more than once")
			}
		}
		stack[current] = true
		defer delete(stack, current)
		for _, include := range source.document.includes {
			paths := []string{include.path}
			if strings.ContainsAny(include.path, "*?[") {
				var known bool
				paths, known = expansions[include.path]
				if !known {
					return fmt.Errorf("receiver graph wildcard has no complete observation")
				}
			}
			for _, next := range paths {
				if err := visit(next, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(graph.entries[0], 0); err != nil {
		return err
	}
	if occurrences != 1 {
		return fmt.Errorf("receiver is not reached exactly once from the independent loader")
	}
	return nil
}

// Only table declarations, literal top-level includes, exact product population
// commands and a leading entry-point flush are admitted outside the receiver.
// Opaque commands and variables could invalidate reload preservation and refuse.
func verifyNFTOperatorReceiverNeighbor(content []byte, source nftPersistenceSource, entry, receiver string) error {
	tokens, err := scanNFTPersistence(content)
	if err != nil {
		return err
	}
	for _, table := range source.document.tables {
		if table.family == "inet" && table.name == receiver {
			return fmt.Errorf("another persistent source defines the operator receiver")
		}
	}
	for _, token := range tokens {
		if nftPersistenceWord(content, token) == receiver {
			return fmt.Errorf("another persistent source references the operator receiver")
		}
	}
	position, statements := 0, 0
	for position < len(tokens) {
		token := tokens[position]
		if token.kind == '\n' || token.kind == ';' {
			position++
			continue
		}
		skipped := false
		for _, table := range source.document.tables {
			if token.start == table.start {
				for position < len(tokens) && tokens[position].end <= table.end {
					position++
				}
				statements++
				skipped = true
				break
			}
		}
		if skipped {
			continue
		}
		for _, include := range source.document.includes {
			if token.start == include.start && include.depth == 0 {
				for position < len(tokens) && tokens[position].end <= include.end {
					position++
				}
				statements++
				skipped = true
				break
			}
		}
		if skipped {
			continue
		}
		end := position
		for end < len(tokens) && tokens[end].kind != '\n' && tokens[end].kind != ';' {
			end++
		}
		words := make([]string, 0, end-position)
		for _, part := range tokens[position:end] {
			words = append(words, string(content[part.start:part.end]))
		}
		leadingFlush := source.path == entry && statements == 0 && len(words) == 2 && words[0] == "flush" && words[1] == "ruleset"
		population := len(words) >= 7 && words[0] == "add" && words[1] == "element" && (words[2] == "inet" && words[3] == "syswarden" || words[2] == "netdev" && words[3] == "syswarden_hw_drop") && words[5] == "{" && words[len(words)-1] == "}"
		if !leadingFlush && !population {
			return fmt.Errorf("receiver persistence includes an unsupported command that could alter reload behavior")
		}
		position = end
		statements++
	}
	return nil
}

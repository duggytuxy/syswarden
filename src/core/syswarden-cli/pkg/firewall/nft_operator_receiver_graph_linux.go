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
	contents := make(map[string][]byte, len(graph.sources))
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
		}
		sources[source.path] = source
		contents[source.path] = content
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
	contexts := map[string]bool{}
	leadingFlush := false
	var visit func(string, int, bool, bool) error
	visit = func(current string, depth int, fragment, scopedReset bool) error {
		visits++
		if depth > maximumNFTPersistenceGraphDepth || visits > maximumNFTPersistenceIncludes || stack[current] {
			return fmt.Errorf("receiver reachability is cyclic or exceeds its bound")
		}
		source, ok := sources[current]
		if !ok {
			return fmt.Errorf("receiver graph references an unobserved source")
		}
		if previous, known := contexts[current]; known && previous != fragment {
			return fmt.Errorf("receiver graph reuses a source in incompatible include contexts")
		}
		contexts[current] = fragment
		if current == path {
			if fragment || !leadingFlush && !scopedReset {
				return fmt.Errorf("receiver requires a top-level include with an exact preceding reload reset")
			}
			occurrences++
			if occurrences > 1 {
				return fmt.Errorf("shared loader would evaluate the receiver more than once")
			}
			return nil
		}
		projection, err := inspectNFTOperatorReceiverNeighbor(contents[current], source, graph.entries[0], model.table, path, fragment)
		if err != nil {
			return err
		}
		leadingFlush = leadingFlush || projection.leadingFlush
		stack[current] = true
		defer delete(stack, current)
		for _, include := range source.document.includes {
			nested := fragment || include.depth != 0
			if include.depth != 0 && !fragment && !nftOperatorIndependentInclude(include, source.document.tables) {
				return fmt.Errorf("nested receiver graph include is outside an independent table")
			}
			paths := []string{include.path}
			if strings.ContainsAny(include.path, "*?[") {
				var known bool
				paths, known = expansions[include.path]
				if !known {
					return fmt.Errorf("receiver graph wildcard has no complete observation")
				}
			}
			for _, next := range paths {
				if err := visit(next, depth+1, nested, projection.scopedIncludes[include.start]); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(graph.entries[0], 0, false, false); err != nil {
		return err
	}
	if occurrences != 1 {
		return fmt.Errorf("receiver is not reached exactly once from the independent loader")
	}
	return nil
}

type nftOperatorReceiverProjection struct {
	leadingFlush   bool
	scopedIncludes map[int]bool
}

// A balanced fragment stays inside its independently declared administrator
// table. It cannot contain a receiving table or escape into loader commands.
func nftOperatorIndependentInclude(include nftPersistentInclude, tables []nftPersistentTable) bool {
	for _, table := range tables {
		if include.start > table.start && include.end < table.end {
			return !isReservedNFTTableForUninstall(nftTableTarget{family: table.family, name: table.name})
		}
	}
	return false
}

// Recognize only bounded reload forms. A scoped receiver reset must be adjacent
// to its literal include. An administrator destroy must immediately precede the
// same complete table declaration. Neither form grants product ownership.
func inspectNFTOperatorReceiverNeighbor(content []byte, source nftPersistenceSource, entry, receiver, receiverPath string, fragment bool) (nftOperatorReceiverProjection, error) {
	projection := nftOperatorReceiverProjection{scopedIncludes: map[int]bool{}}
	refuse := func() (nftOperatorReceiverProjection, error) {
		return projection, fmt.Errorf("receiver persistence includes an unsupported command or reference that could alter reload behavior")
	}
	tokens, err := scanNFTPersistence(content)
	if err != nil {
		return projection, err
	}
	for _, table := range source.document.tables {
		if fragment || table.family == "inet" && table.name == receiver {
			return projection, fmt.Errorf("another persistent source defines the operator receiver or nests a table")
		}
	}
	if fragment {
		if err := verifyNFTOperatorReceiverFragment(content, tokens, receiver); err != nil {
			return projection, err
		}
		return projection, nil
	}
	allowedReferences := map[int]bool{}
	next := func(position int) int {
		for position < len(tokens) && (tokens[position].kind == '\n' || tokens[position].kind == ';') {
			position++
		}
		return position
	}
	commandEnd := func(position int) int {
		for position < len(tokens) && tokens[position].kind != '\n' && tokens[position].kind != ';' {
			position++
		}
		return position
	}
	match := func(start, end int, words ...string) bool {
		if end-start != len(words) {
			return false
		}
		for offset, word := range words {
			if nftPersistenceWord(content, tokens[start+offset]) != word {
				return false
			}
		}
		return true
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
		end := commandEnd(position)
		following := next(end)
		if match(position, end, "add", "table", "inet", receiver) {
			flushEnd := commandEnd(following)
			includeStart := next(flushEnd)
			if !match(following, flushEnd, "flush", "table", "inet", receiver) || includeStart >= len(tokens) {
				return refuse()
			}
			for _, include := range source.document.includes {
				if include.start == tokens[includeStart].start && include.depth == 0 && include.path == receiverPath {
					projection.scopedIncludes[include.start] = true
				}
			}
			if !projection.scopedIncludes[tokens[includeStart].start] {
				return refuse()
			}
			allowedReferences[tokens[position+3].start] = true
			allowedReferences[tokens[following+3].start] = true
			position = includeStart
			statements += 2
			continue
		}
		if end-position == 4 && nftPersistenceWord(content, token) == "destroy" && following < len(tokens) {
			for _, table := range source.document.tables {
				if table.start == tokens[following].start && !isReservedNFTTableForUninstall(nftTableTarget{family: table.family, name: table.name}) &&
					match(position, end, "destroy", "table", table.family, table.name) {
					position = following
					statements++
					skipped = true
					break
				}
			}
			if skipped {
				continue
			}
		}
		words := make([]string, 0, end-position)
		for _, part := range tokens[position:end] {
			words = append(words, string(content[part.start:part.end]))
		}
		leadingFlush := source.path == entry && statements == 0 && len(words) == 2 && words[0] == "flush" && words[1] == "ruleset"
		population := len(words) >= 7 && words[0] == "add" && words[1] == "element" && (words[2] == "inet" && words[3] == "syswarden" || words[2] == "netdev" && words[3] == "syswarden_hw_drop") && words[5] == "{" && words[len(words)-1] == "}"
		if !leadingFlush && !population {
			return refuse()
		}
		projection.leadingFlush = projection.leadingFlush || leadingFlush
		position = end
		statements++
	}
	for _, token := range tokens {
		word := nftPersistenceWord(content, token)
		if strings.Contains(word, "$") || receiver != "" && word == receiver && !allowedReferences[token.start] {
			return refuse()
		}
	}
	return projection, nil
}

func verifyNFTOperatorReceiverFragment(content []byte, tokens []nftPersistenceToken, receiver string) error {
	statementStart := true
	for _, token := range tokens {
		word := nftPersistenceWord(content, token)
		if strings.Contains(word, "$") || receiver != "" && word == receiver {
			return fmt.Errorf("administrator include fragment contains an unsupported variable or receiver reference")
		}
		switch token.kind {
		case '\n', ';', '{', '}':
			statementStart = true
			continue
		}
		if statementStart {
			switch word {
			case "add", "create", "delete", "destroy", "flush", "reset", "rename", "replace", "insert", "list", "export", "import", "monitor", "describe", "define", "undefine", "redefine", "table":
				return fmt.Errorf("administrator include fragment contains a loader command")
			}
		}
		statementStart = false
	}
	return nil
}

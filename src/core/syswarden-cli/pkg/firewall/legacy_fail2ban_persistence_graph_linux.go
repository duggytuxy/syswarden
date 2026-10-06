//go:build linux

package firewall

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func verifyLegacyFail2banIndependentIncludes(document nftPersistenceDocument, targets map[nftTableTarget]bool) error {
	for _, include := range document.includes {
		if include.depth == 0 {
			continue
		}
		if !nftOperatorIndependentInclude(include, document.tables) {
			return fmt.Errorf("persistent fragment is outside an independent administrator table")
		}
		for _, table := range document.tables {
			if include.start > table.start && include.end < table.end && targets[nftTableTarget{family: table.family, name: table.name}] {
				return fmt.Errorf("persistent Fail2ban target has an unproven included dependency")
			}
		}
	}
	return nil
}

// Discover at most one scoped inet reset in a source. This is only a candidate
// for the strict adjacent-command parser, never authority inferred from a name.
// Graph verification separately proves the literal include's complete table.
func inspectLegacyFail2banLoaderSource(content []byte, source nftPersistenceSource, entry string, targets map[nftTableTarget]bool) (string, string, error) {
	tokens, err := scanNFTPersistence(content)
	if err != nil {
		return "", "", err
	}
	table, path := "", ""
	for index := 0; index+3 < len(tokens); index++ {
		if nftPersistenceWord(content, tokens[index]) != "add" || nftPersistenceWord(content, tokens[index+1]) != "table" || nftPersistenceWord(content, tokens[index+2]) != "inet" {
			continue
		}
		if table != "" {
			return "", "", fmt.Errorf("shared source has multiple scoped reset candidates")
		}
		table = nftPersistenceWord(content, tokens[index+3])
		if table == "" || targets[nftTableTarget{family: "inet", name: table}] || isReservedNFTTableForUninstall(nftTableTarget{family: "inet", name: table}) {
			return "", "", fmt.Errorf("shared reset is not an independent literal table")
		}
		for _, include := range source.document.includes {
			if include.depth == 0 && include.start > tokens[index+3].end {
				path = include.path
				break
			}
		}
	}
	_, err = inspectNFTOperatorReceiverNeighbor(content, source, entry, table, path, false)
	return table, path, err
}

// Every original and active source is checked in its actual include context.
// Unchanged rule fragments may only execute inside an independent table. A
// scoped reset may only precede a single complete matching table source. The
// graph proves scope; independently attested native claims still prove edits.
func verifyLegacyFail2banPersistenceGraph(graph nftPersistenceGraph, record legacyFail2banNFTJournalRecord, read func(string) ([]byte, error)) error {
	_, _, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil || read == nil {
		return fmt.Errorf("persistent graph requires exact native Fail2ban claims")
	}
	targets := map[nftTableTarget]bool{}
	for _, plan := range plans {
		targets[nftTableTarget{family: plan.family, name: plan.table}] = true
	}
	sources := map[string]nftPersistenceSource{}
	contents := map[string][]byte{}
	expansions := map[string][]string{}
	for _, source := range graph.sources {
		content, err := read(source.path)
		if err != nil || sha256.Sum256(content) != source.sha256 {
			return fmt.Errorf("persistent graph source changed during context verification")
		}
		sources[source.path], contents[source.path] = source, content
	}
	for _, expansion := range graph.expansions {
		expansions[expansion.pattern] = expansion.paths
	}
	stack, contexts := map[string]bool{}, map[string]bool{}
	visits := 0
	var visit func(string, string, int, bool) error
	visit = func(path, entry string, depth int, fragment bool) error {
		visits++
		if stack[path] || depth > maximumNFTPersistenceGraphDepth || visits > maximumNFTPersistenceIncludes {
			return fmt.Errorf("persistent include context is cyclic or exceeds its bound")
		}
		source, found := sources[path]
		if !found {
			return fmt.Errorf("persistent include context has an unobserved dependency")
		}
		if previous, known := contexts[path]; known && previous != fragment {
			return fmt.Errorf("persistent source is reused in incompatible include contexts")
		}
		contexts[path], stack[path] = fragment, true
		defer delete(stack, path)
		if fragment {
			tokens, err := scanNFTPersistence(contents[path])
			if err != nil || len(source.document.tables) != 0 {
				return fmt.Errorf("administrator fragment contains a nested table or invalid tokens")
			}
			if err := verifyNFTOperatorReceiverFragment(contents[path], tokens, ""); err != nil {
				return err
			}
		} else {
			if err := verifyLegacyFail2banIndependentIncludes(source.document, targets); err != nil {
				return err
			}
			table, include, err := inspectLegacyFail2banLoaderSource(contents[path], source, entry, targets)
			if err != nil {
				return err
			}
			if table != "" {
				receiver, found := sources[include]
				if !found || len(receiver.document.tables) != 1 || len(receiver.document.includes) != 0 || receiver.document.tables[0].family != "inet" || receiver.document.tables[0].name != table {
					return fmt.Errorf("scoped reset include is not its complete independent table")
				}
			}
		}
		for _, include := range source.document.includes {
			paths := []string{include.path}
			if strings.ContainsAny(include.path, "*?[") {
				var known bool
				paths, known = expansions[include.path]
				if !known {
					return fmt.Errorf("persistent wildcard has no complete context observation")
				}
			}
			for _, next := range paths {
				if err := visit(next, entry, depth+1, fragment || include.depth != 0); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, entry := range graph.entries {
		if err := visit(entry, entry, 0, false); err != nil {
			return err
		}
	}
	return nil
}

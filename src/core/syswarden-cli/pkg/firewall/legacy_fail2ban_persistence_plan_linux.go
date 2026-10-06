//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// This planner accepts only literal declarations within complete table blocks.
// Claims come from the independently attested configuration, actions, live jail
// and exact native kernel transition. A matching name never supplies authority.
// The result is a byte-range proposal, not permission to edit a shared file.
func planLegacyFail2banPersistence(content []byte, record legacyFail2banNFTJournalRecord) (nftPersistenceEdit, error) {
	var empty nftPersistenceEdit
	_, _, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil {
		return empty, err
	}
	document, err := inspectNFTPersistence(content)
	if err != nil {
		return empty, err
	}
	tokens, err := scanNFTPersistence(content)
	if err != nil {
		return empty, err
	}
	targets := make(map[nftTableTarget]bool)
	for _, plan := range plans {
		targets[nftTableTarget{family: plan.family, name: plan.table}] = true
	}
	if err := verifyLegacyFail2banLiteralPersistence(content, tokens, document, targets); err != nil {
		return empty, err
	}
	edit := nftPersistenceEdit{originalSHA256: sha256.Sum256(content), content: bytes.Clone(content)}
	dependencies := make(map[string]bool)
	for _, plan := range plans {
		if legacyFail2banRetiresWholeTable(plan) {
			dependencies[plan.table] = true
		}
		claims, err := decodeLegacyFail2banNFTClaims(plan.claims)
		if err != nil {
			return empty, err
		}
		var tables []nftPersistentTable
		for _, table := range document.tables {
			if table.family == plan.family && table.name == plan.table {
				tables = append(tables, table)
			}
		}
		if len(tables) > 1 {
			return empty, fmt.Errorf("persistent Fail2ban table has multiple declarations")
		}
		start := len(edit.removed)
		for _, claim := range claims {
			chain, set, addressType := claim.jail, "f2b-"+claim.jail, "ipv4_addr"
			upstream := claim.profile == "nftables-allports"
			if upstream {
				chain, set = "f2b-chain", "addr-set-"+claim.jail
			}
			if claim.addressFamily == "ip6" {
				set, addressType = "addr6-set-"+claim.jail, "ipv6_addr"
			}
			dependencies[set] = true
			if !upstream {
				dependencies[chain] = true
			}
			if len(tables) == 0 {
				continue
			}
			ranges, err := planLegacyFail2banPersistentClaim(content, tokens, tables[0], claim, chain, set, addressType, upstream)
			if err != nil {
				return empty, err
			}
			edit.removed = append(edit.removed, ranges...)
		}
		if legacyFail2banRetiresWholeTable(plan) && len(tables) == 1 {
			span, err := planLegacyFail2banWholePersistentTable(content, tokens, tables[0], edit.removed[start:])
			if err != nil {
				return empty, err
			}
			edit.removed = append(edit.removed[:start], span)
		}
	}
	sort.Slice(edit.removed, func(i, j int) bool { return edit.removed[i].start < edit.removed[j].start })
	previous := 0
	edit.content = nil
	for _, span := range edit.removed {
		if span.start < previous || span.end <= span.start || span.end > len(content) {
			return empty, fmt.Errorf("persistent Fail2ban claims overlap or exceed the source")
		}
		if bytes.ContainsRune(content[span.start:span.end], '#') {
			return empty, fmt.Errorf("selected persistent block contains annotations requiring separate review")
		}
		edit.content = append(edit.content, content[previous:span.start]...)
		previous = span.end
	}
	edit.content = append(edit.content, content[previous:]...)
	remaining, err := scanNFTPersistence(edit.content)
	if err != nil {
		return empty, err
	}
	for _, token := range remaining {
		value := string(edit.content[token.start:token.end])
		for name := range dependencies {
			if strings.Contains(value, name) {
				return empty, fmt.Errorf("retained persistence still references a historical Fail2ban target")
			}
		}
	}
	return edit, nil
}

// Reject indirection and context-dependent fragments before reasoning about
// a table's scope. The complete include graph is separately bound by callers.
func verifyLegacyFail2banLiteralPersistence(content []byte, tokens []nftPersistenceToken, document nftPersistenceDocument, targets map[nftTableTarget]bool) error {
	// The graph scanner intentionally skips continued newlines. A literal
	// ownership check must not overlook a name assembled across that gap.
	if bytes.Contains(content, []byte{'\\', '\n'}) {
		return fmt.Errorf("continued persistent expressions require separate verified recovery")
	}
	for _, token := range tokens {
		value := string(content[token.start:token.end])
		if strings.ContainsAny(value, "$\\") || token.kind == 'w' && (value == "define" || value == "redefine" || value == "undefine") {
			return fmt.Errorf("indirect persistent expressions require separate verified recovery")
		}
	}
	if err := verifyLegacyFail2banIndependentIncludes(document, targets); err != nil {
		return err
	}
	// Pure byte planning does not know an include's evaluation context. A
	// fragment is allowed here only without table declarations or loader
	// commands. The complete original and active graphs must independently
	// prove its administrator-table context before every file mutation.
	_, _, err := inspectLegacyFail2banLoaderSource(content, nftPersistenceSource{path: "/entry", document: document}, "/entry", targets)
	if err != nil && len(document.tables) == 0 {
		return verifyNFTOperatorReceiverFragment(content, tokens, "")
	}
	return err
}

func legacyFail2banPersistenceWords(content []byte, tokens []nftPersistenceToken) []string {
	var words []string
	for _, token := range tokens {
		if token.kind != '\n' && token.kind != ';' {
			words = append(words, string(content[token.start:token.end]))
		}
	}
	return words
}

func legacyFail2banPersistenceBlockEnd(tokens []nftPersistenceToken, opening int) (int, error) {
	depth := 0
	for index := opening; index < len(tokens); index++ {
		if tokens[index].kind == '{' {
			depth++
		} else if tokens[index].kind == '}' {
			depth--
			if depth == 0 {
				return index, nil
			}
		}
	}
	return 0, fmt.Errorf("persistent declaration has no exact closing boundary")
}

func planLegacyFail2banPersistentClaim(content []byte, all []nftPersistenceToken, table nftPersistentTable, claim legacyFail2banNFTClaim, chain, set, addressType string, upstream bool) ([]nftPersistenceRange, error) {
	var tokens []nftPersistenceToken
	for _, token := range all {
		if token.start >= table.start && token.end <= table.end {
			tokens = append(tokens, token)
		}
	}
	var result []nftPersistenceRange
	setCount, ruleCount := 0, 0
	for index := 4; index < len(tokens)-1; index++ {
		if tokens[index].kind == '\n' || tokens[index].kind == ';' {
			continue
		}
		if index+2 >= len(tokens) || tokens[index+2].kind != '{' {
			return nil, fmt.Errorf("persistent Fail2ban table has unsupported top-level statements")
		}
		kind, name := nftPersistenceWord(content, tokens[index]), nftPersistenceWord(content, tokens[index+1])
		end, err := legacyFail2banPersistenceBlockEnd(tokens, index+2)
		if err != nil {
			return nil, err
		}
		if kind == "set" && name == set {
			words := legacyFail2banPersistenceWords(content, tokens[index+3:end])
			if len(words) < 2 || words[0] != "type" || words[1] != addressType {
				return nil, fmt.Errorf("persistent Fail2ban set differs from its verified native claim")
			}
			var members []string
			if len(words) > 2 {
				if len(words) < 6 || !slices.Equal(words[2:5], []string{"elements", "=", "{"}) || words[len(words)-1] != "}" {
					return nil, fmt.Errorf("persistent Fail2ban set has unsupported attributes")
				}
				members = strings.Split(strings.Join(words[5:len(words)-1], " "), ",")
				for index := range members {
					members[index] = strings.TrimSpace(members[index])
				}
				sort.Strings(members)
			}
			if !slices.Equal(members, claim.bans) {
				return nil, fmt.Errorf("persistent Fail2ban addresses differ from independently attested live bans")
			}
			setCount++
			result = append(result, nftPersistenceRange{tokens[index].start, tokens[end].end})
		}
		if kind == "chain" && name == chain {
			if !upstream {
				// The historical action owns a dedicated base chain. Remove
				// it only when its entire declaration matches that profile;
				// a custom rule or annotation must remain for separate review.
				words := legacyFail2banPersistenceWords(content, tokens[index+3:end])
				match := false
				for _, priority := range [][]string{{"filter", "-", "1"}, {"-1"}, {"filter", "-1"}} {
					expected := append([]string{"type", "filter", "hook", "input", "priority"}, priority...)
					expected = append(expected, "policy", "accept", claim.addressFamily, "saddr", "@"+set, "drop")
					match = match || slices.Equal(words, expected)
				}
				if !match {
					return nil, fmt.Errorf("persistent historical chain differs from its complete action profile")
				}
				ruleCount++
				result = append(result, nftPersistenceRange{tokens[index].start, tokens[end].end})
				index = end
				continue
			}
			reject := "icmp"
			if claim.addressFamily == "ip6" {
				reject = "icmpv6"
			}
			expected := []string{"meta", "l4proto", "tcp", claim.addressFamily, "saddr", "@" + set, "reject", "with", reject, "port-unreachable"}
			start, depth := index+3, 0
			for cursor := start; cursor <= end; cursor++ {
				token := tokens[cursor]
				if depth == 0 && (cursor == end || token.kind == '\n' || token.kind == ';') {
					if slices.Equal(legacyFail2banPersistenceWords(content, tokens[start:cursor]), expected) {
						ruleCount++
						result = append(result, nftPersistenceRange{tokens[start].start, tokens[cursor-1].end})
					}
					start = cursor + 1
				}
				if token.kind == '{' {
					depth++
				} else if token.kind == '}' {
					depth--
				}
			}
		}
		index = end
	}
	if setCount == 0 && ruleCount == 0 {
		return nil, nil
	}
	if setCount != 1 || ruleCount != 1 {
		return nil, fmt.Errorf("persistent Fail2ban targets are partial, duplicated or modified")
	}
	return result, nil
}

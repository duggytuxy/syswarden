//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	maximumNFTPersistenceBytes  = 16 << 20
	maximumNFTPersistenceDepth  = 128
	maximumNFTPersistenceTokens = 1 << 20
	legacyNFTIncludePath        = "/etc/syswarden/syswarden.nft"
	legacyNFTIncludeLine        = "include \"/etc/syswarden/syswarden.nft\""
	legacyNFTIncludeMarker      = "# Added by SysWarden"
)

// These types describe source locations, not ownership. In particular, a
// reserved-looking table name does not authorize deleting the table body.
type nftPersistenceRange struct {
	start int
	end   int
}

type nftPersistenceToken struct {
	nftPersistenceRange
	kind byte
}

type nftPersistentInclude struct {
	nftPersistenceRange
	path  string
	depth int
}

type nftPersistentTable struct {
	nftPersistenceRange
	family string
	name   string
}

type nftPersistenceDocument struct {
	includes []nftPersistentInclude
	tables   []nftPersistentTable
}

// scanNFTPersistence does not evaluate nftables input, expand variables or
// open include paths. It only locates tokens while respecting comments,
// quoted strings and continued lines. Host mutation requires an independent
// file, include-graph and ownership attestation.
func scanNFTPersistence(content []byte) ([]nftPersistenceToken, error) {
	if len(content) > maximumNFTPersistenceBytes || !utf8.Valid(content) {
		return nil, fmt.Errorf("nftables persistence input exceeds the byte limit or is not valid UTF-8")
	}
	for _, value := range content {
		if value < 0x20 && value != '\n' && value != '\r' && value != '\t' || value == 0x7f {
			return nil, fmt.Errorf("nftables persistence input contains an unsupported control byte")
		}
	}
	tokens := make([]nftPersistenceToken, 0)
	for offset := 0; offset < len(content); {
		if len(tokens) == maximumNFTPersistenceTokens {
			return nil, fmt.Errorf("nftables persistence input exceeds the token limit")
		}
		start := offset
		switch content[offset] {
		case ' ', '\t', '\r':
			offset++
			continue
		case '#':
			for offset < len(content) && content[offset] != '\n' {
				offset++
			}
			continue
		case '\\':
			if offset+1 < len(content) && content[offset+1] == '\n' {
				offset += 2
				continue
			}
			return nil, fmt.Errorf("unsupported unquoted escape in nftables persistence input")
		case '\n', ';', '{', '}':
			offset++
			tokens = append(tokens, nftPersistenceToken{nftPersistenceRange{start, offset}, content[start]})
		case '"':
			offset++
			closed := false
			for offset < len(content) {
				value := content[offset]
				offset++
				if value == '\\' {
					if offset == len(content) {
						break
					}
					offset++
				} else if value == '"' {
					closed = true
					break
				}
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted string in nftables persistence input")
			}
			tokens = append(tokens, nftPersistenceToken{nftPersistenceRange{start, offset}, 'q'})
		default:
			for offset < len(content) && !strings.ContainsRune(" \t\r\n#;{}\"\\", rune(content[offset])) {
				offset++
			}
			tokens = append(tokens, nftPersistenceToken{nftPersistenceRange{start, offset}, 'w'})
		}
	}
	return tokens, nil
}

func nftPersistenceWord(content []byte, token nftPersistenceToken) string {
	if token.kind != 'w' {
		return ""
	}
	return string(content[token.start:token.end])
}

func inspectNFTPersistence(content []byte) (nftPersistenceDocument, error) {
	tokens, err := scanNFTPersistence(content)
	if err != nil {
		return nftPersistenceDocument{}, err
	}
	var document nftPersistenceDocument
	depth, statementStart := 0, true
	openTable := -1
	for index, token := range tokens {
		switch token.kind {
		case '\n', ';':
			statementStart = true
			continue
		case '{':
			depth++
			if depth > maximumNFTPersistenceDepth {
				return nftPersistenceDocument{}, fmt.Errorf("nftables persistence input exceeds the nesting limit")
			}
			statementStart = true
			continue
		case '}':
			if depth == 0 {
				return nftPersistenceDocument{}, fmt.Errorf("unmatched closing brace in nftables persistence input")
			}
			depth--
			if depth == 0 && openTable >= 0 {
				document.tables[openTable].end = token.end
				openTable = -1
			}
			statementStart = true
			continue
		}
		if !statementStart {
			continue
		}
		statementStart = false
		switch nftPersistenceWord(content, token) {
		case "include":
			if index+1 >= len(tokens) || tokens[index+1].kind != 'q' {
				return nftPersistenceDocument{}, fmt.Errorf("nftables persistence include does not have a literal quoted path")
			}
			pathToken := tokens[index+1]
			path := string(content[pathToken.start+1 : pathToken.end-1])
			if path == "" || strings.ContainsAny(path, "\\\n\r\t$") {
				return nftPersistenceDocument{}, fmt.Errorf("nftables persistence include uses an unsupported path expression")
			}
			if index+2 < len(tokens) && tokens[index+2].kind != '\n' && tokens[index+2].kind != ';' && tokens[index+2].kind != '}' {
				return nftPersistenceDocument{}, fmt.Errorf("nftables persistence include has trailing tokens")
			}
			document.includes = append(document.includes, nftPersistentInclude{
				nftPersistenceRange: nftPersistenceRange{token.start, pathToken.end}, path: path, depth: depth,
			})
		case "table":
			if depth != 0 || index+3 >= len(tokens) || tokens[index+3].kind != '{' {
				continue
			}
			family := nftPersistenceWord(content, tokens[index+1])
			name := nftPersistenceWord(content, tokens[index+2])
			if family == "" || name == "" {
				continue
			}
			document.tables = append(document.tables, nftPersistentTable{
				nftPersistenceRange: nftPersistenceRange{start: token.start}, family: family, name: name,
			})
			openTable = len(document.tables) - 1
		}
	}
	if depth != 0 {
		return nftPersistenceDocument{}, fmt.Errorf("unclosed brace in nftables persistence input")
	}
	return document, nil
}

type nftPersistenceEdit struct {
	originalSHA256 [sha256.Size]byte
	content        []byte
	removed        []nftPersistenceRange
}

// planLegacyNFTIncludeRetirement proposes only edits matching the two exact
// pre-v2 generator forms. It never deletes table blocks or included files.
// This pure planner is not an authorization to write: callers must attest
// ownership, all include dependencies and stable file metadata separately.
func planLegacyNFTIncludeRetirement(content []byte) (nftPersistenceEdit, error) {
	document, err := inspectNFTPersistence(content)
	if err != nil {
		return nftPersistenceEdit{}, err
	}
	plan := nftPersistenceEdit{originalSHA256: sha256.Sum256(content), content: bytes.Clone(content)}
	defaultFile := "#!/usr/sbin/nft -f\nflush ruleset\n" + legacyNFTIncludeLine + "\n"
	if string(content) == defaultFile {
		// The old installer created this entire file. Leaving its global flush
		// behind would erase unrelated runtime rules on a subsequent reload.
		plan.removed = []nftPersistenceRange{{len("#!/usr/sbin/nft -f\n"), len(content)}}
		plan.content = []byte("#!/usr/sbin/nft -f\n")
		return plan, nil
	}
	for _, include := range document.includes {
		if include.path != legacyNFTIncludePath {
			continue
		}
		lineStart := bytes.LastIndexByte(content[:include.start], '\n') + 1
		lineEnd := include.end
		if lineEnd < len(content) && content[lineEnd] == '\n' {
			lineEnd++
		}
		if include.depth != 0 || lineStart != include.start ||
			string(content[include.start:include.end]) != legacyNFTIncludeLine ||
			include.end < len(content) && content[include.end] != '\n' {
			return nftPersistenceEdit{}, fmt.Errorf("historical nftables include does not match an exact generated line; preserve it for reviewed recovery")
		}
		marker := []byte(legacyNFTIncludeMarker + "\n")
		if lineStart < len(marker) || !bytes.Equal(content[lineStart-len(marker):lineStart], marker) {
			return nftPersistenceEdit{}, fmt.Errorf("historical nftables include lacks its exact generator marker; preserve it for reviewed recovery")
		}
		start := lineStart - len(marker)
		if start > 0 && content[start-1] != '\n' {
			return nftPersistenceEdit{}, fmt.Errorf("historical nftables include marker is not on a separate line")
		}
		plan.removed = append(plan.removed, nftPersistenceRange{start, lineEnd})
	}
	if len(plan.removed) == 0 {
		return plan, nil
	}
	plan.content = make([]byte, 0, len(content))
	previous := 0
	for _, span := range plan.removed {
		if span.start < previous || span.end < span.start || span.end > len(content) {
			return nftPersistenceEdit{}, fmt.Errorf("overlapping or invalid nftables persistence edit")
		}
		plan.content = append(plan.content, content[previous:span.start]...)
		previous = span.end
	}
	plan.content = append(plan.content, content[previous:]...)
	return plan, nil
}

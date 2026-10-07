//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"slices"
)

// Every selected inner declaration was independently matched to the historical
// action. A complete table range is allowed only when no other statement or
// annotation survives. Adjacent administrator bytes remain outside the range.
func planLegacyFail2banWholePersistentTable(content []byte, tokens []nftPersistenceToken, table nftPersistentTable, removed []nftPersistenceRange) (nftPersistenceRange, error) {
	if table.family != "inet" || table.name != "syswarden_f2b" || bytes.ContainsRune(content[table.start:table.end], '#') {
		return nftPersistenceRange{}, fmt.Errorf("historical table declaration requires separate ownership review")
	}
	var retained []nftPersistenceToken
	for _, token := range tokens {
		if token.start < table.start || token.end > table.end {
			continue
		}
		selected := false
		for _, span := range removed {
			selected = selected || token.start >= span.start && token.end <= span.end
		}
		if !selected {
			retained = append(retained, token)
		}
	}
	if !slices.Equal(legacyFail2banPersistenceWords(content, retained), []string{"table", "inet", "syswarden_f2b", "{", "}"}) {
		return nftPersistenceRange{}, fmt.Errorf("persistent historical table contains administrator state outside complete retirement authority")
	}
	return nftPersistenceRange{table.start, table.end}, nil
}

//go:build linux

package firewall

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
)

type nftHistoricalIngressInputs struct {
	Interface   string              `json:"interface"`
	Geo         bool                `json:"geo"`
	ASN         bool                `json:"asn"`
	Populations map[string][]string `json:"populations"`
}

type nftHistoricalFileEvidence struct {
	sourceSHA256 string
	inet         nftInetSourceEvidence
	ingress      *nftIngressPersistentSourceEvidence
}

// The historical installer wrote the complete inet dump, then appended the
// ingress dump if available. There are no other statements in this file form.
// This establishes complete representation coverage with independently supplied
// inputs, even if the old tables are absent or have since been replaced. It
// neither asserts current runtime ownership nor authorizes a filesystem edit.
// Source identity, input provenance, dependencies and producers remain required.
func inspectNFTHistoricalPersistentFile(source []byte, inet nftShellInputs, ingress *nftHistoricalIngressInputs) (nftHistoricalFileEvidence, error) {
	var empty nftHistoricalFileEvidence
	document, err := inspectNFTPersistence(source)
	if err != nil {
		return empty, err
	}
	count := 1
	if ingress != nil {
		count = 2
	}
	if len(document.includes) != 0 || len(document.tables) != count {
		return empty, fmt.Errorf("historical persistent file contains unbound includes or tables")
	}
	position := 0
	for index, table := range document.tables {
		family, name := "inet", "syswarden_table"
		if index == 1 {
			family, name = "netdev", "syswarden_hw_drop"
		}
		if table.family != family || table.name != name || table.start != position || table.end <= table.start || table.end >= len(source) || source[table.end] != '\n' {
			return empty, fmt.Errorf("historical persistent file has changed block order, boundaries or separators")
		}
		position = table.end + 1
	}
	if position != len(source) {
		return empty, fmt.Errorf("historical persistent file has additional trailing content")
	}
	first := document.tables[0]
	inetEvidence, err := inspectNFTShellPersistentSource(source[first.start:first.end], inet)
	if err != nil {
		return empty, err
	}
	evidence := nftHistoricalFileEvidence{sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), inet: inetEvidence}
	if ingress == nil {
		return evidence, nil
	}
	second := document.tables[1]
	ingressEvidence, err := inspectNFTHistoricalIngressPersistentSource(source[second.start:second.end], ingress.Interface, ingress.Geo, ingress.ASN, ingress.Populations)
	if err != nil {
		return empty, err
	}
	// Both official table generators consumed the same whitelist. Accepting two
	// individually valid but inconsistent fragments would invent a lineage that
	// the official installer could not have produced from these supplied inputs.
	for _, family := range []struct{ kind, name string }{{"addr4", "syswarden_whitelist"}, {"addr6", "syswarden_whitelist6"}} {
		var entries []string
		for _, entry := range inet.Whitelist {
			if strings.Contains(entry, ":") == (family.kind == "addr6") {
				entries = append(entries, entry)
			}
		}
		values, err := nftRetirementPopulationValues(entries, family.kind)
		if err != nil {
			return empty, err
		}
		if !reflect.DeepEqual(values, ingressEvidence.populations[family.name]) {
			return empty, fmt.Errorf("historical persistent tables do not share the independently supplied whitelist")
		}
	}
	evidence.ingress = &ingressEvidence
	return evidence, nil
}

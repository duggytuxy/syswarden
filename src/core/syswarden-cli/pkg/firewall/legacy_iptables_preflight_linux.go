//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
)

// This is a refusal signal, never ownership evidence. nft JSON hides the
// content of an xtables comment match, so its read-only text representation
// must be inspected separately, including partial historical generations. Generic LAN ACCEPT
// rules alone cannot distinguish an administrator rule from an old writer.
func preflightLegacyIPTablesRules(document nftJSONDocument) error {
	for _, entry := range document.NFTables {
		rule := entry.Rule
		if rule == nil || rule.Family != "ip" || rule.Table != "filter" || rule.Chain != "INPUT" {
			continue
		}
		if rule.Comment == "SYSWARDEN_CORE" {
			return legacyIPTablesRemovalRefusal()
		}
		opaqueComment := false
		for _, expression := range rule.Expressions {
			var fields map[string]json.RawMessage
			if json.Unmarshal(expression, &fields) != nil {
				return fmt.Errorf("cannot inspect historical iptables compatibility expression")
			}
			if raw, ok := fields["xt"]; ok {
				var match struct{ Type, Name string }
				if json.Unmarshal(raw, &match) == nil && match.Type == "match" && match.Name == "comment" {
					opaqueComment = true
				}
			}
		}
		if opaqueComment {
			return legacyIPTablesRemovalRefusal()
		}
	}
	return nil
}

func legacyIPTablesRemovalRefusal() error {
	return fmt.Errorf("historical iptables compatibility rules may remain in shared ip filter INPUT; preserve the rules, original generation evidence and product payload; inspect bounded recovery with recover-removal --retire-legacy-iptables --historical-inputs; a comment or matching rule shape does not establish ownership")
}

func preflightLegacyIPTablesUsing(ctx context.Context, runner nftCommandRunner) error {
	output, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("inspect shared compatibility rules before removal: %w", err)
	}
	document, err := decodeNFTJSON(output)
	if err != nil {
		return err
	}
	return preflightLegacyIPTablesDocument(ctx, document)
}

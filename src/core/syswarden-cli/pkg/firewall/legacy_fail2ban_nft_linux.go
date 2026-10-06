//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// A claim describes an independently attested action, not a discovery by name.
// The caller must bind it to exact source templates, configured/live actions,
// the durable retirement plan, stopped targets and persistent dependencies.
// The kernel planner below proves shape and shared-table dependencies only.
type legacyFail2banNFTClaim struct {
	jail, profile, addressFamily string
	filePlan, actionsSHA256      string
	bans                         []string
}

type legacyFail2banNFTTransition struct {
	family, table string
	before, after []byte
	claims        []byte
	transaction   []byte
	sha256        string
}

func (plan legacyFail2banNFTTransition) digest() string {
	binding, err := json.Marshal([]string{plan.family, plan.table, string(plan.claims), string(plan.before), string(plan.after), string(plan.transaction)})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(binding))
}

// Reject duplicate keys instead of allowing JSON's usual last-value wins
// interpretation. Bounds cover nesting and total tokens before any traversal.
func decodeLegacyFail2banNFTJSON(content []byte) (map[string]any, error) {
	if len(content) == 0 || len(content) > 8<<20 {
		return nil, fmt.Errorf("Fail2ban nftables observation exceeds its byte limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	tokens := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		tokens++
		if depth > 48 || tokens > 262144 {
			return nil, fmt.Errorf("Fail2ban nftables observation exceeds its structural limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch token {
		case json.Delim('{'):
			value := make(map[string]any)
			for decoder.More() {
				key, err := decoder.Token()
				name, valid := key.(string)
				if err != nil || !valid {
					return nil, fmt.Errorf("invalid nftables object key")
				}
				if _, exists := value[name]; exists {
					return nil, fmt.Errorf("duplicate nftables object key")
				}
				value[name], err = read(depth + 1)
				if err != nil {
					return nil, err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("incomplete nftables object")
			}
			return value, nil
		case json.Delim('['):
			value := []any{}
			for decoder.More() {
				entry, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				value = append(value, entry)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("incomplete nftables array")
			}
			return value, nil
		}
		if _, delimiter := token.(json.Delim); delimiter {
			return nil, fmt.Errorf("unexpected nftables delimiter")
		}
		return token, nil
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("nftables observation contains trailing data")
	}
	object, valid := value.(map[string]any)
	if !valid || len(object) != 1 {
		return nil, fmt.Errorf("nftables observation is not an exact document")
	}
	return object, nil
}

func legacyFail2banNFTHandle(object map[string]any) bool {
	value, valid := object["handle"].(json.Number)
	if !valid {
		return false
	}
	handle, err := strconv.ParseUint(string(value), 10, 64)
	return err == nil && handle > 0 && strconv.FormatUint(handle, 10) == string(value)
}

func legacyFail2banNFTFields(object map[string]any, required, optional string) bool {
	allowed := make(map[string]bool)
	for _, name := range strings.Fields(required) {
		if _, found := object[name]; !found {
			return false
		}
		allowed[name] = true
	}
	for _, name := range strings.Fields(optional) {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return false
		}
	}
	return true
}

func legacyFail2banNFTContains(value any, names map[string]bool) bool {
	switch item := value.(type) {
	case string:
		for name := range names {
			// Conservatively retain indirect or textual references as well.
			if strings.Contains(item, name) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if legacyFail2banNFTContains(child, names) {
				return true
			}
		}
	case map[string]any:
		for key, child := range item {
			if legacyFail2banNFTContains(key, names) || legacyFail2banNFTContains(child, names) {
				return true
			}
		}
	}
	return false
}

func legacyFail2banNFTEntries(content []byte, family, table string) ([]any, error) {
	document, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		return nil, err
	}
	entries, valid := document["nftables"].([]any)
	if !valid || len(entries) > 16384 {
		return nil, fmt.Errorf("invalid bounded nftables entries")
	}
	result := []any{}
	tables, metadata := 0, 0
	identities := make(map[string]bool)
	for _, entry := range entries {
		object, valid := entry.(map[string]any)
		if !valid || len(object) != 1 {
			return nil, fmt.Errorf("ambiguous nftables entry")
		}
		for kind, data := range object {
			value, valid := data.(map[string]any)
			if !valid {
				return nil, fmt.Errorf("nftables entry has no object body")
			}
			if kind == "metainfo" {
				metadata++
				if metadata > 1 || value["json_schema_version"] != json.Number("1") {
					return nil, fmt.Errorf("unsupported nftables JSON schema")
				}
				continue
			}
			if value["family"] != family || !legacyFail2banNFTHandle(value) {
				return nil, fmt.Errorf("nftables entry lacks exact family or handle")
			}
			if kind == "table" {
				tables++
				if value["name"] != table || tables != 1 {
					return nil, fmt.Errorf("nftables observation is not one exact table")
				}
			} else if value["table"] != table {
				return nil, fmt.Errorf("nftables observation crosses table boundaries")
			}
			identity := kind + ":" + string(value["handle"].(json.Number))
			if identities[identity] {
				return nil, fmt.Errorf("nftables observation has duplicate object identity")
			}
			identities[identity] = true
			result = append(result, entry)
		}
	}
	if tables != 1 && len(result) != 0 {
		return nil, fmt.Errorf("nftables table identity is absent")
	}
	return result, nil
}

func legacyFail2banNFTExpression(addressFamily, set string, upstream bool) []any {
	match := map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": addressFamily, "field": "saddr"}}, "right": "@" + set}}
	if upstream {
		protocol := map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": "tcp"}}
		rejectType := "icmp"
		if addressFamily == "ip6" {
			rejectType = "icmpv6"
		}
		return []any{protocol, match, map[string]any{"reject": map[string]any{"type": rejectType, "expr": "port-unreachable"}}}
	}
	return []any{match, map[string]any{"drop": nil}}
}

// Build one atomic, exact deletion transaction. It never flushes a chain or
// removes a table. Unexpected consumers, target changes and unsupported set
// shapes fail before any transaction is returned. Retained entries, including
// unrelated objects in the same table, are bound byte-for-byte canonically.
func prepareLegacyFail2banNFTTransition(content []byte, claims []legacyFail2banNFTClaim) (legacyFail2banNFTTransition, error) {
	var empty legacyFail2banNFTTransition
	if len(claims) == 0 || len(claims) > 256 {
		return empty, fmt.Errorf("exact nftables retirement requires bounded action claims")
	}
	table := "syswarden_f2b"
	if claims[0].profile == "nftables-allports" {
		table = "f2b-table"
	}
	entries, err := legacyFail2banNFTEntries(content, "inet", table)
	if err != nil {
		return empty, err
	}
	removed := make(map[int]bool)
	dependencies := make(map[string]bool)
	var rules, chains, sets []any
	selected := make(map[string]bool)
	for _, claim := range claims {
		if !validLegacyFail2banJailName(claim.jail) || claim.jail[0] == '-' ||
			!validLegacyRetirementDigest(claim.filePlan) || !validLegacyRetirementDigest(claim.actionsSHA256) ||
			claim.profile != claims[0].profile || claim.profile != "syswarden-nft" && claim.profile != "nftables-allports" ||
			claim.addressFamily != "ip" && claim.addressFamily != "ip6" {
			return empty, fmt.Errorf("unsupported or unbound nftables action claim")
		}
		upstream := claim.profile == "nftables-allports"
		chain, set, addrType := claim.jail, "f2b-"+claim.jail, "ipv4_addr"
		if upstream {
			chain, set = "f2b-chain", "addr-set-"+claim.jail
		}
		if claim.addressFamily == "ip6" {
			if !upstream {
				return empty, fmt.Errorf("historical nftables action has no supported IPv6 profile")
			}
			set, addrType = "addr6-set-"+claim.jail, "ipv6_addr"
		}
		if len(claim.bans) > 65536 {
			return empty, fmt.Errorf("Fail2ban nftables ban evidence exceeds its limit")
		}
		for index, text := range claim.bans {
			address, err := netip.ParseAddr(text)
			if err != nil || address.Zone() != "" || address.String() != text || address.Is4() != (addrType == "ipv4_addr") || address.Is4In6() || index > 0 && claim.bans[index-1] >= text {
				return empty, fmt.Errorf("Fail2ban nftables ban evidence is not exact and canonical")
			}
		}
		if selected[set] {
			return empty, fmt.Errorf("duplicate nftables action claim")
		}
		selected[set], dependencies[set] = true, true
		if !upstream {
			dependencies[chain] = true
		}
		chainCount, setCount, ruleCount := 0, 0, 0
		for index, entry := range entries {
			for kind, data := range entry.(map[string]any) {
				value := data.(map[string]any)
				switch {
				case kind == "chain" && value["name"] == chain:
					chainCount++
					if !legacyFail2banNFTFields(value, "family table name handle type hook prio policy", "") || value["type"] != "filter" || value["hook"] != "input" || value["prio"] != json.Number("-1") || value["policy"] != "accept" {
						return empty, fmt.Errorf("Fail2ban nftables chain differs from its action profile")
					}
					if !upstream {
						removed[index] = true
						chains = append(chains, map[string]any{"delete": map[string]any{"chain": map[string]any{"family": "inet", "table": table, "name": chain}}})
					}
				case kind == "set" && value["name"] == set:
					setCount++
					if !legacyFail2banNFTFields(value, "family table name type handle", "elem") || value["type"] != addrType {
						return empty, fmt.Errorf("Fail2ban nftables set differs from its action profile")
					}
					var membership []string
					if elements, exists := value["elem"]; exists {
						list, valid := elements.([]any)
						if !valid || len(list) > 65536 {
							return empty, fmt.Errorf("unsupported Fail2ban nftables set elements")
						}
						seen := make(map[string]bool)
						for _, item := range list {
							text, valid := item.(string)
							address, err := netip.ParseAddr(text)
							if !valid || err != nil || address.Zone() != "" || address.String() != text || address.Is4() != (addrType == "ipv4_addr") || address.Is4In6() || seen[text] {
								return empty, fmt.Errorf("ambiguous Fail2ban nftables set membership")
							}
							seen[text] = true
							membership = append(membership, text)
						}
					}
					sort.Strings(membership)
					if strings.Join(membership, "\n") != strings.Join(claim.bans, "\n") {
						return empty, fmt.Errorf("Fail2ban nftables set contains addresses outside its attested jail bans")
					}
					removed[index] = true
					sets = append(sets, map[string]any{"delete": map[string]any{"set": map[string]any{"family": "inet", "table": table, "name": set}}})
				case kind == "rule" && value["chain"] == chain && reflect.DeepEqual(value["expr"], legacyFail2banNFTExpression(claim.addressFamily, set, upstream)):
					ruleCount++
					if !legacyFail2banNFTFields(value, "family table chain handle expr", "") || removed[index] {
						return empty, fmt.Errorf("Fail2ban nftables rule is modified or multiply claimed")
					}
					removed[index] = true
					rules = append(rules, map[string]any{"delete": map[string]any{"rule": map[string]any{"family": "inet", "table": table, "chain": chain, "handle": value["handle"]}}})
				}
			}
		}
		// Actions create their sets on demand. A profile with no kernel
		// objects needs no deletion, even if a prior ban command failed.
		// Partial or modified objects remain an explicit recovery refusal.
		if setCount == 0 && ruleCount == 0 && (upstream || chainCount == 0) {
			continue
		}
		if chainCount != 1 || setCount != 1 || ruleCount != 1 {
			return empty, fmt.Errorf("Fail2ban nftables target is absent, duplicated or not an exact action result")
		}
	}
	remaining := []any{}
	for index, entry := range entries {
		if removed[index] {
			continue
		}
		if legacyFail2banNFTContains(entry, dependencies) {
			return empty, fmt.Errorf("retained nftables entry still depends on a retirement target")
		}
		remaining = append(remaining, entry)
	}
	before, err := json.Marshal(entries)
	if err != nil {
		return empty, err
	}
	after, err := json.Marshal(remaining)
	if err != nil {
		return empty, err
	}
	commands := append(append(append([]any{}, rules...), chains...), sets...)
	transaction, err := json.Marshal(map[string]any{"nftables": commands})
	if err != nil {
		return empty, err
	}
	claimBytes, err := encodeLegacyFail2banNFTClaims(claims)
	if err != nil {
		return empty, err
	}
	plan := legacyFail2banNFTTransition{family: "inet", table: table, before: before, after: after, claims: claimBytes, transaction: transaction}
	plan.sha256 = plan.digest()
	return plan, nil
}

// Authorization must revalidate the durable intent, source provenance,
// stopped targets, removal barrier and locks. Exact before/after snapshots
// make a retry safe after an unconfirmed atomic transaction. The caller must
// retain this plan durably until configuration and persistence are retired.
func applyLegacyFail2banNFTTransition(ctx context.Context, runner nftCommandRunner, plan legacyFail2banNFTTransition, authorize func(context.Context, string) error) error {
	if runner == nil || authorize == nil || !validLegacyRetirementDigest(plan.sha256) || plan.family != "inet" || plan.table != "syswarden_f2b" && plan.table != "f2b-table" ||
		len(plan.transaction) == 0 || len(plan.transaction) > 1<<20 || len(plan.before) > 8<<20 || len(plan.after) > 8<<20 || len(plan.claims) > 8<<20 || plan.sha256 != plan.digest() {
		return fmt.Errorf("exact nftables retirement lacks complete durable authorization")
	}
	if legacyFail2banRetiresWholeTable(plan) {
		return applyLegacyFail2banTableRetirement(ctx, runner, plan, authorize, func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
			return newNFTGenerationFence(ctx, inspect)
		})
	}
	read := func() ([]byte, error) {
		if err := authorize(ctx, plan.sha256); err != nil {
			return nil, err
		}
		content, err := runner.Run(ctx, nil, "-j", "list", "table", plan.family, plan.table)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect the bound Fail2ban nftables table")
		}
		entries, err := legacyFail2banNFTEntries(content, plan.family, plan.table)
		if err != nil {
			return nil, err
		}
		return json.Marshal(entries)
	}
	current, err := read()
	if err != nil {
		return err
	}
	if bytes.Equal(current, plan.after) {
		return authorize(ctx, plan.sha256)
	}
	if !bytes.Equal(current, plan.before) {
		return fmt.Errorf("Fail2ban nftables state changed outside its exact retirement transaction")
	}
	if err := authorize(ctx, plan.sha256); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, plan.transaction, "-j", "-f", "-"); err != nil {
		return fmt.Errorf("Fail2ban nftables retirement was not confirmed; retain its durable intent")
	}
	current, err = read()
	if err != nil {
		return err
	}
	if !bytes.Equal(current, plan.after) {
		return fmt.Errorf("Fail2ban nftables retirement did not preserve the exact retained entries")
	}
	return authorize(ctx, plan.sha256)
}

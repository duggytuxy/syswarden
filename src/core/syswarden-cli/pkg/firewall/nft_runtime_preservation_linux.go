//go:build linux

package firewall

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func isNFTRuntimeTable(target nftTableTarget) bool {
	return target == (nftTableTarget{family: "inet", name: "syswarden"}) ||
		target == (nftTableTarget{family: "netdev", name: "syswarden_hw_drop"})
}

// Reloading a live runtime set would restart its relative expiration clock.
// Keep compatible sets in the kernel while replacing the surrounding policy.
// Their lifetime then continues through validation, commit and rollback.
func nftRuntimePreservationRules(wire []byte, snapshot nftDynamicSnapshot) (string, error) {
	for _, key := range nftDynamicBanSets {
		if !snapshot.present[key] || len(snapshot.discarded[key]) != 0 {
			return "", nil
		}
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(wire, &document); err != nil {
		return "", err
	}
	chains := make(map[nftTableTarget][]string)
	objects := make(map[nftTableTarget][]string)
	compatible := make(map[nftObjectKey]bool)
	for _, entry := range document.NFTables {
		for kind, raw := range entry {
			var object struct {
				Family  string          `json:"family"`
				Table   string          `json:"table"`
				Name    string          `json:"name"`
				Type    json.RawMessage `json:"type"`
				Flags   []string        `json:"flags"`
				Timeout json.RawMessage `json:"timeout"`
			}
			if err := json.Unmarshal(raw, &object); err != nil {
				return "", fmt.Errorf("inspect runtime preservation object: %w", err)
			}
			target := nftTableTarget{family: object.Family, name: object.Table}
			if !isNFTRuntimeTable(target) {
				continue
			}
			if kind == "rule" || kind == "element" {
				continue
			}
			ownedOperatorChain := kind == "chain" && target == (nftTableTarget{family: "inet", name: "syswarden"}) &&
				object.Name == operatorPolicyChainName
			if !nftSetNameRE.MatchString(object.Name) && !ownedOperatorChain {
				return "", fmt.Errorf("runtime preservation object has an unsupported name")
			}
			key := nftObjectKey{family: target.family, table: target.name, name: object.Name}
			if kind == "set" && snapshot.present[key] {
				var dataType string
				if err := json.Unmarshal(object.Type, &dataType); err != nil {
					return "", nil
				}
				wantedType := "ipv4_addr"
				if strings.HasSuffix(key.name, "6") {
					wantedType = "ipv6_addr"
				}
				sort.Strings(object.Flags)
				if dataType != wantedType || strings.Join(object.Flags, ",") != "interval,timeout" ||
					nftDurationSpecified(object.Timeout) || compatible[key] {
					return "", nil
				}
				compatible[key] = true
				continue
			}
			command := fmt.Sprintf("delete %s %s %s %s\n", kind, target.family, target.name, object.Name)
			switch kind {
			case "chain":
				chains[target] = append(chains[target], command)
			case "set", "map", "counter", "quota", "limit", "flowtable", "ct helper", "ct timeout", "ct expectation", "synproxy", "secmark":
				objects[target] = append(objects[target], command)
			default:
				return "", fmt.Errorf("runtime preservation refuses unsupported owned object %q", kind)
			}
		}
	}
	if len(compatible) != len(nftDynamicBanSets) {
		return "", nil
	}
	var result strings.Builder
	for _, target := range syswardenNFTTables {
		if !isNFTRuntimeTable(target) {
			continue
		}
		_, _ = fmt.Fprintf(&result, "flush table %s %s\n", target.family, target.name)
		sort.Strings(chains[target])
		sort.Strings(objects[target])
		for _, command := range append(chains[target], objects[target]...) {
			result.WriteString(command)
		}
	}
	return result.String(), nil
}

// Only canonical output from the pinned nft executable reaches this parser.
// Dynamic values were independently parsed from its JSON snapshot. Removing
// their declarations prevents a rollback from resurrecting an entry that
// naturally expired while the policy transaction was in progress.
func nftRollbackWithoutRuntimeElements(snapshot string) (string, error) {
	lines := strings.SplitAfter(snapshot, "\n")
	var result strings.Builder
	ownedTable, runtimeSet, elements := false, false, false
	seen := 0
	for _, line := range lines {
		switch strings.TrimSpace(line) {
		case "table inet syswarden {", "table netdev syswarden_hw_drop {":
			ownedTable = true
		}
		if ownedTable && (line == "\tset banned_ips {\n" || line == "\tset banned_ips6 {\n") {
			runtimeSet = true
			seen++
		}
		if runtimeSet && strings.HasPrefix(line, "\t\telements = { ") {
			if elements {
				return "", fmt.Errorf("ambiguous runtime elements in rollback snapshot")
			}
			elements = true
		}
		if runtimeSet && !elements && strings.Contains(line, "elements") {
			return "", fmt.Errorf("noncanonical runtime elements in rollback snapshot")
		}
		if elements {
			if strings.ContainsAny(strings.TrimPrefix(line, "\t\telements = { "), "{\"#") {
				return "", fmt.Errorf("unsupported runtime element syntax in rollback snapshot")
			}
			if strings.HasSuffix(strings.TrimSpace(line), "}") {
				elements = false
			}
			continue
		}
		if line == "\t}\n" {
			runtimeSet = false
		}
		if line == "}\n" {
			ownedTable = false
		}
		result.WriteString(line)
	}
	if elements || runtimeSet || seen != len(nftDynamicBanSets) {
		return "", fmt.Errorf("rollback snapshot lacks four complete canonical runtime set definitions")
	}
	return result.String(), nil
}

//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const nftARPTemplatePrefix = "table arp syswarden_arp {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n"
const nftARPTemplateSuffix = "\t\tarp operation request limit rate over 500/second burst 1000 packets counter log prefix \"[SYSWARDEN-ARP-FLOOD] \" drop\n\t}\n}"
const nftARPSpoofPrefix = "\t\tarp saddr ip { "
const nftARPSpoofSuffix = " } counter log prefix \"[SYSWARDEN-ARP-SPOOF] \" drop\n"

// Exact source and complete kernel shape equivalence for the official ARP
// renderer shared by v4.02.8 and the current Go implementation. This is one
// part of an ownership attestation, not removal permission. The caller must
// independently bind the source file, originating product configuration,
// persistence dependencies, producer quiescence and live kernel generation.
// Never extend this profile by accepting arbitrary rules with a product name.
type nftARPTemplateEvidence struct {
	sourceSHA256   string
	topologySHA256 string
	localAddresses []string
}

func inspectNFTARPTemplateSource(source []byte) ([]string, error) {
	if len(source) > 4096 || !bytes.HasPrefix(source, []byte(nftARPTemplatePrefix)) || !bytes.HasSuffix(source, []byte(nftARPTemplateSuffix)) {
		return nil, fmt.Errorf("ARP persistence is not a complete exact product template")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(string(source), nftARPTemplatePrefix), nftARPTemplateSuffix)
	if body == "" {
		return []string{}, nil
	}
	if !strings.HasPrefix(body, nftARPSpoofPrefix) || !strings.HasSuffix(body, nftARPSpoofSuffix) {
		return nil, fmt.Errorf("ARP persistence contains an unrecognized rule")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(body, nftARPSpoofPrefix), nftARPSpoofSuffix)
	addresses := strings.Split(encoded, ", ")
	if len(addresses) == 0 || len(addresses) > 64 {
		return nil, fmt.Errorf("ARP persistence exceeds its address bound")
	}
	seen := make(map[string]bool)
	for _, address := range addresses {
		parsed, err := netip.ParseAddr(address)
		if err != nil || !parsed.Is4() || parsed.String() != address || parsed.IsUnspecified() || parsed.IsMulticast() || seen[address] {
			return nil, fmt.Errorf("ARP persistence contains an invalid or duplicate literal IPv4 address")
		}
		seen[address] = true
	}
	if body != nftARPSpoofPrefix+strings.Join(addresses, ", ")+nftARPSpoofSuffix {
		return nil, fmt.Errorf("ARP persistence has unrecognized trailing content")
	}
	return addresses, nil
}

func inspectNFTARPTemplate(source, live []byte) (nftARPTemplateEvidence, error) {
	var empty nftARPTemplateEvidence
	addresses, err := inspectNFTARPTemplateSource(source)
	if err != nil {
		return empty, err
	}
	document, err := decodeLegacyFail2banNFTJSON(live)
	if err != nil {
		return empty, err
	}
	entries, ok := document["nftables"].([]any)
	if !ok || len(entries) < 3 || len(entries) > 5 {
		return empty, fmt.Errorf("ARP table observation is incomplete or has extra objects")
	}
	if first, ok := entries[0].(map[string]any); ok && len(first) == 1 {
		if metadata, found := first["metainfo"].(map[string]any); found {
			if !legacyFail2banNFTFields(metadata, "version release_name json_schema_version", "") || metadata["json_schema_version"] != json.Number("1") {
				return empty, fmt.Errorf("ARP table observation has unsupported metadata")
			}
			for _, key := range []string{"version", "release_name"} {
				value, ok := metadata[key].(string)
				if !ok || value == "" || len(value) > 256 {
					return empty, fmt.Errorf("ARP table observation has invalid metadata")
				}
			}
			entries = entries[1:]
		}
	}
	expectedRules := nftARPTemplateExpressions(addresses)
	if len(entries) != 2+len(expectedRules) {
		return empty, fmt.Errorf("ARP table has extra or missing objects")
	}
	normalized := make([]any, 0, len(entries))
	objectHandles := make(map[string]bool)
	for index, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return empty, fmt.Errorf("ARP table has an ambiguous object")
		}
		kind := "rule"
		if index == 0 {
			kind = "table"
		} else if index == 1 {
			kind = "chain"
		}
		object, ok := wrapper[kind].(map[string]any)
		if !ok || !legacyFail2banNFTHandle(object) {
			return empty, fmt.Errorf("ARP table object type, order or handle is invalid")
		}
		switch kind {
		case "table":
			if !legacyFail2banNFTFields(object, "family name handle", "") || object["family"] != "arp" || object["name"] != "syswarden_arp" {
				return empty, fmt.Errorf("ARP table envelope differs from the official template")
			}
		case "chain":
			if !legacyFail2banNFTFields(object, "family table name handle type hook prio policy", "") || object["family"] != "arp" || object["table"] != "syswarden_arp" || object["name"] != "input" || object["type"] != "filter" || object["hook"] != "input" || object["prio"] != json.Number("0") || object["policy"] != "accept" {
				return empty, fmt.Errorf("ARP chain envelope differs from the official template")
			}
			objectHandles[string(object["handle"].(json.Number))] = true
		case "rule":
			if !legacyFail2banNFTFields(object, "family table chain handle expr", "") || object["family"] != "arp" || object["table"] != "syswarden_arp" || object["chain"] != "input" {
				return empty, fmt.Errorf("ARP rule envelope differs from the official template")
			}
			handle := string(object["handle"].(json.Number))
			if objectHandles[handle] {
				return empty, fmt.Errorf("ARP table contains duplicate chain or rule handles")
			}
			objectHandles[handle] = true
			expressions, ok := object["expr"].([]any)
			expected := expectedRules[index-2]
			if !ok || len(expressions) != len(expected) {
				return empty, fmt.Errorf("ARP rule has extra or missing expressions")
			}
			for _, expression := range expressions {
				wrapper, ok := expression.(map[string]any)
				if !ok || len(wrapper) != 1 {
					return empty, fmt.Errorf("ARP rule has an ambiguous expression")
				}
				if raw, found := wrapper["counter"]; found {
					counter, ok := raw.(map[string]any)
					if !ok || !legacyFail2banNFTFields(counter, "packets bytes", "") {
						return empty, fmt.Errorf("ARP rule has a nonstandard counter")
					}
					for _, key := range []string{"packets", "bytes"} {
						value, ok := counter[key].(json.Number)
						count, err := strconv.ParseUint(string(value), 10, 64)
						if !ok || err != nil || strconv.FormatUint(count, 10) != string(value) {
							return empty, fmt.Errorf("ARP rule has an invalid counter value")
						}
						counter[key] = json.Number("0")
					}
				}
			}
			// An anonymous address set is unordered. Normalize only that exact
			// operand, while retaining every other field for full comparison.
			if len(addresses) > 1 && index == 2 && len(expressions) > 0 {
				matchWrapper, _ := expressions[0].(map[string]any)
				match, _ := matchWrapper["match"].(map[string]any)
				right, _ := match["right"].(map[string]any)
				members, ok := right["set"].([]any)
				if !ok || len(right) != 1 || len(members) != len(addresses) {
					return empty, fmt.Errorf("ARP spoof operand is not the exact address set")
				}
				ordered := make([]string, len(members))
				for index, member := range members {
					value, ok := member.(string)
					if !ok {
						return empty, fmt.Errorf("ARP spoof operand contains a nonliteral address")
					}
					ordered[index] = value
				}
				sort.Strings(ordered)
				for index, member := range ordered {
					members[index] = member
				}
			}
			if !reflect.DeepEqual(expressions, expected) {
				return empty, fmt.Errorf("ARP rule content or ordering differs from the official template")
			}
		}
		delete(object, "handle")
		normalized = append(normalized, map[string]any{kind: object})
	}
	topology, err := json.Marshal(normalized)
	if err != nil {
		return empty, err
	}
	return nftARPTemplateEvidence{
		sourceSHA256:   fmt.Sprintf("%x", sha256.Sum256(source)),
		topologySHA256: fmt.Sprintf("%x", sha256.Sum256(topology)),
		localAddresses: append([]string(nil), addresses...),
	}, nil
}

func nftARPTemplateExpressions(addresses []string) [][]any {
	counter := func() any {
		return map[string]any{"counter": map[string]any{"packets": json.Number("0"), "bytes": json.Number("0")}}
	}
	match := func(field string, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "arp", "field": field}}, "right": right}}
	}
	var rules [][]any
	if len(addresses) > 0 {
		var right any = addresses[0]
		if len(addresses) > 1 {
			ordered := append([]string(nil), addresses...)
			sort.Strings(ordered)
			values := make([]any, len(ordered))
			for index, address := range ordered {
				values[index] = address
			}
			right = map[string]any{"set": values}
		}
		rules = append(rules, []any{match("saddr ip", right), counter(), map[string]any{"log": map[string]any{"prefix": "[SYSWARDEN-ARP-SPOOF] "}}, map[string]any{"drop": nil}})
	}
	return append(rules, []any{match("operation", "request"), map[string]any{"limit": map[string]any{"rate": json.Number("500"), "burst": json.Number("1000"), "per": "second", "inv": true}}, counter(), map[string]any{"log": map[string]any{"prefix": "[SYSWARDEN-ARP-FLOOD] "}}, map[string]any{"drop": nil}})
}

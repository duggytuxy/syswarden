//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const listPolicyVersion = "list-filter-v1"

func listPolicyKeepsRule(chain, line string) bool {
	line = strings.TrimSpace(line)
	switch chain {
	case "stateful_protect":
		return line == "jump ipv6-control-plane" || line == "iifname \"lo\" accept" ||
			strings.Contains(line, "@syswarden_whitelist") || strings.Contains(line, "@banned_ips") ||
			strings.Contains(line, "@syswarden_blacklist") || strings.HasPrefix(line, "jump "+operatorPolicyChainName+" ")
	case "data_leak_protect":
		return false
	case "ingress_frontline":
		return !strings.HasPrefix(line, "ip protocol tcp tcp flags ")
	default:
		return true
	}
}

// Project only generated complete source. Callers validating external source
// compare against an independently bound complete template before accepting it.
func listPolicySource(source []byte) ([]byte, error) {
	var out strings.Builder
	chain := ""
	inputChains, outputChains, ingressChains := 0, 0, 0
	for _, line := range strings.SplitAfter(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "\tchain ") {
			fields := strings.Fields(trimmed)
			if len(fields) != 3 || fields[2] != "{" {
				return nil, fmt.Errorf("invalid generated chain declaration")
			}
			chain = fields[1]
			switch chain {
			case "stateful_protect":
				inputChains++
			case "data_leak_protect":
				outputChains++
			case "ingress_frontline":
				ingressChains++
			}
		}
		if line == "\t}\n" {
			chain = ""
		}
		if chain == "stateful_protect" && strings.HasPrefix(trimmed, "type ") {
			line = strings.Replace(line, "policy drop;", "policy accept;", 1)
		}
		if strings.HasPrefix(line, "\t\t") && !strings.HasPrefix(trimmed, "type ") && !listPolicyKeepsRule(chain, line) {
			continue
		}
		out.WriteString(line)
	}
	if inputChains > 1 || outputChains > 1 || ingressChains > 1 || inputChains+ingressChains == 0 {
		return nil, fmt.Errorf("incomplete generated list-policy source")
	}
	return []byte(out.String()), nil
}

func validateListPolicyGeneration(mode string, base nftV4028PersistenceInputs) error {
	if mode == "" {
		return nil
	}
	if mode != listPolicyVersion || base.ARP || base.Inet.Geo || base.Inet.ASN || base.Inet.Strict || base.Inet.WireGuard || base.Inet.Honey {
		return fmt.Errorf("invalid list-only firewall generation")
	}
	return nil
}

// Restore the reference representation only after exact equality with its
// projected list-only generation. This does not adopt a modified source file.
func expandListInetSource(source []byte, input nftInetTemplateInputs) ([]byte, error) {
	var catalogue struct {
		Profiles []nftInetTemplateProfile `json:"profiles"`
	}
	if err := json.Unmarshal(nftInetProfilesJSON, &catalogue); err != nil {
		return nil, err
	}
	profiles := catalogue.Profiles
	for _, profile := range profiles {
		if profile.Profile != "current" {
			continue
		}
		full, err := renderNFTInetTemplate(profile, input)
		if err != nil {
			return nil, err
		}
		minimal, err := listPolicySource([]byte(full))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(source, minimal) {
			return nil, fmt.Errorf("list-only inet source differs from its writer inputs")
		}
		return []byte(full), nil
	}
	return nil, fmt.Errorf("current inet source model unavailable")
}

func expandListGoBaseSource(source []byte, input nftV4028PersistenceInputs) ([]byte, error) {
	if err := validateListPolicyGeneration(listPolicyVersion, input); err != nil {
		return nil, err
	}
	doc, err := inspectNFTPersistence(source)
	if err != nil || len(doc.tables) != 2 || len(doc.includes) != 0 {
		return nil, fmt.Errorf("list-only base must contain exactly its two owned tables")
	}
	first, second := doc.tables[0], doc.tables[1]
	if first.start != 0 || first.family != "netdev" || first.name != "syswarden_hw_drop" || second.family != "inet" || second.name != "syswarden" || second.start != first.end+2 || second.end+2 != len(source) || !bytes.Equal(source[first.end:second.start], []byte("\n\n")) || !bytes.Equal(source[second.end:], []byte("\n\n")) {
		return nil, fmt.Errorf("list-only source layout differs")
	}
	profiles, err := loadNFTNetdevTemplateProfiles()
	if err != nil {
		return nil, err
	}
	var fullIngress string
	for _, profile := range profiles {
		if profile.Profile == "go-current" {
			fullIngress = renderNFTNetdevTemplate(profile, input.Interfaces, false, false)
		}
	}
	minimal, err := listPolicySource([]byte(fullIngress))
	if err != nil || !bytes.Equal(minimal, source[first.start:first.end]) {
		return nil, fmt.Errorf("list-only ingress source differs from bound inputs")
	}
	fullInet, err := expandListInetSource(source[second.start:second.end], input.Inet)
	if err != nil {
		return nil, err
	}
	return []byte(fullIngress + "\n\n" + string(fullInet) + "\n\n"), nil
}

func renderListPolicyReference(input nftV4028PersistenceInputs) ([]byte, []byte, error) {
	if err := validateListPolicyGeneration(listPolicyVersion, input); err != nil {
		return nil, nil, err
	}
	var catalogue struct {
		Profiles []nftInetTemplateProfile `json:"profiles"`
	}
	if err := json.Unmarshal(nftInetProfilesJSON, &catalogue); err != nil {
		return nil, nil, err
	}
	var inet []byte
	for _, profile := range catalogue.Profiles {
		if profile.Profile == "current" {
			full, err := renderNFTInetTemplate(profile, input.Inet)
			if err != nil {
				return nil, nil, err
			}
			inet, err = listPolicySource([]byte(full))
			if err != nil {
				return nil, nil, err
			}
		}
	}
	profiles, err := loadNFTNetdevTemplateProfiles()
	if err != nil {
		return nil, nil, err
	}
	for _, profile := range profiles {
		if profile.Profile == "go-current" {
			ingress, err := listPolicySource([]byte(renderNFTNetdevTemplate(profile, input.Interfaces, false, false)))
			if err != nil {
				return nil, nil, err
			}
			return inet, ingress, nil
		}
	}
	return nil, nil, fmt.Errorf("list-policy reference is unavailable")
}

func verifyListPolicyRuntimeShape(content []byte, generation nftPolicyGeneration) error {
	if generation.PolicyMode == "" {
		return nil
	}
	if err := validateListPolicyGeneration(generation.PolicyMode, generation.Base); err != nil {
		return err
	}
	inetSource, ingressSource, err := renderListPolicyReference(generation.Base)
	if err != nil {
		return err
	}
	document, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		return err
	}
	entries, ok := document["nftables"].([]any)
	if !ok {
		return fmt.Errorf("invalid list-policy runtime document")
	}
	for _, target := range []struct {
		family, table string
		source        []byte
	}{{"inet", "syswarden", inetSource}, {"netdev", "syswarden_hw_drop", ingressSource}} {
		selected := []any{}
		for _, entry := range entries {
			wrapper, ok := entry.(map[string]any)
			if !ok || len(wrapper) != 1 {
				return fmt.Errorf("ambiguous runtime object")
			}
			for kind, raw := range wrapper {
				body, ok := raw.(map[string]any)
				if !ok {
					return fmt.Errorf("invalid runtime body")
				}
				if kind == "metainfo" {
					selected = append(selected, entry)
					continue
				}
				table := body["table"]
				if kind == "table" {
					table = body["name"]
				}
				if body["family"] != target.family || table != target.table {
					continue
				}
				// Element contents are checked independently against the
				// transaction populations and preserved dynamic leases.
				if kind == "element" {
					continue
				}
				if kind == "set" {
					delete(body, "elem")
				}
				selected = append(selected, entry)
			}
		}
		wire, err := json.Marshal(map[string]any{"nftables": selected})
		if err != nil {
			return err
		}
		wire, err = normalizeIPv6ControlPlaneRuntime(wire, target.family, generation.IPv6ControlPlane)
		if err != nil {
			return err
		}
		if target.family == "inet" {
			_, err = inspectNFTInetTemplateTopology(target.source, wire, generation.Base.Inet, listPolicyVersion)
		} else {
			_, err = inspectNFTNetdevTemplateTopology(target.source, wire, listPolicyVersion)
		}
		if err != nil {
			return fmt.Errorf("verify list-only %s policy: %w", target.family, err)
		}
	}
	return nil
}

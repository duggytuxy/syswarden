//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

//go:embed nft_removal_netdev_profiles.json
var nftNetdevProfilesJSON []byte

type nftNetdevTemplateProfile struct {
	Profile              string          `json:"profile"`
	DefaultsSourceSHA256 string          `json:"defaults_source_sha256,omitempty"`
	Commit               string          `json:"commit"`
	SourcePath           string          `json:"source_path"`
	SourceSHA256         string          `json:"source_sha256"`
	Literals             []string        `json:"literals"`
	KernelTemplate       json.RawMessage `json:"kernel_template"`
}

type nftNetdevTemplateEvidence struct {
	profile, sourceSHA256, topologySHA256 string
	interfaces                            []string
	geo, asn                              bool
}

func loadNFTNetdevTemplateProfiles() ([]nftNetdevTemplateProfile, error) {
	var catalogue struct {
		Profiles []nftNetdevTemplateProfile `json:"profiles"`
	}
	decoder := json.NewDecoder(bytes.NewReader(nftNetdevProfilesJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalogue); err != nil {
		return nil, err
	}
	if len(catalogue.Profiles) != 3 {
		return nil, fmt.Errorf("incomplete compiled ingress template catalogue")
	}
	seen := make(map[string]bool)
	for _, profile := range catalogue.Profiles {
		if seen[profile.Profile] || !validLegacyRetirementDigest(profile.SourceSHA256) || len(profile.Commit) != 40 {
			return nil, fmt.Errorf("invalid or duplicate compiled ingress provenance")
		}
		seen[profile.Profile] = true
		switch profile.Profile {
		case "go-v4028", "go-current":
			if profile.SourcePath != "src/core/syswarden-cli/pkg/firewall/firewall_linux.go" || len(profile.Literals) < 32 || len(profile.Literals) > 64 || profile.DefaultsSourceSHA256 != "" {
				return nil, fmt.Errorf("invalid compiled Go ingress template provenance")
			}
		case "shell-pre-v2-netdev":
			if profile.SourcePath != "src/functions/apply_firewall_rules.sh" || profile.Commit != "b1f909c8d774b679f46156443020fa5af45eea33" || profile.SourceSHA256 != "7e4f05b550a2ab01384a635982fdbed9ba39ec04e9ec7cb402d5a2796baca749" || profile.DefaultsSourceSHA256 != "d03de8e07943a397fca60ddd812202c2eee275b1270b057c70ee088133483f1b" || len(profile.Literals) != 27 {
				return nil, fmt.Errorf("invalid historical shell ingress template provenance")
			}
		default:
			return nil, fmt.Errorf("unsupported compiled ingress template generation")
		}
	}
	return catalogue.Profiles, nil
}

func nftNetdevTemplateInterfaces(source []byte) ([]string, error) {
	const suffix = " priority -500; policy accept;"
	if len(source) > 32768 {
		return nil, fmt.Errorf("ingress source exceeds its byte bound")
	}
	prefix := ""
	for _, candidate := range []string{"\tchain ingress_frontline {\n\t\ttype filter hook ingress ", "    chain ingress_frontline {\n        type filter hook ingress "} {
		if count := bytes.Count(source, []byte(candidate)); count != 0 {
			if count != 1 || prefix != "" {
				return nil, fmt.Errorf("ingress source has ambiguous chain declarations")
			}
			prefix = candidate
		}
	}
	if prefix == "" {
		return nil, fmt.Errorf("ingress source lacks one complete official chain")
	}
	tail := strings.SplitN(string(source), prefix, 2)[1]
	declaration, _, ok := strings.Cut(tail, "\n")
	if !ok || !strings.HasSuffix(declaration, suffix) {
		return nil, fmt.Errorf("ingress chain declaration differs from the official template")
	}
	declaration = strings.TrimSuffix(declaration, suffix)
	var encoded []string
	if strings.HasPrefix(declaration, "device ") {
		encoded = []string{strings.TrimPrefix(declaration, "device ")}
	} else if strings.HasPrefix(declaration, "devices = { ") && strings.HasSuffix(declaration, " }") {
		encoded = strings.Split(strings.TrimSuffix(strings.TrimPrefix(declaration, "devices = { "), " }"), ", ")
		if len(encoded) < 2 {
			return nil, fmt.Errorf("ingress device set is not a multi-interface renderer output")
		}
	} else {
		return nil, fmt.Errorf("ingress chain uses an unsupported device declaration")
	}
	if len(encoded) > 32 {
		return nil, fmt.Errorf("ingress interface count exceeds its bound")
	}
	interfaces := make([]string, len(encoded))
	seen := make(map[string]bool)
	for index, value := range encoded {
		name, err := strconv.Unquote(value)
		if err != nil || strconv.Quote(name) != value || seen[name] {
			return nil, fmt.Errorf("ingress interface is noncanonical or duplicated")
		}
		if _, err := canonicalInterfaceName(name); err != nil {
			return nil, fmt.Errorf("ingress interface is outside the canonical profile")
		}
		seen[name] = true
		interfaces[index] = name
	}
	return interfaces, nil
}

func renderNFTNetdevTemplate(profile nftNetdevTemplateProfile, interfaces []string, geo, asn bool) string {
	var result strings.Builder
	for _, literal := range profile.Literals {
		if !geo && (strings.Contains(literal, "syswarden_geoip") || strings.Contains(literal, "[SYSWARDEN-GEO]")) {
			continue
		}
		if !asn && (strings.Contains(literal, "syswarden_asn") || strings.Contains(literal, "[SYSWARDEN-ASN]")) {
			continue
		}
		if strings.Contains(literal, "%s") {
			if strings.Contains(literal, " devices = ") {
				if len(interfaces) == 1 {
					continue
				}
				quoted := make([]string, len(interfaces))
				for index, name := range interfaces {
					quoted[index] = strconv.Quote(name)
				}
				literal = strings.Replace(literal, "%s", strings.Join(quoted, ", "), 1)
			} else {
				if len(interfaces) != 1 {
					continue
				}
				literal = strings.Replace(literal, "%s", interfaces[0], 1)
			}
		}
		result.WriteString(literal)
	}
	return strings.TrimRight(result.String(), "\n")
}

// This inspector requires a terse kernel observation without set elements.
// It proves complete official source/topology equivalence, not the origin of
// populated sets. Independent source lineage, population attestation,
// producer quiescence and a generation fence remain mandatory for retirement.
func inspectNFTNetdevTemplateTopology(source, live []byte) (nftNetdevTemplateEvidence, error) {
	var empty nftNetdevTemplateEvidence
	interfaces, err := nftNetdevTemplateInterfaces(source)
	if err != nil {
		return empty, err
	}
	profiles, err := loadNFTNetdevTemplateProfiles()
	if err != nil {
		return empty, err
	}
	var matched *nftNetdevTemplateProfile
	var geo, asn bool
	for _, profile := range profiles {
		for _, geoCandidate := range []bool{false, true} {
			for _, asnCandidate := range []bool{false, true} {
				if string(source) == renderNFTNetdevTemplate(profile, interfaces, geoCandidate, asnCandidate) {
					if matched != nil {
						return empty, fmt.Errorf("ingress source matches multiple official profiles")
					}
					copied := profile
					matched = &copied
					geo = geoCandidate
					asn = asnCandidate
				}
			}
		}
	}
	if matched == nil {
		return empty, fmt.Errorf("ingress source is modified or outside the complete official profiles")
	}
	observed, err := normalizeNFTNetdevTopology(live)
	if err != nil {
		return empty, err
	}
	expected, err := normalizeNFTNetdevTopology(matched.KernelTemplate)
	if err != nil {
		return empty, err
	}
	var projected []any
	for _, entry := range expected {
		encoded, err := json.Marshal(entry)
		if err != nil {
			return empty, err
		}
		if !geo && (bytes.Contains(encoded, []byte("syswarden_geoip")) || bytes.Contains(encoded, []byte("[SYSWARDEN-GEO]"))) {
			continue
		}
		if !asn && (bytes.Contains(encoded, []byte("syswarden_asn")) || bytes.Contains(encoded, []byte("[SYSWARDEN-ASN]"))) {
			continue
		}
		wrapper := entry.(map[string]any)
		if chain, ok := wrapper["chain"].(map[string]any); ok {
			if len(interfaces) == 1 {
				chain["dev"] = interfaces[0]
			} else {
				ordered := append([]string(nil), interfaces...)
				sort.Strings(ordered)
				devices := make([]any, len(ordered))
				for index, name := range ordered {
					devices[index] = name
				}
				chain["dev"] = devices
			}
		}
		projected = append(projected, entry)
	}
	if !reflect.DeepEqual(observed, projected) {
		return empty, fmt.Errorf("ingress kernel topology includes changed or unrecognized objects, rules or ordering")
	}
	canonical, err := json.Marshal(observed)
	if err != nil {
		return empty, err
	}
	return nftNetdevTemplateEvidence{profile: matched.Profile, sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), topologySHA256: fmt.Sprintf("%x", sha256.Sum256(canonical)), interfaces: append([]string(nil), interfaces...), geo: geo, asn: asn}, nil
}

func normalizeNFTNetdevTopology(wire []byte) ([]any, error) {
	document, err := decodeLegacyFail2banNFTJSON(wire)
	if err != nil {
		return nil, err
	}
	entries, ok := document["nftables"].([]any)
	if !ok || len(entries) < 3 || len(entries) > 128 {
		return nil, fmt.Errorf("ingress observation exceeds its topology bounds")
	}
	var result []any
	sets := make(map[string]any)
	handles := make(map[string]bool)
	for index, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, fmt.Errorf("ambiguous ingress object")
		}
		for kind, raw := range wrapper {
			object, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid ingress object body")
			}
			if kind == "metainfo" && index == 0 {
				if !legacyFail2banNFTFields(object, "version release_name json_schema_version", "") || object["json_schema_version"] != json.Number("1") {
					return nil, fmt.Errorf("unsupported ingress metadata")
				}
				for _, key := range []string{"version", "release_name"} {
					if value, ok := object[key].(string); !ok || len(value) == 0 || len(value) > 256 {
						return nil, fmt.Errorf("invalid ingress metadata")
					}
				}
				continue
			}
			if kind != "table" && kind != "chain" && kind != "set" && kind != "rule" || !legacyFail2banNFTHandle(object) {
				return nil, fmt.Errorf("unsupported ingress object or handle")
			}
			if object["family"] != "netdev" {
				return nil, fmt.Errorf("ingress object belongs to a different family")
			}
			if kind == "table" {
				if object["name"] != "syswarden_hw_drop" {
					return nil, fmt.Errorf("ingress table has a different name")
				}
			} else {
				if object["table"] != "syswarden_hw_drop" {
					return nil, fmt.Errorf("ingress object belongs to another table")
				}
				handle := string(object["handle"].(json.Number))
				if handles[handle] {
					return nil, fmt.Errorf("duplicate ingress object handle")
				}
				handles[handle] = true
			}
			delete(object, "handle")
			if kind == "set" {
				if _, present := object["elem"]; present {
					return nil, fmt.Errorf("ingress topology inspector requires terse output; set populations need separate ownership evidence")
				}
				name, ok := object["name"].(string)
				if !ok || name == "" || len(name) > 256 || sets[name] != nil {
					return nil, fmt.Errorf("ingress set declaration has an invalid or duplicate name")
				}
				sets[name] = wrapper
				continue
			}
			if kind == "chain" {
				if devices, ok := object["dev"].([]any); ok {
					if len(devices) < 2 || len(devices) > 32 {
						return nil, fmt.Errorf("invalid ingress device set")
					}
					names := make([]string, len(devices))
					seen := make(map[string]bool)
					for index, device := range devices {
						name, ok := device.(string)
						if !ok || seen[name] {
							return nil, fmt.Errorf("ambiguous ingress device")
						}
						if _, err := canonicalInterfaceName(name); err != nil {
							return nil, err
						}
						names[index] = name
						seen[name] = true
					}
					sort.Strings(names)
					for index, name := range names {
						devices[index] = name
					}
				}
			}
			if kind == "rule" {
				expressions, ok := object["expr"].([]any)
				if !ok || len(expressions) == 0 || len(expressions) > 16 {
					return nil, fmt.Errorf("invalid ingress rule expression count")
				}
				for _, expression := range expressions {
					value, ok := expression.(map[string]any)
					if !ok || len(value) != 1 {
						return nil, fmt.Errorf("ambiguous ingress expression")
					}
					if raw, present := value["counter"]; present {
						counter, ok := raw.(map[string]any)
						if !ok || !legacyFail2banNFTFields(counter, "packets bytes", "") {
							return nil, fmt.Errorf("ingress counter differs from the anonymous product profile")
						}
						for _, key := range []string{"packets", "bytes"} {
							value, ok := counter[key].(json.Number)
							number, err := strconv.ParseUint(string(value), 10, 64)
							if !ok || err != nil || strconv.FormatUint(number, 10) != string(value) {
								return nil, fmt.Errorf("invalid ingress counter value")
							}
							counter[key] = json.Number("0")
						}
					}
				}
			}
			result = append(result, wrapper)
		}
	}
	// Set declaration order is not packet evaluation order. Native nftables
	// can list the same named sets in a different order after activation.
	// Keep every set field and the exact rule sequence, but compare named
	// declarations independently of their position in the JSON inventory.
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		result = append(result, sets[name])
	}
	return result, nil
}

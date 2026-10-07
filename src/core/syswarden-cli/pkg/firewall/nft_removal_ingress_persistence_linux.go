//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

//go:embed nft_removal_ingress_serialization.json
var nftIngressSerializationJSON []byte

const maximumNFTRetirementPopulationEntries = 131072

type nftIngressPersistenceEvidence struct {
	nftNetdevTemplateEvidence
	populationSHA256 string
}

func historicalNFTIngressSetKinds(geo, asn bool) map[string]string {
	sets := map[string]string{"syswarden_blacklist": "addr4", "syswarden_whitelist": "addr4", "syswarden_whitelist6": "addr6"}
	if geo {
		sets["syswarden_geoip"] = "addr4"
	}
	if asn {
		sets["syswarden_asn"] = "addr4"
	}
	return sets
}

func nftRetirementPopulationEntry(value string, kind string) ([]nftInetInterval, error) {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 128 {
		return nil, fmt.Errorf("invalid bounded retirement population entry")
	}
	var operand any = value
	if strings.Contains(value, "-") {
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid retirement address range")
		}
		operand = map[string]any{"range": []any{parts[0], parts[1]}}
	} else if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || prefix.Masked() != prefix {
			return nil, fmt.Errorf("noncanonical retirement address prefix")
		}
		operand = map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": json.Number(strconv.Itoa(prefix.Bits()))}}
	}
	remaining := 4
	return nftInetOperandIntervals(operand, kind, 0, &remaining)
}

func nftRetirementPopulationValues(entries []string, kind string) ([]string, error) {
	if len(entries) > maximumNFTRetirementPopulationEntries {
		return nil, fmt.Errorf("retirement population exceeds its entry bound")
	}
	var intervals []nftInetInterval
	for _, entry := range entries {
		parsed, err := nftRetirementPopulationEntry(entry, kind)
		if err != nil {
			return nil, err
		}
		intervals = append(intervals, parsed...)
	}
	return canonicalNFTInetIntervals(intervals), nil
}

// Remove only the exact printer field inside one known set block. Its values
// remain separately bound and are never discarded as mere formatting.
func extractNFTIngressPersistentPopulation(source string, name, kind string) (string, []string, error) {
	prefix := "\tset " + name + " {\n"
	if strings.Count(source, prefix) != 1 {
		return "", nil, fmt.Errorf("historical persistence lacks one exact set declaration")
	}
	start := strings.Index(source, prefix) + len(prefix)
	relativeEnd := strings.Index(source[start:], "\t}\n")
	if relativeEnd < 0 {
		return "", nil, fmt.Errorf("historical persistent set is incomplete")
	}
	end := start + relativeEnd
	body := source[start:end]
	const marker = "\t\telements = { "
	count := strings.Count(body, marker)
	if count == 0 {
		return source, []string{}, nil
	}
	if count != 1 {
		return "", nil, fmt.Errorf("historical persistent set has duplicate element fields")
	}
	at := strings.Index(body, marker)
	if at > 0 && body[at-1] != '\n' {
		return "", nil, fmt.Errorf("historical elements are not a complete printer field")
	}
	payloadStart := at + len(marker)
	relativeClose := strings.IndexByte(body[payloadStart:], '}')
	if relativeClose < 0 {
		return "", nil, fmt.Errorf("historical element field is incomplete")
	}
	closeAt := payloadStart + relativeClose
	if closeAt+1 >= len(body) || body[closeAt+1] != '\n' {
		return "", nil, fmt.Errorf("historical element field has unexpected trailing content")
	}
	payload := body[payloadStart:closeAt]
	if strings.Count(payload, ",") >= maximumNFTRetirementPopulationEntries {
		return "", nil, fmt.Errorf("historical population exceeds its entry bound")
	}
	entries := strings.Split(payload, ",")
	for index := range entries {
		entries[index] = strings.TrimSpace(entries[index])
	}
	canonical, err := nftRetirementPopulationValues(entries, kind)
	if err != nil {
		return "", nil, err
	}
	return source[:start+at] + source[start+closeAt+2:], canonical, nil
}

func normalizeNFTRetirementCounterText(source string) (string, error) {
	if len(source) > 32768 {
		return "", fmt.Errorf("historical topology text exceeds its byte bound")
	}
	tokens, err := scanNFTPersistence([]byte(source))
	if err != nil {
		return "", err
	}
	var ranges []nftPersistenceRange
	for index, token := range tokens {
		if token.kind != 'w' || source[token.start:token.end] != "counter" {
			continue
		}
		if index+4 >= len(tokens) || nftPersistenceWord([]byte(source), tokens[index+1]) != "packets" || nftPersistenceWord([]byte(source), tokens[index+3]) != "bytes" {
			return "", fmt.Errorf("historical counter differs from the anonymous printer profile")
		}
		for _, offset := range []int{2, 4} {
			valueToken := tokens[index+offset]
			value := nftPersistenceWord([]byte(source), valueToken)
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil || strconv.FormatUint(number, 10) != value {
				return "", fmt.Errorf("historical counter has noncanonical progress")
			}
			ranges = append(ranges, valueToken.nftPersistenceRange)
		}
	}
	var output strings.Builder
	previous := 0
	for _, part := range ranges {
		output.WriteString(source[previous:part.start])
		output.WriteByte('0')
		previous = part.end
	}
	output.WriteString(source[previous:])
	return output.String(), nil
}

func nftIngressPersistenceTemplate(interfaceName string, geo, asn bool) (string, error) {
	canonical, err := canonicalInterfaceName(interfaceName)
	if err != nil || canonical != interfaceName {
		return "", fmt.Errorf("historical persistence interface is noncanonical")
	}
	var catalogue struct {
		Profile        string            `json:"profile"`
		SourceCommit   string            `json:"source_commit"`
		SourceSHA256   string            `json:"source_sha256"`
		DefaultsSHA256 string            `json:"defaults_source_sha256"`
		Description    string            `json:"description"`
		Templates      map[string]string `json:"templates"`
	}
	decoder := json.NewDecoder(bytes.NewReader(nftIngressSerializationJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalogue); err != nil {
		return "", err
	}
	if catalogue.Profile != "shell-pre-v2-netdev" || catalogue.SourceCommit != "b1f909c8d774b679f46156443020fa5af45eea33" || catalogue.SourceSHA256 != "7e4f05b550a2ab01384a635982fdbed9ba39ec04e9ec7cb402d5a2796baca749" || catalogue.DefaultsSHA256 != "d03de8e07943a397fca60ddd812202c2eee275b1270b057c70ee088133483f1b" || len(catalogue.Templates) != 4 {
		return "", fmt.Errorf("historical ingress persistence provenance is incomplete")
	}
	key := []byte{'0', '0'}
	if geo {
		key[0] = '1'
	}
	if asn {
		key[1] = '1'
	}
	template, known := catalogue.Templates[string(key)]
	if !known || strings.Count(template, "{{interface}}") != 1 {
		return "", fmt.Errorf("historical ingress persistence template is incomplete")
	}
	return strings.TrimSuffix(strings.Replace(template, "{{interface}}", strconv.Quote(interfaceName), 1), "\n"), nil
}

type nftIngressPersistentSourceEvidence struct {
	sourceSHA256, populationSHA256 string
	populations                    map[string][]string
}

// This pure source check also applies when historical runtime is absent or
// replaced. Input and file ownership remain independent prerequisites.
func inspectNFTHistoricalIngressPersistentSource(source []byte, interfaceName string, geo, asn bool, populations map[string][]string) (nftIngressPersistentSourceEvidence, error) {
	var empty nftIngressPersistentSourceEvidence
	if len(source) == 0 || len(source) > maximumNFTPersistenceBytes {
		return empty, fmt.Errorf("historical ingress persistence exceeds its byte bound")
	}
	expected, err := nftIngressPersistenceTemplate(interfaceName, geo, asn)
	if err != nil {
		return empty, err
	}
	kinds := historicalNFTIngressSetKinds(geo, asn)
	if len(populations) != len(kinds) {
		return empty, fmt.Errorf("historical populations lack exact independently supplied set coverage")
	}
	var names []string
	for name := range kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	frame := string(source)
	bound := make(map[string][]string, len(kinds))
	total := 0
	for _, name := range names {
		entries, known := populations[name]
		if !known {
			return empty, fmt.Errorf("historical set population is unbound")
		}
		total += len(entries)
		if total > maximumNFTRetirementPopulationEntries {
			return empty, fmt.Errorf("total historical population exceeds its bound")
		}
		claim, err := nftRetirementPopulationValues(entries, kinds[name])
		if err != nil {
			return empty, err
		}
		var persisted []string
		frame, persisted, err = extractNFTIngressPersistentPopulation(frame, name, kinds[name])
		if err != nil {
			return empty, err
		}
		if !reflect.DeepEqual(claim, persisted) {
			return empty, fmt.Errorf("historical persistent set differs from its independently supplied population")
		}
		bound[name] = claim
	}
	frame, err = normalizeNFTRetirementCounterText(frame)
	if err != nil {
		return empty, err
	}
	if frame != expected {
		return empty, fmt.Errorf("historical ingress persistence contains changed or additional declarations, rules or fields")
	}
	encoded, err := json.Marshal(bound)
	if err != nil {
		return empty, err
	}
	return nftIngressPersistentSourceEvidence{sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), populationSHA256: fmt.Sprintf("%x", sha256.Sum256(encoded)), populations: bound}, nil
}

// Compare persisted populations, current populations and independently supplied
// population inputs as exact closed-interval unions. Equality does not prove
// who supplied those inputs. Their source and ownership, the containing file,
// all consumers and producers must still be externally attested. This pure
// inspector does not issue a removal plan or change host state.
func inspectNFTHistoricalIngressPersistence(source, live []byte, interfaceName string, geo, asn bool, populations map[string][]string) (nftIngressPersistenceEvidence, error) {
	var empty nftIngressPersistenceEvidence
	sourceEvidence, err := inspectNFTHistoricalIngressPersistentSource(source, interfaceName, geo, asn, populations)
	if err != nil {
		return empty, err
	}
	kinds := historicalNFTIngressSetKinds(geo, asn)
	bound := sourceEvidence.populations
	document, err := decodeLegacyFail2banNFTJSON(live)
	if err != nil {
		return empty, err
	}
	objects, ok := document["nftables"].([]any)
	if !ok || len(objects) > 128 {
		return empty, fmt.Errorf("historical ingress kernel observation exceeds its topology bound")
	}
	seen := make(map[string]bool)
	total := 0
	for _, entry := range objects {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return empty, fmt.Errorf("ambiguous historical ingress object")
		}
		set, exists := wrapper["set"]
		if !exists {
			continue
		}
		object, ok := set.(map[string]any)
		if !ok {
			return empty, fmt.Errorf("invalid historical ingress set")
		}
		name, ok := object["name"].(string)
		kind, known := kinds[name]
		if !ok || !known || seen[name] {
			return empty, fmt.Errorf("unrecognized or duplicated historical ingress set")
		}
		seen[name] = true
		var entries []any
		if raw, present := object["elem"]; present {
			entries, ok = raw.([]any)
			if !ok {
				return empty, fmt.Errorf("invalid historical ingress element array")
			}
		}
		total += len(entries)
		if total > maximumNFTRetirementPopulationEntries {
			return empty, fmt.Errorf("kernel population exceeds its bound")
		}
		var intervals []nftInetInterval
		for _, value := range entries {
			if object, ok := value.(map[string]any); ok {
				_, prefix := object["prefix"]
				_, span := object["range"]
				if len(object) != 1 || !prefix && !span {
					return empty, fmt.Errorf("unsupported historical element metadata or expression")
				}
			}
			remaining := 4
			parts, err := nftInetOperandIntervals(value, kind, 0, &remaining)
			if err != nil {
				return empty, err
			}
			intervals = append(intervals, parts...)
		}
		if !reflect.DeepEqual(bound[name], canonicalNFTInetIntervals(intervals)) {
			return empty, fmt.Errorf("historical kernel population differs from its independent and persistent evidence")
		}
		delete(object, "elem")
	}
	if len(seen) != len(kinds) {
		return empty, fmt.Errorf("historical kernel set coverage is incomplete")
	}
	terse, err := json.Marshal(document)
	if err != nil {
		return empty, err
	}
	profiles, err := loadNFTNetdevTemplateProfiles()
	if err != nil {
		return empty, err
	}
	var profile nftNetdevTemplateProfile
	for _, candidate := range profiles {
		if candidate.Profile == "shell-pre-v2-netdev" {
			profile = candidate
		}
	}
	generated := renderNFTNetdevTemplate(profile, []string{interfaceName}, geo, asn)
	topology, err := inspectNFTNetdevTemplateTopology([]byte(generated), terse)
	if err != nil {
		return empty, err
	}
	topology.sourceSHA256 = sourceEvidence.sourceSHA256
	return nftIngressPersistenceEvidence{nftNetdevTemplateEvidence: topology, populationSHA256: sourceEvidence.populationSHA256}, nil
}

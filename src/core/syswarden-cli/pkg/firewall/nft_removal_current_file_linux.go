//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"syswarden-cli/config"
)

type nftCurrentPopulation struct {
	Name    string   `json:"name"`
	Entries []string `json:"entries"`
}

// This additional binding is populated only by explicit preservation recovery.
// Pure source recognition does not establish the existence or validity of that
// proof. Every removal entry point and session must independently recheck it.
type nftPreservedOperatorInputs struct {
	Rules []config.OperatorPolicyRule `json:"rules"`
	Proof string                      `json:"preservation_sha256"`
}

func (input *nftPreservedOperatorInputs) validate() error {
	if input == nil {
		return nil
	}
	if !validLegacyRetirementDigest(input.Proof) || len(input.Rules) == 0 {
		return fmt.Errorf("operator preservation lacks exact typed policy and proof binding")
	}
	_, err := prepareNFTOperatorReceiver(input.Rules)
	return err
}

type nftCurrentPersistenceInputs struct {
	Base        nftV4028PersistenceInputs   `json:"base"`
	Populations []nftCurrentPopulation      `json:"populations"`
	Operator    *nftPreservedOperatorInputs `json:"operator_preservation,omitempty"`
}

type nftCurrentPopulationSpec struct {
	name, kind     string
	port, inetOnly bool
}

type nftCurrentPersistenceEvidence struct {
	sourceSHA256, inputSHA256 string
	base                      []byte
	populations               map[string]map[string][]string
}

// This order and the 4096-entry chunking below are the complete persistent
// writer contract. The origin of these inputs is a separate authorization.
func nftCurrentPopulationSpecs(geo, asn bool) []nftCurrentPopulationSpec {
	result := []nftCurrentPopulationSpec{
		{"syswarden_whitelist", "addr4", false, false},
		{"syswarden_whitelist6", "addr6", false, false},
		{"syswarden_whitelist_ports", "addr4", true, false},
		{"syswarden_whitelist_ports6", "addr6", true, false},
		{"syswarden_ssh_bypass", "addr4", false, true},
		{"syswarden_ssh_bypass6", "addr6", false, true},
		{"syswarden_zt_allowed", "addr4", false, false},
		{"syswarden_zt_allowed6", "addr6", false, false},
		{"syswarden_blacklist", "addr4", false, false},
		{"syswarden_blacklist6", "addr6", false, false},
	}
	if geo {
		result = append(result, nftCurrentPopulationSpec{"syswarden_geoip", "addr4", false, false}, nftCurrentPopulationSpec{"syswarden_geoip6", "addr6", false, false})
	}
	if asn {
		result = append(result, nftCurrentPopulationSpec{"syswarden_asn", "addr4", false, false}, nftCurrentPopulationSpec{"syswarden_asn6", "addr6", false, false})
	}
	return result
}

func canonicalNFTPopulationGroups(groups map[string][]nftInetInterval) map[string][]string {
	result := make(map[string][]string, len(groups))
	for port, intervals := range groups {
		result[port] = canonicalNFTInetIntervals(intervals)
	}
	return result
}

func nftCurrentInputPopulation(entries []string, spec nftCurrentPopulationSpec) (map[string][]string, error) {
	if len(entries) > maximumNFTRetirementPopulationEntries {
		return nil, fmt.Errorf("current population exceeds its entry bound")
	}
	groups := make(map[string][]nftInetInterval)
	for _, entry := range entries {
		address, port := entry, ""
		if spec.port {
			parts := strings.Split(entry, " . ")
			if len(parts) != 2 {
				return nil, fmt.Errorf("current address and port population is malformed")
			}
			canonical, err := canonicalPort(parts[1])
			if err != nil || canonical != parts[1] {
				return nil, fmt.Errorf("current population port is not canonical")
			}
			address, port = parts[0], canonical
		}
		parts, err := nftRetirementPopulationEntry(address, spec.kind)
		if err != nil {
			return nil, err
		}
		groups[port] = append(groups[port], parts...)
	}
	return canonicalNFTPopulationGroups(groups), nil
}

func inspectNFTCurrentPersistentFile(source []byte, input nftCurrentPersistenceInputs) (nftCurrentPersistenceEvidence, error) {
	var empty nftCurrentPersistenceEvidence
	if len(source) == 0 || len(source) > maximumNFTPersistenceBytes {
		return empty, fmt.Errorf("current persistence exceeds its byte bound")
	}
	end := bytes.Index(source, []byte("add element "))
	if end < 0 {
		end = len(source)
	}
	base := source[:end]
	if err := input.Operator.validate(); err != nil {
		return empty, err
	}
	if input.Operator != nil {
		normalized, err := normalizeNFTOperatorSource(base, input.Operator.Rules)
		if err != nil {
			return empty, err
		}
		base = normalized
	}
	if _, err := inspectNFTGoBasePersistentFile(base, input.Base, "current"); err != nil {
		return empty, err
	}
	specs := nftCurrentPopulationSpecs(input.Base.Inet.Geo, input.Base.Inet.ASN)
	if len(input.Populations) != len(specs) {
		return empty, fmt.Errorf("current persistence lacks complete independent population inputs")
	}
	var rendered strings.Builder
	bound := make(map[string]map[string][]string, len(specs))
	totalBytes, totalEntries := 0, 0
	for index, spec := range specs {
		population := input.Populations[index]
		totalEntries += len(population.Entries)
		if population.Name != spec.name || totalEntries > maximumNFTRetirementPopulationEntries {
			return empty, fmt.Errorf("current population names, order or total entry count differ from the writer contract")
		}
		for _, entry := range population.Entries {
			totalBytes += len(entry)
			if totalBytes > maximumNFTPersistenceBytes {
				return empty, fmt.Errorf("current population inputs exceed their byte bound")
			}
		}
		values, err := nftCurrentInputPopulation(population.Entries, spec)
		if err != nil {
			return empty, err
		}
		bound[spec.name] = values
		for start := 0; start < len(population.Entries); start += 4096 {
			stop := min(start+4096, len(population.Entries))
			payload := strings.Join(population.Entries[start:stop], ", ")
			if !spec.inetOnly {
				fmt.Fprintf(&rendered, "add element netdev syswarden_hw_drop %s { %s }\n", spec.name, payload)
			}
			fmt.Fprintf(&rendered, "add element inet syswarden %s { %s }\n", spec.name, payload)
			if rendered.Len() > maximumNFTPersistenceBytes {
				return empty, fmt.Errorf("current population serialization exceeds its byte bound")
			}
		}
	}
	if string(source[end:]) != rendered.String() {
		return empty, fmt.Errorf("current persistent populations differ from their independent inputs or writer contract")
	}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > maximumNFTPersistenceBytes {
		return empty, fmt.Errorf("current persistence inputs cannot be bound within their byte limit")
	}
	return nftCurrentPersistenceEvidence{fmt.Sprintf("%x", sha256.Sum256(source)), fmt.Sprintf("%x", sha256.Sum256(encoded)), bytes.Clone(base), bound}, nil
}

func nftCurrentKernelPopulation(entries []any, spec nftCurrentPopulationSpec) (map[string][]string, error) {
	groups := make(map[string][]nftInetInterval)
	for _, entry := range entries {
		address, port := entry, ""
		if spec.port {
			object, ok := entry.(map[string]any)
			if !ok || len(object) != 1 {
				return nil, fmt.Errorf("current concatenated element has unsupported metadata")
			}
			parts, ok := object["concat"].([]any)
			if !ok || len(parts) != 2 {
				return nil, fmt.Errorf("current concatenated element has an unsupported shape")
			}
			number, ok := parts[1].(json.Number)
			canonical, err := canonicalPort(string(number))
			if !ok || err != nil || canonical != string(number) {
				return nil, fmt.Errorf("current concatenated element has a noncanonical port")
			}
			address, port = parts[0], canonical
		}
		if object, ok := address.(map[string]any); ok {
			_, prefix := object["prefix"]
			_, span := object["range"]
			if len(object) != 1 || !prefix && !span {
				return nil, fmt.Errorf("current address element has unsupported metadata or expression")
			}
		}
		remaining := 4
		parts, err := nftInetOperandIntervals(address, spec.kind, 0, &remaining)
		if err != nil {
			return nil, err
		}
		groups[port] = append(groups[port], parts...)
	}
	return canonicalNFTPopulationGroups(groups), nil
}

// Compare populations with independent writer inputs and runtime claims.
// Unknown metadata is never discarded as formatting.
func inspectNFTCurrentPopulations(live []byte, family string, input nftCurrentPersistenceInputs, evidence nftCurrentPersistenceEvidence, claims *nftRuntimeClaimProof) ([]byte, error) {
	if family != "inet" && family != "netdev" {
		return nil, fmt.Errorf("unsupported current population family")
	}
	document, err := decodeLegacyFail2banNFTJSON(live)
	if err != nil {
		return nil, err
	}
	objects, ok := document["nftables"].([]any)
	if !ok || len(objects) > 512 {
		return nil, fmt.Errorf("current population topology exceeds its object bound")
	}
	specs := make(map[string]nftCurrentPopulationSpec)
	for _, spec := range nftCurrentPopulationSpecs(input.Base.Inet.Geo, input.Base.Inet.ASN) {
		if family == "inet" || !spec.inetOnly {
			specs[spec.name] = spec
		}
	}
	seen := make(map[string]bool)
	total := 0
	for _, entry := range objects {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, fmt.Errorf("ambiguous current kernel object")
		}
		raw, present := wrapper["set"]
		if !present {
			continue
		}
		object, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid current kernel set")
		}
		name, ok := object["name"].(string)
		if !ok || seen[name] {
			return nil, fmt.Errorf("duplicated or invalid current kernel set")
		}
		seen[name] = true
		var entries []any
		if raw, present := object["elem"]; present {
			entries, ok = raw.([]any)
			if !ok {
				return nil, fmt.Errorf("invalid current element array")
			}
		}
		total += len(entries)
		if total > maximumNFTRetirementPopulationEntries {
			return nil, fmt.Errorf("current kernel population exceeds its entry bound")
		}
		if spec, known := specs[name]; known {
			values, err := nftCurrentKernelPopulation(entries, spec)
			if err != nil || !reflect.DeepEqual(values, evidence.populations[name]) {
				return nil, fmt.Errorf("current kernel population differs from its independent inputs: %s", name)
			}
		} else if err := claims.inspect(family, name, entries); err != nil {
			return nil, err
		}
		delete(object, "elem")
	}
	// Sorted names make refusal diagnostics deterministic.
	names := make([]string, 0, len(specs))
	for name := range specs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !seen[name] {
			return nil, fmt.Errorf("current kernel population coverage is incomplete: %s", name)
		}
	}
	return json.Marshal(document)
}

func inspectNFTCurrentPersistenceRuntime(source, inet, ingress, arp []byte, input nftCurrentPersistenceInputs) (nftCurrentPersistenceEvidence, error) {
	return inspectNFTCurrentRuntimeWithClaims(source, inet, ingress, arp, input, nil)
}

func inspectNFTCurrentRuntimeWithClaims(source, inet, ingress, arp []byte, input nftCurrentPersistenceInputs, claims *nftRuntimeClaimProof) (nftCurrentPersistenceEvidence, error) {
	evidence, err := inspectNFTCurrentPersistentFile(source, input)
	if err != nil {
		return nftCurrentPersistenceEvidence{}, err
	}
	document, err := inspectNFTPersistence(evidence.base)
	if err != nil {
		return nftCurrentPersistenceEvidence{}, err
	}
	if input.Operator != nil {
		inet, _, err = normalizeNFTOperatorRuntime(inet, input.Operator.Rules)
		if err != nil {
			return nftCurrentPersistenceEvidence{}, err
		}
	}
	for index, live := range [][]byte{ingress, inet} {
		table := document.tables[index]
		terse, err := inspectNFTCurrentPopulations(live, table.family, input, evidence, claims)
		if err != nil {
			return nftCurrentPersistenceEvidence{}, err
		}
		block := evidence.base[table.start:table.end]
		if index == 0 {
			_, err = inspectNFTNetdevTemplateTopology(block, terse)
		} else {
			_, err = inspectNFTInetTemplateTopology(block, terse, input.Base.Inet)
		}
		if err != nil {
			return nftCurrentPersistenceEvidence{}, err
		}
	}
	if input.Base.ARP {
		table := document.tables[2]
		if _, err := inspectNFTARPTemplate(evidence.base[table.start:table.end], arp); err != nil {
			return nftCurrentPersistenceEvidence{}, err
		}
	} else if len(arp) != 0 {
		return nftCurrentPersistenceEvidence{}, fmt.Errorf("unbound ARP runtime observation")
	}
	if err := claims.complete(); err != nil {
		return nftCurrentPersistenceEvidence{}, err
	}
	return evidence, nil
}

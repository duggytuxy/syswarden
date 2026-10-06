//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
)

type nftV4028PersistenceInputs struct {
	Inet         nftInetTemplateInputs
	Interfaces   []string
	ARP          bool
	ARPAddresses []string
}

type nftV4028PersistenceEvidence struct {
	sourceSHA256, inputsSHA256 string
	inet                       nftInetSourceEvidence
}

// v4.02.8 persisted its empty-set generator output before streaming populations
// separately to the kernel. The exact whole-file template therefore proves no
// live population ownership. Its originating configuration, list inputs, file
// identity, consumers and producers require their own independent attestation.
func inspectNFTV4028PersistentFile(source []byte, input nftV4028PersistenceInputs) (nftV4028PersistenceEvidence, error) {
	return inspectNFTGoBasePersistentFile(source, input, "v4028")
}

// Keep generation selection explicit. An exact current block cannot establish
// the lineage of an older block in the same containing file.
func inspectNFTGoBasePersistentFile(source []byte, input nftV4028PersistenceInputs, profile string) (nftV4028PersistenceEvidence, error) {
	if profile != "v4028" && profile != "current" {
		return nftV4028PersistenceEvidence{}, fmt.Errorf("unsupported persistent renderer generation")
	}
	var empty nftV4028PersistenceEvidence
	if len(source) == 0 || len(source) > 256<<10 || len(input.Interfaces) == 0 || len(input.Interfaces) > 32 || len(input.ARPAddresses) > 64 || !input.ARP && len(input.ARPAddresses) != 0 {
		return empty, fmt.Errorf("Go-rendered persistence inputs exceed their bounds or have inconsistent ARP state")
	}
	seen := make(map[string]bool)
	for _, name := range input.Interfaces {
		canonical, err := canonicalInterfaceName(name)
		if err != nil || canonical != name || seen[name] {
			return empty, fmt.Errorf("Go-rendered persistence requires distinct canonical interfaces")
		}
		seen[name] = true
	}
	if err := validateNFTInetTemplateInputs(profile, input.Inet); err != nil {
		return empty, err
	}
	document, err := inspectNFTPersistence(source)
	if err != nil {
		return empty, err
	}
	count := 2
	if input.ARP {
		count++
	}
	if len(document.includes) != 0 || len(document.tables) != count {
		return empty, fmt.Errorf("Go-rendered persistence has unknown, missing or additional blocks")
	}
	position := 0
	wanted := []nftTableTarget{{family: "netdev", name: "syswarden_hw_drop"}, {family: "inet", name: "syswarden"}, {family: "arp", name: "syswarden_arp"}}
	for index, table := range document.tables {
		if table.start != position || table.end <= table.start || table.end > len(source)-2 || table.family != wanted[index].family || table.name != wanted[index].name || !bytes.Equal(source[table.end:table.end+2], []byte("\n\n")) {
			return empty, fmt.Errorf("Go-rendered persistence has unrecognized block order or separators")
		}
		position = table.end + 2
	}
	if position != len(source) {
		return empty, fmt.Errorf("Go-rendered persistence has trailing content outside the official base file")
	}
	profiles, err := loadNFTNetdevTemplateProfiles()
	if err != nil {
		return empty, err
	}
	var ingress *nftNetdevTemplateProfile
	for _, candidate := range profiles {
		if candidate.Profile == "go-"+profile {
			copied := candidate
			ingress = &copied
		}
	}
	if ingress == nil {
		return empty, fmt.Errorf("Go-rendered ingress source provenance is unavailable")
	}
	first, second := document.tables[0], document.tables[1]
	if string(source[first.start:first.end]) != renderNFTNetdevTemplate(*ingress, input.Interfaces, input.Inet.Geo, input.Inet.ASN) {
		return empty, fmt.Errorf("Go-rendered ingress persistence differs from its independently supplied interface and policy inputs")
	}
	inet, err := inspectNFTInetTemplateSource(source[second.start:second.end], input.Inet)
	if err != nil {
		return empty, err
	}
	if inet.profile != profile {
		return empty, fmt.Errorf("persistent table generations do not match the selected renderer")
	}
	if input.ARP {
		third := document.tables[2]
		addresses, err := inspectNFTARPTemplateSource(source[third.start:third.end])
		if err != nil {
			return empty, err
		}
		if !reflect.DeepEqual(addresses, append([]string{}, input.ARPAddresses...)) {
			return empty, fmt.Errorf("ARP persistence differs from its independently supplied local addresses")
		}
	}
	parameters, err := json.Marshal(input)
	if err != nil {
		return empty, err
	}
	return nftV4028PersistenceEvidence{sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), inputsSHA256: fmt.Sprintf("%x", sha256.Sum256(parameters)), inet: inet}, nil
}

//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

//go:embed nft_removal_inet_profiles.json
var nftInetProfilesJSON []byte

type nftInetTemplateNode struct {
	Kind      string                `json:"kind"`
	Condition string                `json:"condition,omitempty"`
	Arguments []string              `json:"arguments,omitempty"`
	Then      []nftInetTemplateNode `json:"then,omitempty"`
	Else      []nftInetTemplateNode `json:"else,omitempty"`
}

type nftInetTemplateProfile struct {
	Profile      string                           `json:"profile"`
	Commit       string                           `json:"commit"`
	SourceSHA256 string                           `json:"source_sha256"`
	Programs     map[string][]nftInetTemplateNode `json:"programs"`
}

// Inputs must come from independent configuration/source lineage evidence.
// Matching source text alone does not establish kernel or file ownership.
type nftInetTemplateInputs struct {
	Geo, ASN, Strict, WireGuard, Honey bool
	SSHPort, WireGuardSubnet           string
	TCPPorts, UDPPorts, HoneyPorts     []string
	LAN4, LAN6                         []string
}

type nftInetSourceEvidence struct {
	profile, sourceSHA256, inputSHA256 string
}

func validateNFTInetTemplateInputs(profile string, input nftInetTemplateInputs) error {
	if profile != "v4028" && profile != "current" {
		return fmt.Errorf("unsupported inet renderer generation")
	}
	port, err := canonicalPort(input.SSHPort)
	if err != nil || port != input.SSHPort {
		return fmt.Errorf("inet source evidence requires one canonical effective SSH port")
	}
	if input.WireGuardSubnet != "" || input.WireGuard {
		subnet, err := canonicalIPv4Network(input.WireGuardSubnet, "template subnet")
		if err != nil || subnet != input.WireGuardSubnet {
			return fmt.Errorf("inet source evidence has a noncanonical WireGuard subnet")
		}
	}
	oldWebPort := false
	for _, ports := range [][]string{input.TCPPorts, input.UDPPorts, input.HoneyPorts} {
		if len(ports) > 512 {
			return fmt.Errorf("inet source evidence exceeds the bounded port count")
		}
		seen := make(map[string]bool)
		for _, value := range ports {
			port, err := canonicalPort(value)
			if err != nil || port != value || seen[value] {
				return fmt.Errorf("inet source evidence has noncanonical or duplicate ports")
			}
			seen[value] = true
		}
	}
	for _, port := range input.TCPPorts {
		oldWebPort = oldWebPort || port == "62027"
		if profile == "current" && (port == "62027" || port == input.SSHPort) {
			return fmt.Errorf("current inet profile must separate SSH and omit the retired Web-TUI permission")
		}
	}
	if profile == "v4028" && !oldWebPort {
		return fmt.Errorf("historical inet profile lacks its mandatory generated Web-TUI permission")
	}
	if input.Honey && len(input.HoneyPorts) == 0 {
		return fmt.Errorf("enabled honeyport rendering has no bounded ports")
	}
	defaults := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	if len(input.LAN4) < len(defaults) || len(input.LAN4) > 128 || len(input.LAN6) > 128 {
		return fmt.Errorf("inet LAN evidence lacks the official defaults or exceeds its bound")
	}
	for index, network := range defaults {
		if input.LAN4[index] != network {
			return fmt.Errorf("inet LAN evidence changed the mandatory default order")
		}
	}
	if profile == "v4028" && len(input.LAN6) != 0 {
		return fmt.Errorf("historical inet renderer does not support a separate IPv6 LAN input")
	}
	for family, networks := range [][]string{input.LAN4, input.LAN6} {
		seen := make(map[string]bool)
		for _, value := range networks {
			canonical, ipv4, err := canonicalLANPolicyNetwork(value)
			if err != nil || canonical != value || ipv4 != (family == 0) || profile == "current" && seen[value] {
				return fmt.Errorf("inet LAN evidence is noncanonical, duplicated or in the wrong family")
			}
			seen[value] = true
		}
	}
	return nil
}

func nftInetTemplateParameters(profile string, input nftInetTemplateInputs) (map[string]string, map[string]bool) {
	honeySeparator := ", "
	if profile == "v4028" {
		honeySeparator = ","
	}
	parameters := map[string]string{
		"sshPort": input.SSHPort, "wireGuardSubnet": input.WireGuardSubnet, "config.GlobalConfig.WGSubnet": input.WireGuardSubnet,
		"ports":                                strings.Join(input.HoneyPorts, honeySeparator),
		`strings.Join(tcpPorts, ", ")`:         strings.Join(input.TCPPorts, ", "),
		`strings.Join(udpPorts, ", ")`:         strings.Join(input.UDPPorts, ", "),
		`strings.Join(validLANSubnets, ", ")`:  strings.Join(input.LAN4, ", "),
		`strings.Join(validLANSubnets4, ", ")`: strings.Join(input.LAN4, ", "),
		`strings.Join(validLANSubnets6, ", ")`: strings.Join(input.LAN6, ", "),
	}
	conditions := map[string]bool{
		`config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != ""`:          input.Geo,
		`config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != ""`:           input.ASN,
		`config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != ""`: input.Strict,
		"config.GlobalConfig.EnableWG":                                                 input.WireGuard,
		`config.GlobalConfig.LANMode && config.GlobalConfig.HoneyPorts != ""`:          input.Honey,
		"len(tcpPorts) > 0": len(input.TCPPorts) > 0, "len(udpPorts) > 0": len(input.UDPPorts) > 0,
		"len(validLANSubnets) > 0": len(input.LAN4) > 0, "len(validLANSubnets4) > 0": len(input.LAN4) > 0, "len(validLANSubnets6) > 0": len(input.LAN6) > 0,
		"len(validLANSubnets4) > 0 || len(validLANSubnets6) > 0": len(input.LAN4)+len(input.LAN6) > 0, "!configured": !input.Strict,
	}
	return parameters, conditions
}

// The compiled program contains renderer statements only. It cannot execute
// shell commands, read files, inspect the host, or evaluate arbitrary Go.
// Conditions and format arguments are resolved through fixed typed bindings.
func renderNFTInetTemplate(profile nftInetTemplateProfile, input nftInetTemplateInputs) (string, error) {
	return renderNFTInetTemplateTrace(profile, input, nil)
}

// The trace records only the fixed statement that emitted each source fragment.
// It is used to bind kernel expressions to compiled semantic templates.
func renderNFTInetTemplateTrace(profile nftInetTemplateProfile, input nftInetTemplateInputs, emit func(nftInetTemplateNode, string)) (string, error) {
	if err := validateNFTInetTemplateInputs(profile.Profile, input); err != nil {
		return "", err
	}
	parameters, conditions := nftInetTemplateParameters(profile.Profile, input)
	var output strings.Builder
	visits := 0
	var run func([]nftInetTemplateNode, int) (bool, error)
	run = func(nodes []nftInetTemplateNode, depth int) (bool, error) {
		if depth > 8 {
			return false, fmt.Errorf("inet renderer program exceeds its nesting bound")
		}
		for _, node := range nodes {
			visits++
			if visits > 256 || output.Len() > 128<<10 {
				return false, fmt.Errorf("inet renderer program exceeds its size bound")
			}
			start := output.Len()
			switch node.Kind {
			case "return":
				return true, nil
			case "if":
				enabled, known := conditions[node.Condition]
				if !known {
					return false, fmt.Errorf("inet renderer has an unrecognized condition")
				}
				branch := node.Else
				if enabled {
					branch = node.Then
				}
				stopped, err := run(branch, depth+1)
				if err != nil || stopped {
					return stopped, err
				}
			case "literal":
				if len(node.Arguments) != 1 {
					return false, fmt.Errorf("invalid inet literal node")
				}
				argument := node.Arguments[0]
				switch argument {
				case "operatorPolicy.chain":
					compiled, err := compileOperatorPolicy(nil)
					if err != nil {
						return false, err
					}
					output.WriteString(compiled.chain)
				case "operatorPolicyDispatchRule()":
					output.WriteString(operatorPolicyDispatchRule())
				default:
					value, err := strconv.Unquote(argument)
					if err != nil {
						return false, fmt.Errorf("inet renderer literal is not a string")
					}
					output.WriteString(value)
				}
			case "format":
				if len(node.Arguments) < 2 || len(node.Arguments) > 3 {
					return false, fmt.Errorf("invalid inet format node")
				}
				format, err := strconv.Unquote(node.Arguments[0])
				if err != nil {
					return false, err
				}
				parts := strings.Split(format, "%s")
				if len(parts) != len(node.Arguments) {
					return false, fmt.Errorf("inet renderer format has an unexpected substitution count")
				}
				for index, part := range parts {
					if strings.Contains(part, "%") {
						return false, fmt.Errorf("inet renderer contains an unsupported format")
					}
					output.WriteString(part)
					if index+1 < len(parts) {
						value, known := parameters[node.Arguments[index+1]]
						if !known {
							return false, fmt.Errorf("inet renderer has an unbound argument")
						}
						output.WriteString(value)
					}
				}
			case "appendStrictAllowInputRules", "appendStrictAllowForwardRules":
				helper, known := profile.Programs[node.Kind]
				if !known {
					return false, fmt.Errorf("inet renderer helper is unavailable")
				}
				if _, err := run(helper, depth+1); err != nil {
					return false, err
				}
			default:
				return false, fmt.Errorf("inet renderer contains an unsupported operation")
			}
			if emit != nil && (node.Kind == "literal" || node.Kind == "format") {
				emit(node, output.String()[start:])
			}
		}
		return false, nil
	}
	name := "applyPolicies"
	if profile.Profile == "v4028" {
		name = "ApplyPolicies"
	}
	program, known := profile.Programs[name]
	if !known {
		return "", fmt.Errorf("inet renderer program is unavailable")
	}
	stopped, err := run(program, 0)
	if err != nil {
		return "", err
	}
	if stopped || output.Len() > 128<<10 {
		return "", fmt.Errorf("inet renderer output is incomplete or unbounded")
	}
	return strings.TrimSuffix(output.String(), "\n\n"), nil
}

func inspectNFTInetTemplateSource(source []byte, input nftInetTemplateInputs) (nftInetSourceEvidence, error) {
	var empty nftInetSourceEvidence
	if len(source) == 0 || len(source) > 128<<10 {
		return empty, fmt.Errorf("inet template source exceeds its byte bound")
	}
	var catalogue struct {
		Profiles []nftInetTemplateProfile `json:"profiles"`
	}
	decoder := json.NewDecoder(bytes.NewReader(nftInetProfilesJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalogue); err != nil {
		return empty, err
	}
	if len(catalogue.Profiles) != 2 {
		return empty, fmt.Errorf("inet renderer catalogue is incomplete")
	}
	matched := ""
	for _, profile := range catalogue.Profiles {
		if len(profile.Commit) != 40 || !validLegacyRetirementDigest(profile.SourceSHA256) {
			return empty, fmt.Errorf("inet renderer provenance is incomplete")
		}
		if err := validateNFTInetTemplateInputs(profile.Profile, input); err != nil {
			continue
		}
		expected, err := renderNFTInetTemplate(profile, input)
		if err != nil {
			return empty, err
		}
		if expected == string(source) {
			if matched != "" {
				return empty, fmt.Errorf("inet source matches multiple official generations")
			}
			matched = profile.Profile
		}
	}
	if matched == "" {
		return empty, fmt.Errorf("inet source is modified, unsupported or inconsistent with independently supplied inputs")
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return empty, err
	}
	return nftInetSourceEvidence{profile: matched, sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), inputSHA256: fmt.Sprintf("%x", sha256.Sum256(encoded))}, nil
}

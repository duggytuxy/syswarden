//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

//go:embed nft_removal_shell_profile.json
var nftShellProfileJSON []byte

type nftShellInputs struct {
	WireGuard                           bool
	Whitelist                           []string
	ActivePorts, SSHPort, WireGuardPort string
}

type nftShellNode struct {
	Literal    string `json:"literal,omitempty"`
	Whitelist  bool   `json:"whitelist,omitempty"`
	If         string `json:"if,omitempty"`
	Then, Else []nftShellNode
}

type nftShellProfile struct {
	Profile      string                           `json:"profile"`
	Commit       string                           `json:"commit"`
	SourcePath   string                           `json:"source_path"`
	SourceSHA256 string                           `json:"source_sha256"`
	Literals     map[string]string                `json:"literals"`
	Program      []nftShellNode                   `json:"program"`
	Semantics    map[string]nftInetSemanticRecord `json:"semantics"`
}

func loadNFTShellProfile() (nftShellProfile, error) {
	var profile nftShellProfile
	decoder := json.NewDecoder(bytes.NewReader(nftShellProfileJSON))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return profile, err
	}
	if profile.Profile != "shell-pre-v2" || profile.Commit != "b1f909c8d774b679f46156443020fa5af45eea33" || profile.SourcePath != "src/functions/apply_firewall_rules.sh" || profile.SourceSHA256 != "7e4f05b550a2ab01384a635982fdbed9ba39ec04e9ec7cb402d5a2796baca749" || len(profile.Literals) != 12 || len(profile.Semantics) != 21 {
		return profile, fmt.Errorf("incomplete historical shell renderer provenance")
	}
	return profile, nil
}

func validateNFTShellInputs(input nftShellInputs) ([]string, error) {
	for _, value := range []string{input.SSHPort, input.WireGuardPort} {
		canonical, err := canonicalPort(value)
		if err != nil || canonical != value {
			return nil, fmt.Errorf("historical shell template requires canonical ports")
		}
	}
	if len(input.ActivePorts) > 4096 || len(input.Whitelist) > 256 {
		return nil, fmt.Errorf("historical shell parameters exceed their bounds")
	}
	var active []string
	if input.ActivePorts != "" {
		for _, value := range input.ActivePorts {
			if value != ' ' && value != ',' && (value < '0' || value > '9') {
				return nil, fmt.Errorf("unsupported historical active-port syntax")
			}
		}
		active = strings.Split(input.ActivePorts, ",")
		if len(active) > 512 {
			return nil, fmt.Errorf("historical active-port count exceeds its bound")
		}
		for index, value := range active {
			value = strings.TrimSpace(value)
			canonical, err := canonicalPort(value)
			if err != nil || canonical != value {
				return nil, fmt.Errorf("historical active-port input is noncanonical")
			}
			active[index] = value
		}
	}
	for _, value := range input.Whitelist {
		canonical, _, err := canonicalIPOrPrefix(value)
		if err != nil || canonical != value {
			return nil, fmt.Errorf("historical whitelist input is noncanonical")
		}
	}
	return active, nil
}

// The program consists only of independently extracted literal output and
// fixed branches. No historical shell code is evaluated or executed.
func renderNFTShellTemplate(profile nftShellProfile, input nftShellInputs, emit func(string, string, string)) (string, error) {
	active, err := validateNFTShellInputs(input)
	if err != nil {
		return "", err
	}
	quic := false
	for _, port := range active {
		quic = quic || port == "443"
	}
	conditions := map[string]bool{"WireGuard": input.WireGuard, "ActivePorts": len(active) > 0, "QUIC": quic}
	var output strings.Builder
	appendLiteral := func(name, address string) error {
		literal, known := profile.Literals[name]
		if !known {
			return fmt.Errorf("unsupported historical renderer literal")
		}
		replace := strings.NewReplacer("${SSH_PORT:-22}", input.SSHPort, "${WG_PORT:-51820}", input.WireGuardPort, "$ACTIVE_PORTS", input.ActivePorts, "$wl_ip", address)
		fragment := replace.Replace(literal)
		if strings.Contains(fragment, "$") || output.Len()+len(fragment) > 128<<10 {
			return fmt.Errorf("historical renderer has unbound or excessive output")
		}
		output.WriteString(fragment)
		if emit != nil {
			emit(name, fragment, address)
		}
		return nil
	}
	visits := 0
	var run func([]nftShellNode, int) error
	run = func(nodes []nftShellNode, depth int) error {
		if depth > 8 {
			return fmt.Errorf("historical renderer exceeds its nesting bound")
		}
		for _, node := range nodes {
			visits++
			if visits > 64 {
				return fmt.Errorf("historical renderer exceeds its statement bound")
			}
			operations := 0
			if node.Literal != "" {
				operations++
			}
			if node.Whitelist {
				operations++
			}
			if node.If != "" {
				operations++
			}
			if operations != 1 {
				return fmt.Errorf("historical renderer has an ambiguous operation")
			}
			switch {
			case node.Literal != "":
				if err := appendLiteral(node.Literal, ""); err != nil {
					return err
				}
			case node.Whitelist:
				for _, address := range input.Whitelist {
					name := "whitelist4"
					if strings.Contains(address, ":") {
						name = "whitelist6"
					}
					if err := appendLiteral(name, address); err != nil {
						return err
					}
				}
			case node.If != "":
				condition, known := conditions[node.If]
				if !known {
					return fmt.Errorf("unsupported historical renderer condition")
				}
				branch := node.Else
				if condition {
					branch = node.Then
				}
				if err := run(branch, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := run(profile.Program, 0); err != nil {
		return "", err
	}
	return strings.TrimSuffix(output.String(), "\n"), nil
}

// Complete source and kernel equivalence covers only this official historical
// profile. Matching does not establish parameter lineage or authorize removal
// of persistent files, administrator dependencies or shared resources.
func inspectNFTShellTemplateTopology(source, live []byte, input nftShellInputs) (nftInetTopologyEvidence, error) {
	var empty nftInetTopologyEvidence
	if len(source) == 0 || len(source) > 128<<10 {
		return empty, fmt.Errorf("historical source exceeds its byte bound")
	}
	profile, err := loadNFTShellProfile()
	if err != nil {
		return empty, err
	}
	expected, err := renderNFTShellTemplate(profile, input, nil)
	if err != nil || string(source) != expected {
		return empty, fmt.Errorf("historical source differs from the complete official renderer and bound parameters")
	}
	observed, err := normalizeNFTInetTopologyForTable(live, "syswarden_table")
	if err != nil {
		return empty, err
	}
	active, err := validateNFTShellInputs(input)
	if err != nil {
		return empty, err
	}
	combined := append([]string{input.SSHPort}, active...)
	seenObjects := make(map[string]bool)
	seenRules := make(map[string]int)
	chain := ""
	var traceErr error
	_, err = renderNFTShellTemplate(profile, input, func(name, fragment, address string) {
		if traceErr != nil {
			return
		}
		for offset, line := range strings.Split(strings.TrimSuffix(fragment, "\n"), "\n") {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "type ") {
				continue
			}
			if line == "    }" {
				chain = ""
				continue
			}
			if line == "}" {
				continue
			}
			record, known := profile.Semantics[name+":"+strconv.Itoa(offset)]
			if !known {
				traceErr = fmt.Errorf("historical statement lacks compiled kernel semantics")
				return
			}
			if record.Kind != "rule" {
				identity := record.Kind + ":" + record.Name
				if seenObjects[identity] || !reflect.DeepEqual(observed.objects[identity], record.Object) {
					traceErr = fmt.Errorf("historical declaration differs from the official profile")
					return
				}
				seenObjects[identity] = true
				if record.Kind == "chain" {
					chain = record.Name
				}
				continue
			}
			index := seenRules[chain]
			if chain == "" || index >= len(observed.rules[chain]) {
				traceErr = fmt.Errorf("historical rule is missing or has a different chain")
				return
			}
			rule := observed.rules[chain][index]
			values := map[string][]string{"SSHPort": {input.SSHPort}, "WireGuardPort": {input.WireGuardPort}, "WhitelistEntry": {address}, "CombinedPorts": combined}
			if err := bindNFTInetOperandValues(rule, record.Bindings, values); err != nil {
				traceErr = err
				return
			}
			if !reflect.DeepEqual(rule, record.Object) {
				traceErr = fmt.Errorf("historical rule expressions, comments or ordering differ")
				return
			}
			seenRules[chain] = index + 1
		}
	})
	if err != nil {
		return empty, err
	}
	if traceErr != nil {
		return empty, traceErr
	}
	if len(seenObjects) != len(observed.objects) || len(seenRules) != len(observed.rules) {
		return empty, fmt.Errorf("historical table contains extra objects or rules")
	}
	for chain, rules := range observed.rules {
		if seenRules[chain] != len(rules) {
			return empty, fmt.Errorf("historical chain contains extra rules")
		}
	}
	canonical, err := json.Marshal([]any{observed.objects, observed.rules})
	if err != nil {
		return empty, err
	}
	parameters, err := json.Marshal(input)
	if err != nil {
		return empty, err
	}
	return nftInetTopologyEvidence{nftInetSourceEvidence: nftInetSourceEvidence{profile: profile.Profile, sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), inputSHA256: fmt.Sprintf("%x", sha256.Sum256(parameters))}, topologySHA256: fmt.Sprintf("%x", sha256.Sum256(canonical))}, nil
}

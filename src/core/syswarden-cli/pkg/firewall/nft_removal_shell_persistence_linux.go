//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

//go:embed nft_removal_shell_serialization.json
var nftShellSerializationJSON []byte

type nftShellSerialization struct {
	Profile      string            `json:"profile"`
	SourceCommit string            `json:"source_commit"`
	SourceSHA256 string            `json:"source_sha256"`
	Description  string            `json:"description"`
	Statements   map[string]string `json:"statements"`
}

func nftShellSerializedPortSet(ports []string) string {
	unique := make(map[string]bool, len(ports))
	var ordered []string
	for _, port := range ports {
		if !unique[port] {
			ordered = append(ordered, port)
			unique[port] = true
		}
	}
	// Inputs are canonical decimal ports. Length followed by lexical order
	// gives numeric ordering without an unchecked integer conversion.
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) < len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})
	// nft preserves an anonymous set when the original literal had multiple
	// members, even when deduplication leaves one. A literal with one member
	// is instead printed as a scalar.
	if len(ports) == 1 {
		return ordered[0]
	}
	return "{ " + strings.Join(ordered, ", ") + " }"
}

func nftShellSerializedAddress(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Bits() == prefix.Addr().BitLen() {
		return prefix.Addr().String()
	}
	return value
}

// The old installer persisted nft list output, not its original heredocs.
// These compiled serialization templates were captured independently from the
// exact historical generator. Unsupported printer changes remain a refusal.
func renderNFTShellPersistence(input nftShellInputs) (string, error) {
	active, err := validateNFTShellInputs(input)
	if err != nil {
		return "", err
	}
	profile, err := loadNFTShellProfile()
	if err != nil {
		return "", err
	}
	var serialized nftShellSerialization
	decoder := json.NewDecoder(bytes.NewReader(nftShellSerializationJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&serialized); err != nil {
		return "", err
	}
	if serialized.Profile != profile.Profile || serialized.SourceCommit != profile.Commit || serialized.SourceSHA256 != profile.SourceSHA256 || len(serialized.Statements) != len(profile.Semantics) {
		return "", fmt.Errorf("historical persistence serialization provenance is incomplete")
	}
	combined := nftShellSerializedPortSet(append([]string{input.SSHPort}, active...))
	var output strings.Builder
	hasChain := false
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
				output.WriteString("\t}\n")
				continue
			}
			if line == "}" {
				output.WriteString("}\n")
				continue
			}
			key := name + ":" + strconv.Itoa(offset)
			statement, known := serialized.Statements[key]
			record, recorded := profile.Semantics[key]
			if !known || !recorded {
				traceErr = fmt.Errorf("historical persistence statement has no complete serialization binding")
				return
			}
			if record.Kind == "chain" {
				if hasChain {
					output.WriteByte('\n')
				}
				hasChain = true
			}
			replace := strings.NewReplacer("{{SSHPort}}", input.SSHPort, "{{WireGuardPort}}", input.WireGuardPort, "{{WhitelistEntry}}", nftShellSerializedAddress(address), "{{CombinedPorts}}", combined)
			statement = replace.Replace(statement)
			if strings.Contains(statement, "{{") || strings.Contains(statement, "}}") || output.Len()+len(statement) > 128<<10 {
				traceErr = fmt.Errorf("historical persistence serialization is unbound or excessive")
				return
			}
			output.WriteString(statement)
		}
	})
	if err != nil {
		return "", err
	}
	if traceErr != nil {
		return "", traceErr
	}
	return strings.TrimSuffix(output.String(), "\n"), nil
}

// Source-only evidence remains useful when an upgrade replaced the old runtime.
// It attests representation and parameter equality, not file or input ownership.
func inspectNFTShellPersistentSource(source []byte, input nftShellInputs) (nftInetSourceEvidence, error) {
	var empty nftInetSourceEvidence
	if len(source) == 0 || len(source) > 128<<10 {
		return empty, fmt.Errorf("historical persistent table exceeds its byte bound")
	}
	expected, err := renderNFTShellPersistence(input)
	if err != nil || expected != string(source) {
		return empty, fmt.Errorf("historical persistent table differs from the complete official nft list serialization and bound parameters")
	}
	profile, err := loadNFTShellProfile()
	if err != nil {
		return empty, err
	}
	parameters, err := json.Marshal(input)
	if err != nil {
		return empty, err
	}
	return nftInetSourceEvidence{profile: profile.Profile, sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), inputSHA256: fmt.Sprintf("%x", sha256.Sum256(parameters))}, nil
}

// This accepts one complete historical table block, not an entire file or
// include graph. The exact printed block and live topology must describe the
// same independently supplied parameters. File identity, all other statements,
// include dependencies and producer ownership remain separate requirements.
func inspectNFTShellPersistentTable(source, live []byte, input nftShellInputs) (nftInetTopologyEvidence, error) {
	var empty nftInetTopologyEvidence
	sourceEvidence, err := inspectNFTShellPersistentSource(source, input)
	if err != nil {
		return empty, err
	}
	profile, err := loadNFTShellProfile()
	if err != nil {
		return empty, err
	}
	generated, err := renderNFTShellTemplate(profile, input, nil)
	if err != nil {
		return empty, err
	}
	evidence, err := inspectNFTShellTemplateTopology([]byte(generated), live, input)
	if err != nil {
		return empty, err
	}
	evidence.nftInetSourceEvidence = sourceEvidence
	return evidence, nil
}

//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

//go:embed nft_removal_inet_semantics.json
var nftInetSemanticsJSON []byte

type nftInetStatement struct {
	Arguments  []string `json:"arguments"`
	Kind       string   `json:"kind"`
	LineOffset int      `json:"line_offset"`
}

type nftInetOperandBinding struct {
	ExpressionIndex int    `json:"expression_index"`
	Parameter       string `json:"parameter"`
	Kind            string `json:"kind"`
	Protocol        string `json:"protocol"`
	Field           string `json:"field"`
}

type nftInetSemanticRecord struct {
	Source   nftInetStatement        `json:"source"`
	Kind     string                  `json:"kind"`
	Name     string                  `json:"name,omitempty"`
	Object   map[string]any          `json:"object"`
	Bindings []nftInetOperandBinding `json:"bindings,omitempty"`
}

type nftInetTopology struct {
	objects map[string]map[string]any
	rules   map[string][]map[string]any
}

type nftInetTopologyEvidence struct {
	nftInetSourceEvidence
	topologySHA256 string
}

func nftInetStatementKey(statement nftInetStatement) (string, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(statement); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(bytes.TrimSuffix(output.Bytes(), []byte("\n")))), nil
}

func loadNFTInetSemantics() (map[string]nftInetSemanticRecord, error) {
	var compiled struct {
		Description string                           `json:"description"`
		Catalogue   map[string]nftInetSemanticRecord `json:"catalogue"`
	}
	decoder := json.NewDecoder(bytes.NewReader(nftInetSemanticsJSON))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&compiled); err != nil {
		return nil, err
	}
	if len(compiled.Catalogue) != 73 {
		return nil, fmt.Errorf("incomplete compiled inet semantics")
	}
	for key, record := range compiled.Catalogue {
		expected, err := nftInetStatementKey(record.Source)
		if err != nil || key != expected || len(record.Object) == 0 || len(record.Bindings) > 2 {
			return nil, fmt.Errorf("invalid compiled inet statement binding")
		}
	}
	return compiled.Catalogue, nil
}

func normalizeNFTInetTopology(wire []byte) (nftInetTopology, error) {
	return normalizeNFTInetTopologyForTable(wire, "syswarden")
}

func normalizeNFTInetTopologyForTable(wire []byte, table string) (nftInetTopology, error) {
	if table != "syswarden" && table != "syswarden_table" {
		return nftInetTopology{}, fmt.Errorf("unsupported inet template table")
	}
	empty := nftInetTopology{}
	document, err := decodeLegacyFail2banNFTJSON(wire)
	if err != nil {
		return empty, err
	}
	entries, ok := document["nftables"].([]any)
	if !ok || len(entries) < 3 || len(entries) > 192 {
		return empty, fmt.Errorf("invalid inet topology bounds")
	}
	result := nftInetTopology{objects: make(map[string]map[string]any), rules: make(map[string][]map[string]any)}
	handles := make(map[string]bool)
	for index, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return empty, fmt.Errorf("ambiguous inet object")
		}
		for kind, raw := range wrapper {
			object, ok := raw.(map[string]any)
			if !ok {
				return empty, fmt.Errorf("invalid inet object body")
			}
			if kind == "metainfo" && index == 0 {
				if !legacyFail2banNFTFields(object, "version release_name json_schema_version", "") || object["json_schema_version"] != json.Number("1") {
					return empty, fmt.Errorf("unsupported inet metadata")
				}
				for _, key := range []string{"version", "release_name"} {
					value, ok := object[key].(string)
					if !ok || value == "" || len(value) > 256 {
						return empty, fmt.Errorf("invalid inet metadata")
					}
				}
				continue
			}
			if kind != "table" && kind != "chain" && kind != "set" && kind != "rule" || !legacyFail2banNFTHandle(object) || object["family"] != "inet" {
				return empty, fmt.Errorf("unsupported inet object, family or handle")
			}
			if kind == "table" {
				if object["name"] != table {
					return empty, fmt.Errorf("unexpected inet table")
				}
			} else {
				if object["table"] != table {
					return empty, fmt.Errorf("inet object belongs to a different table")
				}
				handle := string(object["handle"].(json.Number))
				if handles[handle] {
					return empty, fmt.Errorf("duplicate inet object handle")
				}
				handles[handle] = true
			}
			delete(object, "handle")
			if kind == "set" {
				if _, present := object["elem"]; present {
					return empty, fmt.Errorf("inet topology requires terse output; set populations need independent ownership evidence")
				}
			}
			if kind != "rule" {
				name, ok := object["name"].(string)
				if !ok || name == "" || len(name) > 255 || result.objects[kind+":"+name] != nil {
					return empty, fmt.Errorf("invalid or duplicate inet declaration")
				}
				result.objects[kind+":"+name] = object
				continue
			}
			chain, ok := object["chain"].(string)
			if !ok || chain == "" || len(chain) > 255 {
				return empty, fmt.Errorf("invalid inet rule chain")
			}
			delete(object, "family")
			delete(object, "table")
			delete(object, "chain")
			if err := normalizeNFTInetCounters(object); err != nil {
				return empty, err
			}
			result.rules[chain] = append(result.rules[chain], object)
		}
	}
	return result, nil
}

func normalizeNFTInetCounters(rule map[string]any) error {
	expressions, ok := rule["expr"].([]any)
	if !ok || len(expressions) == 0 || len(expressions) > 16 {
		return fmt.Errorf("invalid inet rule expressions")
	}
	for _, expression := range expressions {
		value, ok := expression.(map[string]any)
		if !ok || len(value) != 1 {
			return fmt.Errorf("ambiguous inet expression")
		}
		if raw, present := value["counter"]; present {
			counter, ok := raw.(map[string]any)
			if !ok || !legacyFail2banNFTFields(counter, "packets bytes", "") {
				return fmt.Errorf("inet counter differs from the anonymous product profile")
			}
			for _, key := range []string{"packets", "bytes"} {
				value, ok := counter[key].(json.Number)
				number, err := strconv.ParseUint(string(value), 10, 64)
				if !ok || err != nil || strconv.FormatUint(number, 10) != string(value) {
					return fmt.Errorf("invalid inet counter progress")
				}
				counter[key] = json.Number("0")
			}
		}
	}
	return nil
}

type nftInetInterval struct{ first, last *big.Int }

func nftInetScalar(value any, kind string) (*big.Int, error) {
	if kind == "ports" {
		encoded, ok := value.(json.Number)
		number, err := strconv.ParseUint(string(encoded), 10, 16)
		if !ok || err != nil || number == 0 || strconv.FormatUint(number, 10) != string(encoded) {
			return nil, fmt.Errorf("invalid inet port operand")
		}
		return new(big.Int).SetUint64(number), nil
	}
	encoded, ok := value.(string)
	address, err := netip.ParseAddr(encoded)
	if !ok || err != nil || address.Zone() != "" || address.Is4In6() || address.String() != encoded || kind != "addr4" && kind != "addr6" || address.Is4() != (kind == "addr4") {
		return nil, fmt.Errorf("invalid inet address operand")
	}
	return new(big.Int).SetBytes(address.AsSlice()), nil
}

func nftInetOperandIntervals(value any, kind string, depth int, remaining *int) ([]nftInetInterval, error) {
	*remaining--
	if depth > 8 || *remaining < 0 {
		return nil, fmt.Errorf("inet operand exceeds structural bounds")
	}
	object, isObject := value.(map[string]any)
	if !isObject {
		number, err := nftInetScalar(value, kind)
		if err != nil {
			return nil, err
		}
		return []nftInetInterval{{number, number}}, nil
	}
	if len(object) != 1 {
		return nil, fmt.Errorf("ambiguous inet operand")
	}
	if raw, present := object["set"]; present {
		items, ok := raw.([]any)
		if !ok || len(items) == 0 || len(items) > 512 {
			return nil, fmt.Errorf("invalid inet anonymous set")
		}
		var intervals []nftInetInterval
		for _, item := range items {
			parts, err := nftInetOperandIntervals(item, kind, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			intervals = append(intervals, parts...)
		}
		return intervals, nil
	}
	if raw, present := object["range"]; present {
		items, ok := raw.([]any)
		if !ok || len(items) != 2 {
			return nil, fmt.Errorf("invalid inet operand range")
		}
		first, err := nftInetScalar(items[0], kind)
		if err != nil {
			return nil, err
		}
		last, err := nftInetScalar(items[1], kind)
		if err != nil || first.Cmp(last) > 0 {
			return nil, fmt.Errorf("invalid inet operand range endpoints")
		}
		return []nftInetInterval{{first, last}}, nil
	}
	if raw, present := object["prefix"]; present && kind != "ports" {
		prefix, ok := raw.(map[string]any)
		if !ok || !legacyFail2banNFTFields(prefix, "addr len", "") {
			return nil, fmt.Errorf("invalid inet operand prefix")
		}
		first, err := nftInetScalar(prefix["addr"], kind)
		if err != nil {
			return nil, err
		}
		length, ok := prefix["len"].(json.Number)
		bits, err := strconv.ParseUint(string(length), 10, 8)
		width := uint64(128)
		if kind == "addr4" {
			width = 32
		}
		if !ok || err != nil || bits > width || strconv.FormatUint(bits, 10) != string(length) {
			return nil, fmt.Errorf("invalid inet prefix length")
		}
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(width-bits)), big.NewInt(1))
		if new(big.Int).And(first, mask).Sign() != 0 {
			return nil, fmt.Errorf("inet prefix is not masked")
		}
		return []nftInetInterval{{first, new(big.Int).Or(first, mask)}}, nil
	}
	return nil, fmt.Errorf("unsupported inet operand")
}

func canonicalNFTInetIntervals(intervals []nftInetInterval) []string {
	sort.Slice(intervals, func(i, j int) bool {
		if compared := intervals[i].first.Cmp(intervals[j].first); compared != 0 {
			return compared < 0
		}
		return intervals[i].last.Cmp(intervals[j].last) < 0
	})
	var merged []nftInetInterval
	for _, current := range intervals {
		if len(merged) > 0 {
			prior := &merged[len(merged)-1]
			if current.first.Cmp(new(big.Int).Add(prior.last, big.NewInt(1))) <= 0 {
				if current.last.Cmp(prior.last) > 0 {
					prior.last = current.last
				}
				continue
			}
		}
		merged = append(merged, current)
	}
	result := make([]string, len(merged))
	for index, interval := range merged {
		result[index] = interval.first.String() + ":" + interval.last.String()
	}
	return result
}

func bindNFTInetRuleOperands(rule map[string]any, bindings []nftInetOperandBinding, input nftInetTemplateInputs) error {
	values := map[string][]string{"SSHPort": {input.SSHPort}, "WireGuardSubnet": {input.WireGuardSubnet}, "TCPPorts": input.TCPPorts, "UDPPorts": input.UDPPorts, "HoneyPorts": input.HoneyPorts, "LAN4": input.LAN4, "LAN6": input.LAN6}
	return bindNFTInetOperandValues(rule, bindings, values)
}

func bindNFTInetOperandValues(rule map[string]any, bindings []nftInetOperandBinding, values map[string][]string) error {
	expressions, ok := rule["expr"].([]any)
	if !ok {
		return fmt.Errorf("invalid inet expression array")
	}
	used := make(map[int]bool)
	for _, binding := range bindings {
		if binding.ExpressionIndex < 0 || binding.ExpressionIndex >= len(expressions) || used[binding.ExpressionIndex] {
			return fmt.Errorf("invalid inet operand binding index")
		}
		used[binding.ExpressionIndex] = true
		expression, ok := expressions[binding.ExpressionIndex].(map[string]any)
		if !ok || len(expression) != 1 {
			return fmt.Errorf("inet operand expression differs")
		}
		match, ok := expression["match"].(map[string]any)
		expectedLeft := map[string]any{"payload": map[string]any{"protocol": binding.Protocol, "field": binding.Field}}
		if !ok || !legacyFail2banNFTFields(match, "op left right", "") || match["op"] != "==" || !reflect.DeepEqual(match["left"], expectedLeft) {
			return fmt.Errorf("inet operand match differs")
		}
		remaining := 1024
		actual, err := nftInetOperandIntervals(match["right"], binding.Kind, 0, &remaining)
		if err != nil {
			return err
		}
		values, known := values[binding.Parameter]
		if !known || len(values) == 0 {
			return fmt.Errorf("inet parameter is unbound or empty")
		}
		var expected []nftInetInterval
		for _, value := range values {
			var operand any = json.Number(value)
			if binding.Kind != "ports" {
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					operand = value
				} else {
					operand = map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": json.Number(strconv.Itoa(prefix.Bits()))}}
				}
			}
			remaining := 4
			intervals, err := nftInetOperandIntervals(operand, binding.Kind, 0, &remaining)
			if err != nil {
				return err
			}
			expected = append(expected, intervals...)
		}
		if !reflect.DeepEqual(canonicalNFTInetIntervals(actual), canonicalNFTInetIntervals(expected)) {
			return fmt.Errorf("inet operand differs from independently bound configuration")
		}
		match["right"] = map[string]any{"template_parameter": binding.Parameter}
	}
	return nil
}

// This inspector compares the entire terse table with exact official renderer
// semantics. It never reads or changes the host and does not establish source,
// input, population or producer ownership. Those independent attestations and
// a durable intent plus generation fence remain necessary before retirement.
func inspectNFTInetTemplateTopology(source, live []byte, input nftInetTemplateInputs) (nftInetTopologyEvidence, error) {
	var empty nftInetTopologyEvidence
	evidence, err := inspectNFTInetTemplateSource(source, input)
	if err != nil {
		return empty, err
	}
	observed, err := normalizeNFTInetTopology(live)
	if err != nil {
		return empty, err
	}
	catalogue, err := loadNFTInetSemantics()
	if err != nil {
		return empty, err
	}
	var profiles struct {
		Profiles []nftInetTemplateProfile `json:"profiles"`
	}
	if err := json.Unmarshal(nftInetProfilesJSON, &profiles); err != nil {
		return empty, err
	}
	var profile nftInetTemplateProfile
	for _, candidate := range profiles.Profiles {
		if candidate.Profile == evidence.profile {
			profile = candidate
		}
	}
	seenObjects := make(map[string]bool)
	seenRules := make(map[string]int)
	chain := ""
	var traceErr error
	_, err = renderNFTInetTemplateTrace(profile, input, func(node nftInetTemplateNode, fragment string) {
		if traceErr != nil {
			return
		}
		for offset, line := range strings.Split(strings.TrimSuffix(fragment, "\n"), "\n") {
			if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if line == "\t}" {
				chain = ""
				continue
			}
			if line == "}" || strings.HasPrefix(line, "\t\ttype ") {
				continue
			}
			key, keyErr := nftInetStatementKey(nftInetStatement{Arguments: node.Arguments, Kind: node.Kind, LineOffset: offset})
			record, known := catalogue[key]
			if keyErr != nil || !known {
				traceErr = fmt.Errorf("inet emitted statement lacks compiled kernel semantics")
				return
			}
			if record.Kind != "rule" {
				identity := record.Kind + ":" + record.Name
				if seenObjects[identity] || !reflect.DeepEqual(observed.objects[identity], record.Object) {
					traceErr = fmt.Errorf("inet declaration differs from the complete official profile")
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
				traceErr = fmt.Errorf("inet rule is missing or has a different chain")
				return
			}
			rule := observed.rules[chain][index]
			if bindErr := bindNFTInetRuleOperands(rule, record.Bindings, input); bindErr != nil {
				traceErr = bindErr
				return
			}
			if !reflect.DeepEqual(rule, record.Object) {
				traceErr = fmt.Errorf("inet rule expressions, comments or ordering differ from the official profile")
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
		return empty, fmt.Errorf("inet topology contains additional objects or rules")
	}
	for chain, rules := range observed.rules {
		if seenRules[chain] != len(rules) {
			return empty, fmt.Errorf("inet chain contains additional rules")
		}
	}
	canonical, err := json.Marshal([]any{observed.objects, observed.rules})
	if err != nil {
		return empty, err
	}
	return nftInetTopologyEvidence{nftInetSourceEvidence: evidence, topologySHA256: fmt.Sprintf("%x", sha256.Sum256(canonical))}, nil
}

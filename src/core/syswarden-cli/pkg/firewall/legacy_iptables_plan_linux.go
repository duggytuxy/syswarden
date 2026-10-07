//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// These inputs describe an independently retained v4.02.8 generation. Neither
// a current configuration nor a matching live rule can supply missing origin
// evidence. The caller must attest the original captures and their boot scope.
type legacyIPTablesInputs struct {
	HAEnabled  bool     `json:"ha_enabled"`
	HAPeerPort string   `json:"ha_peer_port"`
	LANSubnets []string `json:"lan_subnets"`
}

type legacyIPTablesObservation struct {
	entries []any
	rules   []legacyIPTablesObservedRule
}

type legacyIPTablesObservedRule struct {
	handle uint64
	chain  string
	entry  any
	line   string
}

type legacyIPTablesPlan struct {
	before  []byte
	after   []byte
	targets []nftGenerationRuleTarget
	origins string
	digest  string
}

func legacyIPTablesExpectedBlock(inputs legacyIPTablesInputs) ([]string, error) {
	if len(inputs.LANSubnets) > 32 || inputs.HAEnabled && inputs.HAPeerPort == "" {
		return nil, fmt.Errorf("historical iptables generation inputs exceed the supported profile")
	}
	portRule := func(port string) string {
		return "-A INPUT -p tcp -m tcp --dport " + port + " -m comment --comment SYSWARDEN_CORE -j ACCEPT"
	}
	block := []string{portRule("62027")}
	if inputs.HAPeerPort != "" {
		port, err := strconv.ParseUint(inputs.HAPeerPort, 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != inputs.HAPeerPort {
			return nil, fmt.Errorf("historical iptables peer port is not canonical")
		}
		if inputs.HAEnabled {
			block = append(block, portRule(inputs.HAPeerPort))
		}
	}
	for _, value := range append([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}, inputs.LANSubnets...) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value {
			return nil, fmt.Errorf("historical iptables subnet input is outside the canonical IPv4 profile")
		}
		if prefix.Bits() == 0 {
			block = append(block, "-A INPUT -j ACCEPT")
		} else {
			block = append(block, "-A INPUT -s "+value+" -j ACCEPT")
		}
	}
	// Each old invocation inserted its next rule at the head of INPUT.
	slices.Reverse(block)
	return block, nil
}

// Parse output as data, not as a command language. Unrelated rule bodies stay
// opaque and are compared verbatim; they are never evaluated or reconstructed.
func legacyIPTablesSaveRules(content []byte) (map[string][]string, error) {
	if len(content) > 2<<20 || !utf8.Valid(content) || bytes.ContainsAny(content, "\x00\r") {
		return nil, fmt.Errorf("iptables observation is unbounded or contains unsupported control bytes")
	}
	result := make(map[string][]string)
	inTable, complete := false, false
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		if line == "*filter" && !inTable && !complete {
			inTable = true
			continue
		}
		if line == "COMMIT" && inTable && !complete {
			inTable, complete = false, true
			continue
		}
		if !inTable || len(line) > 65536 {
			return nil, fmt.Errorf("iptables filter observation is incomplete or ambiguous")
		}
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line)
			if len(fields) != 3 || len(fields[0]) < 2 || fields[2][0] != '[' || !strings.HasSuffix(fields[2], "]") {
				return nil, fmt.Errorf("iptables observation has an invalid chain declaration")
			}
			chain := strings.TrimPrefix(fields[0], ":")
			if _, duplicate := result[chain]; duplicate {
				return nil, fmt.Errorf("iptables observation repeats a chain")
			}
			result[chain] = nil
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) != 3 || fields[0] != "-A" || fields[2] == "" || strings.Contains(line, "\\") {
			return nil, fmt.Errorf("iptables observation has an unsupported rule record")
		}
		chain := fields[1]
		if _, exists := result[chain]; !exists || len(result[chain]) >= 16384 {
			return nil, fmt.Errorf("iptables rule has no bounded declared chain")
		}
		result[chain] = append(result[chain], line)
	}
	if !complete || inTable {
		return nil, fmt.Errorf("iptables observation lacks a complete filter table")
	}
	return result, nil
}

// Ignore only numeric packet counters. Preserve every other attribute, even
// unknown ones, so an administrator change cannot disappear in normalization.
func normalizeLegacyIPTablesCounters(entry map[string]any) error {
	raw, exists := entry["rule"]
	if !exists {
		return nil
	}
	rule, valid := raw.(map[string]any)
	if !valid {
		return fmt.Errorf("invalid historical iptables rule object")
	}
	expressions, valid := rule["expr"].([]any)
	if !valid {
		return fmt.Errorf("historical iptables rule lacks expressions")
	}
	for _, raw := range expressions {
		expression, valid := raw.(map[string]any)
		if !valid {
			return fmt.Errorf("invalid historical iptables expression")
		}
		value, exists := expression["counter"]
		if !exists {
			continue
		}
		counter, valid := value.(map[string]any)
		if !valid || len(counter) != 2 || len(expression) != 1 {
			return fmt.Errorf("unsupported historical iptables counter")
		}
		for _, name := range []string{"packets", "bytes"} {
			number, valid := counter[name].(json.Number)
			if _, err := strconv.ParseUint(string(number), 10, 64); !valid || err != nil {
				return fmt.Errorf("historical iptables counter is not unsigned")
			}
			counter[name] = json.Number("0")
		}
	}
	return nil
}

func observeLegacyIPTables(nft, save []byte) (legacyIPTablesObservation, error) {
	var empty legacyIPTablesObservation
	if !utf8.Valid(nft) {
		return empty, fmt.Errorf("historical iptables kernel observation is not valid UTF-8")
	}
	document, err := decodeLegacyFail2banNFTJSON(nft)
	if err != nil {
		return empty, err
	}
	entries, valid := document["nftables"].([]any)
	if !valid || len(entries) > 32768 {
		return empty, fmt.Errorf("invalid bounded historical iptables observation")
	}
	saved, err := legacyIPTablesSaveRules(save)
	if err != nil {
		return empty, err
	}
	result := legacyIPTablesObservation{entries: []any{}}
	counts := make(map[string]int)
	handles := make(map[uint64]bool)
	tables := 0
	for _, raw := range entries {
		entry, valid := raw.(map[string]any)
		if !valid || len(entry) != 1 {
			return empty, fmt.Errorf("ambiguous historical iptables kernel entry")
		}
		for kind, raw := range entry {
			value, valid := raw.(map[string]any)
			if !valid {
				return empty, fmt.Errorf("invalid historical iptables kernel body")
			}
			if kind == "metainfo" || value["family"] != "ip" || kind == "table" && value["name"] != "filter" || kind != "table" && value["table"] != "filter" {
				continue
			}
			if kind == "table" {
				tables++
			}
			if err := normalizeLegacyIPTablesCounters(entry); err != nil {
				return empty, err
			}
			result.entries = append(result.entries, entry)
			if kind != "rule" {
				continue
			}
			chain, valid := value["chain"].(string)
			number, numeric := value["handle"].(json.Number)
			handle, err := strconv.ParseUint(string(number), 10, 64)
			if !valid || !numeric || err != nil || handle == 0 || handles[handle] || counts[chain] >= len(saved[chain]) {
				return empty, fmt.Errorf("iptables kernel handles and text observation do not correspond")
			}
			handles[handle] = true
			result.rules = append(result.rules, legacyIPTablesObservedRule{handle, chain, entry, saved[chain][counts[chain]]})
			counts[chain]++
		}
	}
	if tables > 1 || tables == 0 && len(result.entries) != 0 {
		return empty, fmt.Errorf("historical iptables table identity is ambiguous")
	}
	for chain, lines := range saved {
		if counts[chain] != len(lines) {
			return empty, fmt.Errorf("iptables text observation contains rules absent from the kernel capture")
		}
	}
	return result, nil
}

func legacyIPTablesObservationBytes(observation legacyIPTablesObservation) ([]byte, error) {
	lines := []string{}
	for _, rule := range observation.rules {
		lines = append(lines, rule.line)
	}
	return json.Marshal(struct {
		Entries []any    `json:"entries"`
		Lines   []string `json:"lines"`
	}{observation.entries, lines})
}

func legacyIPTablesGeneratedExpression(line string) ([]any, error) {
	fields := strings.Fields(line)
	counter := map[string]any{"counter": map[string]any{"packets": json.Number("0"), "bytes": json.Number("0")}}
	accept := map[string]any{"accept": nil}
	match := func(protocol, field string, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}, "right": right}}
	}
	if line == "-A INPUT -j ACCEPT" {
		return []any{counter, accept}, nil
	}
	if len(fields) == 6 && fields[0] == "-A" && fields[1] == "INPUT" && fields[2] == "-s" && fields[4] == "-j" && fields[5] == "ACCEPT" {
		prefix, err := netip.ParsePrefix(fields[3])
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != fields[3] || prefix.Bits() == 0 {
			return nil, fmt.Errorf("historical iptables source is not canonical")
		}
		if prefix.Bits() == 32 {
			return []any{match("ip", "saddr", prefix.Addr().String()), counter, accept}, nil
		}
		return []any{match("ip", "saddr", map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": json.Number(strconv.Itoa(prefix.Bits()))}}), counter, accept}, nil
	}
	if len(fields) == 14 && strings.Join(fields[:7], " ") == "-A INPUT -p tcp -m tcp --dport" && strings.Join(fields[8:], " ") == "-m comment --comment SYSWARDEN_CORE -j ACCEPT" {
		port, err := strconv.ParseUint(fields[7], 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != fields[7] {
			return nil, fmt.Errorf("historical iptables port is not canonical")
		}
		return []any{match("tcp", "dport", json.Number(fields[7])), map[string]any{"xt": map[string]any{"type": "match", "name": "comment"}}, counter, accept}, nil
	}
	return nil, fmt.Errorf("unsupported historical iptables generated rule")
}

func verifyLegacyIPTablesGeneratedRule(rule legacyIPTablesObservedRule) error {
	expressions, err := legacyIPTablesGeneratedExpression(rule.line)
	if err != nil {
		return err
	}
	entry, valid := rule.entry.(map[string]any)
	value, body := entry["rule"].(map[string]any)
	if !valid || !body || !legacyFail2banNFTFields(value, "family table chain handle expr", "") ||
		value["family"] != "ip" || value["table"] != "filter" || value["chain"] != "INPUT" || !reflect.DeepEqual(value["expr"], expressions) {
		return fmt.Errorf("historical iptables kernel rule differs from the exact generation profile")
	}
	return nil
}

func historicalIPTablesAddedRules(before, after legacyIPTablesObservation, inputs legacyIPTablesInputs) ([]legacyIPTablesObservedRule, error) {
	block, err := legacyIPTablesExpectedBlock(inputs)
	if err != nil {
		return nil, err
	}
	if err := preserveLegacyIPTablesContainers(before, after); err != nil {
		return nil, err
	}
	original := make(map[uint64]legacyIPTablesObservedRule)
	for _, rule := range before.rules {
		original[rule.handle] = rule
	}
	var added, retained []legacyIPTablesObservedRule
	seenRetainedInput := false
	for _, rule := range after.rules {
		prior, retainedRule := original[rule.handle]
		if retainedRule {
			if !reflect.DeepEqual(prior, rule) {
				return nil, fmt.Errorf("historical observation changed a pre-existing administrator rule")
			}
			retained = append(retained, rule)
			seenRetainedInput = seenRetainedInput || rule.chain == "INPUT"
			continue
		}
		if rule.chain != "INPUT" || seenRetainedInput || rule.line != block[len(added)%len(block)] {
			return nil, fmt.Errorf("historical delta is not an exact sequence of prepended v4.02.8 compatibility blocks")
		}
		if err := verifyLegacyIPTablesGeneratedRule(rule); err != nil {
			return nil, err
		}
		added = append(added, rule)
	}
	if !reflect.DeepEqual(retained, before.rules) || len(added) == 0 || len(added) > maximumNFTGenerationRules || len(added)%len(block) != 0 {
		return nil, fmt.Errorf("historical iptables delta is incomplete or changes administrator rule ordering")
	}
	return added, nil
}

func preserveLegacyIPTablesContainers(before, after legacyIPTablesObservation) error {
	for _, original := range before.entries {
		entry := original.(map[string]any)
		if _, rule := entry["rule"]; rule {
			continue
		}
		matches := 0
		for _, current := range after.entries {
			if reflect.DeepEqual(original, current) {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("historical iptables shared container identity or policy changed")
		}
	}
	return nil
}

// Only handles proven absent in the original pre-generation observation are
// candidates. Identical rules already present, or added since that capture,
// remain administrator-owned for this plan. Captures are necessary but their
// provenance and exclusive-writer interval still require explicit review.
func prepareLegacyIPTablesPlan(before, generated, current legacyIPTablesObservation, inputs legacyIPTablesInputs, origins string) (legacyIPTablesPlan, error) {
	var empty legacyIPTablesPlan
	if !validLegacyRetirementDigest(origins) {
		return empty, fmt.Errorf("historical iptables retirement lacks independently bound origin evidence")
	}
	added, err := historicalIPTablesAddedRules(before, generated, inputs)
	if err != nil {
		return empty, err
	}
	if err := preserveLegacyIPTablesContainers(generated, current); err != nil {
		return empty, err
	}
	selected := make(map[uint64]legacyIPTablesObservedRule)
	for _, rule := range added {
		selected[rule.handle] = rule
	}
	remaining := legacyIPTablesObservation{entries: []any{}}
	var targets []nftGenerationRuleTarget
	for _, rule := range current.rules {
		prior, remove := selected[rule.handle]
		if !remove {
			remaining.rules = append(remaining.rules, rule)
			continue
		}
		if !reflect.DeepEqual(prior, rule) {
			return empty, fmt.Errorf("historical iptables target changed after its original observation")
		}
		targets = append(targets, nftGenerationRuleTarget{"ip", "filter", "INPUT", rule.handle})
	}
	if len(targets) != len(added) {
		return empty, fmt.Errorf("historical iptables target set is partially absent; preserve prior recovery evidence")
	}
	for _, raw := range current.entries {
		entry := raw.(map[string]any)
		if value, rule := entry["rule"].(map[string]any); rule {
			number := value["handle"].(json.Number)
			handle, err := strconv.ParseUint(string(number), 10, 64)
			if err != nil {
				return empty, err
			}
			if _, remove := selected[handle]; remove {
				continue
			}
		}
		remaining.entries = append(remaining.entries, raw)
	}
	first, err := legacyIPTablesObservationBytes(current)
	if err != nil {
		return empty, err
	}
	last, err := legacyIPTablesObservationBytes(remaining)
	if err != nil {
		return empty, err
	}
	plan := legacyIPTablesPlan{before: first, after: last, targets: targets, origins: origins}
	binding, err := json.Marshal([]any{origins, string(first), string(last), targets})
	if err != nil {
		return empty, err
	}
	plan.digest = nftSHA256Hex(binding)
	return plan, nil
}

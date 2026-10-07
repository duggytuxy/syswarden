//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func fixtureNFTInetKernel(t *testing.T) []json.RawMessage {
	t.Helper()
	content, err := os.ReadFile("testdata/nft_removal/inet_kernel.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Cases []struct {
			Profile string
			JSON    json.RawMessage
		}
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	sources := fixtureNFTInetSources(t)
	if len(document.Cases) != len(sources) {
		t.Fatal("incomplete inet kernel fixture coverage")
	}
	result := make([]json.RawMessage, len(sources))
	for index, row := range document.Cases {
		if row.Profile != sources[index].Profile {
			t.Fatal("misaligned inet fixture generation")
		}
		result[index] = row.JSON
	}
	return result
}

func TestNFTInetTopologyIndependentKernelFixtures(t *testing.T) {
	kernels := fixtureNFTInetKernel(t)
	for index, fixture := range fixtureNFTInetSources(t) {
		t.Run(fmt.Sprintf("%s/%02d", fixture.Profile, index), func(t *testing.T) {
			original := bytes.Clone(kernels[index])
			evidence, err := inspectNFTInetTemplateTopology([]byte(strings.TrimSuffix(fixture.Source, "\n\n")), kernels[index], fixtureNFTInetInputs(fixture))
			if err != nil {
				t.Fatal(err)
			}
			if evidence.profile != fixture.Profile || !validLegacyRetirementDigest(evidence.sourceSHA256) || !validLegacyRetirementDigest(evidence.inputSHA256) || !validLegacyRetirementDigest(evidence.topologySHA256) {
				t.Fatal("incomplete source, input or topology binding")
			}
			if !bytes.Equal(original, kernels[index]) {
				t.Fatal("inspection modified original evidence")
			}
		})
	}
}

func TestNFTInetTopologyPreservesCustomizations(t *testing.T) {
	fixtures := fixtureNFTInetSources(t)
	kernels := fixtureNFTInetKernel(t)
	object := func(entries []any, kind string) map[string]any {
		for _, entry := range entries {
			if value, ok := entry.(map[string]any)[kind].(map[string]any); ok {
				return value
			}
		}
		t.Fatal("missing fixture object", kind)
		return nil
	}
	cases := map[string]func(map[string]any, []any){
		"table comment":    func(_ map[string]any, e []any) { object(e, "table")["comment"] = "administrator table" },
		"table flags":      func(_ map[string]any, e []any) { object(e, "table")["flags"] = []any{"dormant"} },
		"table family":     func(_ map[string]any, e []any) { object(e, "table")["family"] = "ip" },
		"chain priority":   func(_ map[string]any, e []any) { object(e, "chain")["prio"] = json.Number("-11") },
		"chain comment":    func(_ map[string]any, e []any) { object(e, "chain")["comment"] = "administrator chain" },
		"rule comment":     func(_ map[string]any, e []any) { object(e, "rule")["comment"] = "administrator rule" },
		"rule chain":       func(_ map[string]any, e []any) { object(e, "rule")["chain"] = "custom" },
		"rule field":       func(_ map[string]any, e []any) { object(e, "rule")["extra"] = true },
		"rule verdict":     func(_ map[string]any, e []any) { object(e, "rule")["expr"] = []any{map[string]any{"reject": nil}} },
		"set metadata":     func(_ map[string]any, e []any) { object(e, "set")["comment"] = "administrator set" },
		"set type":         func(_ map[string]any, e []any) { object(e, "set")["type"] = "ether_addr" },
		"set content":      func(_ map[string]any, e []any) { object(e, "set")["elem"] = []any{"192.0.2.1"} },
		"empty elements":   func(_ map[string]any, e []any) { object(e, "set")["elem"] = []any{} },
		"duplicate handle": func(_ map[string]any, e []any) { object(e, "rule")["handle"] = object(e, "set")["handle"] },
		"invalid handle":   func(_ map[string]any, e []any) { object(e, "rule")["handle"] = json.Number("0") },
		"missing rule":     func(d map[string]any, e []any) { d["nftables"] = e[:len(e)-1] },
		"rule order":       func(_ map[string]any, e []any) { e[len(e)-1], e[len(e)-2] = e[len(e)-2], e[len(e)-1] },
		"extra rule": func(d map[string]any, e []any) {
			d["nftables"] = append(e, map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden", "chain": "input", "handle": json.Number("99999"), "expr": []any{map[string]any{"drop": nil}}}})
		},
		"extra chain": func(d map[string]any, e []any) {
			d["nftables"] = append(e, map[string]any{"chain": map[string]any{"family": "inet", "table": "syswarden", "name": "administrator", "handle": json.Number("99999")}})
		},
		"duplicate declaration": func(d map[string]any, e []any) {
			d["nftables"] = append(e, map[string]any{"table": object(e, "table")})
		},
		"foreign object": func(d map[string]any, e []any) {
			d["nftables"] = append(e, map[string]any{"counter": map[string]any{"name": "custom"}})
		},
		"ambiguous wrapper": func(_ map[string]any, e []any) { e[1].(map[string]any)["extra"] = nil },
	}
	for _, index := range []int{31, 67} {
		fixture := fixtures[index]
		for name, mutate := range cases {
			t.Run(fixture.Profile+"/"+name, func(t *testing.T) {
				document, err := decodeLegacyFail2banNFTJSON(kernels[index])
				if err != nil {
					t.Fatal(err)
				}
				mutate(document, document["nftables"].([]any))
				wire, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := inspectNFTInetTemplateTopology([]byte(strings.TrimSuffix(fixture.Source, "\n\n")), wire, fixtureNFTInetInputs(fixture)); err == nil {
					t.Fatal("modified topology was adopted")
				}
			})
		}
	}
}

func TestNFTInetTopologyRejectsBoundOperandDrift(t *testing.T) {
	fixtures := fixtureNFTInetSources(t)
	kernels := fixtureNFTInetKernel(t)
	for _, index := range []int{31, 67} {
		fixture := fixtures[index]
		document, err := decodeLegacyFail2banNFTJSON(kernels[index])
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for objectIndex, entry := range document["nftables"].([]any) {
			rule, ok := entry.(map[string]any)["rule"].(map[string]any)
			if !ok {
				continue
			}
			for expressionIndex, raw := range rule["expr"].([]any) {
				match, ok := raw.(map[string]any)["match"].(map[string]any)
				if !ok {
					continue
				}
				left, ok := match["left"].(map[string]any)
				if !ok {
					continue
				}
				payload, ok := left["payload"].(map[string]any)
				if !ok || payload["field"] != "saddr" && payload["field"] != "dport" {
					continue
				}
				for _, mutation := range []string{"operand", "operator", "payload", "unknown-field"} {
					fresh, _ := decodeLegacyFail2banNFTJSON(kernels[index])
					target := fresh["nftables"].([]any)[objectIndex].(map[string]any)["rule"].(map[string]any)["expr"].([]any)[expressionIndex].(map[string]any)["match"].(map[string]any)
					switch mutation {
					case "operand":
						target["right"] = json.Number("65535")
					case "operator":
						if target["op"] == "!=" {
							target["op"] = "=="
						} else {
							target["op"] = "!="
						}
					case "payload":
						target["left"].(map[string]any)["payload"].(map[string]any)["field"] = "sport"
					case "unknown-field":
						target["extra"] = true
					}
					wire, _ := json.Marshal(fresh)
					if _, err := inspectNFTInetTemplateTopology([]byte(strings.TrimSuffix(fixture.Source, "\n\n")), wire, fixtureNFTInetInputs(fixture)); err == nil {
						t.Fatalf("operand drift accepted: %s %s %d/%d", fixture.Profile, mutation, objectIndex, expressionIndex)
					}
					count++
				}
			}
		}
		if count < 40 {
			t.Fatal("insufficient payload mutation coverage", count)
		}
	}
}

func TestNFTInetOperandStrictIntervals(t *testing.T) {
	cases := []struct {
		kind, wire string
		valid      bool
		expected   []string
	}{
		{"ports", `{"set":[443,80,81,80,{"range":[82,84]}]}`, true, []string{"80:84", "443:443"}},
		{"addr4", `{"set":[{"prefix":{"addr":"192.0.2.0","len":25}},{"range":["192.0.2.128","192.0.2.255"]}]}`, true, []string{"3221225984:3221226239"}},
		{"addr6", `{"prefix":{"addr":"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe","len":127}}`, true, []string{"340282366920938463463374607431768211454:340282366920938463463374607431768211455"}},
		{"ports", `0`, false, nil}, {"ports", `65536`, false, nil}, {"ports", `1.0`, false, nil}, {"ports", `true`, false, nil},
		{"ports", `{"range":[90,80]}`, false, nil}, {"ports", `{"set":[]}`, false, nil}, {"ports", `{"set":[80],"extra":true}`, false, nil},
		{"ports", `{"prefix":{"addr":"192.0.2.0","len":24}}`, false, nil},
		{"addr4", `"::ffff:192.0.2.1"`, false, nil}, {"addr4", `"2001:db8::1"`, false, nil}, {"addr6", `"fe80::1%lo"`, false, nil},
		{"addr4", `{"prefix":{"addr":"192.0.2.1","len":24}}`, false, nil}, {"addr4", `{"prefix":{"addr":"192.0.2.0","len":33}}`, false, nil},
		{"addr4", `{"prefix":{"addr":"192.0.2.0","len":24,"extra":true}}`, false, nil},
		{"addr6", `{"range":["2001:db8::1","192.0.2.1"]}`, false, nil},
	}
	for _, row := range cases {
		var value any
		decoder := json.NewDecoder(strings.NewReader(row.wire))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		remaining := 1024
		intervals, err := nftInetOperandIntervals(value, row.kind, 0, &remaining)
		if row.valid {
			if err != nil {
				t.Fatal(row.wire, err)
			}
			actual, _ := json.Marshal(canonicalNFTInetIntervals(intervals))
			expected, _ := json.Marshal(row.expected)
			if !bytes.Equal(actual, expected) {
				t.Fatal(row.wire, string(actual), string(expected))
			}
		} else if err == nil {
			t.Fatal("invalid operand accepted", row.wire)
		}
	}
	var recursive any = json.Number("80")
	for index := 0; index < 12; index++ {
		recursive = map[string]any{"set": []any{recursive}}
	}
	remaining := 1024
	if _, err := nftInetOperandIntervals(recursive, "ports", 0, &remaining); err == nil {
		t.Fatal("unbounded operand accepted")
	}
}

func TestNFTInetTopologyLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_INET_TEMPLATE_LIVE") != "1" {
		t.Skip("requires a disposable inet template namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	nft := func(input []byte, args ...string) []byte {
		command := exec.CommandContext(ctx, "/usr/bin/nft", args...) // #nosec G204 -- Fixed fixture binary and synthetic arguments in a verified disposable network namespace.
		command.Stdin = bytes.NewReader(input)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture nft command failed: %v: %s", err, output)
		}
		return output
	}
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	fixtures := fixtureNFTInetSources(t)
	for _, fixture := range fixtures {
		source := []byte(strings.TrimSuffix(fixture.Source, "\n\n"))
		nft(append(bytes.Clone(source), '\n'), "-f", "-")
		if _, err := inspectNFTInetTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "inet", "syswarden"), fixtureNFTInetInputs(fixture)); err != nil {
			t.Fatal(fixture.Profile, err)
		}
		nft(nil, "delete", "table", "inet", "syswarden")
	}
	t.Log("All seventy-two independently generated inet variants match their actual kernel topology.")
	fixture := fixtures[67]
	source := []byte(strings.TrimSuffix(fixture.Source, "\n\n"))
	nft(append(bytes.Clone(source), '\n'), "-f", "-")
	nft(nil, "add", "element", "inet", "syswarden", "syswarden_blacklist", "{ 192.0.2.0/24 }")
	full := nft(nil, "-j", "list", "table", "inet", "syswarden")
	if _, err := inspectNFTInetTemplateTopology(source, full, fixtureNFTInetInputs(fixture)); err == nil {
		t.Fatal("populated observation was adopted as ownership evidence")
	}
	if _, err := inspectNFTInetTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "inet", "syswarden"), fixtureNFTInetInputs(fixture)); err != nil {
		t.Fatal("terse topology recognition failed", err)
	}
	if !bytes.Equal(full, nft(nil, "-j", "list", "table", "inet", "syswarden")) {
		t.Fatal("inspection modified set population")
	}
	nft(nil, "add", "rule", "inet", "syswarden", "stateful_protect", "ip", "saddr", "203.0.113.1", "drop")
	before := nft(nil, "-j", "list", "ruleset")
	if _, err := inspectNFTInetTemplateTopology(source, nft(nil, "-t", "-j", "list", "table", "inet", "syswarden"), fixtureNFTInetInputs(fixture)); err == nil {
		t.Fatal("administrator rule was adopted")
	}
	if !bytes.Equal(before, nft(nil, "-j", "list", "ruleset")) {
		t.Fatal("administrator rule or population changed")
	}
	t.Log("Set population remains unattested; added administrator protection is refused and the complete ruleset remains unchanged.")
}

func TestNFTInetTopologyCounterProgressAndMalformedCounters(t *testing.T) {
	fixture := fixtureNFTInetSources(t)[67]
	kernel := fixtureNFTInetKernel(t)[67]
	source := []byte(strings.TrimSuffix(fixture.Source, "\n\n"))
	input := fixtureNFTInetInputs(fixture)
	before, err := inspectNFTInetTemplateTopology(source, kernel, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		value any
		valid bool
	}{
		{"progress", json.Number("18446744073709551615"), true},
		{"negative", json.Number("-1"), false},
		{"fraction", json.Number("1.0"), false},
		{"overflow", json.Number("18446744073709551616"), false},
		{"string", "1", false},
		{"missing", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, _ := decodeLegacyFail2banNFTJSON(kernel)
			count := 0
			for _, entry := range document["nftables"].([]any) {
				if rule, ok := entry.(map[string]any)["rule"].(map[string]any); ok {
					for _, expression := range rule["expr"].([]any) {
						if counter, ok := expression.(map[string]any)["counter"].(map[string]any); ok {
							counter["bytes"] = test.value
							count++
						}
					}
				}
			}
			if count < 4 {
				t.Fatal("insufficient counter coverage")
			}
			wire, _ := json.Marshal(document)
			after, err := inspectNFTInetTemplateTopology(source, wire, input)
			if test.valid {
				if err != nil || before.topologySHA256 != after.topologySHA256 {
					t.Fatal("counter progress changed topology", err)
				}
			} else if err == nil {
				t.Fatal("invalid counter accepted")
			}
		})
	}
}

func TestNFTInetOperandBindsHostAndEquivalentSets(t *testing.T) {
	input := nftInetTemplateInputs{LAN4: []string{"192.0.2.1", "192.0.2.2/31"}, TCPPorts: []string{"80", "81", "82", "443"}}
	cases := []struct {
		right   string
		binding nftInetOperandBinding
	}{
		{`{"set":["192.0.2.3",{"range":["192.0.2.1","192.0.2.2"]}]}`, nftInetOperandBinding{Parameter: "LAN4", Kind: "addr4", Protocol: "ip", Field: "saddr"}},
		{`{"set":[443,{"range":[80,82]}]}`, nftInetOperandBinding{Parameter: "TCPPorts", Kind: "ports", Protocol: "tcp", Field: "dport"}},
	}
	for _, row := range cases {
		var operand any
		decoder := json.NewDecoder(strings.NewReader(row.right))
		decoder.UseNumber()
		if err := decoder.Decode(&operand); err != nil {
			t.Fatal(err)
		}
		rule := map[string]any{"expr": []any{map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": row.binding.Protocol, "field": row.binding.Field}}, "right": operand}}}}
		if err := bindNFTInetRuleOperands(rule, []nftInetOperandBinding{row.binding}, input); err != nil {
			t.Fatal(err)
		}
	}
}

func FuzzNFTInetOperandIntervals(f *testing.F) {
	for _, seed := range []string{`80`, `{"set":[80,443]}`, `{"prefix":{"addr":"192.0.2.0","len":24}}`, `{"range":["2001:db8::1","2001:db8::ffff"]}`, `{"set":[true]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		if len(wire) > 8192 {
			t.Skip()
		}
		document, err := decodeLegacyFail2banNFTJSON([]byte(`{"operand":` + wire + `}`))
		if err != nil {
			return
		}
		for _, kind := range []string{"ports", "addr4", "addr6"} {
			remaining := 1024
			intervals, err := nftInetOperandIntervals(document["operand"], kind, 0, &remaining)
			if err == nil {
				if len(intervals) == 0 {
					t.Fatal("empty operand accepted")
				}
				for _, interval := range intervals {
					if interval.first == nil || interval.last == nil || interval.first.Sign() < 0 || interval.first.Cmp(interval.last) > 0 {
						t.Fatal("invalid accepted interval")
					}
				}
				if len(canonicalNFTInetIntervals(intervals)) == 0 {
					t.Fatal("canonicalization lost operand")
				}
			}
		}
	})
}

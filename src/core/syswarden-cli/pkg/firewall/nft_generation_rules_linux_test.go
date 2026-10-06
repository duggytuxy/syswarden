//go:build linux

package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNFTGenerationRuleBatchBindsExactHandles(t *testing.T) {
	rules := []nftGenerationRuleTarget{{"ip", "filter", "INPUT", 7}, {"ip", "filter", "INPUT", 9000000000}}
	socket := &nftGenerationSocket{sequence: 1}
	requests, err := socket.mutationRequests(42, nil, rules)
	if err != nil || len(requests) != 4 {
		t.Fatal(requests, err)
	}
	if binary.BigEndian.Uint32(requests[0].wire[24:28]) != 42 {
		t.Fatal("rule batch lost its generation check")
	}
	for index, target := range rules {
		wire := requests[index+1].wire
		if binary.NativeEndian.Uint16(wire[4:6]) != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELRULE || wire[16] != unix.NFPROTO_IPV4 {
			t.Fatal("rule request addresses a different operation or family")
		}
		attributes := map[uint16][]byte{}
		for offset := 20; offset < len(wire); {
			length := int(binary.NativeEndian.Uint16(wire[offset:]))
			kind := binary.NativeEndian.Uint16(wire[offset+2:])
			attributes[kind] = wire[offset+4 : offset+length]
			offset += (length + 3) &^ 3
		}
		if len(attributes) != 3 || string(attributes[unix.NFTA_RULE_TABLE]) != "filter\x00" || string(attributes[unix.NFTA_RULE_CHAIN]) != "INPUT\x00" || binary.BigEndian.Uint64(attributes[unix.NFTA_RULE_HANDLE]) != target.Handle {
			t.Fatal("rule batch lost the exact table, chain or 64-bit handle")
		}
	}
}

// The caller has already established an empty, distinct test namespace.
func testNFTGenerationLiveRuleRetirement(t *testing.T, ctx context.Context, nft func(...string) string, connection func(string) bool) {
	t.Helper()
	nft("add", "table", "ip", "filter")
	nft("add", "chain", "ip", "filter", "INPUT", "{ type filter hook input priority 0; policy accept; }")
	nft("add", "rule", "ip", "filter", "INPUT", "ip", "saddr", "127.0.0.4", "drop")
	for range 2 {
		nft("add", "rule", "ip", "filter", "INPUT", "tcp", "dport", "62027", "accept")
	}
	document, err := decodeNFTJSON([]byte(nft("-j", "list", "ruleset")))
	if err != nil {
		t.Fatal(err)
	}
	var targets []nftGenerationRuleTarget
	for _, entry := range document.NFTables {
		if rule := entry.Rule; rule != nil && rule.Family == "ip" && rule.Table == "filter" && rule.Chain == "INPUT" {
			targets = append(targets, nftGenerationRuleTarget{"ip", "filter", "INPUT", rule.Handle})
		}
	}
	if len(targets) != 3 || connection("127.0.0.4") || !connection("127.0.0.3") {
		t.Fatal("shared rule fixture or independent protection is unavailable")
	}
	makeFence := func(rules []nftGenerationRuleTarget) *nftGenerationFence {
		fence, err := newNFTGenerationRuleFence(ctx, func(context.Context) ([]nftGenerationRuleTarget, error) { return rules, nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(fence.close)
		return fence
	}
	stale := makeFence(targets[2:])
	nft("add", "rule", "ip", "filter", "INPUT", "ip", "saddr", "127.0.0.5", "drop")
	before := nft("-j", "list", "ruleset")
	if err := stale.apply(ctx, func() error { return nil }); !errors.Is(err, unix.ERESTART) || before != nft("-j", "list", "ruleset") {
		t.Fatal("stale shared-rule generation changed the kernel", err)
	}
	failed := makeFence([]nftGenerationRuleTarget{targets[2], {"ip", "filter", "INPUT", ^uint64(0)}})
	if err := failed.apply(ctx, func() error { return nil }); !errors.Is(err, unix.ENOENT) || before != nft("-j", "list", "ruleset") {
		t.Fatal("failed rule batch did not roll back its earlier delete", err)
	}
	selected := []nftGenerationRuleTarget{targets[2]}
	valid := makeFence(selected)
	selected[0] = targets[0]
	if err := valid.apply(ctx, func() error { return nil }); err != nil {
		t.Fatal("exact shared rule retirement failed", err)
	}
	after, err := decodeNFTJSON([]byte(nft("-j", "list", "ruleset")))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint64]bool)
	for _, entry := range after.NFTables {
		if rule := entry.Rule; rule != nil && rule.Family == "ip" && rule.Table == "filter" {
			seen[rule.Handle] = true
		}
	}
	if seen[targets[2].Handle] || !seen[targets[0].Handle] || !seen[targets[1].Handle] || len(seen) != 3 || connection("127.0.0.4") || connection("127.0.0.5") || !connection("127.0.0.3") {
		t.Fatal("exact retirement changed an identical administrator rule or independent protection")
	}
	t.Log("Generation-bound shared rule deletion preserved identical administrator rules, shared table, allowed TCP and both unrelated TCP blocks.")
}

func TestNFTGenerationRuleBatchRejectsAmbiguousTargets(t *testing.T) {
	valid := nftGenerationRuleTarget{"ip", "filter", "INPUT", 7}
	for _, targets := range [][]nftGenerationRuleTarget{{valid, valid}, {{"ip", "filter", "INPUT", 0}}, {{"ip6", "filter", "INPUT", 7}}, {{"ip", "filter", "FORWARD", 7}}, {{"ip", "other", "INPUT", 7}}, make([]nftGenerationRuleTarget, maximumNFTGenerationRules+1)} {
		if validateNFTMutationTargets(nil, targets) == nil {
			t.Fatal("ambiguous rule targets accepted")
		}
	}
	if validateNFTMutationTargets([]nftTableTarget{{"ip", "filter"}}, []nftGenerationRuleTarget{valid}) == nil {
		t.Fatal("rule retirement can delete its shared table")
	}
	if _, err := newNFTGenerationRuleFence(context.Background(), nil); err == nil {
		t.Fatal("missing source inspector accepted")
	}
	socket := &nftGenerationSocket{sequence: 1}
	if _, err := socket.mutationRequests(0, nil, []nftGenerationRuleTarget{valid}); err == nil {
		t.Fatal("zero generation accepted")
	}
	var targets []nftGenerationRuleTarget
	for index := 0; index < maximumNFTGenerationRules; index++ {
		targets = append(targets, nftGenerationRuleTarget{"ip", "filter", "INPUT", uint64(index + 1)})
	}
	requests, err := socket.mutationRequests(3, nil, targets)
	if err != nil {
		t.Fatal(err)
	}
	size := 0
	for _, request := range requests {
		size += len(request.wire)
	}
	if size > maximumNFTGenerationPacket || len(requests) != maximumNFTGenerationRules+2 {
		t.Fatal("maximum rule transaction exceeds the bounded packet")
	}
	if !strings.Contains(legacyIPTablesRemovalRefusal().Error(), "does not establish ownership") {
		t.Fatal("refusal message implied name-based ownership")
	}
}

//go:build linux

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func scopedWireGuardIdentity() wireguardstate.ServerConfigurationIdentity {
	identity := exactWireGuardNFTIdentity()
	identity.PolicyVersion, identity.IPv4Subnet = 2, "10.66.0.0/16"
	return identity
}

// This literal fixture is independent of the production expression renderer.
func scopedWireGuardNFTJSON() []byte {
	wire := strings.Replace(string(exactWireGuardNFTJSON()), "syswarden-wg-v1:", "syswarden-wg-v2:", 1)
	start := strings.Index(wire, `{"rule"`)
	return []byte(wire[:start] + `
{"rule":{"family":"inet","table":"syswarden_wg","chain":"postrouting","handle":11,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-syswarden"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"ens3"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.66.0.0","len":16}}}},{"masquerade":null}]}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","handle":12,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-syswarden"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"ens3"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.66.0.0","len":16}}}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":{"set":["established","related","new"]}}},{"accept":null}]}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","handle":13,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"ens3"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"wg-syswarden"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.66.0.0","len":16}}}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":{"set":["established","related"]}}},{"accept":null}]}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","handle":14,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-syswarden"}},{"drop":null}]}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","handle":15,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"wg-syswarden"}},{"drop":null}]}}
]}`)
}

func TestScopedWireGuardGenerationBindsPolicySubnetAndOrder(t *testing.T) {
	for _, shared := range []bool{false, true} {
		input := validWireGuardRenderInput()
		input.ActiveIf, input.SharedForward = "ens3", shared
		server, _, err := renderWireGuardConfigurations(input)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := wireguardstate.ParseServerConfiguration([]byte(server))
		want := scopedWireGuardIdentity()
		want.SharedForward = shared
		if err != nil || identity != want {
			t.Fatalf("scoped identity = %#v, error = %v", identity, err)
		}
		ordered := []string{
			`postrouting iifname "wg-syswarden" oifname "ens3" ip saddr 10.66.0.0/16 masquerade`,
			`forward iifname "wg-syswarden" oifname "ens3" ip saddr 10.66.0.0/16 ct state { established, related, new } accept`,
			`forward iifname "ens3" oifname "wg-syswarden" ip daddr 10.66.0.0/16 ct state { established, related } accept`,
			`forward iifname "wg-syswarden" drop`,
			`forward oifname "wg-syswarden" drop`,
		}
		position := -1
		for _, fragment := range ordered {
			next := strings.Index(server, fragment)
			if next <= position {
				t.Fatalf("missing or reordered scoped rule %q", fragment)
			}
			position = next
		}
		for _, mutation := range [][2]string{
			{"syswarden-wg-v2:", "syswarden-wg-v1:"},
			{"ip saddr 10.66.0.0/16", "ip saddr 10.67.0.0/16"},
			{"ip daddr 10.66.0.0/16", "ip daddr 0.0.0.0/0"},
			{"ct state { established, related } accept", "ct state { established, related, new } accept"},
			{`forward iifname "wg-syswarden" drop`, `forward iifname "wg-syswarden" accept`},
		} {
			changed := strings.Replace(server, mutation[0], mutation[1], 1)
			if _, err := wireguardstate.ParseServerConfiguration([]byte(changed)); err == nil {
				t.Fatalf("accepted modified generated policy %q", mutation[0])
			}
		}
	}
	input := validWireGuardRenderInput()
	input.ActiveIf = "wg-syswarden"
	if _, _, err := renderWireGuardConfigurations(input); err == nil {
		t.Fatal("accepted the tunnel as its own egress")
	}
}

func TestScopedWireGuardRuntimeOwnershipRejectsBroadenedOrReorderedPolicy(t *testing.T) {
	identity, wire := scopedWireGuardIdentity(), scopedWireGuardNFTJSON()
	if handle, err := validateExistingWireGuardNFTTable(wire, identity); err != nil || handle != 7 {
		t.Fatalf("scoped table: %d %v", handle, err)
	}
	for _, mutation := range [][2]string{
		{`"syswarden-wg-v2:`, `"syswarden-wg-v1:`},
		{`"right":"wg-syswarden"`, `"right":"docker0"`},
		{`"right":"ens3"`, `"right":"lan0"`},
		{`"addr":"10.66.0.0"`, `"addr":"10.67.0.0"`},
		{`"len":16`, `"len":8`},
		{`"set":["established","related"]`, `"set":["established","related","new"]`},
		{`"set":["established","related","new"]`, `"set":["established","related","invalid"]`},
		{`{"drop":null}`, `{"accept":null}`},
		{`"policy":"accept"`, `"policy":"drop"`},
		{`"handle":15`, `"handle":14`},
		{`"protocol":"ip"`, `"protocol":"ip6"`},
	} {
		changed := bytes.Replace(wire, []byte(mutation[0]), []byte(mutation[1]), 1)
		if _, err := validateExistingWireGuardNFTTable(changed, identity); err == nil {
			t.Fatalf("accepted modified runtime policy %q", mutation[0])
		}
		if _, _, err := identifyAttestedOrphanedWireGuardNFTTable(changed); err == nil {
			t.Fatalf("adopted modified orphan %q", mutation[0])
		}
	}
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.NFTables[6], envelope.NFTables[8] = envelope.NFTables[8], envelope.NFTables[6]
	reordered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateExistingWireGuardNFTTable(reordered, identity); err == nil {
		t.Fatal("accepted tunnel drop before outbound permit")
	}
	if _, _, err := identifyAttestedOrphanedWireGuardNFTTable(reordered); err == nil {
		t.Fatal("adopted reordered orphan")
	}
	if _, err := validateExistingWireGuardNFTTable(exactWireGuardNFTJSON(), identity); err == nil {
		t.Fatal("accepted v1 runtime for v2 manifest")
	}
	if _, err := validateExistingWireGuardNFTTable(wire, exactWireGuardNFTIdentity()); err == nil {
		t.Fatal("accepted v2 runtime for v1 manifest")
	}
	other := identity
	other.IPv4Subnet = "10.67.0.0/16"
	if sameWireGuardNFTTableIdentity(identity, other) || sameWireGuardNFTTableIdentity(identity, exactWireGuardNFTIdentity()) {
		t.Fatal("policy identity ignored subnet or version")
	}
}

func TestScopedAndHistoricalWireGuardCleanupRemainVersionBound(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		identity, wire := exactWireGuardNFTIdentity(), exactWireGuardNFTJSON()
		if scoped {
			identity, wire = scopedWireGuardIdentity(), scopedWireGuardNFTJSON()
		}
		orphan, handle, err := identifyAttestedOrphanedWireGuardNFTTable(wire)
		if err != nil || handle != 7 || !sameWireGuardNFTTableIdentity(identity, orphan) {
			t.Fatalf("version-bound orphan: %#v %d %v", orphan, handle, err)
		}
		runner := &fakeWireGuardNFTRunner{tables: []fakeWireGuardNFTTable{{"inet", "operator", 2}, {"inet", "syswarden_wg", 7}}, detail: wire}
		if err := cleanupWireGuardReservedNFTTableWithRunner(runner, identity, func() error { return nil }, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(runner.tables, []fakeWireGuardNFTTable{{"inet", "operator", 2}}) || len(runner.deleteCalls) != 1 {
			t.Fatal("cleanup changed unrelated table")
		}
	}
}

func scopedSharedForwardJSON(t *testing.T) []byte {
	t.Helper()
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(scopedWireGuardNFTJSON(), &envelope); err != nil {
		t.Fatal(err)
	}
	parts := []string{`{"chain":{"family":"inet","table":"filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}}`, `{"rule":{"family":"inet","table":"filter","chain":"forward","handle":10,"expr":[{"drop":null}],"comment":"operator-rule"}}`}
	for _, index := range []int{6, 7} {
		var rule map[string]any
		if err := json.Unmarshal(envelope.NFTables[index]["rule"], &rule); err != nil {
			t.Fatal(err)
		}
		rule["table"], rule["comment"] = "filter", "syswarden-wg-forward-v2:"+strings.Repeat("a", 64)
		wire, err := json.Marshal(map[string]any{"rule": rule})
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, string(wire))
	}
	return []byte(`{"nftables":[` + strings.Join(parts, ",") + `]}`)
}

func TestScopedSharedForwardPreservesOperatorRulesAndRejectsCrossVersion(t *testing.T) {
	identity := scopedWireGuardIdentity()
	identity.SharedForward = true
	wire := scopedSharedForwardJSON(t)
	state, remaining, err := parseWireGuardSharedForward(wire, identity.OwnershipToken, identity)
	if err != nil || len(state.Rules) != 2 || !bytes.Contains(remaining, []byte("operator-rule")) || !bytes.Contains(remaining, []byte(`"policy":"drop"`)) || bytes.Contains(remaining, []byte(identity.OwnershipToken)) {
		t.Fatalf("scoped shared ownership: %#v %v", state, err)
	}
	for _, changed := range [][]byte{
		bytes.Replace(wire, []byte(`"established","related"`), []byte(`"established","related","new"`), 1),
		bytes.Replace(wire, []byte("10.66.0.0"), []byte("10.67.0.0"), 1),
		bytes.Replace(wire, []byte("syswarden-wg-forward-v2:"), []byte("syswarden-wg-forward-v1:"), 1),
	} {
		if _, _, err := parseWireGuardSharedForward(changed, identity.OwnershipToken, identity); err == nil {
			t.Fatal("accepted altered scoped shared rule")
		}
	}
	if _, _, err := parseWireGuardSharedForward(wire, identity.OwnershipToken); err == nil {
		t.Fatal("v1 parser adopted v2 shared rules")
	}
	if _, _, err := parseWireGuardSharedForward(sharedForwardFixture(identity.OwnershipToken), identity.OwnershipToken, identity); err == nil {
		t.Fatal("v2 parser adopted v1 shared rules")
	}
	foreign, retained, err := parseWireGuardSharedForward(wire, strings.Repeat("b", 64))
	if err != nil || len(foreign.Rules) != 0 || !bytes.Contains(retained, []byte(identity.OwnershipToken)) {
		t.Fatal("foreign shared token was adopted")
	}
	runner := &scopedSharedCleanupRunner{fakeWireGuardNFTRunner: &fakeWireGuardNFTRunner{detail: scopedWireGuardNFTJSON(), tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}}, shared: wire, identity: identity}
	if err := cleanupWireGuardSharedRuntime(context.Background(), runner, identity, func() error { return nil }, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(runner.shared, []byte("operator-rule")) || strings.Contains(runner.batch, "handle 10") || !strings.Contains(runner.batch, "handle 12") || !strings.Contains(runner.batch, "handle 13") {
		t.Fatal("shared cleanup changed unrelated policy or omitted owned entries")
	}
}

type scopedSharedCleanupRunner struct {
	*fakeWireGuardNFTRunner
	shared   []byte
	identity wireguardstate.ServerConfigurationIdentity
	batch    string
}

func (runner *scopedSharedCleanupRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	switch strings.Join(args, " ") {
	case "-a -j list chains", "-a -j list chain inet filter forward":
		return runner.shared, nil
	}
	if len(args) == 1 && strings.HasPrefix(args[0], "delete table") {
		runner.batch = args[0]
		_, remaining, err := parseWireGuardSharedForward(runner.shared, runner.identity.OwnershipToken, runner.identity)
		if err != nil {
			return nil, err
		}
		runner.shared = remaining
		return runner.fakeWireGuardNFTRunner.Run(ctx, "delete", "table", "inet", "handle", "7")
	}
	return runner.fakeWireGuardNFTRunner.Run(ctx, args...)
}

func TestScopedPolicyIdentityRejectsAmbiguousVersions(t *testing.T) {
	for _, version := range []int{-1, 1, 3} {
		identity := scopedWireGuardIdentity()
		identity.PolicyVersion = version
		if _, err := validateExistingWireGuardNFTTable(scopedWireGuardNFTJSON(), identity); err == nil {
			t.Fatalf("accepted policy version %d", version)
		}
	}
}

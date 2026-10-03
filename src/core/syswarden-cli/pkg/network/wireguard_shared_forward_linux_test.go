//go:build linux

package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func sharedForwardFixture(token string) []byte {
	return []byte(fmt.Sprintf(`{"nftables":[
{"chain":{"family":"inet","table":"filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"rule":{"family":"inet","table":"filter","chain":"forward","handle":10,"expr":[{"counter":{"packets":0,"bytes":0}},{"drop":null}],"comment":"operator-rule"}},
{"rule":{"family":"inet","table":"filter","chain":"forward","handle":17,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-syswarden"}},{"accept":null}],"comment":"syswarden-wg-forward-v1:%s"}},
{"rule":{"family":"inet","table":"filter","chain":"forward","handle":18,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"wg-syswarden"}},{"accept":null}],"comment":"syswarden-wg-forward-v1:%s"}}]}`, token, token))
}

func TestSharedForwardingRequiresExactTokenExpressionsAndHandles(t *testing.T) {
	token := strings.Repeat("a", 64)
	wire := sharedForwardFixture(token)
	state, remaining, err := parseWireGuardSharedForward(wire, token)
	if err != nil || len(state.Rules) != 2 || state.ChainHandle != 2 || state.ChainSHA256 == "" {
		t.Fatal("exact shared rules not identified", err)
	}
	if bytes.Contains(remaining, []byte(token)) || !bytes.Contains(remaining, []byte("operator-rule")) || !bytes.Contains(remaining, []byte(`"policy":"drop"`)) {
		t.Fatal("filtering changed foreign state or retained owned rules")
	}
	foreign, unchanged, err := parseWireGuardSharedForward(wire, strings.Repeat("b", 64))
	if err != nil || len(foreign.Rules) != 0 || !bytes.Contains(unchanged, []byte(token)) {
		t.Fatal("foreign token was claimed", err)
	}
	for _, mutation := range [][2]string{
		{`"key":"oifname"`, `"key":"iifname"`},
		{`"handle":18`, `"handle":17`},
		{`"handle":17`, `"handle":0`},
		{`"right":"wg-syswarden"`, `"right":"other-vpn"`},
		{`{"accept":null}`, `{"drop":null}`},
		{`"prio":0`, `"prio":-10`},
		{`"type":"filter"`, `"type":"nat"`},
		{`"handle":17`, `"handle":17,"userdata":"unexpected"`},
	} {
		changed := bytes.Replace(wire, []byte(mutation[0]), []byte(mutation[1]), 1)
		if _, _, err := parseWireGuardSharedForward(changed, token); err == nil {
			t.Fatalf("accepted changed owned state: %s", mutation[0])
		}
	}
}

type sharedCleanupTestRunner struct {
	table     *fakeWireGuardNFTRunner
	shared    []byte
	mutations []string
	fail      bool
}

func (runner *sharedCleanupTestRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	switch strings.Join(args, " ") {
	case "-a -j list chains", "-a -j list chain inet filter forward":
		return runner.shared, nil
	}
	if len(args) == 1 && strings.HasPrefix(args[0], "delete ") {
		if runner.fail {
			return nil, errors.New("injected atomic transaction failure")
		}
		runner.mutations = append(runner.mutations, args[0])
		_, remaining, err := parseWireGuardSharedForward(runner.shared, strings.Repeat("a", 64))
		if err != nil {
			return nil, err
		}
		runner.shared = remaining
		if strings.Contains(args[0], "delete table") {
			return runner.table.Run(ctx, "delete", "table", "inet", "handle", "7")
		}
		return nil, nil
	}
	return runner.table.Run(ctx, args...)
}

func TestSharedForwardCleanupPreservesForeignRulesWithOrWithoutPrivateTable(t *testing.T) {
	for _, present := range []bool{true, false} {
		runner := &sharedCleanupTestRunner{table: sharedPrivateTableFixture(present), shared: sharedForwardFixture(strings.Repeat("a", 64))}
		identity := exactWireGuardNFTIdentity()
		identity.SharedForward = true
		if err := cleanupWireGuardReservedNFTTableWithRunner(runner, identity, func() error { return nil }, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if len(runner.mutations) != 1 || strings.Contains(runner.mutations[0], "handle 10") || !bytes.Contains(runner.shared, []byte("operator-rule")) || !bytes.Contains(runner.shared, []byte(`"policy":"drop"`)) {
			t.Fatal("cleanup changed foreign state")
		}
		if err := cleanupWireGuardReservedNFTTableWithRunner(runner, identity, func() error { return nil }, func() error { return nil }); err != nil || len(runner.mutations) != 1 {
			t.Fatal("cleanup not idempotent", err)
		}
	}
}

func TestSharedForwardCleanupRejectsLateDriftAndAtomicFailure(t *testing.T) {
	for _, kind := range []string{"token", "handle", "active", "manifest", "atomic-failure"} {
		t.Run(kind, func(t *testing.T) {
			runner := &sharedCleanupTestRunner{table: sharedPrivateTableFixture(true), shared: sharedForwardFixture(strings.Repeat("a", 64)), fail: kind == "atomic-failure"}
			identity := exactWireGuardNFTIdentity()
			identity.SharedForward = true
			checks := 0
			attest := func() error {
				checks++
				if checks == 2 {
					switch kind {
					case "token":
						runner.shared = bytes.ReplaceAll(runner.shared, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)))
					case "handle":
						runner.shared = bytes.Replace(runner.shared, []byte(`"handle":17`), []byte(`"handle":99`), 1)
					case "manifest":
						return errors.New("manifest changed")
					}
				}
				return nil
			}
			inactive := func() error {
				if kind == "active" && checks >= 2 {
					return errors.New("VPN activated")
				}
				return nil
			}
			if err := cleanupWireGuardReservedNFTTableWithRunner(runner, identity, attest, inactive); err == nil {
				t.Fatal("accepted changed runtime")
			}
			if len(runner.mutations) != 0 {
				t.Fatal("mutated after refusal")
			}
		})
	}
}

func sharedPrivateTableFixture(present bool) *fakeWireGuardNFTRunner {
	runner := &fakeWireGuardNFTRunner{detail: exactWireGuardNFTJSON()}
	if present {
		runner.tables = []fakeWireGuardNFTTable{{family: "inet", name: "syswarden_wg", handle: 7}}
	}
	return runner
}

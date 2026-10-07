//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func fixtureLegacyFail2banNFT(t *testing.T, upstream bool) ([]byte, legacyFail2banNFTClaim) {
	t.Helper()
	claim := legacyFail2banNFTClaim{jail: "syswarden-portscan", profile: "syswarden-nft", addressFamily: "ip", filePlan: strings.Repeat("a", 64), actionsSHA256: strings.Repeat("b", 64), bans: []string{"127.0.0.2"}}
	table, chain, set := "syswarden_f2b", "syswarden-portscan", "f2b-syswarden-portscan"
	if upstream {
		claim.profile = "nftables-allports"
		table, chain, set = "f2b-table", "f2b-chain", "addr-set-syswarden-portscan"
	}
	rule := `[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@SET"}},{"drop":null}]`
	if upstream {
		rule = `[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@SET"}},{"reject":{"type":"icmp","expr":"port-unreachable"}}]`
	}
	content := `{"nftables":[
{"metainfo":{"json_schema_version":1}},
{"table":{"family":"inet","name":"TABLE","handle":1}},
{"chain":{"family":"inet","table":"TABLE","name":"CHAIN","handle":1,"type":"filter","hook":"input","prio":-1,"policy":"accept"}},
{"chain":{"family":"inet","table":"TABLE","name":"administrator","handle":4,"type":"filter","hook":"input","prio":-2,"policy":"accept"}},
{"set":{"family":"inet","table":"TABLE","name":"SET","type":"ipv4_addr","handle":2,"elem":["127.0.0.2"]}},
{"set":{"family":"inet","table":"TABLE","name":"administrator-ban","type":"ipv4_addr","handle":5,"elem":["127.0.0.3"]}},
{"rule":{"family":"inet","table":"TABLE","chain":"CHAIN","handle":3,"expr":RULE}},
{"rule":{"family":"inet","table":"TABLE","chain":"administrator","handle":6,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@administrator-ban"}},{"drop":null}]}}
]}`
	content = strings.NewReplacer("RULE", rule, "TABLE", table, "CHAIN", chain, "SET", set).Replace(content)
	// NewReplacer does not recursively expand the replacement rule.
	content = strings.ReplaceAll(content, "SET", set)
	return []byte(content), claim
}

func TestLegacyFail2banNFTTransitionPreservesSharedProtection(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		content, claim := fixtureLegacyFail2banNFT(t, upstream)
		plan, err := prepareLegacyFail2banNFTTransition(content, []legacyFail2banNFTClaim{claim})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(plan.after, []byte("administrator-ban")) || bytes.Contains(plan.after, []byte("syswarden-portscan")) ||
			bytes.Contains(plan.transaction, []byte("flush")) || bytes.Contains(plan.transaction, []byte(`"delete":{"table"`)) {
			t.Fatal("transaction changed shared protection or retained its target")
		}
		if bytes.Contains(plan.after, []byte("f2b-chain")) != upstream {
			t.Fatal("shared chain was removed or exclusive chain retained")
		}
		other := claim
		other.actionsSHA256 = strings.Repeat("c", 64)
		changed, err := prepareLegacyFail2banNFTTransition(content, []legacyFail2banNFTClaim{other})
		if err != nil || changed.sha256 == plan.sha256 {
			t.Fatal("action provenance was not bound into the transaction")
		}
	}
}

func TestLegacyFail2banNFTTransitionTreatsProvenAbsenceAsNoop(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		_, claim := fixtureLegacyFail2banNFT(t, upstream)
		plan, err := prepareLegacyFail2banNFTTransition([]byte(`{"nftables":[]}`), []legacyFail2banNFTClaim{claim})
		if err != nil || !bytes.Equal(plan.before, []byte(`[]`)) || !bytes.Equal(plan.before, plan.after) || string(plan.transaction) != `{"nftables":[]}` {
			t.Fatal("proven table absence requires no deletion", err)
		}
	}
}

func TestLegacyFail2banNFTTableAbsenceRequiresSuccessfulExactInventory(t *testing.T) {
	for _, fixture := range []struct {
		content string
		valid   bool
		present bool
	}{
		{`{"nftables":[]}`, true, false},
		{`{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, true, false},
		{`{"nftables":[{"table":{"family":"inet","name":"f2b-table","handle":1}}]}`, true, true},
		{`{"nftables":[{"table":{"family":"ip","name":"f2b-table","handle":1}}]}`, true, false},
		{`{"nftables":[{"metainfo":{"json_schema_version":2}}]}`, false, false},
		{`{"nftables":null}`, false, false},
		{`{"nftables":[{"table":{"family":"inet","name":"f2b-table"}}]}`, false, false},
		{`{"nftables":[{"table":{"family":"inet","name":"f2b-table","handle":1}},{"table":{"family":"inet","name":"f2b-table","handle":2}}]}`, false, false},
		{`{"nftables":[{"error":{"message":"missing table"}}]}`, false, false},
	} {
		present, err := legacyFail2banNFTTablePresence([]byte(fixture.content), "f2b-table")
		if (err == nil) != fixture.valid || present != fixture.present {
			t.Fatal("unsafe table-absence decision", err)
		}
	}
}

func TestLegacyFail2banNFTTransitionRefusesAmbiguityAndDependencies(t *testing.T) {
	for _, change := range []string{"duplicate-key", "extra-document", "unbound", "duplicate-claim", "foreign-element", "missing-ban-evidence", "set-type", "set-comment", "set-flags", "non-address", "changed-policy", "changed-verdict", "duplicate-rule", "shared-reference", "chain-reference", "extra-target-rule", "unrecognized-target-expression"} {
		t.Run(change, func(t *testing.T) {
			content, claim := fixtureLegacyFail2banNFT(t, false)
			claims := []legacyFail2banNFTClaim{claim}
			switch change {
			case "duplicate-key":
				content = bytes.Replace(content, []byte(`"type":"ipv4_addr"`), []byte(`"type":"ipv6_addr","type":"ipv4_addr"`), 1)
			case "extra-document":
				content = append(content, []byte(`{}`)...)
			case "unbound":
				claims[0].filePlan = ""
			case "missing-ban-evidence":
				claims[0].bans = nil
			case "foreign-element":
				content = bytes.Replace(content, []byte(`"127.0.0.2"`), []byte(`"127.0.0.2","127.0.0.4"`), 1)
			case "duplicate-claim":
				claims = append(claims, claim)
			case "set-type":
				content = bytes.Replace(content, []byte(`"type":"ipv4_addr"`), []byte(`"type":"ipv6_addr"`), 1)
			case "set-comment":
				content = bytes.Replace(content, []byte(`"type":"ipv4_addr"`), []byte(`"type":"ipv4_addr","comment":"administrator modification"`), 1)
			case "set-flags":
				content = bytes.Replace(content, []byte(`"type":"ipv4_addr"`), []byte(`"type":"ipv4_addr","flags":["interval"]`), 1)
			case "non-address":
				content = bytes.Replace(content, []byte(`"127.0.0.2"`), []byte(`"127.0.0.0/8"`), 1)
			case "changed-policy":
				content = bytes.Replace(content, []byte(`"policy":"accept"`), []byte(`"policy":"drop"`), 1)
			case "changed-verdict":
				content = bytes.Replace(content, []byte(`"drop":null`), []byte(`"accept":null`), 1)
			case "shared-reference":
				content = bytes.Replace(content, []byte(`"@administrator-ban"`), []byte(`"@f2b-syswarden-portscan"`), 1)
			case "chain-reference":
				content = bytes.Replace(content, []byte(`"right":"@administrator-ban"`), []byte(`"right":{"jump":{"target":"syswarden-portscan"}}`), 1)
			case "extra-target-rule":
				content = bytes.Replace(content, []byte(`"chain":"administrator"`), []byte(`"chain":"syswarden-portscan"`), 1)
			case "unrecognized-target-expression":
				content = bytes.Replace(content, []byte(`"expr":[{"match"`), []byte(`"expr":[{"counter":{"packets":0,"bytes":0}},{"match"`), 1)
			case "duplicate-rule":
				doc, err := decodeLegacyFail2banNFTJSON(content)
				if err != nil {
					t.Fatal(err)
				}
				entries := doc["nftables"].([]any)
				doc["nftables"] = append(entries, entries[6])
				content, err = json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
			}
			plan, err := prepareLegacyFail2banNFTTransition(content, claims)
			if err == nil || plan.sha256 != "" || plan.transaction != nil {
				t.Fatal("ambiguous or dependent retirement returned a transaction")
			}
		})
	}
}

type fixtureLegacyFail2banNFTRunner struct {
	before, after []byte
	plan          legacyFail2banNFTTransition
	writes        int
	applied       bool
	unconfirmed   bool
}

func (runner *fixtureLegacyFail2banNFTRunner) Run(_ context.Context, input []byte, args ...string) ([]byte, error) {
	if reflect.DeepEqual(args, []string{"-j", "list", "table", runner.plan.family, runner.plan.table}) && input == nil {
		if runner.applied {
			return runner.after, nil
		}
		return runner.before, nil
	}
	if !reflect.DeepEqual(args, []string{"-j", "-f", "-"}) || !bytes.Equal(input, runner.plan.transaction) {
		return nil, fmt.Errorf("unexpected fixture mutation")
	}
	runner.writes++
	runner.applied = true
	if runner.unconfirmed {
		return nil, fmt.Errorf("fixture lost completion after atomic application")
	}
	return nil, nil
}

func TestLegacyFail2banNFTApplyRequiresExactDurableAuthorizationAndResumes(t *testing.T) {
	for _, change := range []string{"none", "lost-completion", "missing-guard", "refused", "changed-before", "changed-after", "tampered-plan"} {
		t.Run(change, func(t *testing.T) {
			content, claim := fixtureLegacyFail2banNFT(t, true)
			plan, err := prepareLegacyFail2banNFTTransition(content, []legacyFail2banNFTClaim{claim})
			if err != nil {
				t.Fatal(err)
			}
			runner := &fixtureLegacyFail2banNFTRunner{before: content, after: append(append([]byte(`{"nftables":`), plan.after...), '}'), plan: plan}
			calls := 0
			guard := func(_ context.Context, digest string) error {
				calls++
				if digest != runner.plan.sha256 || change == "refused" {
					return fmt.Errorf("fixture authorization refused")
				}
				return nil
			}
			switch change {
			case "missing-guard":
				guard = nil
			case "lost-completion":
				runner.unconfirmed = true
			case "changed-before":
				runner.before = bytes.Replace(content, []byte("127.0.0.3"), []byte("127.0.0.4"), 1)
			case "changed-after":
				runner.after = bytes.Replace(runner.after, []byte("127.0.0.3"), []byte("127.0.0.4"), 1)
			case "tampered-plan":
				plan.transaction = []byte(`{"nftables":[{"flush":{"ruleset":null}}]}`)
			}
			err = applyLegacyFail2banNFTTransition(context.Background(), runner, plan, guard)
			if (err == nil) != (change == "none") {
				t.Fatal("unexpected transaction outcome", err)
			}
			if change == "none" || change == "lost-completion" {
				if err := applyLegacyFail2banNFTTransition(context.Background(), runner, plan, guard); err != nil || runner.writes != 1 || calls < 4 {
					t.Fatal("atomic retry did not recognize the exact after-state", err)
				}
			} else if change != "changed-after" && runner.writes != 0 {
				t.Fatal("refused plan changed kernel state")
			}
		})
	}
}

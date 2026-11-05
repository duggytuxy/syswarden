//go:build linux

package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const inactiveNativeNFTFixture = `{"nftables":[{"metainfo":{"version":"test","json_schema_version":1}},{"table":{"family":"inet","name":"administrator","handle":1}},{"chain":{"family":"inet","table":"administrator","name":"input","handle":2,"type":"filter","hook":"input","prio":0,"policy":"drop"}},{"counter":{"family":"inet","table":"administrator","name":"hits","handle":3,"packets":1,"bytes":20}},{"rule":{"family":"inet","table":"administrator","chain":"input","handle":4,"expr":[{"counter":{"packets":1,"bytes":20}},{"counter":"hits"},{"accept":null}]}}]}`

func TestInactiveNativeNFTPreservesUnrelatedPolicyAndIgnoresOnlyCounters(t *testing.T) {
	first, err := inactiveNativeNFTDigest([]byte(inactiveNativeNFTFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"counter", "metainfo", "policy", "rule", "handle", "table", "named-counter"} {
		t.Run(name, func(t *testing.T) {
			raw := inactiveNativeNFTFixture
			switch name {
			case "counter":
				raw = strings.ReplaceAll(strings.ReplaceAll(raw, `"packets":1`, `"packets":900`), `"bytes":20`, `"bytes":18000`)
			case "metainfo":
				raw = strings.Replace(raw, `"version":"test"`, `"version":"other"`, 1)
			case "policy":
				raw = strings.Replace(raw, `"policy":"drop"`, `"policy":"accept"`, 1)
			case "rule":
				raw = strings.Replace(raw, `"accept":null`, `"drop":null`, 1)
			case "handle":
				raw = strings.Replace(raw, `"handle":4`, `"handle":5`, 1)
			case "table":
				raw = strings.ReplaceAll(raw, "administrator", "other-administrator")
			case "named-counter":
				raw = strings.Replace(raw, `"counter":"hits"`, `"counter":"other"`, 1)
			}
			second, err := inactiveNativeNFTDigest([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if (first == second) != (name == "counter" || name == "metainfo") {
				t.Fatal("firewall semantics lost or counters treated as policy")
			}
		})
	}
}

func TestInactiveNativeNFTRefusesAmbiguousOrProductState(t *testing.T) {
	cases := map[string]string{
		"table":            strings.ReplaceAll(inactiveNativeNFTFixture, "administrator", "syswarden"),
		"comment":          strings.Replace(inactiveNativeNFTFixture, `"handle":4`, `"comment":"SysWarden legacy","handle":4`, 1),
		"legacy-interface": strings.Replace(inactiveNativeNFTFixture, `"counter":"hits"`, `"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-syswarden"}`, 1),
		"duplicate":        `{"nftables":[],"nftables":[]}`,
		"trailing":         `{"nftables":[]} {}`,
		"missing-table":    `{"nftables":[{"chain":{"family":"inet","table":"other","name":"input"}}]}`,
		"unknown":          `{"nftables":[{"unexpected":{"family":"inet","name":"other"}}]}`,
		"family":           strings.ReplaceAll(inactiveNativeNFTFixture, `"family":"inet"`, `"family":"unknown"`),
		"null":             `{"nftables":null}`,
		"negative-counter": strings.Replace(inactiveNativeNFTFixture, `"bytes":20`, `"bytes":-1`, 1),
		"counter-extra":    strings.Replace(inactiveNativeNFTFixture, `"counter":{"packets":1`, `"counter":{"unexpected":1,"packets":1`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := inactiveNativeNFTDigest([]byte(raw)); err == nil {
				t.Fatal("ambiguous/product state accepted")
			}
		})
	}
	if _, err := inactiveNativeNFTDigest([]byte(`{"nftables":[]}`)); err != nil {
		t.Fatal("empty real ruleset representation rejected", err)
	}
}

type inactiveNativeNFTRunner struct {
	t           *testing.T
	calls       int
	drift, fail bool
}

func (r *inactiveNativeNFTRunner) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	r.t.Helper()
	if input != nil || strings.Join(args, " ") != "-j list ruleset" {
		r.t.Fatal("observer attempted mutation or non-fixed command")
	}
	r.calls++
	if r.fail {
		return nil, errors.New("unavailable")
	}
	raw := inactiveNativeNFTFixture
	if r.drift && r.calls > 1 {
		raw = strings.Replace(raw, `"policy":"drop"`, `"policy":"accept"`, 1)
	}
	return []byte(raw), ctx.Err()
}
func TestInactiveNativeNFTDoubleReadIsBoundedReadOnlyAndRefusesDrift(t *testing.T) {
	for _, name := range []string{"valid", "drift", "unavailable", "canceled"} {
		t.Run(name, func(t *testing.T) {
			runner := &inactiveNativeNFTRunner{t: t, drift: name == "drift", fail: name == "unavailable"}
			ctx := t.Context()
			if name == "canceled" {
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelCtx
			}
			_, err := observeInactiveNativeNFTWith(ctx, runner)
			if (err == nil) != (name == "valid") {
				t.Fatalf("read-only observation: %v", err)
			}
			if name == "canceled" && runner.calls != 0 {
				t.Fatal("canceled observation dispatched a command")
			}
			if runner.calls > 2 {
				t.Fatal("unbounded observer retries")
			}
		})
	}
}

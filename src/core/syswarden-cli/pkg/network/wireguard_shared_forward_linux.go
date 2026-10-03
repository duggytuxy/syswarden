//go:build linux

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
)

const wireGuardSharedForwardCommentPrefix = "syswarden-wg-forward-v1:"

type wireGuardSharedForwardState struct {
	ChainHandle uint64                               `json:"chain_handle"`
	ChainSHA256 string                               `json:"chain_sha256"`
	Rules       []LegacyWireGuardForwardRuleEvidence `json:"rules"`
}

// Only rules carrying this manifest's exact token and expression are owned.
// The containing chain and every other rule remain operator-managed.
func parseWireGuardSharedForward(wire []byte, token string) (wireGuardSharedForwardState, []byte, error) {
	state := wireGuardSharedForwardState{Rules: []LegacyWireGuardForwardRuleEvidence{}}
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return state, nil, fmt.Errorf("decode shared WireGuard forwarding state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || envelope.NFTables == nil {
		return state, nil, fmt.Errorf("shared WireGuard forwarding state is incomplete")
	}
	seen := make(map[uint64]bool)
	directions := make(map[string]bool)
	remaining := make([]map[string]json.RawMessage, 0, len(envelope.NFTables))
	for _, element := range envelope.NFTables {
		if len(element) != 1 {
			return state, nil, fmt.Errorf("ambiguous shared WireGuard forwarding element")
		}
		owned := false
		for kind, raw := range element {
			switch kind {
			case "metainfo", "table":
			case "chain":
				var chain struct {
					Family string `json:"family"`
					Table  string `json:"table"`
					Name   string `json:"name"`
					Type   string `json:"type"`
					Hook   string `json:"hook"`
					Prio   *int   `json:"prio"`
					Policy string `json:"policy"`
					Handle uint64 `json:"handle"`
				}
				if err := json.Unmarshal(raw, &chain); err != nil || state.ChainHandle != 0 ||
					chain.Family != "inet" || chain.Table != "filter" || chain.Name != "forward" ||
					chain.Type != "filter" || chain.Hook != "forward" || chain.Prio == nil || *chain.Prio != 0 ||
					(chain.Policy != "accept" && chain.Policy != "drop") || chain.Handle == 0 {
					return state, nil, fmt.Errorf("shared inet filter forward chain is not the historical base chain")
				}
				var canonical bytes.Buffer
				if err := json.Compact(&canonical, raw); err != nil {
					return state, nil, err
				}
				state.ChainHandle, state.ChainSHA256 = chain.Handle, retirementDigest(canonical.Bytes())
			case "rule":
				var rule struct {
					Family  string                       `json:"family"`
					Table   string                       `json:"table"`
					Chain   string                       `json:"chain"`
					Comment string                       `json:"comment"`
					Expr    []map[string]json.RawMessage `json:"expr"`
					Handle  uint64                       `json:"handle"`
				}
				if err := json.Unmarshal(raw, &rule); err != nil || rule.Family != "inet" ||
					rule.Table != "filter" || rule.Chain != "forward" || rule.Handle == 0 || seen[rule.Handle] {
					return state, nil, fmt.Errorf("shared forwarding rule identity is ambiguous")
				}
				seen[rule.Handle] = true
				if rule.Comment != wireGuardSharedForwardCommentPrefix+token {
					continue
				}
				if !wireGuardOwnershipTokenName.MatchString(token) || decodeStrictWireGuardNFTObject(raw, &rule, "owned shared forward rule") != nil {
					return state, nil, fmt.Errorf("owned shared forwarding rule is not exact")
				}
				signature, err := wireGuardNFTExpressionSignature(rule.Expr)
				direction := strings.TrimSuffix(signature, "=wg-syswarden:accept")
				if err != nil || (direction != "iifname" && direction != "oifname") || directions[direction] {
					return state, nil, fmt.Errorf("owned shared forwarding expression is changed or duplicated")
				}
				directions[direction] = true
				state.Rules = append(state.Rules, LegacyWireGuardForwardRuleEvidence{Direction: direction, Handle: rule.Handle})
				owned = true
			default:
				return state, nil, fmt.Errorf("unexpected shared forwarding element %s", kind)
			}
		}
		if !owned {
			remaining = append(remaining, element)
		}
	}
	if state.ChainHandle == 0 {
		return state, nil, fmt.Errorf("shared forwarding chain identity is absent")
	}
	sort.Slice(state.Rules, func(i, j int) bool { return state.Rules[i].Direction < state.Rules[j].Direction })
	envelope.NFTables = remaining
	filtered, err := json.Marshal(envelope)
	return state, filtered, err
}

func inspectWireGuardSharedForward(ctx context.Context, runner wireGuardNFTCommandRunner, token string) (wireGuardSharedForwardState, error) {
	empty := wireGuardSharedForwardState{Rules: []LegacyWireGuardForwardRuleEvidence{}}
	wire, err := runner.Run(ctx, "-a", "-j", "list", "chains")
	if err != nil {
		return empty, fmt.Errorf("inventory shared forwarding chain: %w", err)
	}
	handle, err := retirementForwardChainHandle(wire)
	if err != nil || handle == 0 {
		return empty, err
	}
	wire, err = runner.Run(ctx, "-a", "-j", "list", "chain", "inet", "filter", "forward")
	if err != nil {
		return empty, err
	}
	state, _, err := parseWireGuardSharedForward(wire, token)
	if err != nil || state.ChainHandle != handle {
		return empty, errors.Join(fmt.Errorf("shared forwarding chain changed during inspection"), err)
	}
	return state, nil
}

func attestWireGuardSharedForward(ctx context.Context, runner wireGuardNFTCommandRunner, identity wireguardstate.ServerConfigurationIdentity, tablePresent bool) error {
	if !identity.SharedForward {
		return nil
	}
	state, err := inspectWireGuardSharedForward(ctx, runner, identity.OwnershipToken)
	if err != nil {
		return err
	}
	if state.ChainHandle == 0 {
		return fmt.Errorf("migrated WireGuard requires the existing inet filter forward base chain")
	}
	want := 0
	if tablePresent {
		want = 2
	}
	if len(state.Rules) != want {
		return fmt.Errorf("migrated WireGuard shared forwarding inventory is incomplete or stale")
	}
	return nil
}

type wireGuardSharedCleanupState struct {
	TableHandle uint64
	TableSHA256 string
	Forward     wireGuardSharedForwardState
}

func inspectWireGuardSharedCleanup(ctx context.Context, runner wireGuardNFTCommandRunner, identity wireguardstate.ServerConfigurationIdentity) (wireGuardSharedCleanupState, error) {
	var state wireGuardSharedCleanupState
	present, handle, err := wireGuardReservedNFTTableIdentity(ctx, runner)
	if err != nil {
		return state, err
	}
	if present {
		wire, err := runner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
		if err != nil {
			return state, err
		}
		current, err := validateExistingWireGuardNFTTable(wire, identity)
		if err != nil || current != handle {
			return state, errors.Join(fmt.Errorf("migrated WireGuard table is not manifest-bound"), err)
		}
		state.TableHandle, state.TableSHA256 = handle, retirementDigest(wire)
	}
	state.Forward, err = inspectWireGuardSharedForward(ctx, runner, identity.OwnershipToken)
	return state, err
}

func cleanupWireGuardSharedRuntime(ctx context.Context, runner wireGuardNFTCommandRunner, identity wireguardstate.ServerConfigurationIdentity, reattestIdentity, reattestInactive func() error) error {
	initial, err := inspectWireGuardSharedCleanup(ctx, runner, identity)
	if err != nil {
		return err
	}
	for range 2 {
		if err := reattestIdentity(); err != nil {
			return err
		}
		if err := reattestInactive(); err != nil {
			return err
		}
		current, err := inspectWireGuardSharedCleanup(ctx, runner, identity)
		if err != nil || !reflect.DeepEqual(initial, current) {
			return errors.Join(fmt.Errorf("migrated WireGuard runtime changed before cleanup"), err)
		}
	}
	var script strings.Builder
	if initial.TableHandle != 0 {
		fmt.Fprintf(&script, "delete table inet handle %d;\n", initial.TableHandle)
	}
	for _, rule := range initial.Forward.Rules {
		fmt.Fprintf(&script, "delete rule inet filter forward handle %d;\n", rule.Handle)
	}
	if script.Len() != 0 {
		if _, err := runner.Run(ctx, script.String()); err != nil {
			return fmt.Errorf("remove exact migrated WireGuard runtime: %w", err)
		}
	}
	after, err := inspectWireGuardSharedCleanup(ctx, runner, identity)
	if err != nil || after.TableHandle != 0 || len(after.Forward.Rules) != 0 {
		return errors.Join(fmt.Errorf("migrated WireGuard runtime cleanup did not converge"), err)
	}
	return nil
}

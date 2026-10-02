//go:build linux

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// A failed list-chain command is never interpreted as absence. The successful
// complete chain inventory must first prove absence, or bind the target handle.
func (host legacyWireGuardRecoveryHost) inspectRetirementForwardRules(ctx context.Context) (map[string][]LegacyWireGuardForwardRuleEvidence, uint64, error) {
	empty := map[string][]LegacyWireGuardForwardRuleEvidence{"wg0": {}, "wg-syswarden": {}}
	wire, err := host.nftRunner.Run(ctx, "-a", "-j", "list", "chains")
	if err != nil {
		return nil, 0, fmt.Errorf("inventory shared forward chain before retirement: %w", err)
	}
	handle, err := retirementForwardChainHandle(wire)
	if err != nil {
		return nil, 0, err
	}
	if handle == 0 {
		return empty, 0, nil
	}
	wire, err = host.nftRunner.Run(ctx, "-a", "-j", "list", "chain", "inet", "filter", "forward")
	if err != nil {
		return nil, 0, fmt.Errorf("read inventoried shared forward chain: %w", err)
	}
	currentHandle, err := retirementForwardChainHandle(wire)
	if err != nil || currentHandle != handle {
		return nil, 0, errors.Join(fmt.Errorf("shared forward chain changed during retirement inspection"), err)
	}
	rules, err := matchingLegacyWireGuardForwardRules(wire)
	return rules, handle, err
}

func retirementForwardChainHandle(wire []byte) (uint64, error) {
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return 0, fmt.Errorf("decode shared chain inventory: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || envelope.NFTables == nil {
		return 0, fmt.Errorf("shared chain inventory is incomplete or has trailing data")
	}
	var handle uint64
	for _, element := range envelope.NFTables {
		if len(element) != 1 {
			return 0, fmt.Errorf("ambiguous shared chain inventory element")
		}
		for kind, raw := range element {
			switch kind {
			case "metainfo", "table", "rule":
			case "chain":
				var chain struct {
					Family string `json:"family"`
					Table  string `json:"table"`
					Name   string `json:"name"`
					Handle uint64 `json:"handle"`
				}
				if err := json.Unmarshal(raw, &chain); err != nil {
					return 0, err
				}
				if chain.Family == "" || chain.Table == "" || chain.Name == "" {
					return 0, fmt.Errorf("incomplete chain inventory identity")
				}
				if chain.Family == "inet" && chain.Table == "filter" && chain.Name == "forward" {
					if handle != 0 || chain.Handle == 0 {
						return 0, fmt.Errorf("ambiguous shared forward chain handle")
					}
					handle = chain.Handle
				}
			default:
				return 0, fmt.Errorf("unexpected shared chain inventory element %s", kind)
			}
		}
	}
	return handle, nil
}

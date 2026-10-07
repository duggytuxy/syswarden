//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

const legacyFail2banCompleteNFTJournalSchema = "syswarden-legacy-fail2ban-kernel-v2"

// Complete retirement requires an original table containing exact historical
// action results and nothing else. Empty or familiar names supply no authority.
// The independently verified action claims and durable operator review remain
// mandatory in the caller. Keep the v1 planner unchanged for journal replay.
func prepareLegacyFail2banCompleteNFTTransition(content []byte, claims []legacyFail2banNFTClaim) (legacyFail2banNFTTransition, error) {
	plan, err := prepareLegacyFail2banNFTTransition(content, claims)
	if err != nil || plan.table != "syswarden_f2b" {
		return plan, err
	}
	var before, after []map[string]map[string]any
	if json.Unmarshal(plan.before, &before) != nil || json.Unmarshal(plan.after, &after) != nil {
		return legacyFail2banNFTTransition{}, fmt.Errorf("invalid canonical historical table evidence")
	}
	if len(before) < 4 || len(after) != 1 {
		return plan, nil
	}
	table, ok := after[0]["table"]
	if !ok || !legacyFail2banNFTFields(table, "family name handle", "") {
		return plan, nil
	}
	plan.after = []byte(`[]`)
	plan.transaction = legacyFail2banTableRetirementTransaction()
	plan.sha256 = plan.digest()
	return plan, nil
}

func legacyFail2banTableRetirementTransaction() []byte {
	return []byte(`{"nftables":[{"delete":{"table":{"family":"inet","name":"syswarden_f2b"}}}]}`)
}

func legacyFail2banRetiresWholeTable(plan legacyFail2banNFTTransition) bool {
	return plan.family == "inet" && plan.table == "syswarden_f2b" && bytes.Equal(plan.transaction, legacyFail2banTableRetirementTransaction())
}

// A stopped historical action can leave the original empty table before the
// explicit table retirement. Bind that intermediate state to its original
// handle and metadata instead of accepting any empty table with the same name.
func legacyFail2banTableIntermediate(plan legacyFail2banNFTTransition) ([]byte, error) {
	if !legacyFail2banRetiresWholeTable(plan) {
		return nil, fmt.Errorf("plan does not retire an exact historical table")
	}
	claims, err := decodeLegacyFail2banNFTClaims(plan.claims)
	if err != nil {
		return nil, err
	}
	observation := append(append([]byte(`{"nftables":`), plan.before...), '}')
	complete, err := prepareLegacyFail2banCompleteNFTTransition(observation, claims)
	if err != nil || complete.sha256 != plan.sha256 || plan.sha256 != plan.digest() || !legacyFail2banRetiresWholeTable(complete) {
		return nil, fmt.Errorf("whole-table retirement differs from its complete original action evidence")
	}
	partial, err := prepareLegacyFail2banNFTTransition(observation, claims)
	return partial.after, err
}

func applyLegacyFail2banTableRetirement(ctx context.Context, runner nftCommandRunner, plan legacyFail2banNFTTransition, authorize func(context.Context, string) error, fenceFactory func(context.Context, func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error)) error {
	if runner == nil || authorize == nil || fenceFactory == nil {
		return fmt.Errorf("historical table retirement requires complete independent guards")
	}
	intermediate, err := legacyFail2banTableIntermediate(plan)
	if err != nil {
		return err
	}
	read := func(ctx context.Context) ([]byte, error) {
		if err := authorize(ctx, plan.sha256); err != nil {
			return nil, err
		}
		content, err := runner.Run(ctx, nil, "-j", "list", "table", plan.family, plan.table)
		if err != nil {
			return nil, err
		}
		entries, err := legacyFail2banNFTEntries(content, plan.family, plan.table)
		if err != nil {
			return nil, err
		}
		return json.Marshal(entries)
	}
	current, err := read(ctx)
	if err != nil {
		return err
	}
	if bytes.Equal(current, plan.after) {
		return authorize(ctx, plan.sha256)
	}
	inspect := func(ctx context.Context) ([]nftTableTarget, error) {
		current, err := read(ctx)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(current, plan.before) && !bytes.Equal(current, intermediate) {
			return nil, fmt.Errorf("historical table changed outside the reviewed complete retirement")
		}
		return []nftTableTarget{{family: "inet", name: "syswarden_f2b"}}, nil
	}
	fence, err := fenceFactory(ctx, inspect)
	if err != nil {
		return err
	}
	defer fence.close()
	if err := fence.apply(ctx, func() error {
		_, err := inspect(ctx)
		return err
	}); err != nil {
		return err
	}
	current, err = read(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, plan.after) {
		return fmt.Errorf("historical table absence was not confirmed; retain its durable evidence")
	}
	return authorize(ctx, plan.sha256)
}

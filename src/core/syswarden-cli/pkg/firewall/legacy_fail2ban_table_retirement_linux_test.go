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

func fixtureLegacyFail2banCompleteTable(t *testing.T) ([]byte, legacyFail2banNFTClaim) {
	t.Helper()
	content, claim := fixtureLegacyFail2banNFT(t, false)
	document, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	var entries []any
	for _, entry := range document["nftables"].([]any) {
		keep := true
		for _, raw := range entry.(map[string]any) {
			value := raw.(map[string]any)
			keep = value["name"] != "administrator" && value["name"] != "administrator-ban" && value["chain"] != "administrator"
		}
		if keep {
			entries = append(entries, entry)
		}
	}
	document["nftables"] = entries
	content, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return content, claim
}

func TestLegacyFail2banCompleteTableRequiresFullOriginalActionEvidence(t *testing.T) {
	content, claim := fixtureLegacyFail2banCompleteTable(t)
	plan, err := prepareLegacyFail2banCompleteNFTTransition(content, []legacyFail2banNFTClaim{claim})
	if err != nil || !legacyFail2banRetiresWholeTable(plan) || string(plan.after) != "[]" {
		t.Fatal("complete historical action output was not selected", err)
	}
	intermediate, err := legacyFail2banTableIntermediate(plan)
	if err != nil || !bytes.Contains(intermediate, []byte(`"table"`)) || bytes.Contains(intermediate, []byte(`"chain"`)) {
		t.Fatal("original empty table was not bound independently", err)
	}
	for _, change := range []string{"empty", "comment", "flags", "administrator", "upstream", "absent"} {
		t.Run(change, func(t *testing.T) {
			input, selected := content, claim
			switch change {
			case "empty":
				input = append(append([]byte(`{"nftables":`), intermediate...), '}')
			case "comment":
				input = bytes.Replace(content, []byte(`"name":"syswarden_f2b"`), []byte(`"name":"syswarden_f2b","comment":"administrator"`), 1)
			case "flags":
				input = bytes.Replace(content, []byte(`"name":"syswarden_f2b"`), []byte(`"name":"syswarden_f2b","flags":["owner"]`), 1)
			case "administrator":
				input, selected = fixtureLegacyFail2banNFT(t, false)
			case "upstream":
				input, selected = fixtureLegacyFail2banNFT(t, true)
			case "absent":
				input = []byte(`{"nftables":[]}`)
			}
			actual, err := prepareLegacyFail2banCompleteNFTTransition(input, []legacyFail2banNFTClaim{selected})
			if err != nil || legacyFail2banRetiresWholeTable(actual) {
				t.Fatal("name, emptiness or modified table metadata supplied whole-table authority", err)
			}
		})
	}
}

func fixtureLegacyFail2banCompleteJournal(t *testing.T) legacyFail2banNFTJournalRecord {
	t.Helper()
	_, _, record := fixtureLegacyFail2banNFTJournal(t, false)
	content, claim := fixtureLegacyFail2banCompleteTable(t)
	claim.filePlan, claim.actionsSHA256 = record.Quiescence.FilePlan, record.Quiescence.Actions
	plan, err := prepareLegacyFail2banCompleteNFTTransition(content, []legacyFail2banNFTClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	record = makeLegacyFail2banNFTJournalRecord(record.Quiescence, []legacyFail2banNFTTransition{plan})
	record.Schema = legacyFail2banCompleteNFTJournalSchema
	return record
}

func TestLegacyFail2banCompleteJournalDoesNotReinterpretVersionOne(t *testing.T) {
	record := fixtureLegacyFail2banCompleteJournal(t)
	_, _, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil || len(plans) != 1 || !legacyFail2banRetiresWholeTable(plans[0]) {
		t.Fatal("complete journal did not reconstruct the exact plan", err)
	}
	record.Schema = legacyFail2banNFTJournalSchema
	if _, _, _, err := encodeLegacyFail2banNFTJournalRecord(record); err == nil {
		t.Fatal("v1 journal silently acquired whole-table deletion authority")
	}
	_, _, old := fixtureLegacyFail2banNFTJournal(t, false)
	wire, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, oldPlans, err := encodeLegacyFail2banNFTJournalRecord(old)
	if err != nil || !bytes.Equal(wire, actual) || legacyFail2banRetiresWholeTable(oldPlans[0]) {
		t.Fatal("existing v1 evidence changed during decoding", err)
	}
}

func TestLegacyFail2banOldReviewReobservationKeepsOriginalPlanner(t *testing.T) {
	fixture := fixtureLegacyFail2banRuntimeRetirement(t, false)
	content, _ := fixtureLegacyFail2banCompleteTable(t)
	fixture.runner.before = content
	ctx := context.Background()
	old, digest, err := prepareLegacyFail2banRuntimeRetirementSchema(ctx, fixture.adapter, legacyFail2banNFTJournalSchema)
	if err != nil || len(old.Plans) != 1 || old.Plans[0].After == "[]" {
		t.Fatal("original review did not preserve the dedicated table", err)
	}
	current, currentDigest, err := prepareLegacyFail2banRuntimeRetirement(ctx, fixture.adapter)
	if err != nil || currentDigest == digest || len(current.Plans) != 1 || current.Plans[0].After != "[]" {
		t.Fatal("new review did not explicitly bind its different effect", err)
	}
	// The persistence coordinator compares this fresh observation with its
	// immutable old record before resuming edits. It must compare like schemas.
	reobserved, repeated, err := prepareLegacyFail2banRuntimeRetirementSchema(ctx, fixture.adapter, old.Schema)
	if err != nil || repeated != digest || !reflect.DeepEqual(reobserved, old) {
		t.Fatal("unchanged old persistent review was invalidated by the new default", err)
	}
	journal, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, old, digest, defaultLegacyRetirementFileOps())
	if err != nil || journal == nil || fixture.runner.writes != 1 || string(journal.plans[0].after) == "[]" {
		t.Fatal("reviewed version-one retirement could not finish with its original effect", err)
	}
	if _, _, err := prepareLegacyFail2banRuntimeRetirementSchema(ctx, fixture.adapter, "unknown-review"); err == nil {
		t.Fatal("unknown review semantics were accepted")
	}
}

func TestLegacyFail2banCompleteTableRejectsOrdinaryNFTExecution(t *testing.T) {
	record := fixtureLegacyFail2banCompleteJournal(t)
	_, _, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := bindLegacyFail2banNFTRunner(plans[0], execNFTCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), plans[0].transaction, "-j", "-f", "-"); err == nil || !strings.Contains(err.Error(), "generation fence") {
		t.Fatal("ordinary nft execution accepted whole-table deletion", err)
	}
}

func TestLegacyFail2banCompletePersistencePreservesAdjacentAdministratorBytes(t *testing.T) {
	record := fixtureLegacyFail2banCompleteJournal(t)
	const table = "table inet syswarden_f2b {\n set f2b-syswarden-portscan { type ipv4_addr; elements = { 127.0.0.2 } }\n chain syswarden-portscan { type filter hook input priority -1; policy accept; ip saddr @f2b-syswarden-portscan drop; }\n}"
	const adjacent = "# Administrator policy\ntable inet administrator { chain input { type filter hook input priority 0; policy drop; } }\n"
	content := []byte(adjacent + table + "\n")
	edit, err := planLegacyFail2banPersistence(content, record)
	if err != nil || string(edit.content) != adjacent+"\n" || len(edit.removed) != 1 {
		t.Fatal("complete table retirement changed unrelated source bytes", err)
	}
	again, err := planLegacyFail2banPersistence(edit.content, record)
	if err != nil || !bytes.Equal(again.content, edit.content) || len(again.removed) != 0 {
		t.Fatal("complete persistent retirement is not resumable", err)
	}
	for _, extra := range []string{"# administrator annotation\n", "chain administrator { }\n", "comment \"administrator\";\n"} {
		modified := strings.Replace(table, "table inet syswarden_f2b {\n", "table inet syswarden_f2b {\n"+extra, 1)
		if edit, err := planLegacyFail2banPersistence([]byte(adjacent+modified), record); err == nil || edit.content != nil {
			t.Fatal("unclaimed persistent table content was selected for deletion", extra)
		}
	}
}

type fixtureLegacyTableFence struct {
	applyFn func(func() error) error
	closed  bool
}

func (fence *fixtureLegacyTableFence) apply(_ context.Context, guard func() error) error {
	return fence.applyFn(guard)
}

func (fence *fixtureLegacyTableFence) close() { fence.closed = true }

func TestLegacyFail2banCompleteTableUsesFenceAndPreservesChangedState(t *testing.T) {
	for _, state := range []string{"original", "stopped", "absent", "changed", "generation-change", "uncertain"} {
		t.Run(state, func(t *testing.T) {
			record := fixtureLegacyFail2banCompleteJournal(t)
			_, _, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			plan := plans[0]
			before := plan.before
			if state == "stopped" {
				before, err = legacyFail2banTableIntermediate(plan)
				if err != nil {
					t.Fatal(err)
				}
			} else if state == "absent" {
				before = plan.after
			} else if state == "changed" {
				before = bytes.Replace(before, []byte(`"name":"syswarden_f2b"`), []byte(`"name":"syswarden_f2b","comment":"administrator"`), 1)
			}
			runner := &fixtureLegacyFail2banNFTRunner{before: append(append([]byte(`{"nftables":`), before...), '}'), after: []byte(`{"nftables":[]}`), plan: plan}
			fences, deleted := 0, false
			fence := &fixtureLegacyTableFence{applyFn: func(guard func() error) error {
				if err := guard(); err != nil {
					return err
				}
				if state == "generation-change" {
					return fmt.Errorf("fixture generation changed")
				}
				deleted, runner.applied = true, true
				if state == "uncertain" {
					return fmt.Errorf("fixture lost acknowledgement")
				}
				return nil
			}}
			factory := func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
				fences++
				targets, err := inspect(ctx)
				if err != nil {
					return nil, err
				}
				if !reflect.DeepEqual(targets, []nftTableTarget{{family: "inet", name: "syswarden_f2b"}}) {
					t.Fatal("fence escaped its dedicated table")
				}
				return fence, nil
			}
			authorize := func(_ context.Context, digest string) error {
				if digest != plan.sha256 {
					return fmt.Errorf("unreviewed digest")
				}
				return nil
			}
			err = applyLegacyFail2banTableRetirement(context.Background(), runner, plan, authorize, factory)
			wantError := state == "changed" || state == "generation-change" || state == "uncertain"
			if (err != nil) != wantError || runner.writes != 0 || deleted != (state == "original" || state == "stopped" || state == "uncertain") {
				t.Fatal("unsafe complete-table retirement result", err, runner.writes, deleted)
			}
			if state == "absent" && fences != 0 || state != "absent" && fences != 1 {
				t.Fatal("absence or generation fence was mishandled")
			}
			if state != "absent" && state != "changed" && !fence.closed {
				t.Fatal("generation fence was leaked")
			}
			if state == "uncertain" {
				if err := applyLegacyFail2banTableRetirement(context.Background(), runner, plan, authorize, factory); err != nil || fences != 1 {
					t.Fatal("retry repeated deletion after independently confirmed absence", err)
				}
			}
		})
	}
}

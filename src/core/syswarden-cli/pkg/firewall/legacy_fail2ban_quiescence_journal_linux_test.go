//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixtureLegacyFail2banQuiescenceRecord(plan string) legacyFail2banQuiescenceRecord {
	return legacyFail2banQuiescenceRecord{
		Schema: legacyFail2banQuiescenceSchema, FilePlan: plan, Actions: strings.Repeat("b", 64),
		Invocation: strings.Repeat("c", 32), PID: 123, StartTicks: 456,
		Targets:     []string{"syswarden-portscan"},
		Transitions: [][]string{{"set", "syswarden-portscan", "idle", "on"}, {"set", "syswarden-portscan", "action", "nft", "actionstop", ""}, {"stop", "syswarden-portscan"}},
	}
}

func TestLegacyFail2banQuiescenceRecordRejectsUnboundTransitions(t *testing.T) {
	for _, kind := range []string{"valid", "schema", "digest", "invocation", "pid", "start", "global", "other-jail", "duplicate", "stop-first", "no-stop", "late-hook"} {
		t.Run(kind, func(t *testing.T) {
			record := fixtureLegacyFail2banQuiescenceRecord(strings.Repeat("a", 64))
			switch kind {
			case "schema":
				record.Schema = "other"
			case "digest":
				record.FilePlan = "bad"
			case "invocation":
				record.Invocation = strings.Repeat("0", 32)
			case "pid":
				record.PID = 1
			case "start":
				record.StartTicks = 0
			case "global":
				record.Transitions[2] = []string{"stop", "--all"}
			case "other-jail":
				record.Transitions[2] = []string{"stop", "administrator"}
			case "duplicate":
				record.Transitions = append(record.Transitions, record.Transitions[2])
			case "stop-first":
				record.Transitions[0], record.Transitions[2] = record.Transitions[2], record.Transitions[0]
			case "no-stop":
				record.Transitions = record.Transitions[:2]
			case "late-hook":
				record.Transitions[1], record.Transitions[2] = record.Transitions[2], record.Transitions[1]
			}
			content, digest, err := encodeLegacyFail2banQuiescenceRecord(record)
			if kind == "valid" {
				if err != nil || len(content) == 0 || !validLegacyRetirementDigest(digest) {
					t.Fatal(err)
				}
			} else if err == nil || content != nil || digest != "" {
				t.Fatal("invalid runtime intent accepted")
			}
		})
	}
}

func TestLegacyFail2banQuiescenceJournalIsDurableAndCannotAuthorizeOtherJails(t *testing.T) {
	_, host, plan := fixtureLegacyFail2banJournal(t)
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	record := fixtureLegacyFail2banQuiescenceRecord(plan.sha256)
	guard := func(context.Context) error { _, err := inspectLegacyFail2banPlanState(host, plan.binding); return err }
	ctx := context.Background()
	journal, err := publishLegacyFail2banQuiescenceIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.verifyTransition(ctx, []string{"stop", "syswarden-portscan"}); err != nil {
		t.Fatal(err)
	}
	if err := journal.verifyTransition(ctx, []string{"stop", "administrator"}); err == nil {
		t.Fatal("unrelated jail authorized")
	}
	repeated, err := publishLegacyFail2banQuiescenceIntent(ctx, host, record, guard, defaultLegacyRetirementFileOps())
	if err != nil || !sameLegacyFail2banSource(journal.file, repeated.file) {
		t.Fatal("durable intent was replaced", err)
	}
	record.Transitions[2][1] = "administrator"
	if err := journal.verifyTransition(ctx, []string{"stop", "administrator"}); err == nil {
		t.Fatal("caller mutation changed durable permission")
	}
	state, err := inspectLegacyFail2banPlanState(host, plan.binding)
	if err != nil || len(state.retired) != 0 {
		t.Fatal("runtime intent publication moved active configuration", err)
	}
	path := journal.path + "/intent.json"
	if err := host.root.WriteFile(path[1:], []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := journal.verifyTransition(ctx, []string{"stop", "syswarden-portscan"}); err == nil {
		t.Fatal("changed private intent accepted")
	}
}

func TestLegacyFail2banQuiescenceJournalRecoversUnconfirmedPublication(t *testing.T) {
	for _, failure := range []string{"intent-staged", "quiescence-intent-durable", "sync"} {
		t.Run(failure, func(t *testing.T) {
			_, host, plan := fixtureLegacyFail2banJournal(t)
			if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			record := fixtureLegacyFail2banQuiescenceRecord(plan.sha256)
			guard := func(context.Context) error { return nil }
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(point string) error {
				if point == failure {
					return fmt.Errorf("fixture interruption")
				}
				return nil
			}
			if failure == "sync" {
				ops.sync = func(*os.File) error { return fmt.Errorf("fixture sync unavailable") }
			}
			if journal, err := publishLegacyFail2banQuiescenceIntent(context.Background(), host, record, guard, ops); err == nil || journal != nil {
				t.Fatal("incomplete publication authorized commands")
			}
			journal, err := publishLegacyFail2banQuiescenceIntent(context.Background(), host, record, guard, defaultLegacyRetirementFileOps())
			if err != nil {
				t.Fatal(err)
			}
			content, _, err := encodeLegacyFail2banQuiescenceRecord(record)
			if err != nil || !bytes.Equal(journal.file.content, content) {
				t.Fatal("retry changed intent", err)
			}
		})
	}
}

func TestLegacyFail2banQuiescenceRuntimeAllowsOnlyAuthorizedNeutralization(t *testing.T) {
	for _, change := range []string{"none", "clear", "stopped", "no-intent", "early-stop", "altered-hook", "extra-action", "changed-admin", "disabled-started"} {
		t.Run(change, func(t *testing.T) {
			live := fixtureLegacyFail2banQuiescenceState()
			original := fixtureLegacyFail2banQuiescenceState()
			expected := make(legacyFail2banConfiguredActions)
			for name, jail := range original.jails {
				expected[name] = jail.actions
			}
			targets := map[string]bool{"target": true, "disabled": true}
			allow, clear := true, false
			switch change {
			case "clear", "no-intent":
				for key := range live.jails["target"].actions["nft"] {
					if legacyFail2banHookProperty(key) {
						live.jails["target"].actions["nft"][key] = fixtureLegacyFail2banRuntimeString("")
					}
				}
				clear = true
				allow = change != "no-intent"
			case "stopped":
				delete(live.jails, "target")
				clear = true
			case "early-stop":
				clear = true
			case "altered-hook":
				live.jails["target"].actions["nft"]["actionstop"] = fixtureLegacyFail2banRuntimeString("different command")
			case "extra-action":
				live.jails["target"].actions["custom"] = nil
			case "changed-admin":
				live.jails["administrator"].actions["custom"]["actionstop"] = fixtureLegacyFail2banRuntimeString("")
			case "disabled-started":
				live.jails["disabled"] = legacyFail2banRuntimeJail{}
			}
			err := verifyLegacyFail2banQuiescenceRuntime(expected, live, targets, allow, clear)
			if (err == nil) != (change == "none" || change == "clear" || change == "stopped") {
				t.Fatal("unexpected runtime phase outcome", change, err)
			}
			if !reflect.DeepEqual(expected["administrator"], original.jails["administrator"].actions) {
				t.Fatal("verification changed expected state")
			}
		})
	}
}

//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func cloneLegacyFail2banRuntimeFixture(state legacyFail2banRuntimeSnapshot) legacyFail2banRuntimeSnapshot {
	copy := legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail)}
	for name, jail := range state.jails {
		retained := legacyFail2banRuntimeJail{bans: append([]string(nil), jail.bans...), actions: make(map[string]map[string]legacyFail2banValue)}
		for action, properties := range jail.actions {
			values := make(map[string]legacyFail2banValue)
			for key, value := range properties {
				values[key] = value
			}
			retained.actions[action] = values
		}
		copy.jails[name] = retained
	}
	return copy
}

type legacyFail2banRuntimeRetirementFixture struct {
	inspection *legacyFail2banServiceInspection
	host       nftPersistenceFilesystem
	plan       legacyFail2banRetirementPlan
	adapter    legacyFail2banRuntimeRetirementAdapter
	live       legacyFail2banRuntimeSnapshot
	runner     *fixtureLegacyFail2banNFTRunner
	failure    string
	commands   int
}

func fixtureLegacyFail2banRuntimeRetirement(t *testing.T, upstream bool) *legacyFail2banRuntimeRetirementFixture {
	t.Helper()
	_, host, plan, view := fixtureLegacyFail2banNFTClaimPlan(t, upstream)
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	fixture := &legacyFail2banRuntimeRetirementFixture{host: host, plan: plan, live: fixtureLegacyFail2banClaimRuntime(t, view)}
	observation, _ := fixtureLegacyFail2banNFT(t, upstream)
	fixture.runner = &fixtureLegacyFail2banNFTRunner{before: observation}
	actions, err := decodeLegacyFail2banConfiguredActions(view.actionsEnabled)
	if err != nil {
		t.Fatal(err)
	}
	status, err := decodeLegacyFail2banServiceStatus(fixtureLegacyFail2banServiceStatus())
	if err != nil {
		t.Fatal(err)
	}
	inspection := &legacyFail2banServiceInspection{
		parser:  legacyFail2banParserSnapshot{digest: view.parserSHA256},
		process: &legacyFail2banProcessBinding{start: 456},
		status:  status, actions: actions, actionsSource: view.actionsEnabled,
	}
	fixture.inspection = inspection
	fixture.adapter = legacyFail2banRuntimeRetirementAdapter{
		actions: actions,
		guard: func(ctx context.Context) error {
			if fixture.failure == "service" {
				return fmt.Errorf("fixture service invocation changed")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return reattestLegacyFail2banPlanInventory(host, plan.baseline)
		},
		record: func() (legacyFail2banQuiescenceRecord, error) {
			return makeLegacyFail2banQuiescenceRecord(host, plan, inspection)
		},
		claims: func(context.Context) ([]legacyFail2banNFTClaim, error) {
			return bindLegacyFail2banNFTClaims(host, plan, view.parserSHA256, view.actionsEnabled, fixture.live)
		},
		read: func(context.Context) (legacyFail2banRuntimeSnapshot, error) {
			return cloneLegacyFail2banRuntimeFixture(fixture.live), nil
		},
		observe: func(context.Context, string) ([]byte, error) {
			if fixture.runner.writes > 0 {
				return bytes.Clone(fixture.runner.after), nil
			}
			return bytes.Clone(fixture.runner.before), nil
		},
		runner: func(kernel legacyFail2banNFTTransition) (nftCommandRunner, error) {
			fixture.runner.plan = kernel
			fixture.runner.after = []byte(`{"nftables":` + string(kernel.after) + `}`)
			return fixture.runner, nil
		},
	}
	fixture.adapter.quiesce = func(ctx context.Context, guard func(context.Context) error, ops legacyRetirementFileOps) error {
		record, err := fixture.adapter.record()
		if err != nil {
			return err
		}
		journal, err := publishLegacyFail2banQuiescenceIntent(ctx, host, record, guard, ops)
		if err != nil {
			return err
		}
		if fixture.failure == "false-stop" {
			return nil
		}
		for _, command := range record.Transitions {
			if _, active := fixture.live.jails[command[1]]; !active {
				continue
			}
			if err := journal.verifyTransition(ctx, command); err != nil {
				return err
			}
			fixture.commands++
			if command[0] == "stop" {
				delete(fixture.live.jails, command[1])
				if err := ops.checkpoint("fixture-target-stopped"); err != nil {
					return err
				}
			} else if command[2] == "action" {
				fixture.live.jails[command[1]].actions[command[3]][command[4]] = fixtureLegacyFail2banRuntimeString("")
				if err := ops.checkpoint("fixture-hook-cleared"); err != nil {
					return err
				}
			}
		}
		if fixture.failure == "changed-admin" {
			fixture.live.jails["administrator-new"] = legacyFail2banRuntimeJail{}
		}
		if fixture.failure == "changed-kernel" {
			fixture.runner.before = bytes.ReplaceAll(fixture.runner.before, []byte("127.0.0.3"), []byte("127.0.0.4"))
		}
		if fixture.failure == "missing-intent" {
			return host.root.Remove(journal.path[1:] + "/intent.json")
		}
		return nil
	}
	return fixture
}

func TestLegacyFail2banRuntimeRetirementOrdersDurableIntentAndExactWrites(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		fixture := fixtureLegacyFail2banRuntimeRetirement(t, upstream)
		ctx := context.Background()
		record, digest, err := prepareLegacyFail2banRuntimeRetirement(ctx, fixture.adapter)
		if err != nil {
			t.Fatal(err)
		}
		if fixture.commands != 0 || fixture.runner.writes != 0 {
			t.Fatal("read-only preparation mutated runtime")
		}
		before := cloneLegacyFail2banRuntimeFixture(fixture.live)
		journal, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, record, digest, defaultLegacyRetirementFileOps())
		if err != nil || journal == nil || fixture.runner.writes != 1 {
			t.Fatal("source-bound retirement failed", err)
		}
		if err := verifyLegacyFail2banRuntimePreservation(before, fixture.live, map[string]bool{"syswarden-portscan": true}); err != nil {
			t.Fatal(err)
		}
		if err := reattestLegacyFail2banPlanInventory(fixture.host, fixture.plan.baseline); err != nil {
			t.Fatal("runtime retirement changed active configuration", err)
		}
		if _, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, record, digest, defaultLegacyRetirementFileOps()); err != nil || fixture.runner.writes != 1 {
			t.Fatal("completed retirement repeated a kernel write", err)
		}
	}
}

func TestLegacyFail2banRuntimeRetirementRefusesChangedReviewAndProtection(t *testing.T) {
	for _, failure := range []string{"digest", "service", "fresh-ban", "fresh-kernel", "false-stop", "changed-admin", "changed-kernel", "missing-intent", "missing-guard"} {
		t.Run(failure, func(t *testing.T) {
			fixture := fixtureLegacyFail2banRuntimeRetirement(t, false)
			ctx := context.Background()
			record, digest, err := prepareLegacyFail2banRuntimeRetirement(ctx, fixture.adapter)
			if err != nil {
				t.Fatal(err)
			}
			fixture.failure = failure
			switch failure {
			case "digest":
				digest = strings.Repeat("a", 64)
			case "fresh-ban":
				jail := fixture.live.jails["syswarden-portscan"]
				jail.bans = nil
				fixture.live.jails["syswarden-portscan"] = jail
			case "fresh-kernel":
				fixture.runner.before = bytes.ReplaceAll(fixture.runner.before, []byte("127.0.0.3"), []byte("127.0.0.4"))
			case "missing-guard":
				fixture.adapter.guard = nil
			}
			if journal, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, record, digest, defaultLegacyRetirementFileOps()); err == nil || journal != nil || fixture.runner.writes != 0 {
				t.Fatal("unproven runtime state authorized kernel writes", failure, err)
			}
			if err := reattestLegacyFail2banPlanInventory(fixture.host, fixture.plan.baseline); err != nil {
				t.Fatal("refused runtime retirement changed configuration", err)
			}
		})
	}
}

func TestLegacyFail2banRuntimeRetirementResumesEveryRuntimeBoundary(t *testing.T) {
	for _, phase := range []string{"kernel-staged", "kernel-intent-durable", "quiescence-intent-durable", "fixture-hook-cleared", "fixture-target-stopped", "lost-kernel-ack", "kernel-transition-confirmed"} {
		t.Run(phase, func(t *testing.T) {
			fixture := fixtureLegacyFail2banRuntimeRetirement(t, true)
			ctx := context.Background()
			record, digest, err := prepareLegacyFail2banRuntimeRetirement(ctx, fixture.adapter)
			if err != nil {
				t.Fatal(err)
			}
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(point string) error {
				if phase == point {
					return fmt.Errorf("fixture interruption at %s", point)
				}
				return nil
			}
			fixture.runner.unconfirmed = phase == "lost-kernel-ack"
			if journal, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, record, digest, ops); err == nil || journal != nil {
				t.Fatal("interrupted retirement reported completion", phase)
			}
			encoded, _, _, err := encodeLegacyFail2banNFTJournalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, record, digest, defaultLegacyRetirementFileOps())
			if err != nil || journal == nil || !bytes.Equal(journal.content, encoded) || fixture.runner.writes != 1 {
				t.Fatal("retirement failed to resume the original reviewed plan", phase, err)
			}
			if !reflect.DeepEqual(journal.record, record) {
				t.Fatal("resume changed original kernel evidence")
			}
		})
	}
}

func TestLegacyFail2banRuntimeRetirementRejectsReappearanceAtCompletion(t *testing.T) {
	for _, mutation := range []string{"target", "kernel"} {
		fixture := fixtureLegacyFail2banRuntimeRetirement(t, false)
		ctx := context.Background()
		record, digest, err := prepareLegacyFail2banRuntimeRetirement(ctx, fixture.adapter)
		if err != nil {
			t.Fatal(err)
		}
		ops := defaultLegacyRetirementFileOps()
		ops.checkpoint = func(phase string) error {
			if phase == "kernel-transition-confirmed" {
				if mutation == "target" {
					fixture.live.jails["syswarden-portscan"] = legacyFail2banRuntimeJail{actions: fixture.adapter.actions["syswarden-portscan"]}
				} else {
					fixture.runner.after = bytes.Clone(fixture.runner.before)
				}
			}
			return nil
		}
		if journal, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, record, digest, ops); err == nil || journal != nil {
			t.Fatal("reappearing product state was reported as complete retirement", mutation)
		}
	}
}

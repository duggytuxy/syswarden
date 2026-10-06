//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixtureLegacyFail2banOriginalPaths(plan legacyFail2banRetirementPlan) map[string]os.FileInfo {
	paths := make(map[string]os.FileInfo)
	for _, source := range plan.baseline.sources {
		paths[source.path] = source.snapshot.identity
	}
	for _, directory := range plan.baseline.directories {
		paths[directory.path] = directory.identity
	}
	return paths
}

func TestLegacyFail2banFileGuardAllowsOnlyDurableOriginalMoves(t *testing.T) {
	for _, mutation := range []string{"none", "retained", "backup", "reappeared", "new-file", "unbound-source", "missing-retained", "directory"} {
		t.Run(mutation, func(t *testing.T) {
			_, host, plan := fixtureLegacyFail2banJournal(t)
			expected := fixtureLegacyFail2banOriginalPaths(plan)
			if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			before, absent, err := legacyFail2banRetirementProcessPaths(host, plan.binding, expected)
			if err != nil || len(absent) != 0 || len(before) != len(expected) {
				t.Fatal("intact source paths were changed", err)
			}
			for path, identity := range expected {
				if !sameNFTPersistenceIdentity(identity, before[path]) {
					t.Fatal("intact source identity changed", path)
				}
			}
			guard := func() error {
				_, _, err := legacyFail2banRetirementProcessPaths(host, plan.binding, expected)
				return err
			}
			if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("exact inode movement was refused", err)
			}
			var retained string
			for _, source := range plan.baseline.sources {
				selected := false
				for _, path := range plan.binding.Targets {
					selected = selected || source.path == path
				}
				if !selected {
					retained = source.path
					break
				}
			}
			if retained == "" {
				t.Fatal("fixture lacks a retained configuration")
			}
			source := legacyFail2banPlanFileRecords(plan.binding, plan.sha256)[0]
			backup := legacyRetirementBackupDirectory(source) + "/original"
			switch mutation {
			case "retained":
				err = host.root.WriteFile(retained[1:], []byte("changed administrator configuration"), 0600)
			case "backup":
				err = host.root.WriteFile(backup[1:], []byte("changed original evidence"), 0600)
			case "reappeared":
				err = host.root.WriteFile(source.Source.Path[1:], []byte("recreated active path"), 0600)
			case "new-file":
				err = host.root.WriteFile("etc/fail2ban/jail.d/unreviewed.local", []byte("[new]\nenabled=true\n"), 0600)
			case "unbound-source":
				expected[source.Source.Path] = expected[retained]
			case "missing-retained":
				delete(expected, retained)
			case "directory":
				expected["/etc/fail2ban/jail.d"] = expected["/etc/fail2ban/action.d"]
			}
			if err != nil {
				t.Fatal(err)
			}
			paths, absent, err := legacyFail2banRetirementProcessPaths(host, plan.binding, expected)
			if mutation != "none" {
				if err == nil || paths != nil || absent != nil {
					t.Fatal("unreviewed file-phase path change was accepted", mutation)
				}
				return
			}
			if err != nil || len(absent) != len(plan.binding.Targets) || paths[source.Source.Path] != nil || paths[backup] == nil {
				t.Fatal("exact private backup or required active-path absence was lost", err)
			}
			if !sameNFTPersistenceIdentity(paths[retained], expected[retained]) {
				t.Fatal("retained administrator source gained weaker path checks")
			}
		})
	}
}

func fixtureLegacyFail2banFilePhase(t *testing.T, fixture *legacyFail2banRuntimeRetirementFixture) (legacyFail2banNFTJournalRecord, string, legacyFail2banFileRetirementAdapter) {
	t.Helper()
	ctx := context.Background()
	record, digest, err := prepareLegacyFail2banRuntimeRetirement(ctx, fixture.adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyLegacyFail2banRuntimeRetirement(ctx, fixture.host, fixture.plan, fixture.adapter, record, digest, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	paths := fixtureLegacyFail2banOriginalPaths(fixture.plan)
	adapter := legacyFail2banFileRetirementAdapter{
		guard: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, _, err := legacyFail2banRetirementProcessPaths(fixture.host, fixture.plan.binding, paths)
			return err
		},
		read: fixture.adapter.read, observe: fixture.adapter.observe, actions: fixture.adapter.actions,
		invocation: func(quiescence legacyFail2banQuiescenceRecord) error {
			return verifyLegacyFail2banFilePhaseInvocation(fixture.host, fixture.plan.binding, fixture.inspection, quiescence)
		},
	}
	return record, digest, adapter
}

func TestLegacyFail2banFilePhaseFollowsRuntimeAndResumesPrivateMoves(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		fixture := fixtureLegacyFail2banRuntimeRetirement(t, upstream)
		record, digest, adapter := fixtureLegacyFail2banFilePhase(t, fixture)
		before := cloneLegacyFail2banRuntimeFixture(fixture.live)
		kernel := bytes.Clone(fixture.runner.after)
		interrupted := fmt.Errorf("interrupted after the exact file move")
		ops := defaultLegacyRetirementFileOps()
		ops.checkpoint = func(phase string) error {
			if phase == "source-retired" {
				return interrupted
			}
			return nil
		}
		ctx := context.Background()
		if err := finishLegacyFail2banFileRetirement(ctx, fixture.host, record.Quiescence, digest, adapter, ops); !errors.Is(err, interrupted) {
			t.Fatal("file-move interruption was not observed", err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err := finishLegacyFail2banFileRetirement(ctx, fixture.host, record.Quiescence, digest, adapter, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("exact runtime/file retirement did not resume", err)
			}
		}
		assertLegacyFail2banJournalComplete(t, fixture.host, fixture.plan)
		if !reflect.DeepEqual(before, fixture.live) || !bytes.Equal(kernel, fixture.runner.after) || fixture.runner.writes != 1 {
			t.Fatal("file retirement changed live protection or repeated a kernel write")
		}
	}
}

func TestLegacyFail2banFilePhaseRefusesUnprovenRuntimeOrEvidence(t *testing.T) {
	for _, mutation := range []string{"kernel-incomplete", "kernel-changed", "target-active", "admin-changed", "invocation", "digest", "actions", "missing-guard", "modified-config"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := fixtureLegacyFail2banRuntimeRetirement(t, false)
			record, digest, adapter := fixtureLegacyFail2banFilePhase(t, fixture)
			switch mutation {
			case "kernel-incomplete":
				fixture.runner.after = bytes.Clone(fixture.runner.before)
			case "kernel-changed":
				fixture.runner.after = bytes.ReplaceAll(fixture.runner.after, []byte("127.0.0.3"), []byte("127.0.0.4"))
			case "target-active":
				fixture.live.jails["syswarden-portscan"] = legacyFail2banRuntimeJail{actions: fixture.adapter.actions["syswarden-portscan"]}
			case "admin-changed":
				fixture.live.jails["unexpected-admin"] = legacyFail2banRuntimeJail{}
			case "invocation":
				fixture.inspection.status.values["InvocationID"] = strings.Repeat("f", 32)
			case "digest":
				digest = strings.Repeat("f", 64)
			case "actions":
				fixture.inspection.actionsSource = []byte("changed action evidence")
			case "missing-guard":
				adapter.guard = nil
			case "modified-config":
				if err := fixture.host.root.WriteFile("etc/fail2ban/jail.d/administrator-new.local", []byte("[new]\nenabled=true\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := finishLegacyFail2banFileRetirement(context.Background(), fixture.host, record.Quiescence, digest, adapter, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("file retirement accepted unproven state", mutation)
			}
			for _, target := range fixture.plan.binding.Targets {
				if _, err := fixture.host.snapshot(target); err != nil {
					t.Fatal("refused file phase removed active configuration", err)
				}
			}
		})
	}
}

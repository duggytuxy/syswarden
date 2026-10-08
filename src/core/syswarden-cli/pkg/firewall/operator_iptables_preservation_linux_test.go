//go:build linux

package firewall

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func fixtureOperatorIPTablesPreservation(t *testing.T) (*operatorIPTablesInspection, *legacyIPTablesObservation, *nftRemovalEpoch) {
	t.Helper()
	original, _ := fixtureLegacyIPTablesRecovery(t)
	current, _, _ := legacyIPTablesTestGeneration(t)
	epoch := original.record.Epoch
	inspection, err := inspectOperatorIPTablesUsing(context.Background(), original.host, func() (nftRemovalEpoch, error) { return epoch, nil }, func(context.Context) (legacyIPTablesObservation, error) { return current, nil }, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return inspection, &current, &epoch
}

func TestOperatorIPTablesPreservationExactDecisionDoesNotChangeRules(t *testing.T) {
	inspection, current, epoch := fixtureOperatorIPTablesPreservation(t)
	ctx := context.Background()
	initial, _ := legacyIPTablesObservationBytes(*current)
	summary := inspection.summary()
	if summary.ChangesRules || summary.GrantsDeletionAuthority || !summary.RequiresAdministratorOwnershipConfirmation || !summary.RequiresReviewAfterReboot || summary.RuleCount != len(current.rules) {
		t.Fatal("incorrect preservation authority", summary)
	}
	if _, _, err := readOperatorIPTablesRecord(inspection.host, inspection.digest); err == nil {
		t.Fatal("dry run persisted a decision")
	}
	if err := inspection.apply(ctx, inspection.digest, true, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	_, first, err := readOperatorIPTablesRecord(inspection.host, inspection.digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspection.apply(ctx, inspection.digest, true, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal("idempotent retry failed", err)
	}
	_, second, err := readOperatorIPTablesRecord(inspection.host, inspection.digest)
	if err != nil || !sameLegacyFail2banSource(first, second) {
		t.Fatal("retry replaced the private decision", err)
	}
	if err := authorizeOperatorIPTablesPreservationUsing(ctx, inspection.host, *epoch, inspection.observe); err != nil {
		t.Fatal(err)
	}
	after, _ := legacyIPTablesObservationBytes(*current)
	if string(initial) != string(after) {
		t.Fatal("preservation changed the administrator rules")
	}
	epoch.BootID = "99999999-2222-3333-4444-555555555555"
	if err := authorizeOperatorIPTablesPreservationUsing(ctx, inspection.host, *epoch, inspection.observe); err == nil {
		t.Fatal("old decision survived a reboot")
	}
	renewed, err := inspectOperatorIPTablesUsing(ctx, inspection.host, inspection.epoch, inspection.observe, inspection.guard)
	if err != nil || renewed.digest == inspection.digest {
		t.Fatal("new boot did not require a distinct review", err)
	}
	if err := renewed.apply(ctx, inspection.digest, true, defaultLegacyRetirementFileOps()); err == nil {
		t.Fatal("old digest authorized fresh preservation")
	}
	if err := renewed.apply(ctx, renewed.digest, true, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	if err := authorizeOperatorIPTablesPreservationUsing(ctx, renewed.host, *epoch, renewed.observe); err != nil {
		t.Fatal("fresh explicit review did not recover preservation", err)
	}
}

func TestOperatorIPTablesPreservationRefusesUnreviewedMutation(t *testing.T) {
	for _, kind := range []string{"confirmation", "digest", "boot", "namespace", "rules", "handle", "producer", "observer", "cancelled", "staging drift", "sync"} {
		t.Run(kind, func(t *testing.T) {
			inspection, current, epoch := fixtureOperatorIPTablesPreservation(t)
			ctx := context.Background()
			reviewed, confirmed := inspection.digest, true
			ops := defaultLegacyRetirementFileOps()
			switch kind {
			case "confirmation":
				confirmed = false
			case "digest":
				reviewed = strings.Repeat("f", 64)
			case "boot":
				epoch.BootID = "99999999-2222-3333-4444-555555555555"
			case "namespace":
				epoch.Inode++
			case "rules":
				current.rules[0].line += " changed"
			case "handle":
				*current = legacyIPTablesTestObservation(t, []string{current.rules[0].line, current.rules[1].line}, []uint64{60, 61})
			case "producer":
				inspection.guard = func(context.Context) error { return errors.New("producer changed") }
			case "observer":
				inspection.observe = func(context.Context) (legacyIPTablesObservation, error) {
					return legacyIPTablesObservation{}, errors.New("unavailable")
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "staging drift":
				ops.checkpoint = func(phase string) error {
					if phase == "kernel-staged" {
						current.rules[0].line += " changed"
					}
					return nil
				}
			case "sync":
				ops.sync = func(*os.File) error { return errors.New("not durable") }
			}
			if err := inspection.apply(ctx, reviewed, confirmed, ops); err == nil {
				t.Fatal("unsafe review was accepted")
			}
			if _, _, err := readOperatorIPTablesRecord(inspection.host, inspection.digest); err == nil {
				t.Fatal("failed pre-publication review published a decision")
			}
		})
	}
}

func TestOperatorIPTablesPreservationRejectsUnsafeDecision(t *testing.T) {
	for _, kind := range []string{"bytes", "unknown field", "mode", "directory mode", "parent mode", "symlink", "hardlink", "missing", "rules", "boot", "namespace"} {
		t.Run(kind, func(t *testing.T) {
			inspection, current, epoch := fixtureOperatorIPTablesPreservation(t)
			ctx := context.Background()
			if err := inspection.apply(ctx, inspection.digest, true, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			name := strings.TrimPrefix(inspection.summary().PrivateDecision, "/")
			checked := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "bytes":
				checked(inspection.host.root.WriteFile(name, []byte("{}"), 0600))
			case "unknown field":
				wire, err := inspection.host.root.ReadFile(name)
				checked(err)
				wire = append([]byte(`{"unexpected":true,`), wire[1:]...)
				checked(inspection.host.root.WriteFile(name, wire, 0600))
			case "mode":
				checked(inspection.host.root.Chmod(name, 0644))
			case "directory mode":
				checked(inspection.host.root.Chmod(strings.TrimSuffix(name, "/kernel.json"), 0755))
			case "parent mode":
				checked(inspection.host.root.Chmod(strings.TrimPrefix(operatorIPTablesRoot, "/"), 0755))
			case "symlink":
				checked(inspection.host.root.Rename(name, name+".original"))
				checked(inspection.host.root.Symlink("kernel.json.original", name))
			case "hardlink":
				checked(inspection.host.root.Link(name, name+".duplicate"))
			case "missing":
				checked(inspection.host.root.Remove(name))
			case "rules":
				current.rules[0].line += " changed"
			case "boot":
				epoch.BootID = "99999999-2222-3333-4444-555555555555"
			case "namespace":
				epoch.Inode++
			}
			if err := authorizeOperatorIPTablesPreservationUsing(ctx, inspection.host, *epoch, inspection.observe); err == nil {
				t.Fatal("unsafe decision bypassed removal preflight")
			}
		})
	}
}

func TestOperatorIPTablesPreservationCannotOverrideProductOwnership(t *testing.T) {
	for _, pending := range []bool{false, true} {
		rules := map[string]linuxWrapperRule{"owned": {backend: "iptables", kind: "port", value: "443", pending: pending}}
		if err := requireNoOwnedOperatorIPTablesRules(rules); err == nil {
			t.Fatal("IPv4 ownership was waived")
		}
	}
	if err := requireNoOwnedOperatorIPTablesRules(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyOperatorIPTablesPreservation(context.Background(), strings.Repeat("a", 64), false); err == nil {
		t.Fatal("missing explicit confirmation reached the host")
	}
}

func TestOperatorIPTablesPreservationRefusesNamespaceDriftDuringObservation(t *testing.T) {
	inspection, _, epoch := fixtureOperatorIPTablesPreservation(t)
	observe := inspection.observe
	inspection.observe = func(ctx context.Context) (legacyIPTablesObservation, error) {
		current, err := observe(ctx)
		epoch.Inode++
		return current, err
	}
	if err := inspection.verify(context.Background()); err == nil {
		t.Fatal("namespace drift during observation was accepted")
	}
}

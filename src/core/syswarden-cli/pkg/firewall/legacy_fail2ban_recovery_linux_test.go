//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestLegacyFail2banRecoveryRejectsUnreviewedAuthorizationBeforePreparation(t *testing.T) {
	called := false
	prepare := func() error { called = true; return nil }
	for _, pair := range [][2]string{{"", ""}, {strings.Repeat("a", 64), ""}, {strings.Repeat("A", 64), strings.Repeat("b", 64)}, {strings.Repeat("a", 64), "../intent"}} {
		if _, err := ApplyLegacyFail2banRecovery(context.Background(), pair[0], pair[1], prepare); err == nil {
			t.Fatal("invalid authorization accepted")
		}
	}
	if called {
		t.Fatal("unreviewed recovery prepared product removal")
	}
	if _, err := ApplyLegacyFail2banRecovery(context.Background(), strings.Repeat("a", 64), strings.Repeat("b", 64), nil); err == nil {
		t.Fatal("missing preparation accepted")
	}
}

func TestLegacyFail2banRecoveryFindsOnlyCanonicalReviewedKernelIntent(t *testing.T) {
	for _, mutation := range []string{"none", "bytes", "mode", "wrong-file-plan", "wrong-kernel"} {
		t.Run(mutation, func(t *testing.T) {
			host, plan, record := fixtureLegacyFail2banNFTJournal(t, true)
			guard := func(context.Context) error { return nil }
			journal, err := publishLegacyFail2banNFTIntent(context.Background(), host, record, guard, defaultLegacyRetirementFileOps())
			if err != nil {
				t.Fatal(err)
			}
			canonical, _, _, err := encodeLegacyFail2banNFTJournalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			kernel := fmt.Sprintf("%x", sha256.Sum256(canonical))
			fileDigest := plan.sha256
			switch mutation {
			case "bytes":
				err = host.root.WriteFile(strings.TrimPrefix(journal.path, "/")+"/kernel.json", append(canonical, '\n'), 0600)
			case "mode":
				err = host.root.Chmod(strings.TrimPrefix(journal.path, "/")+"/kernel.json", 0644)
			case "wrong-file-plan":
				fileDigest = strings.Repeat("c", 64)
			case "wrong-kernel":
				kernel = strings.Repeat("d", 64)
			}
			if err != nil {
				t.Fatal(err)
			}
			actual, found, err := findLegacyFail2banRecoveryKernel(host, fileDigest, kernel)
			if mutation != "none" {
				if err == nil && found {
					t.Fatal("unreviewed intent accepted")
				}
				return
			}
			if err != nil || !found {
				t.Fatal("reviewed intent unavailable", err)
			}
			restored, _, _, err := encodeLegacyFail2banNFTJournalRecord(actual)
			if err != nil || !bytes.Equal(restored, canonical) {
				t.Fatal("recovery intent changed", err)
			}
		})
	}
}

func TestLegacyFail2banUnusedRecoveryBindsReviewAndRetainedRuntime(t *testing.T) {
	fixture := fixtureLegacyFail2banUnused(t)
	fileOnly, err := legacyFail2banRecoveryUsesOnlyDefinitions(fixture.plan)
	if err != nil || !fileOnly {
		t.Fatal("exact unused definitions were not selected", err)
	}
	digest, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, fixture.live)
	if err != nil || !validLegacyRetirementDigest(digest) {
		t.Fatal("unused recovery could not bind its runtime", err)
	}
	if _, err := readLegacyFail2banPlan(fixture.host, fixture.plan.sha256); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection published a recovery record", err)
	}
	changed := cloneLegacyFail2banRuntimeFixture(fixture.live)
	changed.jails["new-admin-jail"] = legacyFail2banRuntimeJail{bans: []string{}}
	other, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, changed)
	if err != nil || other == digest {
		t.Fatal("review did not bind complete jail membership", err)
	}
	if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	retry, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, fixture.live)
	if err != nil || retry != digest {
		t.Fatal("retirement changed the reviewed file-only intent", err)
	}
	if _, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, changed); err == nil {
		t.Fatal("retired definitions adopted changed runtime protection")
	}
	path := strings.TrimPrefix(legacyFail2banPlanPath(fixture.plan.sha256), "/") + "/unused-runtime.json"
	if err := fixture.host.root.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, fixture.live); err == nil {
		t.Fatal("public runtime evidence was accepted")
	}
	if err := fixture.host.root.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, fixture.live); err == nil {
		t.Fatal("retired definitions recreated missing runtime evidence")
	}
}

func TestLegacyFail2banRecoveryDoesNotTreatActiveJailAsUnused(t *testing.T) {
	_, plan, _ := fixtureLegacyFail2banNFTJournal(t, true)
	fileOnly, err := legacyFail2banRecoveryUsesOnlyDefinitions(plan)
	if err != nil || fileOnly {
		t.Fatal("active jail selected the file-only path", err)
	}
	plan.binding.Targets = append(plan.binding.Targets, "/etc/fail2ban/filter.d/missing.conf")
	if _, err := legacyFail2banRecoveryUsesOnlyDefinitions(plan); err == nil {
		t.Fatal("incomplete source inventory accepted")
	}
}

func TestLegacyFail2banCompletedUnusedRecoveryRequiresEveryOriginalAndIntent(t *testing.T) {
	fixture := fixtureLegacyFail2banUnused(t)
	if _, complete, err := inspectCompletedUnusedLegacyFail2banRecovery(fixture.host, fixture.plan); err != nil || complete {
		t.Fatal("unretired files were reported complete", err)
	}
	wanted, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, fixture.live)
	if err != nil {
		t.Fatal(err)
	}
	if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	actual, complete, err := inspectCompletedUnusedLegacyFail2banRecovery(fixture.host, fixture.plan)
	if err != nil || !complete || actual != wanted {
		t.Fatal("completed recovery lost its reviewed original intent", err)
	}
	path := strings.TrimPrefix(legacyFail2banPlanPath(fixture.plan.sha256), "/") + "/unused-runtime.json"
	original, err := fixture.host.root.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.host.root.WriteFile(path, append(bytes.Clone(original), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := inspectCompletedUnusedLegacyFail2banRecovery(fixture.host, fixture.plan); err == nil || complete {
		t.Fatal("changed completion intent accepted")
	}
	if err := fixture.host.root.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.host.root.WriteFile(strings.TrimPrefix(fixture.plan.binding.Targets[0], "/"), []byte("recreated active source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := inspectCompletedUnusedLegacyFail2banRecovery(fixture.host, fixture.plan); err == nil || complete {
		t.Fatal("recreated source accepted as completed recovery")
	}
}

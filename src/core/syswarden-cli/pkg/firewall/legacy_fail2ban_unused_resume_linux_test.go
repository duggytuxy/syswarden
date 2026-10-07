//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func fixtureLegacyUnusedPartialResume(t *testing.T) *legacyFail2banUnusedFixture {
	t.Helper()
	fixture := fixtureLegacyFail2banUnused(t)
	interrupted := errors.New("synthetic interruption after the first unused file")
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == "source-retired" {
			return interrupted
		}
		return nil
	}
	if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, ops); !errors.Is(err, interrupted) {
		t.Fatal("partial retirement fixture did not stop at its first move", err)
	}
	state, err := inspectLegacyFail2banPlanState(fixture.host, fixture.plan.binding)
	if err != nil || len(state.retired) != 1 || len(state.retired) == len(fixture.plan.binding.Targets) {
		t.Fatal("fixture is not an exact partial retirement", err)
	}
	jail := fixture.live.jails["administrator-active"]
	jail.bans = append(jail.bans, "127.0.0.9 \tnew independently reviewed expiration")
	fixture.live.jails["administrator-active"] = jail
	return fixture
}

func TestLegacyUnusedResumeRequiresFreshReviewAndPreservesOriginalEvidence(t *testing.T) {
	fixture := fixtureLegacyUnusedPartialResume(t)
	originalPath := legacyFail2banPlanPath(fixture.plan.sha256) + "/unused-runtime.json"
	original, err := fixture.host.snapshot(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectUnusedLegacyFail2banRecoveryIntent(fixture.host, fixture.plan, fixture.live); err == nil {
		t.Fatal("ordinary recovery accepted a changed runtime baseline")
	}
	intent, complete, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, "")
	if err != nil || complete || !validLegacyRetirementDigest(intent.digest) {
		t.Fatal("new read-only review is unavailable", err)
	}
	path := legacyFail2banPlanPath(fixture.plan.sha256) + "/" + legacyUnusedResumePrefix + intent.digest + ".json"
	if _, err := fixture.host.snapshot(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection wrote a resume intent", err)
	}
	if _, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, strings.Repeat("a", 64)); err == nil {
		t.Fatal("a different reviewed digest authorized resumption")
	}
	fixture.adapter.bindRuntime = legacyUnusedResumeBinder(intent)
	if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal("explicit reviewed file-only resumption failed", err)
	}
	assertLegacyFail2banJournalComplete(t, fixture.host, fixture.plan)
	after, err := fixture.host.snapshot(originalPath)
	if err != nil || !sameLegacyFail2banSource(original, after) {
		t.Fatal("resumption changed the original runtime evidence", err)
	}
	ack, complete, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, nil, intent.digest)
	if err != nil || !complete || ack.digest != intent.digest {
		t.Fatal("completed resumption lost its exact immutable acknowledgement", err)
	}
	if _, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, nil, strings.Repeat("b", 64)); err == nil {
		t.Fatal("completed resumption accepted a different review")
	}
}

func TestLegacyUnusedResumeRejectsChangedReviewAndMissingOriginal(t *testing.T) {
	for _, mutation := range []string{"live-ban", "missing-original", "public-original", "modified-original", "recreated-source", "missing-plan"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := fixtureLegacyUnusedPartialResume(t)
			intent, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, "")
			if err != nil {
				t.Fatal(err)
			}
			original := strings.TrimPrefix(legacyFail2banPlanPath(fixture.plan.sha256), "/") + "/unused-runtime.json"
			switch mutation {
			case "live-ban":
				jail := fixture.live.jails["administrator-active"]
				jail.bans = nil
				fixture.live.jails["administrator-active"] = jail
			case "missing-original":
				err = fixture.host.root.Remove(original)
			case "public-original":
				err = fixture.host.root.Chmod(original, 0644)
			case "modified-original":
				wire, readErr := fixture.host.root.ReadFile(original)
				if readErr != nil {
					t.Fatal(readErr)
				}
				err = fixture.host.root.WriteFile(original, append(bytes.Clone(wire), '\n'), 0600)
			case "recreated-source":
				state, inspectErr := inspectLegacyFail2banPlanState(fixture.host, fixture.plan.binding)
				if inspectErr != nil {
					t.Fatal(inspectErr)
				}
				for path := range state.retired {
					err = fixture.host.root.WriteFile(strings.TrimPrefix(path, "/"), []byte("administrator replacement\n"), 0600)
				}
			case "missing-plan":
				err = fixture.host.root.Remove(strings.TrimPrefix(legacyFail2banPlanPath(fixture.plan.sha256), "/") + "/plan.json")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, intent.digest); err == nil {
				t.Fatal("changed evidence was accepted under the old review")
			}
		})
	}
}

func TestLegacyUnusedResumePreservesEveryInterruptedAttempt(t *testing.T) {
	for _, phase := range []string{"staged", "unused-resume-durable", "source-retired", "retirement-durable"} {
		t.Run(phase, func(t *testing.T) {
			fixture := fixtureLegacyUnusedPartialResume(t)
			intent, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, "")
			if err != nil {
				t.Fatal(err)
			}
			fixture.adapter.bindRuntime = legacyUnusedResumeBinder(intent)
			interrupted := errors.New("synthetic reviewed resumption interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(current string) error {
				if current == phase || phase == "staged" && current == legacyUnusedResumePrefix+intent.digest+"-staged" {
					return interrupted
				}
				return nil
			}
			if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, ops); !errors.Is(err, interrupted) {
				t.Fatal("resumption did not preserve its interruption boundary", err)
			}
			reopened, complete, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, intent.digest)
			if err != nil || reopened.digest != intent.digest {
				t.Fatal("exact interrupted intent could not be reopened", err)
			}
			if !complete {
				fixture.adapter.bindRuntime = legacyUnusedResumeBinder(reopened)
				if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal("exact interrupted resumption failed", err)
				}
			}
			assertLegacyFail2banJournalComplete(t, fixture.host, fixture.plan)
		})
	}
}

func TestLegacyUnusedResumeRejectsTamperedPublishedAuthority(t *testing.T) {
	for _, mutation := range []string{"missing-intent", "modified-intent", "public-intent", "symlink-intent", "missing-original", "modified-original", "missing-plan"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := fixtureLegacyUnusedPartialResume(t)
			intent, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, "")
			if err != nil {
				t.Fatal(err)
			}
			verify, err := bindLegacyUnusedResume(fixture.host, fixture.plan, fixture.live, intent, func() error { return nil }, defaultLegacyRetirementFileOps())
			if err != nil {
				t.Fatal("could not publish the reviewed authority", err)
			}
			directory := strings.TrimPrefix(legacyFail2banPlanPath(fixture.plan.sha256), "/")
			path := directory + "/" + legacyUnusedResumePrefix + intent.digest + ".json"
			switch mutation {
			case "missing-intent":
				err = fixture.host.root.Remove(path)
			case "modified-intent":
				err = fixture.host.root.WriteFile(path, []byte("{}"), 0600)
			case "public-intent":
				err = fixture.host.root.Chmod(path, 0644)
			case "symlink-intent":
				if err = fixture.host.root.Remove(path); err == nil {
					err = fixture.host.root.Symlink("unused-runtime.json", path)
				}
			case "missing-original":
				err = fixture.host.root.Remove(directory + "/unused-runtime.json")
			case "modified-original":
				err = fixture.host.root.WriteFile(directory+"/unused-runtime.json", []byte("{}"), 0600)
			case "missing-plan":
				err = fixture.host.root.Remove(directory + "/plan.json")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := verify(); err == nil {
				t.Fatal("published authority changed without invalidating its guard")
			}
			// Missing immutable intent can be re-created from the same current
			// review only before another move. The in-flight guard must stop.
			if mutation != "missing-intent" {
				if _, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, intent.digest); err == nil {
					t.Fatal("tampered published authority could be reopened")
				}
			}
		})
	}
}

func TestLegacyUnusedResumeStopsWhenCurrentProtectionChanges(t *testing.T) {
	fixture := fixtureLegacyUnusedPartialResume(t)
	intent, _, err := inspectLegacyUnusedResume(fixture.host, fixture.plan, &fixture.live, "")
	if err != nil {
		t.Fatal(err)
	}
	fixture.adapter.bindRuntime = legacyUnusedResumeBinder(intent)
	fixture.adapter.read = func(ctx context.Context, _ bool) (legacyFail2banRuntimeSnapshot, error) {
		live := cloneLegacyFail2banRuntimeFixture(fixture.live)
		return live, verifyLegacyUnusedResumeRuntime(ctx, fixture.plan.sha256, intent, live)
	}
	moved := 0
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == "source-retired" {
			moved++
			jail := fixture.live.jails["administrator-active"]
			jail.bans = nil
			fixture.live.jails["administrator-active"] = jail
		}
		return nil
	}
	if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, ops); err == nil {
		t.Fatal("reviewed resumption ignored changed current protection")
	}
	if moved != 1 {
		t.Fatal("resumption moved another file after current protection changed", moved)
	}
}

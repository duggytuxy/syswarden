//go:build linux

package system

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type apkTerminalTestActivation struct {
	apkTransitionTestActivation
	effects  []byte
	original nativeActivationRuntimeSnapshot
}

func (activation apkTerminalTestActivation) OriginalRuntime() nativeActivationRuntimeSnapshot {
	return activation.original
}

func (activation apkTerminalTestActivation) DurableEffects() ([]byte, error) {
	return activation.effects, nil
}
func (activation apkTerminalTestActivation) EffectPlanSHA256() string {
	return apkTransitionDigest(activation.effects)
}

// Native acknowledgments below are deliberately synthetic component evidence.
// Real APK2/3 process ancestry and ordering are covered by the opt-in oracle.
func apkTerminalCompleteFixture(t *testing.T) (*apkExecutionTestFixture, func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error)) {
	t.Helper()
	return apkTerminalCompleteFixtureWithSetup(t, nil)
}

func apkTerminalCompleteFixtureWithSetup(t *testing.T, setup func(*authenticatedAPKCandidate, *apkTransitionServices)) (*apkExecutionTestFixture, func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error)) {
	t.Helper()
	candidate, services, _ := apkTransitionFixture(t)
	services.root = filepath.Join(services.hostRoot, strings.TrimPrefix(apkTransitionRoot, "/"))
	if setup != nil {
		setup(&candidate, &services)
	}
	boundary := apkExecutionTestAuthority()
	services.activation = func(ctx context.Context, c authenticatedAPKCandidate) (apkTransitionActivation, error) {
		capability, err := attestNativeActivationCandidate(ctx, c.target, c.file)
		if err != nil {
			return nil, err
		}
		policy, err := services.policy(ctx)
		if err != nil {
			return nil, err
		}
		installed, err := c.attestInstalled(ctx, c.target, c.uid)
		if err != nil {
			return nil, err
		}
		original, err := captureNativeActivationRuntime(ctx, filepath.Join(services.hostRoot, "opt/syswarden/bin"), c.uid)
		if err != nil {
			return nil, err
		}
		plan := nativeActivationBindingPlan{Schema: policy.effectSchema(), PackageName: c.target.packageName, Format: packageFormatAPK, Installer: c.target.installer, CandidateVersion: c.version, Artifact: c.artifact, ManifestSHA256: apkTransitionDigest(c.manifest), SignatureSHA256: apkTransitionDigest(c.signature), Capability: capability.Review(), InstalledVersion: installed.version, Installed: original, RuntimePolicy: policy, HostObservationSHA256: strings.Repeat("a", 64), Offline: c.offline}
		if policy.inactive() {
			source, _, _, err := observeNativePublicationExclusionSource(ctx, services.hostRoot)
			if err != nil {
				return nil, err
			}
			plan.SourcePublicationSHA256 = source.SHA256()
		}
		raw, err := apkExecutionJSON(plan)
		if err != nil {
			return nil, err
		}
		activation := apkTerminalTestActivation{effects: raw, original: original}
		boundary.digest = activation.EffectPlanSHA256()
		return activation, nil
	}
	f := &apkExecutionTestFixture{candidate: candidate, services: services, installed: installedQualificationEvidence{version: candidate.version, cliSHA256: candidate.cliSHA256}}
	old := candidate.attestInstalled
	f.candidate.attestInstalled = func(ctx context.Context, target packageTarget, uid int) (installedQualificationEvidence, error) {
		if f.post {
			return f.installed, f.installErr
		}
		return old(ctx, target, uid)
	}
	err := prepareAPKTransition(t.Context(), f.candidate, f.services)
	if !errors.As(err, &f.preparation) {
		t.Fatal(err)
	}
	f.review, err = planAPKTransitionExecution(t.Context(), f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, boundary)
	if err != nil {
		t.Fatal(err)
	}
	inventory, _, err := readAPKTransitionInventory(t.Context(), candidate.file)
	if err != nil {
		t.Fatal(err)
	}
	boundary.factory = func(ctx context.Context, path string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry) (apkExecutionLaunchers, error) {
		return prepareAPKLauncherCustodyWithTargetsAt(ctx, f.services.hostRoot, path, binding, original, inventory, boundary.digest)
	}
	var handoffSHA string
	runner := func(ctx context.Context, prepared *verifiedPreparedAPKTransition, overlay *os.File, args []string, out io.Writer) error {
		if err := f.run(ctx, prepared, overlay, args, out); err != nil {
			return err
		}
		for _, member := range apkTransitionFixtureMembers() {
			if len(member.content) == 0 || !(strings.HasPrefix(member.header.Name, "opt/syswarden/") || member.header.Name == apkTransitionGateDirectory+"/syswarden-recovery") {
				continue
			}
			if member.header.Mode < 0 || member.header.Mode > 0777 {
				return errors.New("inert fixture member permission exceeds its supported range")
			}
			if err := os.WriteFile(filepath.Join(f.services.hostRoot, member.header.Name), member.content, os.FileMode(member.header.Mode)); err != nil {
				return err
			}
		}
		directory, err := openExistingPinnedServiceDirectory(f.review.Directory)
		if err != nil {
			return err
		}
		defer directory.close()
		write := func(name string, value any) error {
			raw, err := apkExecutionJSON(value)
			if err != nil {
				return err
			}
			return writeAPKTransitionBytes(directory, name, raw)
		}
		approvalRaw, err := readAPKTransitionBytes(directory, "execution-approval.json", 4096)
		if err != nil {
			return err
		}
		helper, err := openAPKExecutionHelper(directory, candidate.cliSHA256)
		if err != nil {
			return err
		}
		info, err := helper.Stat()
		closeErr := helper.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
		body, err := apkTransitionGateBytes(f.review.PlanSHA256)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(f.services.root, "active-hook"), body, 0700); err != nil { // #nosec G306 -- fixed active-hook path inside the temporary private custody models required executable0700 metadata
			return err
		}
		if err := os.WriteFile(filepath.Join(f.services.hostRoot, apkTransitionGateDirectory, apkTransitionGateName), body, 0755); err != nil { // #nosec G306 -- fixed commit-gate path inside the temporary host models required executable0755 metadata
			return err
		}
		parent, err := os.OpenRoot(f.services.root)
		if err != nil {
			return err
		}
		defer parent.Close()
		hooks, err := os.OpenRoot(filepath.Join(f.services.hostRoot, apkTransitionGateDirectory))
		if err != nil {
			return err
		}
		defer hooks.Close()
		active, err := readAPKNativeHookMode(parent, "active-hook", 0700)
		if err != nil {
			return err
		}
		gate, err := readAPKNativeHook(hooks, apkTransitionGateName)
		if err != nil {
			return err
		}
		record := apkNativeHandoffRecord{Schema: apkNativeHandoffSchema, PlanSHA256: f.review.PlanSHA256, ApprovalSHA256: apkTransitionDigest(approvalRaw), Helper: nativeActivationRuntimeFile{Identity: apkTransitionStat(info.Sys().(*syscall.Stat_t)), SHA256: candidate.cliSHA256}, Coordinator: apkNativeProcess{PID: 40, ParentPID: 39, Start: 100}, Hook: gate, Active: active}
		raw, err := apkExecutionJSON(record)
		if err != nil {
			return err
		}
		handoffSHA = apkTransitionDigest(raw)
		if err := writeAPKTransitionBytes(directory, "native-handoff.json", raw); err != nil {
			return err
		}
		child := apkNativeProcess{PID: 42, ParentPID: 40, Start: 101}
		if err := write("native-child.json", child); err != nil {
			return err
		}
		for _, phase := range []string{"pre-commit", "pre-upgrade", "post-upgrade", "post-commit"} {
			ack := apkNativeHookAcknowledgment{Request: apkNativeHookPacket{apkNativeHandoffSchema, f.review.PlanSHA256, handoffSHA, phase, "request"}, Native: child, Helper: apkNativeProcess{PID: 43, ParentPID: 42, Start: 102, Executable: record.Helper}}
			if phase == "post-commit" {
				database, err := os.ReadFile(filepath.Join(f.services.hostRoot, "lib/apk/db/installed"))
				if err != nil {
					return err
				}
				ack.DatabaseSHA256 = apkTransitionDigest(database)
				if err := writeAPKTransitionBytes(directory, "native-post-commit-database.txt", database); err != nil {
					return err
				}
			}
			if err := write("native-hook-"+phase+".json", ack); err != nil {
				return err
			}
		}
		return retainAPKNativeResult(directory, &apkTransitionHandoff{record: record, digest: handoffSHA, phases: 4}, []byte("inert native transaction fixture\n"))
	}
	if err := f.execute(t.Context(), boundary, apkExecutionServices{run: runner}); err != nil {
		t.Fatal(err)
	}
	// Bind the synthetic adapter observations explicitly. Production receives this
	// digest only from prepareAPKTransitionHandoff and the actual native adapter.
	for _, state := range []string{"armed", "native-started", "observed", "completed"} {
		path := filepath.Join(f.review.Directory, state+".json")
		raw, err := os.ReadFile(path) // #nosec G304 -- closed state-name table selects only records in this test private execution directory
		if err != nil {
			t.Fatal(err)
		}
		var event apkExecutionEvent
		if err := decodeAPKTransitionJSON(raw, &event); err != nil {
			t.Fatal(err)
		}
		event.NativeHandoffSHA256 = handoffSHA
		raw, err = apkExecutionJSON(event)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := retainAPKExecutionClosure(t.Context(), f.services.root, f.review.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	factory := func(ctx context.Context, prepared *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
		return &apkExecutionTestBoundary{digest: prepared.plan.EffectPlanSHA256}, ctx.Err()
	}
	return f, factory
}

func inspectAPKTerminalFixture(ctx context.Context, f *apkExecutionTestFixture, factory func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error)) (*apkTerminalAuthority, error) {
	return inspectAPKTransitionTerminal(ctx, f.review.PlanSHA256, map[string]ed25519.PublicKey(f.candidate.keys), f.candidate.attestInstalled, f.services, factory)
}

func TestAPKTerminalIndependentInspectionAndGateFinalization(t *testing.T) {
	f, factory := apkTerminalCompleteFixture(t)
	authority, err := inspectAPKTerminalFixture(t.Context(), f, factory)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := authority.Finalize(t.Context()); err != nil {
		t.Fatal("exact finalization retry", err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(f.services.root, "active-hook"), filepath.Join(f.services.hostRoot, apkTransitionGateDirectory, apkTransitionGateName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned gate remains", err)
		}
	}
	if f.calls != 1 {
		t.Fatal("terminal action replayed native execution")
	}
}

func TestAPKTerminalRefusesIncompleteContradictoryOrChangedOutcomes(t *testing.T) {
	for _, kind := range []string{"missing-closure", "missing-result", "missing-ack", "unresolved", "unknown", "wrong-version", "runtime-bytes", "original-bytes", "gate-inode", "gate-missing", "policy", "lifecycle", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f, factory := apkTerminalCompleteFixture(t)
			ctx := t.Context()
			switch kind {
			case "missing-closure":
				_ = os.Remove(filepath.Join(f.review.Directory, "resources-closed.json"))
			case "missing-result":
				_ = os.Remove(filepath.Join(f.review.Directory, "native-result.json"))
			case "missing-ack":
				_ = os.Remove(filepath.Join(f.review.Directory, "native-hook-post-commit.json"))
			case "unresolved", "unknown":
				if err := os.WriteFile(filepath.Join(f.review.Directory, kind+".json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-version":
				f.installed.version = "v5.01.0"
			case "runtime-bytes":
				if err := os.WriteFile(filepath.Join(f.services.hostRoot, "opt/syswarden/bin/syswarden-core"), []byte("changed candidate\n"), 0750); err != nil { // #nosec G306 -- fixed temporary candidate core bytes are deliberately corrupted
					t.Fatal(err)
				}
			case "original-bytes":
				if err := os.WriteFile(filepath.Join(f.review.Directory, "original-runtime/bin/syswarden-core"), []byte("changed evidence\n"), 0750); err != nil { // #nosec G306 -- fixed temporary retained original-core bytes are deliberately corrupted
					t.Fatal(err)
				}
			case "gate-inode":
				path := filepath.Join(f.services.root, "active-hook")
				raw, err := os.ReadFile(path) // #nosec G304 -- fixed active-hook record inside this test private custody root
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0700); err != nil { // #nosec G306 G703 -- fixed temporary active-hook record is deliberately replaced with identical bytes and executable0700 metadata
					t.Fatal(err)
				}
			case "gate-missing":
				if err := os.Remove(filepath.Join(f.services.root, "active-hook")); err != nil {
					t.Fatal(err)
				}
			case "policy":
				f.services.policy = func(context.Context) (apkTransitionPolicyBinding, error) {
					return apkTransitionPolicyBinding{}, errors.New("changed runtime approval")
				}
			case "lifecycle":
				factory = func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
					return nil, errors.New("lifecycle refusal")
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			authority, err := inspectAPKTerminalFixture(ctx, f, factory)
			if err == nil {
				_ = authority.Close()
				t.Fatal("unqualified terminal outcome accepted")
			}
			if f.calls != 1 {
				t.Fatal("refusal replayed APK")
			}
		})
	}
}

func TestAPKTerminalOwningWrapperPreservesLateClosureFailure(t *testing.T) {
	for _, kind := range []string{"clean", "close-error", "close-cancel", "close-error-marker-fails", "proof-publication-fails", "proof-sync-marker-fails"} {
		t.Run(kind, func(t *testing.T) {
			f, factory := apkTerminalCompleteFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind != "clean" {
				factory = func(_ context.Context, prepared *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
					return &apkTerminalClosingTestBoundary{digest: prepared.plan.EffectPlanSHA256, fail: kind == "close-error" || kind == "close-error-marker-fails", cancel: func() {
						if kind == "close-cancel" {
							cancel()
						}
						if kind == "proof-publication-fails" {
							if err := os.WriteFile(filepath.Join(f.review.Directory, "terminal-closed.pending"), []byte("interrupted private metadata write\n"), 0600); err != nil {
								t.Fatal(err)
							}
						}
					}}, nil
				}
			}
			failureWriter := writeAPKTransitionBytes
			if kind == "close-error-marker-fails" || kind == "proof-sync-marker-fails" {
				failureWriter = func(*pinnedServiceDirectory, string, []byte) error { return syscall.ENOSPC }
			}
			closurePublisher := publishAPKTerminalClosure
			if kind == "proof-sync-marker-fails" {
				closurePublisher = func(ctx context.Context, path string, identity apkTransitionIdentity, intent, closure []byte) error {
					return publishAPKTerminalClosureUsing(ctx, path, identity, intent, closure, func(*pinnedServiceDirectory) error { return syscall.ENOSPC })
				}
			}
			err := finalizeAPKTransitionUsing(ctx, f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory, failureWriter, closurePublisher)
			if kind == "clean" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(f.review.Directory, "terminal-closed.json")); err != nil {
					t.Fatal("positive effect-resource closure missing", err)
				}
				h, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), f.services.hostRoot)
				if err != nil {
					t.Fatal("closed terminal lineage unavailable", err)
				}
				if err := h.close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			var failure *APKTransitionExecutionError
			if !errors.As(err, &failure) || !failure.Unresolved {
				t.Fatal("late terminal failure was hidden", err)
			}
			raw, readErr := os.ReadFile(filepath.Join(f.review.Directory, "terminal-unresolved.json"))
			var event apkExecutionEvent
			if kind == "close-error-marker-fails" || kind == "proof-sync-marker-fails" {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatal("failure injection unexpectedly published a marker", readErr)
				}
			} else if readErr != nil || decodeAPKTransitionJSON(raw, &event) != nil || event.State != "terminal-unresolved" || event.PlanSHA256 != f.review.PlanSHA256 {
				t.Fatal("late terminal failure debt missing", readErr)
			}
			if kind == "proof-sync-marker-fails" {
				pending, err := os.Lstat(filepath.Join(f.review.Directory, "terminal-closed.pending"))
				closed, closeErr := os.Lstat(filepath.Join(f.review.Directory, "terminal-closed.json"))
				if err != nil || closeErr != nil || !os.SameFile(pending, closed) || closed.Sys().(*syscall.Stat_t).Nlink != 2 {
					t.Fatal("failed publication did not preserve pending debt", err, closeErr)
				}
			} else if _, err := os.Lstat(filepath.Join(f.review.Directory, "terminal-closed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed closure published positive proof", err)
			}
			h, removalErr := inspectAPKLauncherLifecycleRemovalAt(t.Context(), f.services.hostRoot)
			if removalErr == nil {
				_ = h.close()
				t.Fatal("removal accepted failed closure without positive proof")
			}
			if _, err := os.Lstat(filepath.Join(f.review.Directory, "terminal-finalized.json")); err != nil {
				t.Fatal("fixture did not reach finalization before failure", err)
			}
			reopened, err := inspectAPKTerminalFixture(t.Context(), f, func(ctx context.Context, prepared *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
				return &apkExecutionTestBoundary{digest: prepared.plan.EffectPlanSHA256}, ctx.Err()
			})
			if err == nil {
				_ = reopened.Close()
				if kind != "close-error-marker-fails" {
					t.Fatal("finalized record bypassed later unresolved closure")
				}
			}
		})
	}
}

type apkTerminalClosingTestBoundary struct {
	digest string
	fail   bool
	cancel func()
}

func (boundary *apkTerminalClosingTestBoundary) EffectPlanSHA256() string { return boundary.digest }
func (boundary *apkTerminalClosingTestBoundary) AttestResult(ctx context.Context) error {
	return ctx.Err()
}
func (boundary *apkTerminalClosingTestBoundary) Close() error {
	if boundary.cancel != nil {
		boundary.cancel()
	}
	if boundary.fail {
		return syscall.EIO
	}
	return nil
}

func TestAPKTerminalProductionWrapperRefusesMissingAuthority(t *testing.T) {
	if err := finalizeAPKTransition(t.Context(), "", nil, nil, apkTransitionServices{}); err == nil {
		t.Fatal("missing terminal authority accepted")
	}
}

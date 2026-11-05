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
	"testing"
)

func apkInactiveCoordinatorFixtureServices(t *testing.T, f *apkExecutionTestFixture) (apkInactiveCustodyServices, **apkInactiveTestLease, *nativeActivationPolicyObservation) {
	t.Helper()
	prepared, err := openVerifiedPreparedAPKTransition(t.Context(), f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services)
	if err != nil {
		t.Fatal(err)
	}
	services, lease, observed := apkInactiveTestCustodyServices(t, prepared)
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	return services, lease, observed
}

// The signed candidate, retained plans, real launcher custody, execution engine,
// terminal reader and activation preflight are exercised together. Native bytes,
// acknowledgments and original process/host observations are inert fixtures.
func TestAPKInactiveCoordinatorPlansExecutesAndClosesOriginalCustody(t *testing.T) {
	for _, selected := range nativeProductPackageNames {
		t.Run(selected, func(t *testing.T) {
			for _, outcome := range []string{"success", "native-error", "missing-install", "wrong-execution", "policy-drift", "candidate-drift", "missing-completed", "cancel-after-native", "close-error"} {
				t.Run(outcome, func(t *testing.T) {
					f, _, runner, bindNative := apkTerminalReadyFixture(t, func(candidate *authenticatedAPKCandidate, s *apkTransitionServices) {
						if selected == baseNativePackageName {
							var replacement apkTransitionServices
							*candidate, replacement, _ = apkTransitionFixtureForName(t, selected)
							*s = replacement
							s.root = filepath.Join(s.hostRoot, strings.TrimPrefix(apkTransitionRoot, "/"))
						}
						apkInactiveTestSource(t, s)
					})
					planning, planningLease, _ := apkInactiveCoordinatorFixtureServices(t, f)
					review, err := planAPKInactiveTransitionExecution(t.Context(), f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, planning)
					if err != nil || review == nil || review.PlanSHA256 != f.review.PlanSHA256 || (*planningLease).closes != 1 || f.calls != 0 {
						t.Fatal("planning changed the proposal, retained its lease or dispatched", err)
					}
					assertAPKExecutionState(t, f, "execution-approval", false)
					custody, lease, observed := apkInactiveCoordinatorFixtureServices(t, f)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					sentinel := errors.New("inert coordinator failure")
					digest := review.PlanSHA256
					if outcome == "wrong-execution" {
						digest = strings.Repeat("f", 64)
					}
					run := func(check context.Context, preparation, execution string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, factory apkExecutionBoundaryFactory) error {
						guardedFactory := func(check context.Context, prepared *verifiedPreparedAPKTransition) (apkExecutionBoundary, error) {
							boundary, err := factory(check, prepared)
							if err != nil {
								return boundary, err
							}
							(*lease).afterClose = func() error {
								if outcome != "wrong-execution" && preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot) == nil {
									return errors.New("activation opened before independent terminal closure")
								}
								return nil
							}
							if outcome == "close-error" {
								(*lease).closeErr = sentinel
							}
							return boundary, nil
						}
						inertRunner := runner
						if outcome == "native-error" || outcome == "missing-install" {
							inertRunner = func(context.Context, *verifiedPreparedAPKTransition, *os.File, []string, io.Writer) error {
								f.calls++
								// The injected runner replaces the real handoff. Model its
								// durable gate even when native dispatch fails immediately.
								if err := os.WriteFile(filepath.Join(f.services.root, "active-hook"), []byte("inert pending native handoff\n"), 0600); err != nil {
									return err
								}
								if outcome == "native-error" {
									return sentinel
								}
								return nil
							}
						}
						if err := executeAPKTransitionWith(check, preparation, execution, keys, attest, services, guardedFactory, apkExecutionServices{run: inertRunner}); err != nil {
							return err
						}
						bindNative()
						if *lease == nil || (*lease).closes != 0 {
							return errors.New("execution cleanup released coordinator custody")
						}
						switch outcome {
						case "policy-drift":
							observed.binding.PolicySHA256 = strings.Repeat("f", 64)
						case "candidate-drift":
							if err := os.WriteFile(filepath.Join(f.services.hostRoot, "opt/syswarden/bin/syswarden-core"), []byte("changed candidate\n"), 0600); err != nil {
								return err
							}
						case "missing-completed":
							if err := os.Remove(filepath.Join(f.review.Directory, "completed.json")); err != nil {
								return err
							}
						case "cancel-after-native":
							cancel()
						}
						return nil
					}
					err = executeAPKInactiveTransitionWith(ctx, f.preparation.PlanSHA256, digest, f.candidate.keys, f.candidate.attestInstalled, f.services, custody, run)
					if (err == nil) != (outcome == "success") {
						t.Fatal("coordinator accepted incomplete native closure", err)
					}
					if *lease == nil || (*lease).closes != 1 {
						t.Fatal("original lease not closed exactly once")
					}
					if outcome == "native-error" || outcome == "close-error" {
						if !errors.Is(err, sentinel) {
							t.Fatal("failure concealed", err)
						}
					}
					calls := 1
					if outcome == "wrong-execution" {
						calls = 0
					}
					if f.calls != calls {
						t.Fatal("native dispatch bypassed exact review or replayed", f.calls)
					}
					assertAPKExecutionState(t, f, "terminal-closed", outcome == "success")
					activation := preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot)
					if (activation == nil) != (outcome == "success" || outcome == "wrong-execution") {
						t.Fatal("activation ignored complete terminal outcome", activation)
					}
					competitor := apkExecutionFactoryTestRoot(t, filepath.Join(f.services.hostRoot, "etc/syswarden/config"))
					assertAPKExecutionFactoryLock(t, competitor, false)
					// An exact repeat cannot reopen completed or failed original state.
					before := f.calls
					if err := executeAPKInactiveTransitionWith(t.Context(), f.preparation.PlanSHA256, digest, f.candidate.keys, f.candidate.attestInstalled, f.services, custody, run); err == nil || f.calls != before {
						t.Fatal("completed or failed coordinator replayed", err)
					}
				})
			}
		})
	}
}

func TestAPKInactiveCoordinatorRejectsMissingExecutionOrPublicationOwner(t *testing.T) {
	for _, kind := range []string{"nil-context", "bad-preparation", "bad-execution", "nil-run", "cancel", "missing-owner"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			preparation, execution := strings.Repeat("a", 64), strings.Repeat("b", 64)
			calls := 0
			var run apkInactiveExecute = func(context.Context, string, string, map[string]ed25519.PublicKey, installedVersionAttestor, apkTransitionServices, apkExecutionBoundaryFactory) error {
				calls++
				return nil
			}
			switch kind {
			case "nil-context":
				ctx = nil
			case "bad-preparation":
				preparation = ""
			case "bad-execution":
				execution = ""
			case "nil-run":
				run = nil
			case "cancel":
				cancel()
			}
			err := executeAPKInactiveTransitionWith(ctx, preparation, execution, nil, nil, apkTransitionServices{}, apkInactiveCustodyServices{}, run)
			if err == nil || calls > 1 || (kind != "missing-owner" && calls != 0) {
				t.Fatal("incomplete coordination dispatched or succeeded", err, calls)
			}
		})
	}
	if err := executeAPKInactiveTransition(t.Context(), "", "", nil, nil, apkTransitionServices{}, apkInactiveCustodyServices{}); err == nil {
		t.Fatal("production entry admitted missing authority")
	}
}

func TestAPKInactivePlanningCustodyCannotAuthorizeExecution(t *testing.T) {
	f, _, _, _ := apkTerminalReadyFixture(t, func(_ *authenticatedAPKCandidate, s *apkTransitionServices) { apkInactiveTestSource(t, s) })
	prepared, err := openVerifiedPreparedAPKTransition(t.Context(), f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	services, lease, _ := apkInactiveTestCustodyServices(t, prepared)
	owner, err := openAPKInactivePreparationCustody(t.Context(), prepared, services)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	boundary := &apkInactiveExecutionBoundary{owner: owner, prepared: prepared}
	if owner.executionSHA256 != "" {
		t.Fatal("planning manufactured execution approval")
	}
	if _, err := boundary.PrepareLaunchers(t.Context(), f.review.Directory, apkLauncherCustodyBinding{PlanSHA256: f.review.PlanSHA256}, nil); err == nil {
		t.Fatal("planning owner authorized launcher mutation")
	}
	if err := boundary.AttestResult(t.Context()); err == nil {
		t.Fatal("planning owner accepted native completion")
	}
	if err := boundary.Close(); err != nil || (*lease).closes != 0 {
		t.Fatal("borrower released original publication lease", err)
	}
	if boundary.EffectPlanSHA256() != "" || boundary.Revalidate(t.Context()) == nil {
		t.Fatal("closed borrower retained authority")
	}
	if err := finalizeAPKInactiveTransition(t.Context(), "", f.candidate.keys, f.candidate.attestInstalled, f.services, owner); err == nil || (*lease).closes != 1 {
		t.Fatal("planning authority reached finalization", err)
	}
	assertAPKExecutionState(t, f, "execution-approval", false)
	assertAPKExecutionState(t, f, "terminal-closed", false)
}

func TestAPKInactivePlanningCloseFailureDoesNotReturnSuccessfulReview(t *testing.T) {
	f, _, _, _ := apkTerminalReadyFixture(t, func(_ *authenticatedAPKCandidate, s *apkTransitionServices) { apkInactiveTestSource(t, s) })
	services, lease, _ := apkInactiveCoordinatorFixtureServices(t, f)
	hold := services.hold
	sentinel := errors.New("inert planning close failure")
	services.hold = func(ctx context.Context, expected apkTransitionPolicyBinding) (apkInactiveLease, error) {
		value, err := hold(ctx, expected)
		if err == nil {
			(*lease).closeErr = sentinel
		}
		return value, err
	}
	_, err := planAPKInactiveTransitionExecution(t.Context(), f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, services)
	if !errors.Is(err, sentinel) || (*lease).closes != 1 || f.calls != 0 {
		t.Fatal("planning concealed cleanup failure or dispatched", err)
	}
	assertAPKExecutionState(t, f, "execution-approval", false)
}

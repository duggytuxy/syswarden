//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type apkInactiveTestLease struct {
	file       *os.File
	digest     string
	closeErr   error
	checkErr   error
	afterClose func() error
	closes     int
}

func (lease *apkInactiveTestLease) SHA256() string { return lease.digest }
func (lease *apkInactiveTestLease) Revalidate(ctx context.Context) error {
	if lease.file == nil || lease.closes != 0 {
		return errors.New("inert publication lease is closed")
	}
	return errors.Join(lease.checkErr, ctx.Err())
}
func (lease *apkInactiveTestLease) Close() error {
	lease.closes++
	err := lease.file.Close()
	if lease.afterClose != nil {
		err = errors.Join(err, lease.afterClose())
	}
	return errors.Join(err, lease.closeErr)
}

func apkInactiveTestSource(t *testing.T, s *apkTransitionServices) {
	t.Helper()
	s.policy = func(ctx context.Context) (apkTransitionPolicyBinding, error) {
		return inactivePolicyFixture(), ctx.Err()
	}
	runtime, err := captureNativeActivationRuntime(t.Context(), filepath.Join(s.hostRoot, "opt/syswarden/bin"), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(runtime.CLI.SHA256, runtime.Core.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(s.hostRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile(nativeActivationDescriptorPath, raw, 0644); err != nil {
		t.Fatal(err)
	}
}

func apkInactiveTestCustodyServices(t *testing.T, prepared *verifiedPreparedAPKTransition) (apkInactiveCustodyServices, **apkInactiveTestLease, *nativeActivationPolicyObservation) {
	t.Helper()
	var lease *apkInactiveTestLease
	observed := &nativeActivationPolicyObservation{binding: inactivePolicyFixture(), hostSHA256: strings.Repeat("a", 64), revalidate: func(ctx context.Context) error { return ctx.Err() }, verifyPolicy: func(ctx context.Context) error { return ctx.Err() }}
	services := apkInactiveCustodyServices{
		hold: func(ctx context.Context, expected apkTransitionPolicyBinding) (apkInactiveLease, error) {
			if expected != observed.binding || lease != nil {
				return nil, errors.New("incorrect or repeated publication lease acquisition")
			}
			file := apkExecutionFactoryTestRoot(t, filepath.Join(prepared.services.hostRoot, "etc/syswarden/config"))
			if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				return nil, err
			}
			lease = &apkInactiveTestLease{file: file, digest: expected.AbsenceSHA256}
			return lease, ctx.Err()
		},
		observe: func(ctx context.Context) (nativeActivationPolicyObservation, error) {
			if lease == nil || lease.closes != 0 {
				return nativeActivationPolicyObservation{}, errors.New("independent observer lost publication exclusion")
			}
			return *observed, ctx.Err()
		},
		source: func(ctx context.Context, original nativeActivationBindingPlan, candidate NativeActivationCandidate) (func(context.Context, bool) error, error) {
			if !original.validPublicationBinding(candidate) {
				return nil, errors.New("inert source binding is incomplete")
			}
			return func(check context.Context, _ bool) error { return check.Err() }, ctx.Err()
		},
		installed: func(ctx context.Context, candidate NativeActivationCandidate) error {
			return candidate.verifyInstalledAt(ctx, prepared.services.hostRoot, apkInactiveTestID(t, os.Geteuid()), apkInactiveTestID(t, os.Getegid()))
		},
	}
	return services, &lease, observed
}

// The real retained execution/terminal component path uses inert package bytes
// and synthetic native acknowledgments. The publication lease is a real flock,
// while policy/source observations are controlled fixtures, not host acceptance.
func TestAPKInactiveCustodyOutlivesExecutionAndGatesTerminalClosure(t *testing.T) {
	for _, outcome := range []string{"success", "lease-close", "absence-drift", "host-drift", "policy-drift", "source-drift", "candidate-drift", "execution-substitution", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			var owner *apkInactiveCustody
			var lease **apkInactiveTestLease
			var observation *nativeActivationPolicyObservation
			var competitor *os.File
			var boundary *apkExecutionTestBoundary
			f, _ := apkTerminalCompleteFixtureWithCustody(t, func(_ *authenticatedAPKCandidate, s *apkTransitionServices) {
				apkInactiveTestSource(t, s)
			}, func(ctx context.Context, prepared *verifiedPreparedAPKTransition, execution string, b *apkExecutionTestBoundary) (apkExecutionBoundary, error) {
				services, held, observed := apkInactiveTestCustodyServices(t, prepared)
				lease, observation = held, observed
				var err error
				owner, err = openAPKInactiveCustody(ctx, prepared, execution, services)
				if err != nil {
					return nil, err
				}
				t.Cleanup(func() { _ = owner.Close() })
				competitor = apkExecutionFactoryTestRoot(t, filepath.Join(prepared.services.hostRoot, "etc/syswarden/config"))
				assertAPKExecutionFactoryLock(t, competitor, true)
				b.before = func(ctx context.Context) error { return owner.Revalidate(ctx, false) }
				b.after = func(ctx context.Context) error { return owner.Revalidate(ctx, true) }
				boundary = b
				return b, nil
			})
			if owner == nil || (*lease).closes != 0 || boundary.calls[len(boundary.calls)-1] != "close" {
				t.Fatal("execution resource cleanup did not retain independent publication custody")
			}
			assertAPKExecutionFactoryLock(t, competitor, true)
			if err := preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot); err == nil {
				t.Fatal("retained native transaction permitted activation")
			}
			(*lease).afterClose = func() error {
				if err := preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot); err == nil {
					return errors.New("lease release opened activation before positive terminal closure")
				}
				return nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			digest := f.review.PlanSHA256
			sentinel := errors.New("inert final lease close failure")
			switch outcome {
			case "lease-close":
				(*lease).closeErr = sentinel
			case "absence-drift":
				(*lease).digest = strings.Repeat("f", 64)
			case "host-drift":
				observation.hostSHA256 = strings.Repeat("b", 64)
			case "policy-drift":
				observation.binding.PolicySHA256 = strings.Repeat("b", 64)
			case "source-drift":
				owner.source = func(context.Context, bool) error { return errors.New("original coordinator changed") }
			case "candidate-drift":
				owner.installed = func(context.Context, NativeActivationCandidate) error { return errors.New("candidate changed") }
			case "execution-substitution":
				digest = strings.Repeat("a", 64)
			case "cancel":
				cancel()
			}
			err := finalizeAPKInactiveTransition(ctx, digest, f.candidate.keys, f.candidate.attestInstalled, f.services, owner)
			if (err == nil) != (outcome == "success") {
				t.Fatal("inactive terminal accepted incomplete custody", err)
			}
			if outcome == "lease-close" && !errors.Is(err, sentinel) {
				t.Fatal("terminal concealed lease closure failure", err)
			}
			if (*lease).closes != 1 || !owner.closed || f.calls != 1 {
				t.Fatal("custody closure repeated or native transaction replayed", (*lease).closes, f.calls)
			}
			assertAPKExecutionFactoryLock(t, competitor, false)
			assertAPKExecutionState(t, f, "terminal-closed", outcome == "success")
			activationErr := preflightAPKConfigurationActivationAt(t.Context(), f.services.hostRoot)
			if (activationErr == nil) != (outcome == "success") {
				t.Fatal("activation ignored positive terminal closure or retained failure", activationErr)
			}
			if outcome == "lease-close" {
				assertAPKExecutionState(t, f, "terminal-unresolved", true)
			}
			if err := owner.Revalidate(t.Context(), true); err == nil {
				t.Fatal("closed custody retained authority")
			}
			if err := owner.Close(); err != nil || (*lease).closes != 1 {
				t.Fatal("custody cleanup was not idempotent", err)
			}
		})
	}
}

func apkInactiveTestID(t *testing.T, value int) uint32 {
	t.Helper()
	if value < 0 || value > 0xffffffff {
		t.Fatal("test owner does not fit native credentials")
		return 0
	}
	return uint32(value)
}

func TestAPKInactiveCustodyConstructionRefusesIncompleteAuthorityAndReleasesPartialLease(t *testing.T) {
	apkTerminalCompleteFixtureWithCustody(t, func(_ *authenticatedAPKCandidate, s *apkTransitionServices) {
		apkInactiveTestSource(t, s)
	}, func(ctx context.Context, prepared *verifiedPreparedAPKTransition, execution string, boundary *apkExecutionTestBoundary) (apkExecutionBoundary, error) {
		for _, scenario := range []string{"active", "unlocked", "missing-execution", "source-error", "source-nil", "hold-partial-error", "hold-and-close-error", "typed-nil", "lease-witness", "host-drift", "policy-drift", "source-drift", "cancel"} {
			t.Run(scenario, func(t *testing.T) {
				copy := *prepared
				services, lease, observed := apkInactiveTestCustodyServices(t, &copy)
				hold := services.hold
				digest := execution
				check, cancel := context.WithCancel(ctx)
				defer cancel()
				sentinel := errors.New("inert constructor error")
				closeErr := errors.New("inert partial lease close error")
				switch scenario {
				case "active":
					copy.plan.Policy.LifecycleMode = ""
				case "unlocked":
					copy.locked = false
				case "missing-execution":
					digest = ""
				case "source-error", "source-nil", "source-drift":
					services.source = func(context.Context, nativeActivationBindingPlan, NativeActivationCandidate) (func(context.Context, bool) error, error) {
						if scenario == "source-nil" {
							return nil, nil
						}
						if scenario == "source-error" {
							return nil, sentinel
						}
						return func(context.Context, bool) error { return sentinel }, nil
					}
				case "hold-partial-error", "hold-and-close-error", "lease-witness":
					services.hold = func(ctx context.Context, expected apkTransitionPolicyBinding) (apkInactiveLease, error) {
						value, err := hold(ctx, expected)
						if err != nil {
							return value, err
						}
						if scenario == "lease-witness" {
							(*lease).digest = strings.Repeat("f", 64)
							return value, nil
						}
						if scenario == "hold-and-close-error" {
							(*lease).closeErr = closeErr
						}
						return value, sentinel
					}
				case "typed-nil":
					services.hold = func(context.Context, apkTransitionPolicyBinding) (apkInactiveLease, error) {
						var missing *apkInactiveTestLease
						return missing, nil
					}
				case "host-drift":
					observed.hostSHA256 = strings.Repeat("b", 64)
				case "policy-drift":
					services.observe = func(ctx context.Context) (nativeActivationPolicyObservation, error) {
						changed := *observed
						changed.binding.AbsenceSHA256 = strings.Repeat("b", 64)
						return changed, ctx.Err()
					}
				case "cancel":
					cancel()
				}
				owner, err := openAPKInactiveCustody(check, &copy, digest, services)
				if err == nil || owner != nil {
					t.Fatal("incomplete original authority acquired inactive custody", err)
				}
				if *lease != nil && (*lease).closes != 1 {
					t.Fatal("partial lease not closed exactly once")
				}
				if scenario == "hold-and-close-error" && (!errors.Is(err, sentinel) || !errors.Is(err, closeErr)) {
					t.Fatal("partial construction or closure failure was hidden", err)
				}
				competitor := apkExecutionFactoryTestRoot(t, filepath.Join(prepared.services.hostRoot, "etc/syswarden/config"))
				assertAPKExecutionFactoryLock(t, competitor, false)
				if prepared.closed {
					t.Fatal("failed lease construction closed its caller's preparation")
				}
			})
		}
		return boundary, nil
	})
}

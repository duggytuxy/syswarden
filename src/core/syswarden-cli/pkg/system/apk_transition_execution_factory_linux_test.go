//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

type apkExecutionFactoryTestBoundary struct {
	*apkExecutionTestBoundary
	close func() error
}

func (b *apkExecutionFactoryTestBoundary) Close() error {
	return errors.Join(b.apkExecutionTestBoundary.Close(), b.close())
}

func apkExecutionFactoryTestRoot(t *testing.T, path string) *os.File {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	file, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func assertAPKExecutionFactoryLock(t *testing.T, file *os.File, held bool) {
	t.Helper()
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			t.Fatal(err)
		}
	}
	if held && !errors.Is(err, syscall.EWOULDBLOCK) || !held && err != nil {
		t.Fatalf("preparation lock held=%t, observed error=%v", held, err)
	}
}

func TestAPKExecutionFactoryRetainsPreparationThroughConstructionAndClose(t *testing.T) {
	for _, execute := range []bool{false, true} {
		name := "plan"
		if execute {
			name = "execute"
		}
		t.Run(name, func(t *testing.T) {
			for _, outcome := range []string{"success", "error-without-resource", "error-with-resource", "typed-nil", "nil", "partial-close-error", "close-error", "cancel-during-construction"} {
				t.Run(outcome, func(t *testing.T) {
					f := newAPKExecutionTestFixture(t)
					competitor := apkExecutionFactoryTestRoot(t, f.services.root)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					constructionErr := errors.New("inert construction refusal")
					closeErr := errors.New("inert construction resource close failure")
					var observed *verifiedPreparedAPKTransition
					constructions, closes := 0, 0
					factory := func(ctx context.Context, prepared *verifiedPreparedAPKTransition) (apkExecutionBoundary, error) {
						constructions++
						observed = prepared
						if prepared.closed || !prepared.locked || prepared.path != f.preparation.Directory || prepared.plan.Artifact.SHA256 != f.candidate.artifact.SHA256 {
							t.Fatal("factory received unverified or different preparation")
						}
						if err := prepared.Revalidate(ctx); err != nil {
							t.Fatal("factory cannot inspect verified original state", err)
						}
						assertAPKExecutionFactoryLock(t, competitor, true)
						boundary := &apkExecutionFactoryTestBoundary{apkExecutionTestAuthority(), func() error {
							closes++
							if prepared.closed {
								t.Fatal("preparation closed before constructed resource")
							}
							assertAPKExecutionFactoryLock(t, competitor, true)
							if outcome == "partial-close-error" || outcome == "close-error" {
								return closeErr
							}
							return nil
						}}
						switch outcome {
						case "error-without-resource":
							return nil, constructionErr
						case "error-with-resource", "partial-close-error":
							return boundary, constructionErr
						case "typed-nil":
							var absent *apkExecutionFactoryTestBoundary
							return absent, nil
						case "nil":
							return nil, nil
						case "cancel-during-construction":
							cancel()
						}
						return boundary, nil
					}
					var err error
					if execute {
						err = executeAPKTransitionWith(ctx, f.preparation.PlanSHA256, f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory, apkExecutionServices{run: f.run})
					} else {
						_, err = planAPKTransitionExecution(ctx, f.preparation.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory)
					}
					if (err == nil) != (outcome == "success") || constructions != 1 || observed == nil || !observed.closed {
						t.Fatal("incorrect construction or cleanup outcome", err, constructions)
					}
					wantCloses := 1
					if outcome == "error-without-resource" || outcome == "typed-nil" || outcome == "nil" {
						wantCloses = 0
					}
					if closes != wantCloses {
						t.Fatal("constructed resource not closed exactly once", closes)
					}
					if strings.HasPrefix(outcome, "error-") || outcome == "partial-close-error" {
						if !errors.Is(err, constructionErr) {
							t.Fatal("construction failure lost", err)
						}
					}
					if outcome == "partial-close-error" || outcome == "close-error" {
						if !errors.Is(err, closeErr) {
							t.Fatal("resource closure failure lost", err)
						}
					}
					if outcome == "cancel-during-construction" && !errors.Is(err, context.Canceled) {
						t.Fatal("construction cancellation lost", err)
					}
					wantDispatch := execute && (outcome == "success" || outcome == "close-error")
					if (f.calls != 0) != wantDispatch {
						t.Fatal("construction failure dispatched native manager", f.calls)
					}
					for _, state := range []string{"execution-approval", "armed", "native-started"} {
						assertAPKExecutionState(t, f, state, wantDispatch)
					}
					assertAPKExecutionState(t, f, "completed", execute && outcome == "success")
					assertAPKExecutionFactoryLock(t, competitor, false)
				})
			}
		})
	}
}

func TestAPKExecutionFactoryCannotRunBeforeOriginalPreparationIsAvailable(t *testing.T) {
	for _, execute := range []bool{false, true} {
		name := "plan"
		if execute {
			name = "execute"
		}
		t.Run(name, func(t *testing.T) {
			for _, refusal := range []string{"cancelled", "locked", "unknown-preparation", "original-state-drift"} {
				t.Run(refusal, func(t *testing.T) {
					f := newAPKExecutionTestFixture(t)
					competitor := apkExecutionFactoryTestRoot(t, f.services.root)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					digest := f.preparation.PlanSHA256
					switch refusal {
					case "cancelled":
						cancel()
					case "locked":
						if err := syscall.Flock(int(competitor.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
							t.Fatal(err)
						}
					case "unknown-preparation":
						digest = strings.Repeat("a", 64)
					case "original-state-drift":
						if err := rewriteAPKExecutionFixture(t, f, "etc/syswarden/config/modules/99-user.toml", func(s string) string { return s + "# administrator change\n" }); err != nil {
							t.Fatal(err)
						}
					}
					constructions := 0
					factory := func(context.Context, *verifiedPreparedAPKTransition) (apkExecutionBoundary, error) {
						constructions++
						return apkExecutionTestAuthority(), nil
					}
					var err error
					if execute {
						err = executeAPKTransitionWith(ctx, digest, f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory, apkExecutionServices{run: f.run})
					} else {
						_, err = planAPKTransitionExecution(ctx, digest, f.candidate.keys, f.candidate.attestInstalled, f.services, factory)
					}
					if err == nil || constructions != 0 || f.calls != 0 {
						t.Fatal("unverified preparation reached boundary construction or native manager", err, constructions, f.calls)
					}
					if refusal == "locked" {
						if err := syscall.Flock(int(competitor.Fd()), syscall.LOCK_UN); err != nil {
							t.Fatal(err)
						}
					}
					assertAPKExecutionFactoryLock(t, competitor, false)
					assertAPKExecutionState(t, f, "native-started", false)
				})
			}
		})
	}
}

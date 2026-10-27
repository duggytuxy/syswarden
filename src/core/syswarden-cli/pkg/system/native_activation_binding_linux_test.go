//go:build linux

package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func nativeBindingFixture(t *testing.T) (authenticatedAPKCandidate, nativeActivationBindingServices, *nativeActivationRuntimeSnapshot, *error) {
	t.Helper()
	candidate, _, _ := apkTransitionFixture(t)
	raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(candidate.cliSHA256, strings.Repeat("b", 64)))
	if err != nil {
		t.Fatal(err)
	}
	capability, err := parseNativeActivationDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &nativeActivationRuntimeSnapshot{CLI: nativeActivationRuntimeFile{SHA256: strings.Repeat("a", 64)}, Core: nativeActivationRuntimeFile{SHA256: strings.Repeat("c", 64)}}
	var policyErr error
	services := nativeActivationBindingServices{
		classify: func(context.Context, packageTarget, *os.File) (NativeActivationCandidate, error) {
			return capability, nil
		},
		installedRuntime: func(context.Context, int) (nativeActivationRuntimeSnapshot, error) { return *runtime, nil },
		policy: func(context.Context) (nativeActivationPolicyObservation, error) {
			verify := func(ctx context.Context) error { return errors.Join(policyErr, ctx.Err()) }
			return nativeActivationPolicyObservation{binding: apkTransitionPolicyBinding{strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)}, hostSHA256: strings.Repeat("1", 64), revalidate: verify, verifyPolicy: verify}, nil
		},
	}
	return candidate, services, runtime, &policyErr
}

func TestNativeActivationBindingBindsCandidateAndOriginalRuntime(t *testing.T) {
	candidate, services, runtime, _ := nativeBindingFixture(t)
	binding, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
	if err != nil {
		t.Fatal(err)
	}
	if !validSHA256(binding.EffectPlanSHA256()) || binding.plan.Capability.CoreSHA256 != strings.Repeat("b", 64) || binding.plan.Installed.Core.SHA256 != runtime.Core.SHA256 {
		t.Fatal("candidate and original core identity were not independently bound")
	}
	same, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
	if err != nil || same.EffectPlanSHA256() != binding.EffectPlanSHA256() {
		t.Fatalf("stable evidence changed plan: %v", err)
	}
	runtime.Core.SHA256 = strings.Repeat("2", 64)
	if err := binding.Revalidate(t.Context()); err == nil {
		t.Fatal("changed original core accepted")
	}
	changed, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
	if err != nil {
		t.Fatal(err)
	}
	if changed.EffectPlanSHA256() == binding.EffectPlanSHA256() {
		t.Fatal("core change did not invalidate previous review")
	}
	if (*nativeActivationBinding)(nil).EffectPlanSHA256() != "" {
		t.Fatal("nil binding returned authority")
	}
	if err := (*nativeActivationBinding)(nil).Revalidate(t.Context()); err == nil {
		t.Fatal("nil binding accepted")
	}
}

func TestNativeActivationBindingRejectsChangedEvidenceBeforeReplacement(t *testing.T) {
	for _, name := range []string{"core-bytes", "core-metadata", "cli-bytes", "parent", "policy", "registration", "candidate", "cancellation", "nil-context"} {
		t.Run(name, func(t *testing.T) {
			candidate, services, runtime, policyErr := nativeBindingFixture(t)
			registered := "v4.10.4"
			candidate.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
				return installedQualificationEvidence{registered, strings.Repeat("a", 64)}, nil
			}
			binding, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			switch name {
			case "core-bytes":
				runtime.Core.SHA256 = strings.Repeat("2", 64)
			case "core-metadata":
				runtime.Core.Identity.Inode++
			case "cli-bytes":
				runtime.CLI.SHA256 = strings.Repeat("2", 64)
			case "parent":
				runtime.Directory.Inode++
			case "policy":
				*policyErr = errors.New("changed source or approval")
			case "registration":
				registered = "v4.10.3"
			case "candidate":
				if _, err := candidate.file.WriteAt([]byte{0}, 0); err != nil {
					t.Fatal(err)
				}
			case "cancellation":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			if err := binding.Revalidate(ctx); err == nil {
				t.Fatal("changed evidence accepted")
			}
		})
	}
}

func TestNativeActivationBindingRefusesUnclassifiedAndIncompleteEvidence(t *testing.T) {
	for _, name := range []string{"missing-classifier", "missing-policy", "missing-runtime", "missing-installed", "zero-capability", "cli-mismatch", "invalid-core", "missing-policy-revalidator", "missing-policy-digest", "manifest", "equal-version", "unknown-manager", "foreign-owner", "canceled"} {
		t.Run(name, func(t *testing.T) {
			candidate, services, runtime, _ := nativeBindingFixture(t)
			ctx := t.Context()
			switch name {
			case "missing-classifier":
				services.classify = nil
			case "missing-policy":
				services.policy = nil
			case "missing-runtime":
				services.installedRuntime = nil
			case "missing-installed":
				candidate.attestInstalled = nil
			case "zero-capability":
				services.classify = func(context.Context, packageTarget, *os.File) (NativeActivationCandidate, error) {
					return NativeActivationCandidate{}, nil
				}
			case "cli-mismatch":
				candidate.cliSHA256 = strings.Repeat("0", 64)
			case "invalid-core":
				runtime.Core.SHA256 = ""
			case "missing-policy-revalidator", "missing-policy-digest":
				base := services.policy
				services.policy = func(ctx context.Context) (nativeActivationPolicyObservation, error) {
					p, err := base(ctx)
					if name == "missing-policy-revalidator" {
						p.verifyPolicy = nil
					} else {
						p.binding.ApprovalSHA256 = ""
					}
					return p, err
				}
			case "manifest":
				candidate.signature = []byte("invalid signature")
			case "equal-version":
				candidate.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
					return installedQualificationEvidence{candidate.version, strings.Repeat("a", 64)}, nil
				}
			case "unknown-manager":
				candidate.target.installer = "/tmp/apk"
			case "foreign-owner":
				candidate.uid++
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := captureNativeActivationBindingWith(ctx, candidate, services); err == nil {
				t.Fatal("incomplete authority accepted")
			}
		})
	}
}

func TestNativeActivationRuntimeSnapshotObservesBothExecutables(t *testing.T) {
	anchor := t.TempDir()
	directory := filepath.Join(anchor, "opt/syswarden/bin")
	if err := os.MkdirAll(directory, 0750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"syswarden-cli", "syswarden-core"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("inert "+name), 0750); err != nil {
			t.Fatal(err)
		}
	} // #nosec G306 -- exact installed executable fixture mode; never executed
	original, err := captureNativeActivationRuntime(t.Context(), directory, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if original.CLI.SHA256 == original.Core.SHA256 || !validSHA256(original.Core.SHA256) {
		t.Fatal("original core was not observed independently")
	}
	if err := os.Chmod(filepath.Join(directory, "syswarden-core"), 0770); err != nil {
		t.Fatal(err)
	} // #nosec G302 -- deliberately unsafe negative-test mode
	if _, err := captureNativeActivationRuntime(t.Context(), directory, os.Geteuid()); err == nil {
		t.Fatal("writable original core accepted")
	}
	if err := os.Remove(filepath.Join(directory, "syswarden-core")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("syswarden-cli", filepath.Join(directory, "syswarden-core")); err != nil {
		t.Fatal(err)
	}
	if _, err := captureNativeActivationRuntime(t.Context(), directory, os.Geteuid()); err == nil {
		t.Fatal("aliased original core accepted")
	}
}

func TestNativeActivationGuardCannotBeAbsentInProductionUpdaters(t *testing.T) {
	for _, constructor := range []func() (*updater, error){newProductionUpdater, newQualificationUpdater} {
		u, err := constructor()
		if err != nil {
			t.Fatal(err)
		}
		if u.guardNativeActivation == nil || reflect.ValueOf(u.guardNativeActivation).Pointer() != reflect.ValueOf(requireProductionNativeActivationTransaction).Pointer() {
			t.Fatal("production native replacement is not guarded")
		}
		u.guardNativeActivation = nil
		u.requireRoot = false
		if u.client != nil {
			if err := u.validateConfiguration(); err == nil {
				t.Fatal("missing online gate accepted")
			}
		} else if err := u.validateQualificationConfiguration(); err == nil {
			t.Fatal("missing offline gate accepted")
		}
	}
}

func TestNativeActivationPreflightDeadlineAndExactInputs(t *testing.T) {
	candidate, _, _ := apkTransitionFixture(t)
	candidate.target.format = packageFormatDEB
	candidate.target.installer = "/usr/bin/apt-get"
	u := &updater{attestTimeout: time.Second, effectiveUID: candidate.uid, trustedKeys: candidate.keys, attestInstalled: candidate.attestInstalled}
	calls := 0
	u.guardNativeActivation = func(ctx context.Context, got authenticatedAPKCandidate) error {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("native preflight is not bounded")
		}
		if got.target != candidate.target || got.file != candidate.file || got.path != candidate.path || got.cliSHA256 != candidate.cliSHA256 || !got.offline {
			t.Fatal("native gate lost exact candidate selection")
		}
		<-ctx.Done()
		return nil
	}
	u.attestTimeout = time.Millisecond
	err := u.preflightNativeActivation(t.Context(), candidate.target, candidate.version, candidate.artifact, candidate.file, candidate.path, candidate.manifest, candidate.signature, candidate.cliSHA256, true)
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("late gate success accepted: %v calls=%d", err, calls)
	}
}

func TestNativeActivationRefusalPrecedesOnlineAndOfflinePackageEffects(t *testing.T) {
	refusal := &nativeActivationTransactionRequiredError{PlanSHA256: strings.Repeat("1", 64)}
	t.Run("online", func(t *testing.T) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte("opaque transport fixture")
		manifest := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, payload))
		var installs atomic.Int32
		u := testUpdater(newUpdaterTestClient(manifest, testSignManifest(private, manifest), payload), t.TempDir(), "amd64", map[string]ed25519.PublicKey{testReleaseKeyID: public}, func(context.Context, string, ...string) error { installs.Add(1); return nil })
		seen := 0
		u.guardNativeActivation = func(_ context.Context, candidate authenticatedAPKCandidate) error {
			seen++
			if candidate.offline || candidate.target.format != packageFormatDEB {
				t.Fatal("wrong online selection")
			}
			return refusal
		}
		if err := u.run(t.Context()); !errors.Is(err, refusal) {
			t.Fatalf("refusal lost: %v", err)
		}
		if installs.Load() != 0 || seen != 1 {
			t.Fatal("native effects preceded exact activation authority")
		}
		assertEmptyDirectory(t, u.tempBase)
	})
	t.Run("offline", func(t *testing.T) {
		fixture := newQualificationFixture(t)
		var network, installs atomic.Int32
		u, output, temp := qualificationTestUpdater(t, fixture, "v4.04.2", &network, &installs)
		u.guardNativeActivation = func(_ context.Context, candidate authenticatedAPKCandidate) error {
			if !candidate.offline {
				t.Fatal("offline authority lost")
			}
			return refusal
		}
		u.activateCandidate = func(context.Context, installedQualificationEvidence) error {
			t.Fatal("activation preceded native approval")
			return nil
		}
		if err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate); !errors.Is(err, refusal) {
			t.Fatalf("refusal lost: %v", err)
		}
		if network.Load() != 0 || installs.Load() != 0 || strings.Contains(output.String(), "completed successfully") {
			t.Fatal("refused offline transition produced effects or success")
		}
		assertEmptyDirectory(t, temp)
	})
}

func TestNativeActivationRuntimePairRefusesEarlierBinaryDrift(t *testing.T) {
	for _, kind := range []string{"content", "mode", "replacement"} {
		t.Run(kind, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "opt/syswarden/bin")
			if err := os.MkdirAll(directory, 0750); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"syswarden-cli", "syswarden-core"} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte("original inert binary"), 0750); err != nil {
					t.Fatal(err)
				}
			} // #nosec G306 -- exact installed executable fixture mode; never executed
			_, err := captureNativeActivationRuntimeWith(t.Context(), directory, os.Geteuid(), func(name string) error {
				if name != "syswarden-core" {
					return nil
				}
				cli := filepath.Join(directory, "syswarden-cli")
				switch kind {
				case "content":
					return os.WriteFile(cli, []byte("changed inert binary!"), 0750) // #nosec G306 -- deliberate same-path executable mutation fixture; never executed
				case "mode":
					return os.Chmod(cli, 0700) // #nosec G302 -- Deliberate executable-mode drift on a test-owned runtime fixture.
				default:
					moved := filepath.Join(directory, "original-cli")
					if err := os.Rename(cli, moved); err != nil {
						return err
					}
					return os.WriteFile(cli, []byte("original inert binary"), 0750) // #nosec G306 -- deliberate replacement executable fixture; never executed
				}
			})
			if err == nil {
				t.Fatal("earlier CLI changed during core capture but pair was accepted")
			}
		})
	}
}

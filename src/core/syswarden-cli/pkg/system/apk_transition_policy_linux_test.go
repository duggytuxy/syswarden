//go:build linux

package system

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func inactivePolicyFixture() apkTransitionPolicyBinding {
	return apkTransitionPolicyBinding{PolicySHA256: strings.Repeat("c", 64), HostSHA256: strings.Repeat("d", 64), LifecycleMode: apkInactivePreservationMode, AbsenceSHA256: strings.Repeat("e", 64)}
}

func TestAPKPolicyModeRejectsImplicitAndMixedAuthority(t *testing.T) {
	for _, name := range []string{"active", "inactive", "no-approval", "mixed", "missing-absence", "wrong-mode", "policy", "host", "legacy-absence"} {
		t.Run(name, func(t *testing.T) {
			policy := inactivePolicyFixture()
			switch name {
			case "active":
				policy.LifecycleMode, policy.AbsenceSHA256, policy.ApprovalSHA256 = "", "", strings.Repeat("b", 64)
			case "no-approval":
				policy.LifecycleMode, policy.AbsenceSHA256 = "", ""
			case "mixed":
				policy.ApprovalSHA256 = strings.Repeat("b", 64)
			case "missing-absence":
				policy.AbsenceSHA256 = ""
			case "wrong-mode":
				policy.LifecycleMode = "inactive"
			case "policy":
				policy.PolicySHA256 = ""
			case "host":
				policy.HostSHA256 = ""
			case "legacy-absence":
				policy.LifecycleMode, policy.ApprovalSHA256 = "", strings.Repeat("b", 64)
			}
			if policy.valid() != (name == "active" || name == "inactive") {
				t.Fatal("mixed or incomplete policy authority accepted")
			}
		})
	}
}

func TestAPKActivePolicyKeepsCanonicalV1Bytes(t *testing.T) {
	policy := apkTransitionPolicyBinding{ApprovalSHA256: strings.Repeat("b", 64), PolicySHA256: strings.Repeat("c", 64), HostSHA256: strings.Repeat("d", 64)}
	raw, err := json.Marshal(policy)
	expected := `{"approval_sha256":"` + policy.ApprovalSHA256 + `","policy_sha256":"` + policy.PolicySHA256 + `","host_sha256":"` + policy.HostSHA256 + `"}`
	if err != nil || string(raw) != expected || policy.preparationSchema() != apkTransitionSchema || policy.effectSchema() != nativeActivationBindingSchema {
		t.Fatal("historical policy encoding changed", err)
	}
	_, binding, effects, _ := apkTerminalLifecycleFixture(t)
	if bytes.Contains(effects, []byte("source_publication_sha256")) || bytes.Contains(effects, []byte("lifecycle_mode")) || binding.plan.Schema != nativeActivationBindingSchema {
		t.Fatal("new fields leaked into v1 effect bytes")
	}
}

func inactiveNativeBindingFixture(t *testing.T) (authenticatedAPKCandidate, nativeActivationBindingServices) {
	t.Helper()
	candidate, services, runtime, _ := nativeBindingFixture(t)
	services.policy = func(ctx context.Context) (nativeActivationPolicyObservation, error) {
		verify := func(ctx context.Context) error { return ctx.Err() }
		return nativeActivationPolicyObservation{binding: inactivePolicyFixture(), hostSHA256: strings.Repeat("1", 64), revalidate: verify, verifyPolicy: verify}, ctx.Err()
	}
	raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(runtime.CLI.SHA256, runtime.Core.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	source, err := parseNativeActivationDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	services.publication = func(ctx context.Context) (NativeActivationCandidate, error) { return source, ctx.Err() }
	return candidate, services
}

func TestNativeInactiveBindingRequiresBothCooperativeRuntimes(t *testing.T) {
	for _, name := range []string{"valid", "source-missing", "source-error", "source-legacy", "source-cli", "source-core", "candidate-legacy", "mixed-policy"} {
		t.Run(name, func(t *testing.T) {
			candidate, services := inactiveNativeBindingFixture(t)
			originalSource := services.publication
			switch name {
			case "source-missing":
				services.publication = nil
			case "source-error":
				services.publication = func(context.Context) (NativeActivationCandidate, error) {
					return NativeActivationCandidate{}, errors.New("unreadable source")
				}
			case "source-legacy", "source-cli", "source-core":
				services.publication = func(ctx context.Context) (NativeActivationCandidate, error) {
					source, err := originalSource(ctx)
					if err != nil {
						return source, err
					}
					descriptor := nativeActivationDescriptorFor(source.Review().CLISHA256, source.Review().CoreSHA256)
					if name == "source-legacy" {
						descriptor = nativeActivationLegacyDescriptorFor(source.Review().CLISHA256, source.Review().CoreSHA256)
					}
					if name == "source-cli" {
						descriptor.CLISHA256 = strings.Repeat("9", 64)
					}
					if name == "source-core" {
						descriptor.CoreSHA256 = strings.Repeat("9", 64)
					}
					raw, err := canonicalNativeActivationDescriptor(descriptor)
					if err != nil {
						return NativeActivationCandidate{}, err
					}
					return parseNativeActivationDescriptor(raw)
				}
			case "candidate-legacy":
				classify := services.classify
				services.classify = func(ctx context.Context, target packageTarget, file *os.File) (NativeActivationCandidate, error) {
					current, err := classify(ctx, target, file)
					if err != nil {
						return current, err
					}
					raw, err := canonicalNativeActivationDescriptor(nativeActivationLegacyDescriptorFor(current.Review().CLISHA256, current.Review().CoreSHA256))
					if err != nil {
						return NativeActivationCandidate{}, err
					}
					return parseNativeActivationDescriptor(raw)
				}
			case "mixed-policy":
				observe := services.policy
				services.policy = func(ctx context.Context) (nativeActivationPolicyObservation, error) {
					p, err := observe(ctx)
					p.binding.ApprovalSHA256 = strings.Repeat("a", 64)
					return p, err
				}
			}
			binding, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
			if (err == nil) != (name == "valid") {
				t.Fatalf("inactive capability validation: %v", err)
			}
			if err != nil {
				return
			}
			if !binding.plan.validPublicationBinding(binding.candidate) || binding.plan.Schema != nativeInactiveBindingSchema || binding.plan.RuntimePolicy.ApprovalSHA256 != "" {
				t.Fatal("inactive binding manufactured active authority")
			}
			services.publication = nil // The captured callback remains bound to its original function.
			if err := binding.Revalidate(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeInactiveBindingRejectsSourceCapabilityDrift(t *testing.T) {
	candidate, services := inactiveNativeBindingFixture(t)
	original := services.publication
	changed := false
	services.publication = func(ctx context.Context) (NativeActivationCandidate, error) {
		if changed {
			return NativeActivationCandidate{}, errors.New("changed source descriptor")
		}
		return original(ctx)
	}
	binding, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
	if err != nil {
		t.Fatal(err)
	}
	changed = true
	if binding.Revalidate(t.Context()) == nil {
		t.Fatal("source publication drift accepted")
	}
}

// This is a complete retained-record/coordinator component path with inert
// payloads and synthetic native hook acknowledgments. It is not native package,
// kernel inactivity, independent SSH access or final product qualification.
func TestAPKInactiveRetainedPathAndIndependentTerminalPreserveMode(t *testing.T) {
	for _, drift := range []string{"none", "approval", "absence", "mode", "host", "source-publication"} {
		t.Run(drift, func(t *testing.T) {
			policy := inactivePolicyFixture()
			f, _ := apkTerminalCompleteFixtureWithSetup(t, func(_ *authenticatedAPKCandidate, s *apkTransitionServices) {
				s.policy = func(ctx context.Context) (apkTransitionPolicyBinding, error) { return policy, ctx.Err() }
				runtime, err := captureNativeActivationRuntime(t.Context(), filepath.Join(s.hostRoot, "opt/syswarden/bin"), os.Geteuid())
				if err != nil {
					t.Fatal(err)
				}
				raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(runtime.CLI.SHA256, runtime.Core.SHA256))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(s.hostRoot, nativeActivationDescriptorPath), raw, 0644); err != nil {
					t.Fatal(err)
				} // #nosec G306 -- exact temporary public descriptor metadata models the native package contract
			})
			observed := nativeActivationPolicyObservation{binding: policy, hostSHA256: strings.Repeat("a", 64), revalidate: func(ctx context.Context) error { return ctx.Err() }, verifyPolicy: func(ctx context.Context) error { return ctx.Err() }}
			switch drift {
			case "approval":
				policy.ApprovalSHA256 = strings.Repeat("b", 64)
			case "absence":
				observed.binding.AbsenceSHA256 = strings.Repeat("f", 64)
			case "mode":
				policy.LifecycleMode = ""
			case "host":
				observed.hostSHA256 = strings.Repeat("b", 64)
			case "source-publication":
				directory, err := openExistingPinnedServiceDirectory(f.preparation.Directory)
				if err != nil {
					t.Fatal(err)
				}
				defer directory.close()
				raw, err := readAPKTransitionBytes(directory, "native-effects.json", 64<<10)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.Replace(raw, []byte(`"source_publication_sha256":"`), []byte(`"source_publication_sha256":"0`), 1)
				if err := directory.root.WriteFile("native-effects.json", raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			factory := func(ctx context.Context, p *verifiedPreparedAPKTransition) (apkTerminalBoundary, error) {
				if p.plan.Schema != apkInactivePreparationSchema || !p.plan.Policy.inactive() {
					t.Fatal("inactive preparation lost its mode")
				}
				return openAPKTerminalLifecycleWith(ctx, p, apkTerminalEffectReader(p), func(ctx context.Context) (nativeActivationPolicyObservation, error) { return observed, ctx.Err() }, func(ctx context.Context) error {
					return p.capability.verifyInstalledAt(ctx, f.services.hostRoot, uint32(os.Geteuid()), uint32(os.Getegid()))
				}) // #nosec G115 -- effective Linux uid/gid values fit native uint32
			}
			authority, err := inspectAPKTerminalFixture(t.Context(), f, factory)
			if drift != "none" {
				if err == nil {
					_ = authority.Close()
					t.Fatal("changed inactive outcome accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.Finalize(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := authority.Close(); err != nil {
				t.Fatal(err)
			}
			if f.calls != 1 {
				t.Fatal("terminal verifier replayed native installation")
			}
		})
	}
}

func TestAPKInactiveEffectRecordRejectsSchemaAndPublicationSubstitution(t *testing.T) {
	for _, name := range []string{"valid", "legacy-schema", "active-policy", "mixed-approval", "missing-source", "other-source", "other-source-core", "non-apk"} {
		t.Run(name, func(t *testing.T) {
			candidate, services := inactiveNativeBindingFixture(t)
			binding, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
			if err != nil {
				t.Fatal(err)
			}
			plan := binding.plan
			switch name {
			case "legacy-schema":
				plan.Schema = nativeActivationBindingSchema
			case "active-policy":
				plan.RuntimePolicy.LifecycleMode = ""
				plan.RuntimePolicy.AbsenceSHA256 = ""
				plan.RuntimePolicy.ApprovalSHA256 = strings.Repeat("a", 64)
				plan.Schema = nativeActivationBindingSchema
			case "mixed-approval":
				plan.RuntimePolicy.ApprovalSHA256 = strings.Repeat("a", 64)
			case "missing-source":
				plan.SourcePublicationSHA256 = ""
			case "other-source":
				plan.SourcePublicationSHA256 = strings.Repeat("f", 64)
			case "other-source-core":
				plan.Installed.Core.SHA256 = strings.Repeat("f", 64)
			case "non-apk":
				plan.Format = packageFormatDEB
			}
			if plan.validPublicationBinding(binding.candidate) != (name == "valid") {
				t.Fatal("inconsistent lifecycle or original source capability accepted")
			}
		})
	}
}

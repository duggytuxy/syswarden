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

func apkTerminalLifecycleFixture(t *testing.T) (*verifiedPreparedAPKTransition, *nativeActivationBinding, []byte, nativeActivationBindingServices) {
	t.Helper()
	candidate, services, _, _ := nativeBindingFixture(t)
	binding, err := captureNativeActivationBindingWith(t.Context(), candidate, services)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := binding.DurableEffects()
	if err != nil {
		t.Fatal(err)
	}
	effects := binding.plan
	prepared := &verifiedPreparedAPKTransition{capability: binding.candidate, plan: apkTransitionPlan{
		EffectPlanSHA256: binding.digest, PackageName: effects.PackageName, Installer: effects.Installer, CandidateVersion: effects.CandidateVersion,
		Artifact: effects.Artifact, ManifestSHA256: effects.ManifestSHA256, SignatureSHA256: effects.SignatureSHA256, InstalledVersion: effects.InstalledVersion,
		InstalledCLISHA256: effects.Installed.CLI.SHA256, Policy: effects.RuntimePolicy, Offline: effects.Offline,
		CandidateCapabilitySHA256: binding.candidate.SHA256(), CandidateCLISHA256: binding.candidate.Review().CLISHA256,
	}}
	return prepared, binding, raw, services
}

func TestAPKTerminalLifecycleRequiresOriginalEffectRecord(t *testing.T) {
	for _, name := range []string{"valid", "missing", "digest", "noncanonical", "unknown", "schema", "package", "format", "installer", "version", "artifact", "manifest", "signature", "installed-version", "installed-cli", "core", "policy", "host", "offline", "capability", "closed"} {
		t.Run(name, func(t *testing.T) {
			prepared, binding, raw, _ := apkTerminalLifecycleFixture(t)
			plan := binding.plan
			switch name {
			case "missing":
				raw = nil
			case "digest":
				prepared.plan.EffectPlanSHA256 = strings.Repeat("0", 64)
			case "noncanonical":
				raw = append(raw, ' ')
				prepared.plan.EffectPlanSHA256 = apkTransitionDigest(raw)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`{"schema"`), []byte(`{"unexpected":true,"schema"`), 1)
				prepared.plan.EffectPlanSHA256 = apkTransitionDigest(raw)
			case "schema":
				plan.Schema = "other"
			case "package":
				plan.PackageName = "other"
			case "format":
				plan.Format = packageFormatDEB
			case "installer":
				plan.Installer = "/tmp/apk"
			case "version":
				plan.CandidateVersion = "v5.01.0"
			case "artifact":
				plan.Artifact.SHA256 = strings.Repeat("0", 64)
			case "manifest":
				plan.ManifestSHA256 = strings.Repeat("0", 64)
			case "signature":
				plan.SignatureSHA256 = strings.Repeat("0", 64)
			case "installed-version":
				plan.InstalledVersion = "v1.00.0"
			case "installed-cli":
				plan.Installed.CLI.SHA256 = strings.Repeat("0", 64)
			case "core":
				plan.Installed.Core.SHA256 = ""
			case "policy":
				plan.RuntimePolicy.PolicySHA256 = strings.Repeat("0", 64)
			case "host":
				plan.HostObservationSHA256 = ""
			case "offline":
				plan.Offline = !plan.Offline
			case "capability":
				plan.Capability.CoreSHA256 = strings.Repeat("0", 64)
			case "closed":
				prepared.closed = true
			}
			if name != "valid" && name != "missing" && name != "digest" && name != "noncanonical" && name != "unknown" && name != "closed" {
				data, err := json.Marshal(plan)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(data, '\n')
				prepared.plan.EffectPlanSHA256 = apkTransitionDigest(raw)
			}
			_, err := verifyAPKTerminalEffectPlan(raw, prepared)
			if (err == nil) != (name == "valid") {
				t.Fatalf("original effect verification: %v", err)
			}
		})
	}
}

func TestAPKTerminalLifecycleRejectsPostTransactionDrift(t *testing.T) {
	for _, name := range []string{"record", "policy", "approval", "host", "policy-error", "installed", "during-installed", "canceled", "nil-context", "closed"} {
		t.Run(name, func(t *testing.T) {
			prepared, _, raw, services := apkTerminalLifecycleFixture(t)
			observed, err := services.policy(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var policyErr, installedErr, errorDuringInstalled error
			installedCalls := 0
			boundary, err := openAPKTerminalLifecycleWith(t.Context(), prepared, func() ([]byte, error) { return bytes.Clone(raw), nil }, func(context.Context) (nativeActivationPolicyObservation, error) { return observed, policyErr }, func(context.Context) error {
				installedCalls++
				if errorDuringInstalled != nil {
					observed.revalidate = func(context.Context) error { return errorDuringInstalled }
				}
				return installedErr
			})
			if err != nil {
				t.Fatal(err)
			}
			if boundary.EffectPlanSHA256() != prepared.plan.EffectPlanSHA256 {
				t.Fatal("original digest changed")
			}
			ctx := t.Context()
			switch name {
			case "record":
				raw = append(raw, ' ')
			case "policy":
				observed.binding.PolicySHA256 = strings.Repeat("0", 64)
			case "approval":
				observed.binding.ApprovalSHA256 = strings.Repeat("0", 64)
			case "host":
				observed.hostSHA256 = strings.Repeat("0", 64)
			case "policy-error":
				policyErr = errors.New("unresolved policy")
			case "installed":
				installedErr = errors.New("candidate runtime drift")
			case "during-installed":
				errorDuringInstalled = errors.New("policy changed during runtime check")
				observed.revalidate = func(context.Context) error {
					if installedCalls > 1 {
						return errorDuringInstalled
					}
					return nil
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			case "closed":
				if err := boundary.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := boundary.AttestResult(ctx); err == nil {
				t.Fatal("changed terminal lifecycle accepted")
			}
		})
	}
}

func TestAPKDurableEffectsRefusesChangedOrMissingBinding(t *testing.T) {
	_, binding, raw, _ := apkTerminalLifecycleFixture(t)
	second, err := binding.DurableEffects()
	if err != nil || !bytes.Equal(raw, second) {
		t.Fatal("stable original record changed", err)
	}
	second[0] = '!'
	third, err := binding.DurableEffects()
	if err != nil || !bytes.Equal(raw, third) {
		t.Fatal("caller changed original record", err)
	}
	binding.plan.HostObservationSHA256 = strings.Repeat("0", 64)
	if _, err := binding.DurableEffects(); err == nil {
		t.Fatal("mutated review was rebased")
	}
	if _, err := (*nativeActivationBinding)(nil).DurableEffects(); err == nil {
		t.Fatal("missing review accepted")
	}
}

func TestAPKTerminalOriginalRecordIdentityRemainsPinned(t *testing.T) {
	for _, change := range []string{"bytes", "identical-replacement", "mode", "link", "parent", "closed"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "preparation")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			directory, err := openExistingPinnedServiceDirectory(path)
			if err != nil {
				t.Fatal(err)
			}
			prepared := &verifiedPreparedAPKTransition{path: path, directory: directory}
			t.Cleanup(func() { _ = prepared.Close() })
			raw := []byte("original private effect record\n")
			if err := writeAPKTransitionBytes(directory, "native-effects.json", raw); err != nil {
				t.Fatal(err)
			}
			read := apkTerminalEffectReader(prepared)
			if actual, err := read(); err != nil || !bytes.Equal(actual, raw) {
				t.Fatal("initial record read failed", err)
			}
			name := filepath.Join(path, "native-effects.json")
			switch change {
			case "bytes":
				err = os.WriteFile(name, []byte("changed\n"), 0600)
			case "identical-replacement":
				err = os.WriteFile(name+".new", raw, 0600)
				if err == nil {
					err = os.Rename(name+".new", name)
				}
			case "mode":
				err = os.Chmod(name, 0640) // #nosec G302 -- Deliberately loosen a fixed private t.TempDir record to verify that terminal custody rejects changed permissions.
			case "link":
				err = os.Link(name, name+".link")
			case "parent":
				err = os.Rename(path, path+".old")
				if err == nil {
					err = os.Mkdir(path, 0700)
				}
			case "closed":
				err = prepared.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := read(); err == nil {
				t.Fatal("changed original record identity accepted")
			}
		})
	}
}

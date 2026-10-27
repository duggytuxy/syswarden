//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type apkLauncherTargetFixture struct {
	apkLauncherFixture
	inventory []apkTransitionMember
	proposal  *apkLauncherTargetProposal
	plan      apkExecutionPlan
	effect    string
	candidate [2][]byte
}

func newAPKLauncherTargetFixture(t *testing.T, relative bool) *apkLauncherTargetFixture {
	t.Helper()
	base := newAPKLauncherFixture(t, "product-link")
	f := &apkLauncherTargetFixture{apkLauncherFixture: base, effect: strings.Repeat("7", 64), candidate: [2][]byte{[]byte("candidate cli\n"), []byte("candidate tui\n")}}
	if err := f.root.MkdirAll("opt/syswarden/bin", 0755); err != nil {
		t.Fatal(err)
	}
	for i, target := range apkLauncherTargets {
		if err := f.root.WriteFile(strings.TrimPrefix(target, "/"), []byte("original executable "+filepath.Base(target)+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := f.root.Remove(apkLauncherPaths[i]); err != nil {
				t.Fatal(err)
			}
		}
		link := target
		if relative {
			link = "../../../" + strings.TrimPrefix(target, "/")
		}
		if err := f.root.Symlink(link, apkLauncherPaths[i]); err != nil {
			t.Fatal(err)
		}
		f.inventory = append(f.inventory, apkTransitionMember{Stream: "apk-data", Path: strings.TrimPrefix(target, "/"), Mode: 0750, Size: int64(len(f.candidate[i])), SHA256: apkTransitionDigest(f.candidate[i])})
	}
	var err error
	f.original, err = captureAPKLauncherCustodyAt(t.Context(), f.host)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := apkLauncherCanonical(f.original)
	if err != nil {
		t.Fatal(err)
	}
	f.binding.OriginalSnapshotSHA256 = apkTransitionDigest(raw)
	raw, err = apkLauncherCanonical(f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	f.binding.InventorySHA256 = apkTransitionDigest(raw)
	f.binding.CandidateCLISHA256 = f.inventory[0].SHA256
	f.proposal, err = captureAPKLauncherTargetProposalAt(t.Context(), f.host, f.original, f.inventory)
	if err != nil || f.proposal == nil {
		t.Fatal("target proposal unavailable", err)
	}
	raw, err = apkLauncherCanonical(f.proposal)
	if err != nil {
		t.Fatal(err)
	}
	f.plan = apkExecutionPlan{Schema: apkExecutionSchema, PreparationSHA256: strings.Repeat("8", 64), CandidateSHA256: f.binding.CandidateSHA256,
		CandidateCLISHA256: f.binding.CandidateCLISHA256, CandidateCapabilitySHA256: f.binding.CandidateCapabilitySHA256, InventorySHA256: f.binding.InventorySHA256,
		EffectPlanSHA256: f.effect, OriginalLaunchersSHA256: f.binding.OriginalSnapshotSHA256, LauncherTargets: f.proposal, LauncherTargetsSHA256: apkTransitionDigest(raw)}
	f.seal(t)
	return f
}

func (f *apkLauncherTargetFixture) seal(t *testing.T) {
	t.Helper()
	raw, err := apkLauncherCanonical(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	f.binding.PlanSHA256 = apkTransitionDigest(raw)
	relative := strings.TrimPrefix(apkTransitionRoot, "/") + "/execution-" + f.binding.PlanSHA256
	f.transaction = filepath.Join(f.host, relative)
	if err := f.root.MkdirAll(relative, 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.root.WriteFile(relative+"/execution-plan.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	approval, err := apkLauncherCanonical(apkExecutionApproval{apkExecutionSchema, "explicit-native-execution", f.binding.PlanSHA256, f.effect})
	if err != nil {
		t.Fatal(err)
	}
	f.binding.ApprovalSHA256 = apkTransitionDigest(approval)
	if err := f.root.WriteFile(relative+"/execution-approval.json", approval, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *apkLauncherTargetFixture) prepareTargets(t *testing.T) *APKLauncherCustody {
	t.Helper()
	h, err := prepareAPKLauncherCustodyWithTargetsAt(t.Context(), f.host, f.transaction, f.binding, f.original, f.inventory, f.effect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func (f *apkLauncherTargetFixture) installTargets(t *testing.T) {
	t.Helper()
	for i, target := range apkLauncherTargets {
		path := strings.TrimPrefix(target, "/")
		if err := f.root.WriteFile(path+".candidate", f.candidate[i], 0750); err != nil {
			t.Fatal(err)
		}
		if err := f.root.Rename(path+".candidate", path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAPKLauncherTargetsUpgradePreservesUnownedAliasesAndRemovalDebt(t *testing.T) {
	for _, relative := range []bool{false, true} {
		t.Run(map[bool]string{false: "absolute", true: "relative"}[relative], func(t *testing.T) {
			f := newAPKLauncherTargetFixture(t, relative)
			h := f.prepareTargets(t)
			if err := h.RefuseProductTargetDependencies(); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Commit(); err == nil {
				t.Fatal("upgrade accepted without independent installed-target observation")
			}
			if err := h.CreateAbsent(); err == nil {
				t.Fatal("upgrade authority broadened to alias creation")
			}
			f.installTargets(t)
			if err := h.Revalidate(); err == nil {
				t.Fatal("original-target guard accepted replaced targets before attestation")
			}
			if err := h.AttestUpgradeTargets(); err != nil {
				t.Fatal(err)
			}
			if err := h.AttestUpgradeTargets(); err != nil {
				t.Fatal("repeat exact observation failed", err)
			}
			digest, err := h.Commit()
			if err != nil || !validSHA256(digest) {
				t.Fatal(digest, err)
			}
			for _, alias := range h.record.Aliases {
				if alias.Disposition != "retained-administrator" || alias.Original != alias.Committed || alias.CreationSHA256 != "" {
					t.Fatal("target approval adopted an inherited alias")
				}
			}
			f.barrier(t)
			if err := h.RetireOwned(); err == nil {
				t.Fatal("live upgrade authority authorized target-dependent removal")
			}
			if err := h.AttestTerminal(); err == nil {
				t.Fatal("live upgrade authority authorized terminal removal")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := f.reopen(t, digest)
			if reopened.targetAuthority != nil {
				t.Fatal("removal reader minted upgrade authority")
			}
			if err := reopened.Revalidate(); err != nil {
				t.Fatal(err)
			}
			if err := reopened.RetireOwned(); err == nil {
				t.Fatal("stored target approval authorized removal")
			}
			if err := reopened.AttestTerminal(); err == nil {
				t.Fatal("stored target approval authorized terminal removal")
			}
			current, err := captureAPKLauncherCustodyAt(t.Context(), f.host)
			if err != nil || !reflect.DeepEqual(current, f.original) {
				t.Fatal("inherited alias identity or text changed", err)
			}
		})
	}
}

func TestAPKLauncherTargetsRejectStaleOrDifferentApproval(t *testing.T) {
	for _, kind := range []string{"original-bytes", "original-replacement", "parent-mode", "parent-metadata", "alias-replacement", "wrong-effect", "wrong-approval", "wrong-inventory", "missing-approval", "wrong-role-proposal"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKLauncherTargetFixture(t, false)
			effect := f.effect
			switch kind {
			case "original-bytes":
				if err := f.root.WriteFile("opt/syswarden/bin/syswarden-tui", []byte("changed\n"), 0755); err != nil {
					t.Fatal(err)
				}
			case "original-replacement":
				data, err := f.root.ReadFile("opt/syswarden/bin/syswarden-cli")
				if err != nil {
					t.Fatal(err)
				}
				if err := f.root.Remove("opt/syswarden/bin/syswarden-cli"); err != nil {
					t.Fatal(err)
				}
				if err := f.root.WriteFile("opt/syswarden/bin/syswarden-cli", data, 0755); err != nil {
					t.Fatal(err)
				}
			case "parent-mode":
				if err := f.root.Chmod("opt/syswarden/bin", 0700); err != nil {
					t.Fatal(err)
				}
			case "parent-metadata":
				if err := f.root.WriteFile("opt/syswarden/bin/unrelated", []byte("entry"), 0600); err != nil {
					t.Fatal(err)
				}
			case "alias-replacement":
				if err := f.root.Remove(apkLauncherPaths[0]); err != nil {
					t.Fatal(err)
				}
				if err := f.root.Symlink(apkLauncherTargets[0], apkLauncherPaths[0]); err != nil {
					t.Fatal(err)
				}
			case "wrong-effect":
				effect = strings.Repeat("9", 64)
			case "wrong-approval":
				f.binding.ApprovalSHA256 = strings.Repeat("9", 64)
			case "wrong-inventory":
				f.inventory[1].SHA256 = strings.Repeat("9", 64)
			case "missing-approval":
				if err := f.root.Remove(strings.TrimPrefix(f.transaction, f.host+"/") + "/execution-approval.json"); err != nil {
					t.Fatal(err)
				}
			case "wrong-role-proposal":
				f.plan.LauncherTargets.Targets[1] = f.plan.LauncherTargets.Targets[0]
				raw, err := apkLauncherCanonical(f.plan.LauncherTargets)
				if err != nil {
					t.Fatal(err)
				}
				f.plan.LauncherTargetsSHA256 = apkTransitionDigest(raw)
				f.seal(t)
			}
			if h, err := prepareAPKLauncherCustodyWithTargetsAt(t.Context(), f.host, f.transaction, f.binding, f.original, f.inventory, effect); err == nil {
				_ = h.Close()
				t.Fatal("stale or mismatched authority was accepted")
			}
		})
	}
}

func TestAPKLauncherTargetsRefuseUnsupportedDependencyAndTargetKinds(t *testing.T) {
	for _, kind := range []string{"wrong-role", "product-directory", "alternate-link", "lexical-chain", "target-symlink", "parent-symlink", "missing-tui", "writable-target", "linked-target"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKLauncherTargetFixture(t, false)
			switch kind {
			case "wrong-role", "product-directory", "alternate-link", "lexical-chain":
				target := map[string]string{"wrong-role": apkLauncherTargets[1], "product-directory": "/opt/syswarden", "alternate-link": "/opt/syswarden/bin/alternate", "lexical-chain": "/opt/alternate/../syswarden/bin/syswarden-cli"}[kind]
				if err := f.root.Remove(apkLauncherPaths[0]); err != nil {
					t.Fatal(err)
				}
				if err := f.root.Symlink(target, apkLauncherPaths[0]); err != nil {
					t.Fatal(err)
				}
			case "target-symlink":
				if err := f.root.Remove("opt/syswarden/bin/syswarden-tui"); err != nil {
					t.Fatal(err)
				}
				if err := f.root.Symlink("syswarden-cli", "opt/syswarden/bin/syswarden-tui"); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := f.root.Rename("opt/syswarden/bin", "opt/syswarden/real-bin"); err != nil {
					t.Fatal(err)
				}
				if err := f.root.Symlink("real-bin", "opt/syswarden/bin"); err != nil {
					t.Fatal(err)
				}
			case "missing-tui":
				if err := f.root.Remove("opt/syswarden/bin/syswarden-tui"); err != nil {
					t.Fatal(err)
				}
			case "writable-target":
				if err := f.root.Chmod("opt/syswarden/bin/syswarden-tui", 0777); err != nil {
					t.Fatal(err)
				}
			case "linked-target":
				if err := f.root.Link("opt/syswarden/bin/syswarden-tui", "opt/syswarden/bin/additional-link"); err != nil {
					t.Fatal(err)
				}
			}
			original, err := captureAPKLauncherCustodyAt(t.Context(), f.host)
			if err != nil {
				t.Fatal(err)
			}
			if proposal, err := captureAPKLauncherTargetProposalAt(t.Context(), f.host, original, f.inventory); err == nil || proposal != nil {
				t.Fatal("unsupported target dependency accepted", err)
			}
		})
	}
}

func TestAPKLauncherTargetsAttestationAndPublicationCannotBePromoted(t *testing.T) {
	for _, kind := range []string{"wrong-cli", "wrong-tui", "wrong-mode", "target-link", "alias-drift", "parent-replacement", "before-publish", "after-publish", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKLauncherTargetFixture(t, false)
			h := f.prepareTargets(t)
			f.installTargets(t)
			switch kind {
			case "wrong-cli", "wrong-tui":
				index := 0
				if kind == "wrong-tui" {
					index = 1
				}
				if err := f.root.WriteFile(strings.TrimPrefix(apkLauncherTargets[index], "/"), []byte("different"), 0750); err != nil {
					t.Fatal(err)
				}
			case "wrong-mode":
				if err := f.root.Chmod("opt/syswarden/bin/syswarden-tui", 0755); err != nil {
					t.Fatal(err)
				}
			case "target-link":
				if err := f.root.Remove("opt/syswarden/bin/syswarden-tui"); err != nil {
					t.Fatal(err)
				}
				if err := f.root.Symlink("syswarden-cli", "opt/syswarden/bin/syswarden-tui"); err != nil {
					t.Fatal(err)
				}
			case "alias-drift":
				if err := f.root.Remove(apkLauncherPaths[1]); err != nil {
					t.Fatal(err)
				}
				if err := f.root.Symlink(apkLauncherTargets[1], apkLauncherPaths[1]); err != nil {
					t.Fatal(err)
				}
			case "parent-replacement":
				if err := f.root.Rename("opt/syswarden/bin", "opt/syswarden/old-bin"); err != nil {
					t.Fatal(err)
				}
				if err := f.root.Mkdir("opt/syswarden/bin", 0755); err != nil {
					t.Fatal(err)
				}
			case "before-publish", "after-publish":
				point := strings.TrimSuffix(kind, "publish") + "launcher-target-observation.json"
				h.fault = func(actual string) error {
					if actual == point {
						return errors.New("injected publication failure")
					}
					return nil
				}
			case "cancel":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				h.ctx = ctx
			}
			if err := h.AttestUpgradeTargets(); err == nil {
				t.Fatal("invalid installed target observation accepted")
			}
			if !h.failed {
				t.Fatal("target attestation failure did not retain unresolved custody")
			}
			if receipt, err := h.Commit(); err == nil || receipt != "" {
				t.Fatal("failed target observation promoted", err)
			}
			if err := h.AttestUpgradeTargets(); err == nil {
				t.Fatal("failed target observation retried")
			}
		})
	}
}

func TestAPKLauncherTargetsPostObservationAndReceiptDrift(t *testing.T) {
	for _, kind := range []string{"target-replacement", "observation", "approval", "execution-plan", "missing-observation", "retained-original", "originals-record"} {
		t.Run(kind, func(t *testing.T) {
			f := newAPKLauncherTargetFixture(t, false)
			h := f.prepareTargets(t)
			f.installTargets(t)
			if err := h.AttestUpgradeTargets(); err != nil {
				t.Fatal(err)
			}
			digest, err := h.Commit()
			if err != nil {
				t.Fatal(err)
			}
			relative := strings.TrimPrefix(f.transaction, f.host+"/")
			switch kind {
			case "target-replacement":
				f.installTargets(t)
			case "observation", "approval", "execution-plan":
				name := map[string]string{"observation": "launcher-target-observation.json", "approval": "execution-approval.json", "execution-plan": "execution-plan.json"}[kind]
				if err := f.root.WriteFile(relative+"/"+name, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "retained-original":
				if err := f.root.WriteFile(relative+"/launcher-original-tui.bin", []byte("changed original evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			case "originals-record":
				if err := f.root.WriteFile(relative+"/launcher-target-originals.json", []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-observation":
				if err := f.root.Remove(relative + "/launcher-target-observation.json"); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.Revalidate(); err == nil {
				t.Fatal("post-observation target or authority drift accepted")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			if kind != "target-replacement" {
				if got, err := inspectAPKLaunchersForRemovalAt(t.Context(), f.host, f.binding.PlanSHA256, digest); err == nil {
					_ = got.Close()
					t.Fatal("incomplete target receipt accepted for removal inspection")
				}
			}
		})
	}
}

func TestAPKLauncherTargetsOpaqueWrappersDoNotMintBehaviorApproval(t *testing.T) {
	f := newAPKLauncherFixture(t, "retained")
	proposal, err := captureAPKLauncherTargetProposalAt(t.Context(), f.host, f.original, nil)
	if err != nil || proposal != nil {
		t.Fatal("opaque wrappers produced target behavior authority", err)
	}
	h := f.prepare(t)
	if err := h.AttestUpgradeTargets(); err != nil {
		t.Fatal(err)
	}
	if h.targetAuthority != nil {
		t.Fatal("ordinary alias custody minted upgrade capability")
	}
	if _, err := f.root.Lstat("sentinel"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrapper fixture executed")
	}
}

func TestAPKLauncherTargetsOriginalRetentionFailureRefusesBeforeDispatch(t *testing.T) {
	for _, point := range []string{"before-launcher-original-cli.bin", "copy-launcher-original-cli.bin", "copy-launcher-original-tui.bin", "before-launcher-target-originals.json", "after-launcher-target-originals.json"} {
		t.Run(point, func(t *testing.T) {
			f := newAPKLauncherTargetFixture(t, false)
			fault := func(actual string) error {
				if actual == point {
					return errors.New("injected original retention failure")
				}
				return nil
			}
			h, err := prepareAPKLauncherCustodyWithTargetsFaultAt(t.Context(), f.host, f.transaction, f.binding, f.original, f.inventory, f.effect, fault)
			if err == nil || h != nil {
				if h != nil {
					_ = h.Close()
				}
				t.Fatal("partial original retention minted target authority")
			}
			for i, target := range apkLauncherTargets {
				data, err := f.root.ReadFile(strings.TrimPrefix(target, "/"))
				if err != nil || apkTransitionDigest(data) != f.proposal.Targets[i].Original.SHA256 {
					t.Fatal("retention failure changed original target", err)
				}
			}
			if _, err := f.root.Lstat(strings.TrimPrefix(f.transaction, f.host+"/") + "/launcher-custody.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed preparation published committed custody")
			}
		})
	}
}

func TestAPKLauncherTargetsRetainedBytesSurviveOriginalReplacement(t *testing.T) {
	f := newAPKLauncherTargetFixture(t, false)
	h := f.prepareTargets(t)
	f.installTargets(t)
	if err := h.AttestUpgradeTargets(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Commit(); err != nil {
		t.Fatal(err)
	}
	for i := range apkLauncherTargets {
		name := strings.TrimPrefix(f.transaction, f.host+"/") + "/" + apkLauncherOriginalTargetName(i)
		data, err := f.root.ReadFile(name)
		if err != nil || apkTransitionDigest(data) != f.proposal.Targets[i].Original.SHA256 {
			t.Fatal("original target bytes were not retained", err)
		}
		info, err := f.root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("retained target evidence is not private non-executable data", err)
		}
	}
}

//go:build linux

package wireguardstate

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// This helper runs only in a marked isolated fixture and exits without defers.
// It exercises durable file recovery, never service or runtime acceptance.
func TestPolicyTransitionCrashProcessHelper(t *testing.T) {
	point := os.Getenv("SYSWARDEN_TEST_POLICY_CRASH")
	if point == "" {
		t.Skip("private policy transaction subprocess only")
	}
	marker, err := os.ReadFile(".policy-test-only")
	if err != nil || string(marker) != "isolated policy transition crash fixture\n" {
		t.Fatal("refusing policy crash helper outside its fixture")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := wireGuardStateTestIdentity(t)
	crash := func(current string) {
		if current == point {
			os.Exit(73)
		}
	}
	policyTransitionFault = func(current string) error { crash(current); return nil }
	wireGuardStateFaultPoint = crash
	initial, err := InspectOwnedPolicy(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := BeginPolicyTransition(root, initial, uid, gid); err != nil {
		t.Fatal(err)
	}
	pending, err := InspectPolicyTransition(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ContinuePolicyTransition(root, pending, uid, gid); err != nil {
		t.Fatal(err)
	}
	committed, err := InspectPolicyTransition(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic acknowledgment tests only the file layer. Production has no
	// caller until independent host acceptance and a start fence are qualified.
	if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
		t.Fatal(err)
	}
	t.Fatal("requested crash boundary was not reached")
}

func TestPolicyTransitionSurvivesAbruptExitAtEveryDurableBoundary(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	points := []string{"intent", "server-stage", "manifest-stage", "prepared", "server-exchange", "manifest-exchange",
		"server-archive", "manifest-archive", "receipt", "remove-before-rename:" + PolicyTransitionPath,
		"remove-renamed:" + PolicyTransitionPath, "remove-before-unlink:" + PolicyTransitionPath,
		"remove-unlinked:" + PolicyTransitionPath, "finalized"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			root, uid, gid, originalManifest, contents := ownedPolicyFixture(t, true)
			files := legacyTestFiles(t, root)
			originalManifestWire, err := files.ReadFile(strings.TrimPrefix(ManifestPath, "/"))
			if err != nil {
				t.Fatal(err)
			}
			if err := files.WriteFile(".policy-test-only", []byte("isolated policy transition crash fixture\n"), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(binary, "-test.run=^TestPolicyTransitionCrashProcessHelper$") // #nosec G204 -- current test binary in a marked isolated fixture
			command.Dir = root
			command.Env = append(os.Environ(), "SYSWARDEN_TEST_POLICY_CRASH="+point)
			output, err := command.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("crash boundary not reached: %v %s", err, output)
			}
			pending, err := InspectPolicyTransition(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			if !pending.Complete {
				if RefusePendingPolicyTransition(root) == nil {
					t.Fatal("crashed transaction lost pending debt")
				}
				for label, operation := range map[string]func() error{
					"read":    func() error { _, err := ReadAndVerify(root, uid, gid); return err },
					"remove":  func() error { return RemoveOwnedArtifacts(root, uid, gid) },
					"recover": func() error { _, err := Recover(root, uid, gid); return err },
				} {
					if err := operation(); err == nil {
						t.Fatalf("ordinary %s accepted pending policy debt", label)
					}
				}
				if !pending.finalizing {
					if err := ContinuePolicyTransition(root, pending, uid, gid); err != nil {
						t.Fatal(err)
					}
				}
				committed, err := InspectPolicyTransition(root, uid, gid)
				if err != nil || !committed.FilesCommitted || committed.Complete {
					t.Fatal("file commitment incorrectly acknowledged host debt", err)
				}
				if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
					t.Fatal(err)
				}
			}
			complete, err := InspectPolicyTransition(root, uid, gid)
			if err != nil || !complete.Complete {
				t.Fatal("file-layer finalization did not converge", err)
			}
			for logical, expected := range map[string][]byte{PolicyTransitionServerArchivePath: contents[ServerConfigurationPath], PolicyTransitionManifestArchivePath: originalManifestWire,
				ClientConfigurationPath: contents[ClientConfigurationPath], ForwardingConfigurationPath: contents[ForwardingConfigurationPath]} {
				actual, err := files.ReadFile(strings.TrimPrefix(logical, "/"))
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatalf("private original or companion changed: %s: %v", logical, err)
				}
			}
			current, err := ReadAndVerify(root, uid, gid)
			if err != nil || !reflect.DeepEqual(current.Artifacts[1:], originalManifest.Artifacts[1:]) ||
				!reflect.DeepEqual(current.OpenRCServiceLink, originalManifest.OpenRCServiceLink) {
				t.Fatal("policy replacement changed unrelated ownership", err)
			}
			if !policySameAt(complete.ServerArchive, originalManifest.Artifacts[0]) {
				t.Fatal("archival lost the original server inode")
			}
		})
	}
}

func TestPolicyTransitionFinalizedLineageSupportsLaterUUIDBinding(t *testing.T) {
	root, uid, gid, manifest, _ := ownedPolicyFixture(t, true)
	files := legacyTestFiles(t, root)
	if manifest.Artifacts[0].FilesystemUUID == "" {
		t.Skip("kernel filesystem UUID unavailable; strict device matching remains covered")
	}
	for index := range manifest.Artifacts {
		manifest.Artifacts[index].FilesystemUUID = ""
	}
	manifest.OpenRCServiceLink.FilesystemUUID = ""
	wire, err := canonicalManifestBytes(manifest, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.WriteFile(strings.TrimPrefix(ManifestPath, "/"), wire, 0600); err != nil {
		t.Fatal(err)
	}
	initial, err := InspectOwnedPolicy(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := BeginPolicyTransition(root, initial, uid, gid); err != nil {
		t.Fatal(err)
	}
	pending, err := InspectPolicyTransition(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ContinuePolicyTransition(root, pending, uid, gid); err != nil {
		t.Fatal(err)
	}
	committed, err := InspectPolicyTransition(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
		t.Fatal(err)
	}
	before := observeOwnedPolicyFiles(t, root)
	bound, err := CaptureManifest(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	link, present, err := InspectOpenRCServiceLink(root, uid, gid)
	if err != nil || !present {
		t.Fatal("owned link missing before UUID binding", err)
	}
	bound.OpenRCServiceLink = &link
	// A normal UUID enrichment preserves current physical objects. Changing
	// only recorded st_dev models reboot renumbering, not an on-host operation.
	for index := range bound.Artifacts {
		bound.Artifacts[index].Device ^= 16
	}
	bound.OpenRCServiceLink.Device ^= 16
	wire, err = canonicalManifestBytes(bound, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	path := strings.TrimPrefix(ManifestPath, "/")
	if err := files.WriteFile(path+".binding-test", wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.Rename(path+".binding-test", path); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectOwnedPolicy(root, uid, gid); err != nil {
		t.Fatal("legal UUID binding invalidated policy lineage", err)
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
		t.Fatal("bound successor removal failed", err)
	}
	after := observeOwnedPolicyFiles(t, root)
	for _, logical := range []string{PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath, PolicyTransitionManifestArchivePath} {
		path := strings.TrimPrefix(logical, "/")
		if !reflect.DeepEqual(before[path], after[path]) {
			t.Fatalf("binding or removal rewrote private lineage: %s", logical)
		}
	}
}

func TestPolicyTransitionFinalizedLineageRejectsChangedLiveEnvelope(t *testing.T) {
	for _, logical := range []string{ServerConfigurationPath, ClientConfigurationPath} {
		t.Run(logical, func(t *testing.T) {
			root, uid, gid, _, _ := ownedPolicyFixture(t, false)
			committed := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
			if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
				t.Fatal(err)
			}
			adversarialPolicyReplaceSameBytes(t, root, logical)
			// A newly captured envelope alone cannot supersede immutable lineage.
			changed, err := CaptureManifest(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := canonicalManifestBytes(changed, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			files := legacyTestFiles(t, root)
			if err := files.WriteFile(strings.TrimPrefix(ManifestPath, "/"), wire, 0600); err != nil {
				t.Fatal(err)
			}
			before := observeOwnedPolicyFiles(t, root)
			if _, err := ReadAndVerify(root, uid, gid); err == nil {
				t.Fatal("changed live lineage passed ordinary verified read")
			}
			if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
				t.Fatal("new removal adopted changed successor lineage")
			}
			if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
				t.Fatal("refused new removal modified changed evidence")
			}
		})
	}
}

func TestPolicyTransitionRetainedLineageRefusesFreshPublication(t *testing.T) {
	root, uid, gid, _, contents := ownedPolicyFixture(t, false)
	committed := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
	if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	before := observeOwnedPolicyFiles(t, root)
	if _, err := StageOwnedArtifacts(root, contents, uid, gid); err == nil {
		t.Fatal("fresh publication overwrote retained generation lineage")
	}
	if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
		t.Fatal("unsupported reinstall changed private originals or created stages")
	}
}

func TestPolicyTransitionFinalizedLineageAllowsIndependentRecoveryDebt(t *testing.T) {
	root, uid, gid, _, _ := ownedPolicyFixture(t, true)
	committed := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
	if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
		t.Fatal(err)
	}
	files := legacyTestFiles(t, root)
	binding := "etc/wireguard/.syswarden-filesystem-binding-v1.json"
	// ReadAndVerify verifies the coherent live envelope while a separate
	// filesystem binder still owns its journal. It does not authorize that
	// journal or perform recovery; the network binder validates its contents.
	if err := files.WriteFile(binding, []byte("separate filesystem binding debt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAndVerify(root, uid, gid); err != nil {
		t.Fatal("separate binding debt blocked a verified current envelope", err)
	}
	if err := files.Remove(binding); err != nil {
		t.Fatal(err)
	}
	if ready, err := PrepareRemoval(root, uid, gid); err != nil || !ready {
		t.Fatal("successor removal could not prepare", err)
	}
	if recovered, err := RecoverRemoval(root, uid, gid); err != nil || !recovered {
		t.Fatal("immutable policy proof blocked ordinary removal recovery", err)
	}
	if finalized, err := FinalizeRemoval(root, uid, gid); err != nil || !finalized {
		t.Fatal("successor removal debt could not finalize", err)
	}
	if retained, err := InspectPolicyTransition(root, uid, gid); err != nil || retained.State != "retained" {
		t.Fatal("completed removal did not retain inert lineage", err)
	}
}

func TestPolicyTransitionUnchangedLegacyEnvelopeCannotDowngradeBoundUUID(t *testing.T) {
	for _, component := range []string{"client", "owned-link"} {
		t.Run(component, func(t *testing.T) {
			root, uid, gid, manifest, _ := ownedPolicyFixture(t, true)
			if manifest.Artifacts[1].FilesystemUUID == "" || manifest.OpenRCServiceLink.FilesystemUUID == "" {
				t.Skip("kernel filesystem UUID unavailable; strict device matching remains covered")
			}
			files := legacyTestFiles(t, root)
			for index := range manifest.Artifacts {
				manifest.Artifacts[index].FilesystemUUID = ""
			}
			manifest.OpenRCServiceLink.FilesystemUUID = ""
			wire, err := canonicalManifestBytes(manifest, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			if err := files.WriteFile(strings.TrimPrefix(ManifestPath, "/"), wire, 0600); err != nil {
				t.Fatal(err)
			}
			committed := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
			if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
				t.Fatal(err)
			}
			wire, err = files.ReadFile(strings.TrimPrefix(PolicyTransitionReceiptPath, "/"))
			if err != nil {
				t.Fatal(err)
			}
			var record policyTransitionRecord
			if err := policyDecode(wire, &record); err != nil {
				t.Fatal(err)
			}
			// Model contradictory sealed filesystem evidence without touching
			// live bytes or the exact UUID-free original manifest archive.
			uuid := &record.Intent.OriginalArtifacts[1].FilesystemUUID
			if component == "owned-link" {
				uuid = &record.Intent.OriginalServiceLink.FilesystemUUID
			}
			if strings.HasPrefix(*uuid, "a") {
				*uuid = "b" + (*uuid)[1:]
			} else {
				*uuid = "a" + (*uuid)[1:]
			}
			intentWire, err := policyCanonical(record.Intent)
			if err != nil {
				t.Fatal(err)
			}
			record.IntentArtifact.SHA256 = plannedArtifact(PolicyTransitionPath, intentWire, uid, gid).SHA256
			wire, err = policyCanonical(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := files.WriteFile(strings.TrimPrefix(PolicyTransitionReceiptPath, "/"), wire, 0600); err != nil {
				t.Fatal(err)
			}
			before := observeOwnedPolicyFiles(t, root)
			if _, err := InspectPolicyTransition(root, uid, gid); err == nil {
				t.Fatal("unchanged manifest downgraded bound filesystem proof")
			}
			if _, err := ReadAndVerify(root, uid, gid); err == nil {
				t.Fatal("ordinary verification ignored the bound current UUID")
			}
			if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
				t.Fatal("removal ignored contradictory bound filesystem proof")
			}
			if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
				t.Fatal("refused UUID mismatch modified evidence")
			}
		})
	}
}

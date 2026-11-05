//go:build linux

package wireguardstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func adversarialPolicyTransitionPause(t *testing.T, root string, uid, gid uint32, point string) PolicyTransitionSnapshot {
	t.Helper()
	initial, err := InspectOwnedPolicy(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	previous := policyTransitionFault
	defer func() { policyTransitionFault = previous }()
	interruption := errors.New("independent policy transaction interruption")
	hits := 0
	policyTransitionFault = func(current string) error {
		if current == point {
			hits++
			return interruption
		}
		return nil
	}
	err = BeginPolicyTransition(root, initial, uid, gid)
	if err == nil {
		pending, inspectErr := InspectPolicyTransition(root, uid, gid)
		if inspectErr != nil {
			t.Fatal(inspectErr)
		}
		err = ContinuePolicyTransition(root, pending, uid, gid)
	}
	if !errors.Is(err, interruption) || hits != 1 {
		t.Fatalf("interruption %q was not reached exactly once: hits=%d error=%v", point, hits, err)
	}
	pending, err := InspectPolicyTransition(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

func adversarialPolicyReplaceSameBytes(t *testing.T, root, logical string) {
	t.Helper()
	files := legacyTestFiles(t, root)
	path := strings.TrimPrefix(logical, "/")
	before, err := files.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := files.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	temporary := path + ".independent-replacement"
	if err := files.WriteFile(temporary, wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
	after, err := files.Stat(path)
	if err != nil || os.SameFile(before, after) {
		t.Fatal("adversarial replacement did not change the inode", err)
	}
}

func adversarialPolicyAssertRefusalPreservesFiles(t *testing.T, root string, uid, gid uint32, expected PolicyTransitionSnapshot) {
	t.Helper()
	before := observeOwnedPolicyFiles(t, root)
	if _, err := InspectPolicyTransition(root, uid, gid); err == nil {
		t.Fatal("unsafe transition evidence passed inspection")
	}
	if err := ContinuePolicyTransition(root, expected, uid, gid); err == nil {
		t.Fatal("unsafe transition evidence reached continuation")
	}
	if err := FinalizePolicyTransition(root, expected, uid, gid); err == nil {
		t.Fatal("unsafe transition evidence reached finalization")
	}
	if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
		t.Fatal("refused transition changed files, identities or metadata")
	}
}

func TestPolicyTransitionAdversarialOrphanAndUnsafeEntries(t *testing.T) {
	paths := append([]string(nil), policyTransitionPendingPaths[:]...)
	paths = append(paths, PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath, PolicyTransitionManifestArchivePath)
	for _, logical := range paths {
		for _, kind := range []string{"regular", "symlink", "directory", "fifo"} {
			t.Run(filepath.Base(logical)+"/"+kind, func(t *testing.T) {
				root, uid, gid, _, _ := ownedPolicyFixture(t, false)
				files := legacyTestFiles(t, root)
				path := strings.TrimPrefix(logical, "/")
				var err error
				switch kind {
				case "regular":
					err = files.WriteFile(path, []byte("unattributed private transaction evidence\n"), 0600)
				case "symlink":
					err = files.Symlink("clients/admin-pc.conf", path)
				case "directory":
					err = files.Mkdir(path, 0700)
				case "fifo":
					directory, openErr := files.Open("etc/wireguard")
					if openErr != nil {
						t.Fatal(openErr)
					}
					err = unix.Mkfifoat(int(directory.Fd()), filepath.Base(logical), 0600)
					closeErr := directory.Close()
					err = errors.Join(err, closeErr)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := observeOwnedPolicyFiles(t, root)
				for _, pending := range policyTransitionPendingPaths {
					if logical == pending && RefusePendingPolicyTransition(root) == nil {
						t.Fatal("pending presence guard accepted an unsafe or orphaned entry")
					}
				}
				if _, err := InspectPolicyTransition(root, uid, gid); err == nil {
					t.Fatal("orphaned or unsafe transition entry was accepted")
				}
				if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
					t.Fatal("orphan inspection changed private evidence or followed its symlink")
				}
			})
		}
	}
}

func TestPolicyTransitionAdversarialSealedIdentityReplacement(t *testing.T) {
	for _, tc := range []struct{ point, path string }{
		{"prepared", PolicyTransitionPath},
		{"prepared", policyTransitionServerStage},
		{"prepared", policyTransitionManifestStage},
		{"server-exchange", policyTransitionServerStage},
		{"manifest-exchange", policyTransitionManifestStage},
		{"receipt", PolicyTransitionServerArchivePath},
		{"receipt", PolicyTransitionManifestArchivePath},
		{"receipt", ClientConfigurationPath},
		{"receipt", ForwardingConfigurationPath},
	} {
		t.Run(tc.point+"/"+filepath.Base(tc.path), func(t *testing.T) {
			root, uid, gid, _, _ := ownedPolicyFixture(t, true)
			pending := adversarialPolicyTransitionPause(t, root, uid, gid, tc.point)
			adversarialPolicyReplaceSameBytes(t, root, tc.path)
			adversarialPolicyAssertRefusalPreservesFiles(t, root, uid, gid, pending)
		})
	}
}

func TestPolicyTransitionAdversarialIllegalFilePairs(t *testing.T) {
	for _, tc := range []struct{ name, point string }{
		{"missing-target-server-stage", "prepared"},
		{"missing-target-manifest-stage", "prepared"},
		{"missing-original-server-stage", "server-exchange"},
		{"missing-original-manifest-stage", "manifest-exchange"},
		{"manifest-archived-before-server", "manifest-exchange"},
		{"receipt-before-manifest-archive", "server-archive"},
		{"duplicate-original-server", "server-archive"},
		{"unknown-stage-after-receipt", "receipt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, uid, gid, _, _ := ownedPolicyFixture(t, false)
			pending := adversarialPolicyTransitionPause(t, root, uid, gid, tc.point)
			files := legacyTestFiles(t, root)
			var err error
			switch tc.name {
			case "missing-target-server-stage", "missing-original-server-stage":
				err = files.Remove(strings.TrimPrefix(policyTransitionServerStage, "/"))
			case "missing-target-manifest-stage", "missing-original-manifest-stage":
				err = files.Remove(strings.TrimPrefix(policyTransitionManifestStage, "/"))
			case "manifest-archived-before-server":
				err = files.Rename(strings.TrimPrefix(policyTransitionManifestStage, "/"), strings.TrimPrefix(PolicyTransitionManifestArchivePath, "/"))
			case "receipt-before-manifest-archive":
				err = files.Rename(strings.TrimPrefix(policyTransitionPreparedPath, "/"), strings.TrimPrefix(PolicyTransitionReceiptPath, "/"))
			case "duplicate-original-server":
				var wire []byte
				wire, err = files.ReadFile(strings.TrimPrefix(PolicyTransitionServerArchivePath, "/"))
				if err == nil {
					err = files.WriteFile(strings.TrimPrefix(policyTransitionServerStage, "/"), wire, 0600)
				}
			case "unknown-stage-after-receipt":
				err = files.WriteFile(strings.TrimPrefix(policyTransitionManifestStage, "/"), []byte("administrator evidence\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			adversarialPolicyAssertRefusalPreservesFiles(t, root, uid, gid, pending)
		})
	}
}

func TestPolicyTransitionAdversarialPredecessorRemainsExact(t *testing.T) {
	for _, logical := range []string{LegacyMigrationReceiptPath, legacyMigrationOriginal,
		LegacyMigrationBackupPath(ServerConfigurationPath), LegacyMigrationBackupPath(ClientConfigurationPath),
		LegacyMigrationBackupPath(ForwardingConfigurationPath)} {
		t.Run(filepath.Base(logical), func(t *testing.T) {
			root, uid, gid := completedOwnedPolicyPredecessor(t)
			pending := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
			adversarialPolicyReplaceSameBytes(t, root, logical)
			adversarialPolicyAssertRefusalPreservesFiles(t, root, uid, gid, pending)
		})
	}
}

func TestPolicyTransitionAdversarialFileCommitRetainsDebtAndRejectsStaleFinalization(t *testing.T) {
	root, uid, gid, _, _ := ownedPolicyFixture(t, false)
	pending := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
	if !pending.FilesCommitted || pending.Complete || pending.Journal == nil || pending.Receipt == nil {
		t.Fatal("file commitment lost the pending host-confirmation boundary")
	}
	if err := RefusePendingPolicyTransition(root); err == nil {
		t.Fatal("file commitment released the ordinary lifecycle guard")
	}
	before := observeOwnedPolicyFiles(t, root)
	if err := ContinuePolicyTransition(root, pending, uid, gid); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
		t.Fatal("repeated file continuation consumed debt or rewrote its receipt")
	}
	adversarialPolicyReplaceSameBytes(t, root, PolicyTransitionReceiptPath)
	before = observeOwnedPolicyFiles(t, root)
	if err := FinalizePolicyTransition(root, pending, uid, gid); err == nil {
		t.Fatal("stale confirmation accepted a replacement receipt inode")
	}
	if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
		t.Fatal("stale finalization changed the receipt or pending debt")
	}
}

func TestPolicyTransitionAdversarialUnownedOpenRCLinkIsNeverAdoptedOrRemoved(t *testing.T) {
	root, uid, gid, _, _ := ownedPolicyFixture(t, false)
	files := legacyTestFiles(t, root)
	if err := files.Mkdir("etc/init.d", 0755); err != nil { // #nosec G301 -- protected OpenRC directory fixture
		t.Fatal(err)
	}
	linkPath := strings.TrimPrefix(OpenRCServiceLinkPath, "/")
	if err := files.Symlink(OpenRCServiceLinkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	linkBefore := observeOwnedPolicyFiles(t, root)[linkPath]
	pending := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
	if err := FinalizePolicyTransition(root, pending, uid, gid); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadAndVerify(root, uid, gid)
	if err != nil || manifest.OpenRCServiceLink != nil {
		t.Fatal("transition adopted an administrator OpenRC link", err)
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	if after := observeOwnedPolicyFiles(t, root)[linkPath]; !reflect.DeepEqual(linkBefore, after) {
		t.Fatal("post-finalization owned removal changed an unowned OpenRC link")
	}
	retained, err := InspectPolicyTransition(root, uid, gid)
	if err != nil || !retained.Complete || retained.State != "retained" {
		t.Fatal("owned removal made private successor lineage incoherent", err)
	}
}

func TestPolicyTransitionAdversarialOwnedOpenRCIdentityCannotBeReplaced(t *testing.T) {
	root, uid, gid, _, _ := ownedPolicyFixture(t, true)
	pending := adversarialPolicyTransitionPause(t, root, uid, gid, "prepared")
	files := legacyTestFiles(t, root)
	path := strings.TrimPrefix(OpenRCServiceLinkPath, "/")
	if err := files.Rename(path, path+".independent-original"); err != nil {
		t.Fatal(err)
	}
	if err := files.Symlink(OpenRCServiceLinkTarget, path); err != nil {
		t.Fatal(err)
	}
	adversarialPolicyAssertRefusalPreservesFiles(t, root, uid, gid, pending)
}

func TestPolicyTransitionAdversarialPartialRemovalCannotBecomeRetainedLineage(t *testing.T) {
	for _, remaining := range []string{ClientConfigurationPath, ForwardingConfigurationPath, OpenRCServiceLinkPath} {
		t.Run(filepath.Base(remaining), func(t *testing.T) {
			root, uid, gid, _, _ := ownedPolicyFixture(t, true)
			pending := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
			if err := FinalizePolicyTransition(root, pending, uid, gid); err != nil {
				t.Fatal(err)
			}
			complete, err := InspectPolicyTransition(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			files := legacyTestFiles(t, root)
			for _, logical := range []string{ServerConfigurationPath, ClientConfigurationPath,
				ForwardingConfigurationPath, ManifestPath, OpenRCServiceLinkPath} {
				if logical != remaining {
					if err := files.Remove(strings.TrimPrefix(logical, "/")); err != nil {
						t.Fatal(err)
					}
				}
			}
			adversarialPolicyAssertRefusalPreservesFiles(t, root, uid, gid, complete)
		})
	}
}

func TestPolicyTransitionAdversarialFinalizedLineageAllowsForwardingManifestReplacement(t *testing.T) {
	for _, predecessor := range []bool{false, true} {
		name := "owned-openrc"
		if predecessor {
			name = "sealed-legacy-predecessor"
		}
		t.Run(name, func(t *testing.T) {
			var root string
			var uid, gid uint32
			if predecessor {
				root, uid, gid = completedOwnedPolicyPredecessor(t)
			} else {
				root, uid, gid, _, _ = ownedPolicyFixture(t, true)
			}
			pending := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
			if err := FinalizePolicyTransition(root, pending, uid, gid); err != nil {
				t.Fatal(err)
			}
			files := legacyTestFiles(t, root)
			before := observeOwnedPolicyFiles(t, root)
			manifest, err := ReadAndVerify(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			// Model the file envelope produced by a separately authorized forwarding
			// change. This does not execute or qualify its host runtime transaction.
			forwarding := []byte("# SYSWARDEN net.ipv4.ip_forward baseline v1 token=" + pending.Target.OwnershipToken + " value=0\n")
			path := strings.TrimPrefix(ForwardingConfigurationPath, "/")
			if err := files.WriteFile(path+".independent-stage", forwarding, 0600); err != nil {
				t.Fatal(err)
			}
			if err := files.Rename(path+".independent-stage", path); err != nil {
				t.Fatal(err)
			}
			manifest.Artifacts[2], _, err = captureLogical(root, ForwardingConfigurationPath, uid, gid, maximumOwnedArtifactBytes)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := canonicalManifestBytes(manifest, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			manifestPath := strings.TrimPrefix(ManifestPath, "/")
			if err := files.WriteFile(manifestPath+".independent-stage", wire, 0600); err != nil {
				t.Fatal(err)
			}
			if err := files.Rename(manifestPath+".independent-stage", manifestPath); err != nil {
				t.Fatal(err)
			}
			complete, err := InspectPolicyTransition(root, uid, gid)
			if err != nil || !complete.Complete || complete.State != "complete" {
				t.Fatal("legal forwarding envelope invalidated finalized policy lineage", err)
			}
			if _, err := InspectOwnedPolicy(root, uid, gid); err != nil {
				t.Fatal("owned assessment lost successor lineage after forwarding update", err)
			}
			if predecessor {
				legacy, err := InspectLegacyMigration(root, uid, gid)
				if err != nil || !legacy.Completed() {
					t.Fatal("forwarding update invalidated immutable predecessor lineage", err)
				}
			}
			if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
				t.Fatal("finalized successor no longer supports exact owned removal", err)
			}
			retained, err := InspectPolicyTransition(root, uid, gid)
			if err != nil || !retained.Complete || retained.State != "retained" {
				t.Fatal("owned removal lost inert successor lineage", err)
			}
			after := observeOwnedPolicyFiles(t, root)
			for _, logical := range []string{PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath,
				PolicyTransitionManifestArchivePath, LegacyMigrationReceiptPath, legacyMigrationOriginal,
				LegacyMigrationBackupPath(ServerConfigurationPath), LegacyMigrationBackupPath(ClientConfigurationPath),
				LegacyMigrationBackupPath(ForwardingConfigurationPath)} {
				path := strings.TrimPrefix(logical, "/")
				if !reflect.DeepEqual(before[path], after[path]) {
					t.Fatalf("forwarding or removal changed retained private evidence %s", logical)
				}
			}
			if !predecessor {
				if _, exists := after[strings.TrimPrefix(OpenRCServiceLinkPath, "/")]; exists {
					t.Fatal("exact owned OpenRC link remained after finalized removal")
				}
			}
		})
	}
}

func TestPolicyTransitionAdversarialRecordsAndSnapshotContainNoConfigurationSecrets(t *testing.T) {
	root, uid, gid, _, contents := ownedPolicyFixture(t, true)
	pending := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
	files := legacyTestFiles(t, root)
	wires := make(map[string][]byte)
	for _, logical := range []string{PolicyTransitionPath, PolicyTransitionReceiptPath} {
		wire, err := files.ReadFile(strings.TrimPrefix(logical, "/"))
		if err != nil {
			t.Fatal(err)
		}
		wires[logical] = wire
	}
	wire, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	wires["snapshot"] = wire
	lines := strings.Split(string(contents[ServerConfigurationPath]), "\n")
	for _, index := range []int{3, 8, 9} {
		_, secret, ok := strings.Cut(lines[index], " = ")
		if !ok || secret == "" {
			t.Fatal("synthetic key fixture is incomplete")
		}
		for label, wire := range wires {
			if bytes.Contains(wire, []byte(secret)) {
				t.Fatalf("%s exposed synthetic configuration key bytes", label)
			}
		}
	}
	for label, wire := range wires {
		for _, logical := range []string{ServerConfigurationPath, ClientConfigurationPath} {
			encoded, err := json.Marshal(string(contents[logical]))
			if err != nil || bytes.Contains(wire, encoded[1:len(encoded)-1]) {
				t.Fatalf("%s exposed full private configuration bytes", label)
			}
		}
	}
}

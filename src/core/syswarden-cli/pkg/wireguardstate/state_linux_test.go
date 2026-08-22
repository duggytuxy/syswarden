//go:build linux

package wireguardstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func prepareStateRoot(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	root := t.TempDir()
	for path, mode := range map[string]os.FileMode{
		"etc/wireguard/clients": 0700,
		"etc/sysctl.d":          0755,
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(full, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "etc/wireguard"), 0700); err != nil { // #nosec G302 -- owner-only mode secures private WireGuard fixture material
		t.Fatal(err)
	}
	uid, gid := wireGuardStateTestIdentity(t)
	return root, uid, gid
}

func TestPinnedPresenceInspectionRejectsSymlinkedRootAndParent_SW2_WGSTATE_001(t *testing.T) {
	realRoot, uid, gid := prepareStateRoot(t)
	assertRejected := func(t *testing.T, root string, expectedUID, expectedGID uint32) {
		t.Helper()
		if _, err := inventoryLogicalExists(root, ServerConfigurationPath); err == nil {
			t.Fatal("inventory presence inspection accepted a symlinked boundary")
		}
		if _, err := logicalExistsAt(root, ManifestPath, expectedUID, expectedGID); err == nil {
			t.Fatal("owned presence inspection accepted a symlinked boundary")
		}
		if _, err := AnyOwnedArtifactExists(root); err == nil {
			t.Fatal("owned-artifact inventory accepted a symlinked boundary")
		}
		if _, err := Inspect(root); err == nil {
			t.Fatal("complete inventory accepted a symlinked boundary")
		}
	}

	linkedRoot := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	t.Run("root", func(t *testing.T) {
		assertRejected(t, linkedRoot, uid, gid)
	})

	parentRoot, parentUID, parentGID := prepareStateRoot(t)
	if err := os.RemoveAll(filepath.Join(parentRoot, "etc/wireguard")); err != nil {
		t.Fatal(err)
	}
	realParent := filepath.Join(parentRoot, "real-wireguard")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, filepath.Join(parentRoot, "etc/wireguard")); err != nil {
		t.Fatal(err)
	}
	t.Run("parent", func(t *testing.T) {
		assertRejected(t, parentRoot, parentUID, parentGID)
	})
}

func TestPinnedPresenceInspectionCountsFinalSymlinkWithoutFollowing_SW2_WGSTATE_001(t *testing.T) {
	root, _, _ := prepareStateRoot(t)
	serverPath := filepath.Join(root, strings.TrimPrefix(ServerConfigurationPath, "/"))
	danglingTarget := filepath.Join(t.TempDir(), "missing-operator-target")
	if err := os.Symlink(danglingTarget, serverPath); err != nil {
		t.Fatal(err)
	}
	present, err := AnyOwnedArtifactExists(root)
	if err != nil || !present {
		t.Fatalf("final symlink presence = %t, error = %v", present, err)
	}
	inventory, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Artifacts) != 1 || inventory.Artifacts[0] != ServerConfigurationPath {
		t.Fatalf("final symlink inventory = %#v", inventory)
	}
}

func testOwnedContents() map[string][]byte {
	return map[string][]byte{
		ServerConfigurationPath:     []byte("server-private-material\n"),
		ClientConfigurationPath:     []byte("client-private-material\n"),
		ForwardingConfigurationPath: []byte("net.ipv4.ip_forward = 1\n"),
	}
}

func exactTestServerConfiguration() []byte {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	return []byte(fmt.Sprintf(`[Interface]
Address = 10.66.0.1/16
ListenPort = 51820
PrivateKey = %s
PostUp = /usr/sbin/nft 'create table inet syswarden_wg { comment "syswarden-wg-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }; add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }; add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }; add chain inet syswarden_wg forward { type filter hook forward priority 0; policy accept; }; add rule inet syswarden_wg postrouting oifname "ens3" masquerade; add rule inet syswarden_wg forward iifname "wg-syswarden" accept; add rule inet syswarden_wg forward oifname "wg-syswarden" accept'
PostDown = /usr/bin/true

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 10.66.0.2/32
`, key, key, key))
}

func TestVerifyServerConfigurationAcceptsOnlyExactOwnedHooks_SW2_WGSTATE_001(t *testing.T) {
	valid := exactTestServerConfiguration()
	if err := VerifyServerConfiguration(valid); err != nil {
		t.Fatalf("valid generated configuration: %v", err)
	}
	for name, changed := range map[string][]byte{
		"relative nft": bytes.Replace(valid, []byte("/usr/sbin/nft"), []byte("nft"), 1),
		"extra hook":   bytes.Replace(valid, []byte("; add chain"), []byte("; touch /tmp/x; add chain"), 1),
		"postdown":     bytes.Replace(valid, []byte("PostDown = /usr/bin/true"), []byte("PostDown = /bin/sh -c true"), 1),
		"token":        bytes.Replace(valid, []byte("aaaaaaaa"), []byte("gggggggg"), 1),
		"peer host":    bytes.Replace(valid, []byte("10.66.0.2/32"), []byte("10.66.0.3/32"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyServerConfiguration(changed); err == nil {
				t.Fatal("changed WireGuard hook configuration was accepted")
			}
		})
	}
}

func publishTestState(t *testing.T, root string, uid, gid uint32) Manifest {
	t.Helper()
	publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publication.Rollback() })
	for _, logical := range ArtifactPaths() {
		if _, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(logical, "/"))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging published %s early: %v", logical, err)
		}
	}
	if err := publication.Publish(); err != nil {
		t.Fatal(err)
	}
	manifest, err := CaptureManifest(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	manifestPublication, err := publication.StageManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifestPublication.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func publishTestStateWithOwnedOpenRCLink(t *testing.T, root string, uid, gid uint32) Manifest {
	t.Helper()
	// #nosec G301 G703 -- root is the private fixture root returned by prepareStateRoot
	if err := os.MkdirAll(filepath.Join(root, "etc/init.d"), 0755); err != nil {
		t.Fatal(err)
	}
	publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publication.Rollback() })
	if err := publication.PlanOpenRCServiceLink(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Publish(); err != nil {
		t.Fatal(err)
	}
	link, err := publication.CreateOpenRCServiceLink()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := CaptureManifest(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	manifest.OpenRCServiceLink = &link
	manifestPublication, err := publication.StageManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifestPublication.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestManifestBindsExactOwnedArtifactSet_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	manifest := publishTestState(t, root, uid, gid)

	verified, err := ReadAndVerify(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, manifest) {
		t.Fatalf("verified manifest mismatch:\n got: %#v\nwant: %#v", verified, manifest)
	}
	if got, want := len(verified.Artifacts), len(canonicalArtifactPaths); got != want {
		t.Fatalf("artifact count = %d, want %d", got, want)
	}
	contents := testOwnedContents()
	for index, artifact := range verified.Artifacts {
		if artifact.Path != canonicalArtifactPaths[index] || artifact.Mode != uint32(0600) ||
			artifact.UID != uid || artifact.GID != gid || artifact.NLink != 1 || artifact.Inode == 0 {
			t.Fatalf("invalid artifact record: %#v", artifact)
		}
		digest := sha256.Sum256(contents[artifact.Path])
		if artifact.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("digest for %s = %s", artifact.Path, artifact.SHA256)
		}
	}
	manifestInfo, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(ManifestPath, "/")))
	if err != nil {
		t.Fatal(err)
	}
	manifestStat, ok := manifestInfo.Sys().(*syscall.Stat_t)
	if !ok || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode().Perm() != 0600 ||
		manifestStat.Uid != uid || manifestStat.Gid != gid || manifestStat.Nlink != 1 {
		t.Fatalf("manifest identity is not exact: mode=%v stat=%#v", manifestInfo.Mode(), manifestStat)
	}
}

func TestManifestVerificationRejectsContentMetadataAndLinkDrift_SW2_WGSTATE_001(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "content",
			mutate: func(t *testing.T, root string) {
				path := filepath.Join(root, strings.TrimPrefix(ClientConfigurationPath, "/"))
				if err := os.WriteFile(path, []byte("tampered\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mode",
			mutate: func(t *testing.T, root string) {
				path := filepath.Join(root, strings.TrimPrefix(ServerConfigurationPath, "/"))
				if err := os.Chmod(path, 0640); err != nil { // #nosec G302 -- adversarial fixture deliberately proves relaxed secret modes are rejected
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			mutate: func(t *testing.T, root string) {
				path := filepath.Join(root, strings.TrimPrefix(ForwardingConfigurationPath, "/"))
				if err := os.Link(path, path+".operator-copy"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, uid, gid := prepareStateRoot(t)
			publishTestState(t, root, uid, gid)
			test.mutate(t, root)
			if _, err := ReadAndVerify(root, uid, gid); err == nil {
				t.Fatal("changed generated artifact passed manifest verification")
			}
		})
	}
}

func TestStageRefusesReplacementAndRollbackPreservesExistingFile_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	existingPath := filepath.Join(root, strings.TrimPrefix(ServerConfigurationPath, "/"))
	if err := os.WriteFile(existingPath, []byte("operator-owned-existing-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
	if err == nil || publication != nil || !strings.Contains(err.Error(), "refusing to stage over") {
		t.Fatalf("replacement refusal: publication=%v err=%v", publication, err)
	}
	content, err := os.ReadFile(existingPath) // #nosec G304 -- existingPath is confined to the private state fixture root
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "operator-owned-existing-content\n" {
		t.Fatalf("existing file changed: %q", content)
	}
}

func TestRemoveOwnedArtifactsPreservesNeighborsAndDirectories_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	neighbors := map[string]string{
		"etc/wireguard/operator.conf":           "operator server\n",
		"etc/wireguard/clients/alice.conf":      "operator client\n",
		"etc/sysctl.d/98-operator-routing.conf": "operator sysctl\n",
	}
	for relative, content := range neighbors {
		if err := os.WriteFile(filepath.Join(root, relative), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, logical := range append(ArtifactPaths(), ManifestPath) {
		if _, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(logical, "/"))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned path %s remains: %v", logical, err)
		}
	}
	for relative, want := range neighbors {
		content, err := os.ReadFile(filepath.Join(root, relative)) // #nosec G304 -- relative comes from the fixed neighbor fixture map above
		if err != nil {
			t.Fatalf("neighbor %s missing: %v", relative, err)
		}
		if string(content) != want {
			t.Fatalf("neighbor %s changed: %q", relative, content)
		}
	}
	for _, relative := range []string{"etc/wireguard", "etc/wireguard/clients", "etc/sysctl.d"} {
		info, err := os.Stat(filepath.Join(root, relative))
		if err != nil || !info.IsDir() {
			t.Fatalf("directory %s was removed: %v", relative, err)
		}
	}
}

func TestRemoveOwnedArtifactsFailsClosedAfterDrift_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	serverPath := filepath.Join(root, strings.TrimPrefix(ServerConfigurationPath, "/"))
	if err := os.WriteFile(serverPath, []byte("changed by operator\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
		t.Fatal("removal accepted drifted generated state")
	}
	if content, err := os.ReadFile(serverPath); err != nil || string(content) != "changed by operator\n" { // #nosec G304 -- serverPath is confined to the private state fixture root
		t.Fatalf("drifted file was removed or changed: content=%q err=%v", content, err)
	}
	if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(ManifestPath, "/"))); err != nil {
		t.Fatalf("manifest was removed after failed verification: %v", err)
	}
}

func simulatePublicationCrash(t *testing.T, publication *StagedPublication) {
	t.Helper()
	if err := closeDirectories(publication.entries); err != nil {
		t.Fatal(err)
	}
	publication.closed = true
}

func assertRecoveredStateEmpty(t *testing.T, root string) {
	t.Helper()
	inventory, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if !inventory.Empty() {
		t.Fatalf("recovered inventory is not empty: %#v", inventory)
	}
	for _, relative := range []string{"etc/wireguard", "etc/wireguard/clients", "etc/sysctl.d"} {
		entries, err := os.ReadDir(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".syswarden-stage-") || strings.Contains(entry.Name(), ".syswarden-transaction-") || strings.Contains(entry.Name(), ".syswarden-quarantine-") {
				t.Fatalf("recovery left transaction debris %s/%s", relative, entry.Name())
			}
		}
	}
}

func TestRecoverInterruptedPublicationAtDurableBoundaries_SW2_WGSTATE_001(t *testing.T) {
	t.Run("private staging", func(t *testing.T) {
		root, uid, gid := prepareStateRoot(t)
		publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		simulatePublicationCrash(t, publication)
		if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
			t.Fatalf("recover private staging: recovered=%v err=%v", recovered, err)
		}
		assertRecoveredStateEmpty(t, root)
	})

	t.Run("first final rename", func(t *testing.T) {
		root, uid, gid := prepareStateRoot(t)
		publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		entry := publication.entries[0]
		if err := unix.Renameat2(
			int(entry.directory.file.Fd()), entry.stageName,
			int(entry.directory.file.Fd()), entry.finalName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			t.Fatal(err)
		}
		entry.published = true
		simulatePublicationCrash(t, publication)
		if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
			t.Fatalf("recover first rename: recovered=%v err=%v", recovered, err)
		}
		assertRecoveredStateEmpty(t, root)
	})

	t.Run("all artifacts before manifest", func(t *testing.T) {
		root, uid, gid := prepareStateRoot(t)
		publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := publication.Publish(); err != nil {
			t.Fatal(err)
		}
		simulatePublicationCrash(t, publication)
		if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
			t.Fatalf("recover artifact publication: recovered=%v err=%v", recovered, err)
		}
		assertRecoveredStateEmpty(t, root)
	})

	t.Run("manifest completion before journal removal", func(t *testing.T) {
		root, uid, gid := prepareStateRoot(t)
		publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := publication.Publish(); err != nil {
			t.Fatal(err)
		}
		manifest, err := CaptureManifest(root, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		stagedManifest, err := publication.StageManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := stagedManifest.Publish(); err != nil {
			t.Fatal(err)
		}
		simulatePublicationCrash(t, publication)
		if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
			t.Fatalf("recover completed publication: recovered=%v err=%v", recovered, err)
		}
		if _, err := ReadAndVerify(root, uid, gid); err != nil {
			t.Fatalf("completed state was not retained: %v", err)
		}
		inventory, err := Inspect(root)
		if err != nil {
			t.Fatal(err)
		}
		if inventory.Transaction {
			t.Fatal("completed transaction journal remains")
		}
	})
}

func TestRecoverInterruptedRemovalContinuesForward_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	manifest := publishTestState(t, root, uid, gid)
	_, manifestRecord, err := readManifestWithRecord(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	manifestQuarantine, err := randomTemporaryName(filepath.Base(ManifestPath), "quarantine")
	if err != nil {
		t.Fatal(err)
	}
	journal := transactionJournal{
		Schema: transactionSchema, Operation: "remove",
		Artifacts: make([]journalArtifact, 0, len(manifest.Artifacts)),
		Manifest:  &journalArtifact{Artifact: manifestRecord, QuarantineName: manifestQuarantine},
	}
	for _, artifact := range manifest.Artifacts {
		quarantineName, err := randomTemporaryName(filepath.Base(artifact.Path), "quarantine")
		if err != nil {
			t.Fatal(err)
		}
		journal.Artifacts = append(journal.Artifacts, journalArtifact{Artifact: artifact, QuarantineName: quarantineName})
	}
	if _, err := publishTransactionJournal(root, journal, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := removeExactLogical(root, manifest.Artifacts[0], journal.Artifacts[0].QuarantineName, uid, gid); err != nil {
		t.Fatal(err)
	}
	neighbor := filepath.Join(root, "etc/wireguard/operator.conf")
	if err := os.WriteFile(neighbor, []byte("operator\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
		t.Fatalf("recover removal: recovered=%v err=%v", recovered, err)
	}
	assertRecoveredStateEmpty(t, root)
	if content, err := os.ReadFile(neighbor); err != nil || string(content) != "operator\n" { // #nosec G304 -- neighbor is confined to the private recovery fixture root
		t.Fatalf("operator neighbor changed during recovery: content=%q err=%v", content, err)
	}
}

func plannedPublishJournalForTest(t *testing.T, uid, gid uint32) transactionJournal {
	t.Helper()
	journal := transactionJournal{
		Schema: transactionSchema, Operation: "publish",
		Artifacts: make([]journalArtifact, 0, len(canonicalArtifactPaths)),
	}
	contents := testOwnedContents()
	for _, logical := range canonicalArtifactPaths {
		stageName, err := randomTemporaryName(filepath.Base(logical), "stage")
		if err != nil {
			t.Fatal(err)
		}
		quarantineName, err := randomTemporaryName(filepath.Base(logical), "quarantine")
		if err != nil {
			t.Fatal(err)
		}
		journal.Artifacts = append(journal.Artifacts, journalArtifact{
			Artifact:  plannedArtifact(logical, contents[logical], uid, gid),
			StageName: stageName, QuarantineName: quarantineName,
		})
	}
	return journal
}

func plannedRemovalJournalForTest(
	t *testing.T,
	root string,
	uid, gid uint32,
	operation TransactionOperation,
) transactionJournal {
	t.Helper()
	manifest, manifestRecord, err := readManifestWithRecord(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	manifestQuarantine, err := randomTemporaryName(filepath.Base(ManifestPath), "quarantine")
	if err != nil {
		t.Fatal(err)
	}
	journal := transactionJournal{
		Schema: transactionSchema, Operation: string(operation),
		Artifacts: make([]journalArtifact, 0, len(manifest.Artifacts)),
		Manifest: &journalArtifact{
			Artifact: manifestRecord, QuarantineName: manifestQuarantine,
		},
	}
	if manifest.OpenRCServiceLink != nil {
		quarantineName, err := randomTemporaryName(filepath.Base(OpenRCServiceLinkPath), "quarantine")
		if err != nil {
			t.Fatal(err)
		}
		journal.OpenRCServiceLink = &journalSymlink{
			Artifact: *manifest.OpenRCServiceLink, QuarantineName: quarantineName,
		}
	}
	for _, artifact := range manifest.Artifacts {
		quarantineName, err := randomTemporaryName(filepath.Base(artifact.Path), "quarantine")
		if err != nil {
			t.Fatal(err)
		}
		journal.Artifacts = append(journal.Artifacts, journalArtifact{
			Artifact: artifact, QuarantineName: quarantineName,
		})
	}
	return journal
}

func TestRecoverInitialJournalScratchAndInventory_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	journal := plannedPublishJournalForTest(t, uid, gid)
	wire, err := canonicalJournalBytes(journal, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openPinnedDirectory(root, filepath.Dir(TransactionPath), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePrivateNamed(
		directory, transactionScratchName, TransactionPath, wire,
		uid, gid, maximumOwnershipManifestSize,
	); err != nil {
		_ = directory.file.Close()
		t.Fatal(err)
	}
	if err := directory.file.Close(); err != nil {
		t.Fatal(err)
	}
	inventory, err := Inspect(root)
	if err != nil || inventory.Empty() || !inventory.Transaction {
		t.Fatalf("journal scratch inventory: %#v err=%v", inventory, err)
	}
	if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
		t.Fatalf("recover initial journal scratch: recovered=%v err=%v", recovered, err)
	}
	assertRecoveredStateEmpty(t, root)
}

func TestRecoverCorruptJournalScratchFailsClosed_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	scratch := filepath.Join(root, "etc/wireguard", transactionScratchName)
	if err := os.WriteFile(scratch, []byte("partial or hostile journal\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inventory, err := Inspect(root)
	if err != nil || inventory.Empty() || !inventory.Transaction {
		t.Fatalf("corrupt scratch inventory: %#v err=%v", inventory, err)
	}
	if recovered, err := Recover(root, uid, gid); err == nil || recovered {
		t.Fatalf("corrupt scratch recovery was not fail closed: recovered=%v err=%v", recovered, err)
	}
	if content, err := os.ReadFile(scratch); err != nil || string(content) != "partial or hostile journal\n" { // #nosec G304 -- scratch is confined to the private recovery fixture root
		t.Fatalf("corrupt scratch changed: content=%q err=%v", content, err)
	}
}

func TestRemovalOnlyRecoveryRefusesPublicationWithoutMutation_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publication.Rollback() })
	operation, present, err := InspectTransaction(root, uid, gid)
	if err != nil || !present || operation != TransactionOperationPublish {
		t.Fatalf("inspect publication transaction: operation=%q present=%v err=%v", operation, present, err)
	}
	before, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := RecoverRemoval(root, uid, gid); err == nil || recovered {
		t.Fatalf("publication accepted by removal-only recovery: recovered=%v err=%v", recovered, err)
	}
	after, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("publication state changed by removal-only recovery: before=%#v after=%#v", before, after)
	}
	operation, present, err = InspectTransaction(root, uid, gid)
	if err != nil || !present || operation != TransactionOperationPublish {
		t.Fatalf("publication transaction changed: operation=%q present=%v err=%v", operation, present, err)
	}
}

func TestExternalReloadRemovalAPIsRefuseImmediateRemovalJournal_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	journal := plannedRemovalJournalForTest(t, root, uid, gid, TransactionOperationRemove)
	if _, err := publishTransactionJournal(root, journal, uid, gid); err != nil {
		t.Fatal(err)
	}
	for name, invoke := range map[string]func() (bool, error){
		"recover":  func() (bool, error) { return RecoverRemoval(root, uid, gid) },
		"prepare":  func() (bool, error) { return PrepareRemoval(root, uid, gid) },
		"finalize": func() (bool, error) { return FinalizeRemoval(root, uid, gid) },
	} {
		t.Run(name, func(t *testing.T) {
			if changed, err := invoke(); err == nil || changed {
				t.Fatalf("immediate removal journal accepted: changed=%v err=%v", changed, err)
			}
		})
	}
	if _, err := ReadAndVerify(root, uid, gid); err != nil {
		t.Fatalf("external-reload API mutated immediate removal state: %v", err)
	}
	if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
		t.Fatalf("general recovery did not finish immediate removal: recovered=%v err=%v", recovered, err)
	}
	assertRecoveredStateEmpty(t, root)
}

func TestPrepareRemovalRetainsReloadDebtAcrossRetry_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	neighbor := filepath.Join(root, "etc/wireguard/operator.conf")
	if err := os.WriteFile(neighbor, []byte("operator\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareRemoval(root, uid, gid)
	if err != nil || !prepared {
		t.Fatalf("prepare removal: prepared=%v err=%v", prepared, err)
	}
	operation, present, err := InspectTransaction(root, uid, gid)
	if err != nil || !present || operation != TransactionOperationRemovePendingReload {
		t.Fatalf("inspect durable reload debt: operation=%q present=%v err=%v", operation, present, err)
	}
	inventory, err := Inspect(root)
	if err != nil || inventory.Manifest || len(inventory.Artifacts) != 0 || !inventory.Transaction {
		t.Fatalf("prepared removal inventory: %#v err=%v", inventory, err)
	}
	if recovered, err := Recover(root, uid, gid); err == nil || recovered {
		t.Fatalf("general recovery consumed reload debt: recovered=%v err=%v", recovered, err)
	}
	prepared, err = PrepareRemoval(root, uid, gid)
	if err != nil || !prepared {
		t.Fatalf("retry prepared removal: prepared=%v err=%v", prepared, err)
	}
	operation, present, err = InspectTransaction(root, uid, gid)
	if err != nil || !present || operation != TransactionOperationRemovePendingReload {
		t.Fatalf("retry lost durable reload debt: operation=%q present=%v err=%v", operation, present, err)
	}
	// This boundary represents the caller's successful idempotent runtime reload.
	finalized, err := FinalizeRemoval(root, uid, gid)
	if err != nil || !finalized {
		t.Fatalf("finalize removal after reload: finalized=%v err=%v", finalized, err)
	}
	assertRecoveredStateEmpty(t, root)
	if content, err := os.ReadFile(neighbor); err != nil || string(content) != "operator\n" { // #nosec G304 -- neighbor is confined to the private removal fixture root
		t.Fatalf("operator neighbor changed across removal retry: content=%q err=%v", content, err)
	}
}

func TestFinalizeRemovalRefusesIncompleteDebt_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	journal := plannedRemovalJournalForTest(
		t, root, uid, gid, TransactionOperationRemovePendingReload,
	)
	if _, err := publishTransactionJournal(root, journal, uid, gid); err != nil {
		t.Fatal(err)
	}
	if finalized, err := FinalizeRemoval(root, uid, gid); err == nil || finalized {
		t.Fatalf("incomplete removal debt finalized: finalized=%v err=%v", finalized, err)
	}
	if _, err := ReadAndVerify(root, uid, gid); err != nil {
		t.Fatalf("incomplete finalization changed committed state: %v", err)
	}
	if recovered, err := RecoverRemoval(root, uid, gid); err != nil || !recovered {
		t.Fatalf("recover incomplete removal: recovered=%v err=%v", recovered, err)
	}
	finalized, err := FinalizeRemoval(root, uid, gid)
	if err != nil || !finalized {
		t.Fatalf("finalize recovered removal: finalized=%v err=%v", finalized, err)
	}
	assertRecoveredStateEmpty(t, root)
}

func TestInspectTransactionRejectsMixedCanonicalOperations_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	removal := plannedRemovalJournalForTest(
		t, root, uid, gid, TransactionOperationRemovePendingReload,
	)
	if _, err := publishTransactionJournal(root, removal, uid, gid); err != nil {
		t.Fatal(err)
	}
	publishWire, err := canonicalJournalBytes(plannedPublishJournalForTest(t, uid, gid), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openPinnedDirectory(root, filepath.Dir(TransactionPath), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePrivateNamed(
		directory, transactionNextName, TransactionPath, publishWire,
		uid, gid, maximumOwnershipManifestSize,
	); err != nil {
		_ = directory.file.Close()
		t.Fatal(err)
	}
	if err := directory.file.Close(); err != nil {
		t.Fatal(err)
	}
	if operation, present, err := InspectTransaction(root, uid, gid); err == nil || !present || operation != TransactionOperationNone {
		t.Fatalf("mixed operations were accepted: operation=%q present=%v err=%v", operation, present, err)
	}
	if recovered, err := RecoverRemoval(root, uid, gid); err == nil || recovered {
		t.Fatalf("mixed operations were mutated: recovered=%v err=%v", recovered, err)
	}
}

func TestStageRejectsUnsafeParentWithoutMutation_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	wireGuardDirectory := filepath.Join(root, "etc/wireguard")
	if err := os.Chmod(wireGuardDirectory, 0770); err != nil { // #nosec G302 -- adversarial fixture deliberately proves group-writable state parents are rejected
		t.Fatal(err)
	}
	publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
	if err == nil || publication != nil {
		t.Fatalf("unsafe parent accepted: publication=%v err=%v", publication, err)
	}
	entries, readErr := os.ReadDir(wireGuardDirectory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != "clients" {
		t.Fatalf("unsafe parent was mutated: %v", entries)
	}
}

func TestRemovalCASRestoresConcurrentFinalSwap_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	server := filepath.Join(root, strings.TrimPrefix(ServerConfigurationPath, "/"))
	backup := server + ".operator-original"
	previousFault := wireGuardStateFaultPoint
	t.Cleanup(func() { wireGuardStateFaultPoint = previousFault })
	triggered := false
	wireGuardStateFaultPoint = func(point string) {
		if triggered || point != "remove-before-rename:"+ServerConfigurationPath {
			return
		}
		triggered = true
		if err := os.Rename(server, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(server, []byte("operator replacement\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
		t.Fatal("concurrent final replacement was removed")
	}
	if !triggered {
		t.Fatal("removal swap boundary was not reached")
	}
	if content, err := os.ReadFile(server); err != nil || string(content) != "operator replacement\n" { // #nosec G304 -- server is confined to the private CAS fixture root
		t.Fatalf("operator replacement was not restored: content=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(backup); err != nil || string(content) != "server-private-material\n" { // #nosec G304 -- backup is confined to the private CAS fixture root
		t.Fatalf("original generated secret was lost: content=%q err=%v", content, err)
	}
}

func TestRemovalCASRestoresQuarantineSwapImmediatelyBeforeUnlink_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	directory := filepath.Join(root, "etc/wireguard")
	finalPath := filepath.Join(root, strings.TrimPrefix(ServerConfigurationPath, "/"))
	backup := finalPath + ".owned-backup"
	previousFault := wireGuardStateFaultPoint
	t.Cleanup(func() { wireGuardStateFaultPoint = previousFault })
	triggered := false
	wireGuardStateFaultPoint = func(point string) {
		if triggered || point != "remove-before-unlink:"+ServerConfigurationPath {
			return
		}
		triggered = true
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		quarantine := ""
		prefix := "." + filepath.Base(ServerConfigurationPath) + ".syswarden-quarantine-"
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), prefix) {
				quarantine = filepath.Join(directory, entry.Name())
				break
			}
		}
		if quarantine == "" {
			t.Fatal("journal-bound quarantine was not found")
		}
		if err := os.Rename(quarantine, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(quarantine, []byte("operator replacement\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
		t.Fatal("quarantine replacement immediately before unlink was removed")
	}
	if !triggered {
		t.Fatal("pre-unlink CAS boundary was not reached")
	}
	if content, err := os.ReadFile(finalPath); err != nil || string(content) != "operator replacement\n" { // #nosec G304 -- finalPath is confined to the private CAS fixture root
		t.Fatalf("operator replacement was not restored to the final path: content=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(backup); err != nil || string(content) != "server-private-material\n" { // #nosec G304 -- backup is confined to the private CAS fixture root
		t.Fatalf("original generated secret was lost: content=%q err=%v", content, err)
	}
}

func TestOpenRCRemovalCASPreservesConcurrentFinalReplacement_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestStateWithOwnedOpenRCLink(t, root, uid, gid)
	finalPath := filepath.Join(root, strings.TrimPrefix(OpenRCServiceLinkPath, "/"))
	backup := finalPath + ".owned-backup"
	previousFault := wireGuardStateFaultPoint
	t.Cleanup(func() { wireGuardStateFaultPoint = previousFault })
	triggered := false
	var operatorIdentity os.FileInfo
	wireGuardStateFaultPoint = func(point string) {
		if triggered || point != "remove-before-rename:"+OpenRCServiceLinkPath {
			return
		}
		triggered = true
		if err := os.Rename(finalPath, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(OpenRCServiceLinkTarget, finalPath); err != nil {
			t.Fatal(err)
		}
		operatorIdentity, _ = os.Lstat(finalPath)
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
		t.Fatal("concurrent OpenRC final replacement was removed")
	}
	if !triggered || operatorIdentity == nil {
		t.Fatal("OpenRC final replacement boundary was not reached")
	}
	after, err := os.Lstat(finalPath)
	if err != nil || !os.SameFile(operatorIdentity, after) {
		t.Fatalf("operator OpenRC replacement was not preserved: before=%v after=%v err=%v", operatorIdentity, after, err)
	}
	if _, err := os.Lstat(backup); err != nil {
		t.Fatalf("owned OpenRC service link was lost: %v", err)
	}
}

func TestOpenRCRemovalCASRestoresQuarantineSwapBeforeUnlink_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestStateWithOwnedOpenRCLink(t, root, uid, gid)
	initDirectory := filepath.Join(root, "etc/init.d")
	finalPath := filepath.Join(root, strings.TrimPrefix(OpenRCServiceLinkPath, "/"))
	backup := finalPath + ".owned-backup"
	previousFault := wireGuardStateFaultPoint
	t.Cleanup(func() { wireGuardStateFaultPoint = previousFault })
	triggered := false
	var operatorIdentity os.FileInfo
	wireGuardStateFaultPoint = func(point string) {
		if triggered || point != "remove-before-unlink:"+OpenRCServiceLinkPath {
			return
		}
		triggered = true
		entries, err := os.ReadDir(initDirectory)
		if err != nil {
			t.Fatal(err)
		}
		quarantine := ""
		prefix := "." + filepath.Base(OpenRCServiceLinkPath) + ".syswarden-quarantine-"
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), prefix) {
				quarantine = filepath.Join(initDirectory, entry.Name())
				break
			}
		}
		if quarantine == "" {
			t.Fatal("journal-bound OpenRC quarantine was not found")
		}
		if err := os.Rename(quarantine, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(OpenRCServiceLinkTarget, quarantine); err != nil {
			t.Fatal(err)
		}
		operatorIdentity, _ = os.Lstat(quarantine)
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
		t.Fatal("changed OpenRC quarantine was removed")
	}
	if !triggered || operatorIdentity == nil {
		t.Fatal("OpenRC pre-unlink replacement boundary was not reached")
	}
	after, err := os.Lstat(finalPath)
	if err != nil || !os.SameFile(operatorIdentity, after) {
		t.Fatalf("operator OpenRC quarantine was not restored publicly: before=%v after=%v err=%v", operatorIdentity, after, err)
	}
	if _, err := os.Lstat(backup); err != nil {
		t.Fatalf("owned OpenRC service link was lost: %v", err)
	}
}

func TestScratchRemovalCASRestoresConcurrentSwap_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	journal := plannedPublishJournalForTest(t, uid, gid)
	wire, err := canonicalJournalBytes(journal, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openPinnedDirectory(root, filepath.Dir(TransactionPath), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePrivateNamed(
		directory, transactionScratchName, TransactionPath, wire,
		uid, gid, maximumOwnershipManifestSize,
	); err != nil {
		_ = directory.file.Close()
		t.Fatal(err)
	}
	if err := directory.file.Close(); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(root, "etc/wireguard", transactionScratchName)
	backup := scratch + ".operator-original"
	previousFault := wireGuardStateFaultPoint
	t.Cleanup(func() { wireGuardStateFaultPoint = previousFault })
	triggered := false
	wireGuardStateFaultPoint = func(point string) {
		expectedPoint := "remove-before-rename:" + filepath.Join(filepath.Dir(TransactionPath), transactionScratchName)
		if triggered || point != expectedPoint {
			return
		}
		triggered = true
		if err := os.Rename(scratch, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(scratch, []byte("operator scratch\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Recover(root, uid, gid); err == nil {
		t.Fatal("concurrent scratch replacement was removed")
	}
	if content, err := os.ReadFile(scratch); err != nil || string(content) != "operator scratch\n" { // #nosec G304 -- scratch is confined to the private CAS fixture root
		t.Fatalf("operator scratch was not restored: content=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(backup); err != nil || !bytes.Equal(content, wire) { // #nosec G304 -- backup is confined to the private CAS fixture root
		t.Fatalf("canonical scratch was lost: bytes=%d err=%v", len(content), err)
	}
}

func TestOpenRCLinkPlanNeverAdoptsConcurrentExactFinal_SW2_WGSTATE_001(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	initDirectory := filepath.Join(root, "etc/init.d")
	if err := os.MkdirAll(initDirectory, 0755); err != nil { // #nosec G301 -- fixture models an OpenRC service directory beneath a private root
		t.Fatal(err)
	}
	publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := publication.PlanOpenRCServiceLink(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Publish(); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(root, strings.TrimPrefix(OpenRCServiceLinkPath, "/"))
	if err := os.Symlink(OpenRCServiceLinkTarget, finalPath); err != nil {
		t.Fatal(err)
	}
	operatorIdentity, err := os.Lstat(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.CreateOpenRCServiceLink(); err == nil || !errors.Is(err, unix.EEXIST) {
		t.Fatalf("concurrent exact final link was adopted: %v", err)
	}
	if err := publication.Rollback(); err != nil {
		t.Fatalf("rollback after exclusive-link collision: %v", err)
	}
	after, err := os.Lstat(finalPath)
	if err != nil || !os.SameFile(operatorIdentity, after) {
		t.Fatalf("operator exact link changed during rollback: before=%v after=%v err=%v", operatorIdentity, after, err)
	}
	assertRecoveredStateEmpty(t, root)
}

func TestWireGuardStateCrashWorker(t *testing.T) {
	root := os.Getenv("SYSWARDEN_WG_CRASH_ROOT")
	if root == "" {
		return
	}
	target := os.Getenv("SYSWARDEN_WG_CRASH_POINT")
	action := os.Getenv("SYSWARDEN_WG_CRASH_ACTION")
	targetOccurrence, err := strconv.Atoi(os.Getenv("SYSWARDEN_WG_CRASH_OCCURRENCE"))
	if err != nil || targetOccurrence < 1 {
		targetOccurrence = 1
	}
	occurrence := 0
	uid, gid := wireGuardStateTestIdentity(t)
	wireGuardStateFaultPoint = func(point string) {
		if point == target {
			occurrence++
			if occurrence == targetOccurrence {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		}
	}
	switch action {
	case "publish", "publish-openrc":
		if action == "publish-openrc" {
			// #nosec G301 G703 -- root is required non-empty and supplied only to the isolated crash-worker test process
			if err := os.MkdirAll(filepath.Join(root, "etc/init.d"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		publication, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if action == "publish-openrc" {
			if err := publication.PlanOpenRCServiceLink(); err != nil {
				t.Fatal(err)
			}
		}
		if err := publication.Publish(); err != nil {
			t.Fatal(err)
		}
		var openRCLink *SymlinkArtifact
		if action == "publish-openrc" {
			identity, err := publication.CreateOpenRCServiceLink()
			if err != nil {
				t.Fatal(err)
			}
			openRCLink = &identity
		}
		manifest, err := CaptureManifest(root, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		manifest.OpenRCServiceLink = openRCLink
		stagedManifest, err := publication.StageManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := stagedManifest.Publish(); err != nil {
			t.Fatal(err)
		}
		if err := publication.Commit(); err != nil {
			t.Fatal(err)
		}
	case "remove":
		if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
			t.Fatal(err)
		}
	case "remove-debt":
		if prepared, err := PrepareRemoval(root, uid, gid); err != nil || !prepared {
			t.Fatalf("prepare two-phase removal: prepared=%v err=%v", prepared, err)
		}
	case "finalize-removal":
		if prepared, err := PrepareRemoval(root, uid, gid); err != nil || !prepared {
			t.Fatalf("prepare two-phase removal before finalization: prepared=%v err=%v", prepared, err)
		}
		if finalized, err := FinalizeRemoval(root, uid, gid); err != nil || !finalized {
			t.Fatalf("finalize two-phase removal: finalized=%v err=%v", finalized, err)
		}
	case "remove-openrc":
		publishTestStateWithOwnedOpenRCLink(t, root, uid, gid)
		if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown crash action %q", action)
	}
	t.Fatalf("crash point %q was not reached", target)
}

func runWireGuardStateCrashProcess(t *testing.T, root, action, point string, occurrence int) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestWireGuardStateCrashWorker$") // #nosec G204 -- current test binary
	command.Env = append(os.Environ(),
		"SYSWARDEN_WG_CRASH_ROOT="+root,
		"SYSWARDEN_WG_CRASH_ACTION="+action,
		"SYSWARDEN_WG_CRASH_POINT="+point,
		"SYSWARDEN_WG_CRASH_OCCURRENCE="+strconv.Itoa(occurrence),
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("crash worker reached normal exit at %s: %s", point, output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("crash worker error at %s: %v: %s", point, err, output)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("worker was not SIGKILLed at %s: status=%v output=%s", point, exitErr.Sys(), output)
	}
}

func TestRecoverRealSIGKILLTransactionBoundaries_SW2_WGSTATE_001(t *testing.T) {
	publishCases := []struct {
		point          string
		occurrence     int
		complete       bool
		recoveryNeeded bool
	}{
		{point: "journal-initial-linked", occurrence: 1, recoveryNeeded: true},
		{point: "artifact-staged:0", occurrence: 1, recoveryNeeded: true},
		{point: "artifact-staged:1", occurrence: 1, recoveryNeeded: true},
		{point: "artifact-staged:2", occurrence: 1, recoveryNeeded: true},
		{point: "artifact-journal-updated", occurrence: 1, recoveryNeeded: true},
		{point: "artifact-published:0", occurrence: 1, recoveryNeeded: true},
		{point: "artifact-published:1", occurrence: 1, recoveryNeeded: true},
		{point: "artifact-published:2", occurrence: 1, recoveryNeeded: true},
		{point: "manifest-staged", occurrence: 1, recoveryNeeded: true},
		{point: "manifest-journal-updated", occurrence: 1, recoveryNeeded: true},
		{point: "manifest-published", occurrence: 1, complete: true, recoveryNeeded: true},
	}
	for occurrence := 1; occurrence <= 3; occurrence++ {
		publishCases = append(publishCases,
			struct {
				point          string
				occurrence     int
				complete       bool
				recoveryNeeded bool
			}{point: "journal-update-linked", occurrence: occurrence, recoveryNeeded: true},
			struct {
				point          string
				occurrence     int
				complete       bool
				recoveryNeeded bool
			}{point: "journal-update-exchanged", occurrence: occurrence, recoveryNeeded: true},
		)
		for _, phase := range []string{"remove-before-rename:", "remove-renamed:", "remove-before-unlink:", "remove-unlinked:"} {
			publishCases = append(publishCases, struct {
				point          string
				occurrence     int
				complete       bool
				recoveryNeeded bool
			}{
				point:      phase + filepath.Join(filepath.Dir(TransactionPath), transactionNextName),
				occurrence: occurrence, recoveryNeeded: true,
			})
		}
	}
	for _, phase := range []string{"remove-before-rename:", "remove-renamed:", "remove-before-unlink:", "remove-unlinked:"} {
		publishCases = append(publishCases, struct {
			point          string
			occurrence     int
			complete       bool
			recoveryNeeded bool
		}{
			point: phase + TransactionPath, occurrence: 1, complete: true,
			recoveryNeeded: phase != "remove-unlinked:",
		})
	}
	for _, test := range publishCases {
		name := fmt.Sprintf("publish-%s-%d", strings.NewReplacer("/", "_", ":", "_").Replace(test.point), test.occurrence)
		t.Run(name, func(t *testing.T) {
			root, uid, gid := prepareStateRoot(t)
			neighbor := filepath.Join(root, "etc/wireguard/operator.conf")
			if err := os.WriteFile(neighbor, []byte("operator\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runWireGuardStateCrashProcess(t, root, "publish", test.point, test.occurrence)
			if recovered, err := Recover(root, uid, gid); err != nil || recovered != test.recoveryNeeded {
				t.Fatalf("recover %s occurrence %d: recovered=%v want=%v err=%v", test.point, test.occurrence, recovered, test.recoveryNeeded, err)
			}
			if test.complete {
				if _, err := ReadAndVerify(root, uid, gid); err != nil {
					t.Fatalf("completed publication lost at %s: %v", test.point, err)
				}
				inventory, err := Inspect(root)
				if err != nil || inventory.Transaction {
					t.Fatalf("completed transaction debris at %s: %#v err=%v", test.point, inventory, err)
				}
			} else {
				assertRecoveredStateEmpty(t, root)
			}
			if content, err := os.ReadFile(neighbor); err != nil || string(content) != "operator\n" { // #nosec G304 -- neighbor is confined to the private crash fixture root
				t.Fatalf("neighbor changed at %s: content=%q err=%v", test.point, content, err)
			}
		})
	}

	for _, point := range []string{"openrc-link-staged", "openrc-link-journal-updated", "openrc-link-published"} {
		t.Run("publish-openrc-"+point, func(t *testing.T) {
			root, uid, gid := prepareStateRoot(t)
			runWireGuardStateCrashProcess(t, root, "publish-openrc", point, 1)
			if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
				t.Fatalf("recover %s: recovered=%v err=%v", point, recovered, err)
			}
			assertRecoveredStateEmpty(t, root)
			linkPath := filepath.Join(root, strings.TrimPrefix(OpenRCServiceLinkPath, "/"))
			if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("OpenRC link remains after %s recovery: %v", point, err)
			}
			entries, err := os.ReadDir(filepath.Join(root, "etc/init.d"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("OpenRC link transaction debris remains after %s: entries=%v err=%v", point, entries, err)
			}
		})
	}

	removeCases := []struct {
		point          string
		complete       bool
		recoveryNeeded bool
	}{{point: "journal-initial-linked", complete: true, recoveryNeeded: true}}
	for _, logical := range append(append([]string(nil), canonicalArtifactPaths[:]...), ManifestPath, TransactionPath) {
		for _, phase := range []string{"remove-before-rename:", "remove-renamed:", "remove-before-unlink:", "remove-unlinked:"} {
			removeCases = append(removeCases, struct {
				point          string
				complete       bool
				recoveryNeeded bool
			}{
				point:          phase + logical,
				recoveryNeeded: !(logical == TransactionPath && phase == "remove-unlinked:"),
			})
		}
	}
	for _, test := range removeCases {
		t.Run("remove-"+strings.NewReplacer("/", "_", ":", "_").Replace(test.point), func(t *testing.T) {
			root, uid, gid := prepareStateRoot(t)
			publishTestState(t, root, uid, gid)
			neighbor := filepath.Join(root, "etc/wireguard/operator.conf")
			if err := os.WriteFile(neighbor, []byte("operator\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runWireGuardStateCrashProcess(t, root, "remove", test.point, 1)
			if recovered, err := Recover(root, uid, gid); err != nil || recovered != test.recoveryNeeded {
				t.Fatalf("recover %s: recovered=%v want=%v err=%v", test.point, recovered, test.recoveryNeeded, err)
			}
			if test.complete {
				if _, err := ReadAndVerify(root, uid, gid); err != nil {
					t.Fatalf("pre-removal committed state lost at %s: %v", test.point, err)
				}
			} else {
				assertRecoveredStateEmpty(t, root)
			}
			if content, err := os.ReadFile(neighbor); err != nil || string(content) != "operator\n" { // #nosec G304 -- neighbor is confined to the private crash fixture root
				t.Fatalf("neighbor changed at %s: content=%q err=%v", test.point, content, err)
			}
		})
	}

	for _, phase := range []string{"remove-before-rename:", "remove-renamed:", "remove-before-unlink:", "remove-unlinked:"} {
		point := phase + OpenRCServiceLinkPath
		t.Run("remove-openrc-"+strings.NewReplacer("/", "_", ":", "_").Replace(point), func(t *testing.T) {
			root, uid, gid := prepareStateRoot(t)
			if err := os.MkdirAll(filepath.Join(root, "etc/init.d"), 0755); err != nil { // #nosec G301 -- fixture models an OpenRC service directory beneath a private root
				t.Fatal(err)
			}
			neighbor := filepath.Join(root, "etc/init.d/operator-service")
			if err := os.WriteFile(neighbor, []byte("operator\n"), 0700); err != nil { // #nosec G306 -- owner-only executable mode models an OpenRC operator service fixture
				t.Fatal(err)
			}
			runWireGuardStateCrashProcess(t, root, "remove-openrc", point, 1)
			if recovered, err := Recover(root, uid, gid); err != nil || !recovered {
				t.Fatalf("recover %s: recovered=%v err=%v", point, recovered, err)
			}
			assertRecoveredStateEmpty(t, root)
			if content, err := os.ReadFile(neighbor); err != nil || string(content) != "operator\n" { // #nosec G304 -- neighbor is confined to the private OpenRC crash fixture root
				t.Fatalf("OpenRC operator neighbor changed at %s: content=%q err=%v", point, content, err)
			}
			linkPath := filepath.Join(root, strings.TrimPrefix(OpenRCServiceLinkPath, "/"))
			if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("owned OpenRC service link remains at %s: %v", point, err)
			}
		})
	}
}

func TestTwoPhaseRemovalRealSIGKILLBoundaries_SW2_WGSTATE_001(t *testing.T) {
	preparePoints := []string{"journal-initial-linked", "removal-reload-debt-ready"}
	for _, logical := range append(append([]string(nil), canonicalArtifactPaths[:]...), ManifestPath) {
		for _, phase := range []string{
			"remove-before-rename:", "remove-renamed:",
			"remove-before-unlink:", "remove-unlinked:",
		} {
			preparePoints = append(preparePoints, phase+logical)
		}
	}
	for _, point := range preparePoints {
		t.Run("prepare-"+strings.NewReplacer("/", "_", ":", "_").Replace(point), func(t *testing.T) {
			root, uid, gid := prepareStateRoot(t)
			publishTestState(t, root, uid, gid)
			neighbor := filepath.Join(root, "etc/wireguard/operator.conf")
			if err := os.WriteFile(neighbor, []byte("operator\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runWireGuardStateCrashProcess(t, root, "remove-debt", point, 1)
			prepared, err := PrepareRemoval(root, uid, gid)
			if err != nil || !prepared {
				t.Fatalf("retry prepare at %s: prepared=%v err=%v", point, prepared, err)
			}
			operation, present, err := InspectTransaction(root, uid, gid)
			if err != nil || !present || operation != TransactionOperationRemovePendingReload {
				t.Fatalf("reload debt at %s: operation=%q present=%v err=%v", point, operation, present, err)
			}
			// This boundary represents the successful idempotent runtime reload.
			if finalized, err := FinalizeRemoval(root, uid, gid); err != nil || !finalized {
				t.Fatalf("finalize at %s: finalized=%v err=%v", point, finalized, err)
			}
			assertRecoveredStateEmpty(t, root)
			if content, err := os.ReadFile(neighbor); err != nil || string(content) != "operator\n" { // #nosec G304 -- neighbor is confined to the private two-phase fixture root
				t.Fatalf("neighbor changed at %s: content=%q err=%v", point, content, err)
			}
		})
	}

	for _, phase := range []string{
		"remove-before-rename:", "remove-renamed:",
		"remove-before-unlink:", "remove-unlinked:",
	} {
		point := phase + TransactionPath
		t.Run("finalize-"+strings.NewReplacer("/", "_", ":", "_").Replace(point), func(t *testing.T) {
			root, uid, gid := prepareStateRoot(t)
			publishTestState(t, root, uid, gid)
			runWireGuardStateCrashProcess(t, root, "finalize-removal", point, 1)
			operation, present, err := InspectTransaction(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			if present {
				if operation != TransactionOperationRemovePendingReload {
					t.Fatalf("unexpected finalization operation at %s: %q", point, operation)
				}
				// The prior process reloaded before entering FinalizeRemoval. Repeating
				// finalization is therefore safe and must consume the exact debt.
				if finalized, err := FinalizeRemoval(root, uid, gid); err != nil || !finalized {
					t.Fatalf("retry finalization at %s: finalized=%v err=%v", point, finalized, err)
				}
			}
			assertRecoveredStateEmpty(t, root)
		})
	}
}

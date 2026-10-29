//go:build linux

package wireguardstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ownedPolicyDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func ownedPolicyFixture(t *testing.T, withOpenRC bool) (string, uint32, uint32, Manifest, map[string][]byte) {
	t.Helper()
	root, uid, gid := prepareStateRoot(t)
	files := legacyTestFiles(t, root)
	contents := testOwnedContents()
	contents[ServerConfigurationPath] = policyUpgradeFixture(t, "192.0.2.1/30", "192.0.2.2/32", false)
	publication, err := StageOwnedArtifacts(root, contents, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publication.Rollback() })
	if withOpenRC {
		if err := files.Mkdir("etc/init.d", 0755); err != nil { // #nosec G301 -- protected service-directory fixture
			t.Fatal(err)
		}
		if err := publication.PlanOpenRCServiceLink(); err != nil {
			t.Fatal(err)
		}
	}
	if err := publication.Publish(); err != nil {
		t.Fatal(err)
	}
	manifest, err := CaptureManifest(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if withOpenRC {
		link, err := publication.CreateOpenRCServiceLink()
		if err != nil {
			t.Fatal(err)
		}
		manifest.OpenRCServiceLink = &link
	}
	staged, err := publication.StageManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := staged.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(); err != nil {
		t.Fatal(err)
	}
	return root, uid, gid, manifest, contents
}

type ownedPolicyFileObservation struct {
	Mode          fs.FileMode
	Size          int64
	Modified      int64
	Changed       unix.Timespec
	UID, GID      uint32
	Device, Inode uint64
	Links         uint64
	Content       []byte
	SymlinkTarget string
}

// Read-only inspection may update access times. All content, directory entries,
// permissions, ownership, object identities, size, mtime and ctime stay exact.
func observeOwnedPolicyFiles(t *testing.T, root string) map[string]ownedPolicyFileObservation {
	t.Helper()
	files := legacyTestFiles(t, root)
	observations := make(map[string]ownedPolicyFileObservation)
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := files.Lstat(relative)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("fixture has no Linux file identity")
		}
		observation := ownedPolicyFileObservation{Mode: info.Mode(), Size: info.Size(), Modified: info.ModTime().UnixNano(),
			Changed: unix.Timespec{Sec: stat.Ctim.Sec, Nsec: stat.Ctim.Nsec},
			UID:     stat.Uid, GID: stat.Gid, Device: uint64(stat.Dev), Inode: stat.Ino, Links: uint64(stat.Nlink)}
		if info.Mode().IsRegular() {
			observation.Content, err = files.ReadFile(relative)
		} else if info.Mode()&os.ModeSymlink != 0 {
			observation.SymlinkTarget, err = files.Readlink(relative)
		}
		if err != nil {
			return err
		}
		observations[relative] = observation
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return observations
}

func TestOwnedPolicySnapshotRetainsCompleteManifestAndExactHashesWithoutSecrets(t *testing.T) {
	for _, withOpenRC := range []bool{false, true} {
		root, uid, gid, originalManifest, contents := ownedPolicyFixture(t, withOpenRC)
		before := observeOwnedPolicyFiles(t, root)
		snapshot, err := InspectOwnedPolicy(root, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(snapshot.Manifest, originalManifest) || (snapshot.Manifest.OpenRCServiceLink != nil) != withOpenRC {
			t.Fatal("assessment lost or changed original manifest ownership")
		}
		manifestBytes := before[strings.TrimPrefix(ManifestPath, "/")].Content
		if snapshot.ManifestArtifact.SHA256 != ownedPolicyDigest(manifestBytes) || snapshot.ManifestArtifact.Path != ManifestPath {
			t.Fatal("assessment does not bind the exact original manifest bytes")
		}
		for _, artifact := range snapshot.Manifest.Artifacts {
			if artifact.SHA256 != ownedPolicyDigest(contents[artifact.Path]) {
				t.Fatal("assessment source digest differs from the original artifact")
			}
		}
		source, err := ParseServerConfiguration(contents[ServerConfigurationPath])
		if err != nil {
			t.Fatal(err)
		}
		targetBytes, err := ScopedServerConfiguration(contents[ServerConfigurationPath])
		if err != nil {
			t.Fatal(err)
		}
		target, err := ParseServerConfiguration(targetBytes)
		if err != nil || snapshot.Source != source || snapshot.Target != target || snapshot.TargetServerSHA256 != ownedPolicyDigest(targetBytes) {
			t.Fatal("assessment source or deterministic target identity is incorrect", err)
		}
		if snapshot.Source.PolicyVersion != 0 || snapshot.Target.PolicyVersion != 2 || snapshot.PredecessorReceipt != nil {
			t.Fatal("assessment reported an incorrect policy version or predecessor")
		}
		wire, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(contents[ServerConfigurationPath]), "\n")
		for _, index := range []int{3, 8, 9} {
			_, value, ok := strings.Cut(lines[index], " = ")
			if !ok || bytes.Contains(wire, []byte(value)) {
				t.Fatal("assessment JSON contains synthetic key material")
			}
		}
		for _, content := range [][]byte{contents[ClientConfigurationPath], contents[ServerConfigurationPath], targetBytes} {
			encoded, err := json.Marshal(string(content))
			if err != nil || bytes.Contains(wire, encoded[1:len(encoded)-1]) {
				t.Fatal("assessment JSON contains private configuration bytes", err)
			}
		}
		if withOpenRC && !bytes.Contains(wire, []byte(`"openrc_service_link"`)) {
			t.Fatal("serialized assessment omitted owned OpenRC link")
		}
		repeated, err := InspectOwnedPolicy(root, uid, gid)
		if err != nil || !reflect.DeepEqual(snapshot, repeated) {
			t.Fatal("read-only assessment is not deterministic", err)
		}
		if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
			t.Fatal("read-only assessment changed files or metadata")
		}
	}
}

func TestOwnedPolicyAssessmentRefusesChangedOwnershipWithoutMutation(t *testing.T) {
	for _, kind := range []string{"missing-manifest", "corrupt-manifest", "manifest-digest", "manifest-extra-field", "manifest-symlink", "server", "client", "forwarding", "server-mode", "server-symlink", "owned-openrc-link", "corrupt-receipt", "receipt-symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, uid, gid, manifest, _ := ownedPolicyFixture(t, true)
			files := legacyTestFiles(t, root)
			manifestPath := strings.TrimPrefix(ManifestPath, "/")
			serverPath := strings.TrimPrefix(ServerConfigurationPath, "/")
			var err error
			switch kind {
			case "missing-manifest":
				err = files.Remove(manifestPath)
			case "corrupt-manifest":
				err = files.WriteFile(manifestPath, []byte("{}\n"), 0600)
			case "manifest-digest":
				manifest.Artifacts[0].SHA256 = strings.Repeat("0", 64)
				var wire []byte
				wire, err = canonicalManifestBytes(manifest, uid, gid)
				if err == nil {
					err = files.WriteFile(manifestPath, wire, 0600)
				}
			case "manifest-extra-field":
				var wire []byte
				wire, err = files.ReadFile(manifestPath)
				if err == nil {
					err = files.WriteFile(manifestPath, bytes.Replace(wire, []byte("{\n"), []byte("{\n  \"foreign\": true,\n"), 1), 0600)
				}
			case "manifest-symlink":
				err = files.Remove(manifestPath)
				if err == nil {
					err = files.Symlink("missing-manifest", manifestPath)
				}
			case "server", "client", "forwarding":
				path := map[string]string{"server": ServerConfigurationPath, "client": ClientConfigurationPath, "forwarding": ForwardingConfigurationPath}[kind]
				err = files.WriteFile(strings.TrimPrefix(path, "/"), []byte("changed administrator bytes\n"), 0600)
			case "server-mode":
				err = files.Chmod(serverPath, 0640) // #nosec G302 -- adversarial fixture proves relaxed private-file permissions are refused
			case "server-symlink":
				err = files.Remove(serverPath)
				if err == nil {
					err = files.Symlink("missing-server", serverPath)
				}
			case "owned-openrc-link":
				path := strings.TrimPrefix(OpenRCServiceLinkPath, "/")
				err = files.Remove(path)
				if err == nil {
					err = files.Symlink("/etc/init.d/administrator-vpn", path)
				}
			case "corrupt-receipt":
				err = files.WriteFile(strings.TrimPrefix(LegacyMigrationReceiptPath, "/"), []byte("{}\n"), 0600)
			case "receipt-symlink":
				err = files.Symlink("missing-receipt", strings.TrimPrefix(LegacyMigrationReceiptPath, "/"))
			}
			if err != nil {
				t.Fatal(err)
			}
			before := observeOwnedPolicyFiles(t, root)
			snapshot, err := InspectOwnedPolicy(root, uid, gid)
			if err == nil || !reflect.DeepEqual(snapshot, OwnedPolicySnapshot{}) {
				t.Fatal("changed ownership produced an assessment")
			}
			if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
				t.Fatal("refused assessment changed retained bytes or metadata")
			}
		})
	}
}

func TestOwnedPolicyAssessmentRejectsPendingJournalsWithoutOpeningFIFOOrSymlink(t *testing.T) {
	for _, kind := range []string{"ownership", "ownership-scratch", "ownership-next", "legacy", "forwarding", "forwarding-fifo", "forwarding-symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, uid, gid, _, _ := ownedPolicyFixture(t, false)
			files := legacyTestFiles(t, root)
			path := ForwardingTransitionPath
			switch kind {
			case "ownership":
				path = TransactionPath
			case "ownership-scratch":
				path = filepath.Join(filepath.Dir(TransactionPath), transactionScratchName)
			case "ownership-next":
				path = filepath.Join(filepath.Dir(TransactionPath), transactionNextName)
			case "legacy":
				path = LegacyMigrationPath
			}
			var err error
			switch kind {
			case "forwarding-fifo":
				directory, openErr := files.Open("etc/wireguard")
				if openErr != nil {
					t.Fatal(openErr)
				}
				err = unix.Mkfifoat(int(directory.Fd()), filepath.Base(path), 0600)
				if closeErr := directory.Close(); err == nil {
					err = closeErr
				}
			case "forwarding-symlink":
				err = files.Symlink("clients/admin-pc.conf", strings.TrimPrefix(path, "/"))
			default:
				err = files.WriteFile(strings.TrimPrefix(path, "/"), []byte("pending private journal\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := observeOwnedPolicyFiles(t, root)
			done := make(chan error, 1)
			go func() {
				_, err := InspectOwnedPolicy(root, uid, gid)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("pending journal was ignored")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("pending journal presence check blocked on a special file")
			}
			if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
				t.Fatal("pending journal inspection changed files or metadata")
			}
		})
	}
}

func completedOwnedPolicyPredecessor(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	root, uid, gid := migrationFixture(t)
	initial, err := InspectLegacyMigration(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	server := exactTestServerConfiguration()
	if err := BeginLegacyMigration(root, initial, server, uid, gid); err != nil {
		t.Fatal(err)
	}
	pending, err := InspectLegacyMigration(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ContinueLegacyMigration(root, pending, server, uid, gid); err != nil {
		t.Fatal(err)
	}
	return root, uid, gid
}

func TestOwnedPolicyAssessmentPreservesSealedPredecessorAndOriginalBackups(t *testing.T) {
	root, uid, gid := completedOwnedPolicyPredecessor(t)
	before := observeOwnedPolicyFiles(t, root)
	snapshot, err := InspectOwnedPolicy(root, uid, gid)
	if err != nil || snapshot.PredecessorReceipt == nil || snapshot.Source.PolicyVersion != 0 || snapshot.Target.PolicyVersion != 2 {
		t.Fatal("completed v1 predecessor was not bound to the assessment", err)
	}
	receipt := before[strings.TrimPrefix(LegacyMigrationReceiptPath, "/")]
	if snapshot.PredecessorReceipt.SHA256 != ownedPolicyDigest(receipt.Content) || snapshot.PredecessorReceipt.Inode != receipt.Inode {
		t.Fatal("assessment predecessor differs from the sealed receipt")
	}
	for path, original := range testOwnedContents() {
		backup := before[strings.TrimPrefix(LegacyMigrationBackupPath(path), "/")]
		if !bytes.Equal(backup.Content, original) {
			t.Fatal("synthetic predecessor does not preserve its original bytes")
		}
	}
	if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
		t.Fatal("assessment changed the sealed predecessor, backups or live state")
	}
}

func TestOwnedPolicyAssessmentRefusesChangedSealedPredecessor(t *testing.T) {
	for _, kind := range []string{"receipt-target", "server-backup", "client-backup", "forwarding-backup", "missing-original-archive"} {
		t.Run(kind, func(t *testing.T) {
			root, uid, gid := completedOwnedPolicyPredecessor(t)
			files := legacyTestFiles(t, root)
			var err error
			switch kind {
			case "receipt-target":
				path := strings.TrimPrefix(LegacyMigrationReceiptPath, "/")
				var wire []byte
				wire, err = files.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var journal legacyMigrationJournal
				journal, err = decodeLegacyMigration(wire, uid, gid)
				if err != nil {
					t.Fatal(err)
				}
				journal.ServerSHA256 = strings.Repeat("0", 64)
				wire, err = json.Marshal(journal)
				if err == nil {
					err = files.WriteFile(path, wire, 0600)
				}
			case "missing-original-archive":
				err = files.Remove(strings.TrimPrefix(legacyMigrationOriginal, "/"))
			default:
				path := map[string]string{"server-backup": ServerConfigurationPath, "client-backup": ClientConfigurationPath, "forwarding-backup": ForwardingConfigurationPath}[kind]
				err = files.WriteFile(strings.TrimPrefix(LegacyMigrationBackupPath(path), "/"), []byte("changed private predecessor evidence\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := observeOwnedPolicyFiles(t, root)
			if _, err := InspectOwnedPolicy(root, uid, gid); err == nil {
				t.Fatal("changed sealed predecessor was accepted")
			}
			if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
				t.Fatal("assessment modified refused predecessor evidence")
			}
		})
	}
}

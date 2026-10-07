//go:build linux

package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

func fixtureNFTPersistenceVerification(t *testing.T) (string, nftPersistenceFilesystem, nftPersistenceGraph) {
	t.Helper()
	root, host := fixtureNFTPersistenceFilesystem(t)
	writeNFTPersistenceFixture(t, root, "etc/nftables.conf", "include \"/etc/nftables.d/*.nft\"\ninclude \"/etc/missing/*.nft\"\n")
	writeNFTPersistenceFixture(t, root, "etc/nftables.d/admin.nft", "# administrator fragment\n")
	writeNFTPersistenceFixture(t, root, "etc/nftables.d/product.nft", legacyNFTIncludeMarker+"\n"+legacyNFTIncludeLine+"\n")
	writeNFTPersistenceFixture(t, root, "etc/syswarden/syswarden.nft", "table inet syswarden_table {\n}\n")
	graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, host.reader())
	if err != nil {
		t.Fatal(err)
	}
	return root, host, graph
}

func TestNFTPersistenceGraphReattestationAcceptsUnchangedInputs(t *testing.T) {
	root, host, graph := fixtureNFTPersistenceVerification(t)
	// An unrelated backup excluded by the shell pattern is not a dependency.
	writeNFTPersistenceFixture(t, root, "etc/nftables.d/custom.backup", "private backup\n")
	if err := verifyNFTPersistenceGraph(graph, host.reader()); err != nil {
		t.Fatal(err)
	}
}

func TestNFTPersistenceGraphReattestationRejectsChangesWithoutWriting(t *testing.T) {
	for _, mutation := range []string{"content", "same_bytes_new_inode", "mode", "new_include", "removed_include", "previously_empty_include", "linked_source", "changed_parent"} {
		t.Run(mutation, func(t *testing.T) {
			root, host, graph := fixtureNFTPersistenceVerification(t)
			logical := "etc/nftables.d/admin.nft"
			path := filepath.Join(root, logical)
			var err error
			switch mutation {
			case "content":
				writeNFTPersistenceFixture(t, root, logical, "# changed administrator fragment\n")
			case "same_bytes_new_inode":
				err = os.Rename(path, path+".backup")
				if err == nil {
					writeNFTPersistenceFixture(t, root, logical, "# administrator fragment\n")
				}
			case "mode":
				err = os.Chmod(path, 0644) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			case "new_include":
				writeNFTPersistenceFixture(t, root, "etc/nftables.d/new.nft", "# new administrator fragment\n")
			case "removed_include":
				err = os.Remove(path)
			case "previously_empty_include":
				err = os.Mkdir(filepath.Join(root, "etc/missing"), 0755) // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
				if err == nil {
					writeNFTPersistenceFixture(t, root, "etc/missing/new.nft", "# newly included administrator file\n")
				}
			case "linked_source":
				err = os.Rename(path, path+".backup")
				if err == nil {
					err = os.Symlink(path+".backup", path)
				}
			case "changed_parent":
				err = os.Chmod(filepath.Dir(path), 0775) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyNFTPersistenceGraph(graph, host.reader()); err == nil {
				t.Fatal("stale plan was accepted")
			}
			content, err := os.ReadFile(filepath.Join(root, "etc/nftables.d/product.nft")) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			if err != nil || string(content) != legacyNFTIncludeMarker+"\n"+legacyNFTIncludeLine+"\n" {
				t.Fatal("failed reattestation changed the proposed target")
			}
		})
	}
}

func TestNFTPersistenceGraphReattestationRejectsUnboundOrModifiedPlans(t *testing.T) {
	for _, mutation := range []string{"empty", "no_identity", "wrong_digest", "changed_output", "changed_range"} {
		t.Run(mutation, func(t *testing.T) {
			_, host, graph := fixtureNFTPersistenceVerification(t)
			switch mutation {
			case "empty":
				graph = nftPersistenceGraph{}
			case "no_identity":
				graph.sources[0].identity = nil
			case "wrong_digest":
				graph.sources[0].sha256[0] ^= 1
			case "changed_output":
				graph.sources[0].edit.content = []byte("flush ruleset\n")
			case "changed_range":
				graph.sources[0].edit.removed = []nftPersistenceRange{{0, 1}}
			}
			if err := verifyNFTPersistenceGraph(graph, host.reader()); err == nil {
				t.Fatal("unbound or modified plan was accepted")
			}
		})
	}
}

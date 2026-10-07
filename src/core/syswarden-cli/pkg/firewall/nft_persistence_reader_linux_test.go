//go:build linux

package firewall

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func fixtureNFTPersistenceFilesystem(t *testing.T) (string, nftPersistenceFilesystem) {
	t.Helper()
	path := t.TempDir()
	for _, directory := range []string{"etc/nftables.d", "etc/syswarden"} {
		if err := os.MkdirAll(filepath.Join(path, directory), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return path, fixtureNFTPersistencePinnedRoot(t, root)
}

func fixtureNFTPersistencePinnedRoot(t *testing.T, root *os.Root) nftPersistenceFilesystem {
	t.Helper()
	info, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture root has no Linux ownership metadata")
	}
	return nftPersistenceFilesystem{root: root, expectedUID: stat.Uid, expectedGID: stat.Gid}
}

func writeNFTPersistenceFixture(t *testing.T, root, path, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0600); err != nil { // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
		t.Fatal(err)
	}
}

func TestNFTPersistenceFilesystemReadsAnAttestedIncludeGraph(t *testing.T) {
	root, host := fixtureNFTPersistenceFilesystem(t)
	files := map[string]string{
		"etc/nftables.conf":                   "include \"/etc/nftables.d/*.nft\"\n",
		"etc/nftables.d/10-admin.nft":         "# custom policy stays unchanged\n",
		"etc/nftables.d/20-product.nft":       legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n",
		"etc/syswarden/syswarden.nft":         "table inet syswarden_table {\n}\n",
		"etc/nftables.d/administrator.backup": "ignored by the include pattern\n",
		"etc/nftables.d/.hidden.nft":          "not a valid nftables fragment\n",
	}
	for path, content := range files {
		writeNFTPersistenceFixture(t, root, path, content)
	}
	graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, host.reader())
	if err != nil || len(graph.sources) != 4 {
		t.Fatalf("attested graph failed: %v", err)
	}
	want := []string{"/etc/nftables.d/10-admin.nft", "/etc/nftables.d/20-product.nft"}
	if len(graph.expansions) != 1 || !reflect.DeepEqual(graph.expansions[0].paths, want) {
		t.Fatal("wildcard inventory was not sorted or included an unrelated backup")
	}
	for path, expected := range files {
		actual, err := os.ReadFile(filepath.Join(root, path)) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
		if err != nil || string(actual) != expected {
			t.Fatal("read-only inspection modified a file")
		}
	}
}

func TestNFTPersistenceFilesystemRequiresExplicitHiddenFilePattern(t *testing.T) {
	root, host := fixtureNFTPersistenceFilesystem(t)
	writeNFTPersistenceFixture(t, root, "etc/nftables.d/.hidden.nft", "# explicit hidden fragment\n")
	paths, err := host.expand("/etc/nftables.d/.*.nft")
	if err != nil || !reflect.DeepEqual(paths, []string{"/etc/nftables.d/.hidden.nft"}) {
		t.Fatalf("explicit hidden file pattern was not preserved: %v", err)
	}
	for _, pattern := range []string{"/etc/nftables.d/?.nft", "/etc/nftables.d/[[:digit:]]*.nft", "/etc/nftables.d/[.]hidden.nft"} {
		if _, err := host.expand(pattern); err == nil {
			t.Fatal("unsupported shell pattern was approximated instead of refused")
		}
	}
}

func TestNFTPersistenceFilesystemRecordsMissingWildcardDirectory(t *testing.T) {
	root, host := fixtureNFTPersistenceFilesystem(t)
	writeNFTPersistenceFixture(t, root, "etc/nftables.conf", "include \"/etc/not-created/*.nft\"\n")
	graph, err := inspectNFTPersistenceGraph([]string{"/etc/nftables.conf"}, host.reader())
	if err != nil || len(graph.sources) != 1 || len(graph.expansions) != 1 || len(graph.expansions[0].paths) != 0 {
		t.Fatalf("missing wildcard directory should retain an empty expansion: %v", err)
	}
	if _, err := host.read("/etc/not-created/required.nft"); err == nil {
		t.Fatal("a missing literal include must remain an error")
	}
}

func TestNFTPersistenceFilesystemRefusesLinksAndUnsafeMetadata(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "writable_file", "writable_parent", "linked_parent", "wrong_owner", "special_mode"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureNFTPersistenceFilesystem(t)
			path := filepath.Join(root, "etc/nftables.d/custom.nft")
			writeNFTPersistenceFixture(t, root, "etc/nftables.d/custom.nft", "# original\n")
			var err error
			switch kind {
			case "symlink":
				err = os.Rename(path, path+".saved")
				if err == nil {
					err = os.Symlink(path+".saved", path)
				}
			case "hardlink":
				err = os.Link(path, path+".link")
			case "fifo":
				err = os.Remove(path)
				if err == nil {
					err = syscall.Mkfifo(path, 0600)
				}
			case "writable_file":
				err = os.Chmod(path, 0660) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			case "writable_parent":
				err = os.Chmod(filepath.Dir(path), 0775) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			case "linked_parent":
				err = os.Rename(filepath.Dir(path), filepath.Dir(path)+".saved")
				if err == nil {
					err = os.Symlink(filepath.Dir(path)+".saved", filepath.Dir(path))
				}
			case "wrong_owner":
				host.expectedUID++
			case "special_mode":
				err = os.Chmod(path, 0600|os.ModeSetuid)
			}
			if err != nil {
				t.Fatal(err)
			}
			if data, err := host.read("/etc/nftables.d/custom.nft"); err == nil || data != nil {
				t.Fatal("unsafe source was read")
			}
			if paths, err := host.expand("/etc/nftables.d/*.nft"); err == nil || paths != nil {
				t.Fatal("unsafe wildcard match was accepted")
			}
		})
	}
}

func TestNFTPersistenceFilesystemRefusesChangesDuringRead(t *testing.T) {
	for _, kind := range []string{"replace_file", "rewrite_file", "change_mode", "replace_directory"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureNFTPersistenceFilesystem(t)
			logical := "etc/nftables.d/custom.nft"
			path := filepath.Join(root, logical)
			writeNFTPersistenceFixture(t, root, logical, "# original\n")
			host.afterRead = func() {
				var err error
				switch kind {
				case "replace_file":
					err = os.Rename(path, path+".saved")
					if err == nil {
						writeNFTPersistenceFixture(t, root, logical, "# original\n")
					}
				case "rewrite_file":
					writeNFTPersistenceFixture(t, root, logical, "# modified\n")
				case "change_mode":
					err = os.Chmod(path, 0644) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
				case "replace_directory":
					directory := filepath.Dir(path)
					err = os.Rename(directory, directory+".saved")
					if err == nil {
						err = os.Mkdir(directory, 0755) // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
					}
					if err == nil {
						writeNFTPersistenceFixture(t, root, logical, "# original\n")
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if data, err := host.read("/" + logical); err == nil || data != nil {
				t.Fatal("changed source produced a trusted snapshot")
			}
		})
	}
}

func TestNFTPersistenceFilesystemAllowsHistoricalExecutableConfigMode(t *testing.T) {
	root, host := fixtureNFTPersistenceFilesystem(t)
	writeNFTPersistenceFixture(t, root, "etc/nftables.conf", "#!/usr/sbin/nft -f\n")
	if err := os.Chmod(filepath.Join(root, "etc/nftables.conf"), 0755); err != nil { // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
		t.Fatal(err)
	}
	if _, err := host.read("/etc/nftables.conf"); err != nil {
		t.Fatal("the exact historical executable configuration mode must remain readable:", err)
	}
}

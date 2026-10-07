//go:build linux

package system

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func operatorRetirementFixture(t *testing.T, keep bool) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "configuration")
	for _, relative := range []string{"config/modules", "lists", "tls"} {
		if err := os.MkdirAll(filepath.Join(root, relative), 0750); err != nil {
			t.Fatal(err)
		}
	}
	user := filepath.Join(root, "config/modules/99-user.toml")
	if keep {
		if err := os.WriteFile(user, []byte("# Administrator settings\n[core]\nfirewall_backend = \"keep\"\n"), 0640); err != nil { // #nosec G306 -- verifies the documented group-readable operator configuration mode.
			t.Fatal(err)
		}
	}
	return root, user
}

func TestOperatorConfigurationFinalizationPreservesBytesAndOriginalInode(t *testing.T) {
	root, user := operatorRetirementFixture(t, true)
	before, err := os.Stat(user)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(user) // #nosec G304 -- user is a fixed fixture path created below t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := finalizeRetainedOperatorConfigurationAt(root, systemTestUID(t), systemTestGID(t), nil); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(user)
		got, readErr := os.ReadFile(user) // #nosec G304 -- user is a fixed fixture path created below t.TempDir.
		if err != nil || readErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !bytes.Equal(got, content) {
			t.Fatal("operator configuration changed", err, readErr)
		}
		if err := attestRuntimeRetirementRoot(root, "/etc/syswarden", systemTestUID(t), systemTestGID(t), nil); err != nil {
			t.Fatal("native erase did not recognize the retained operator surface", err)
		}
	}
	for _, relative := range []string{"lists", "tls"} {
		if _, err := os.Lstat(filepath.Join(root, relative)); !os.IsNotExist(err) {
			t.Fatal("empty known directory remained", relative, err)
		}
	}
}

func TestOperatorConfigurationFinalizationRemovesOnlyEmptySkeleton(t *testing.T) {
	root, _ := operatorRetirementFixture(t, false)
	for attempt := 0; attempt < 2; attempt++ {
		if err := finalizeRetainedOperatorConfigurationAt(root, systemTestUID(t), systemTestGID(t), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(root); !os.IsNotExist(err) {
			t.Fatal("empty skeleton remained", err)
		}
	}
}

func TestOperatorConfigurationFinalizationRefusesUnknownOrUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"module", "list", "directory", "symlink", "hardlink", "mode", "race"} {
		t.Run(kind, func(t *testing.T) {
			root, user := operatorRetirementFixture(t, true)
			unknown := filepath.Join(root, "config/modules/75-custom.toml")
			var hook func()
			change := func() {
				if err := os.WriteFile(unknown, []byte("unclassified settings\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "module":
				change()
			case "list":
				unknown = filepath.Join(root, "lists/whitelist.txt")
				change()
			case "directory":
				if err := os.Mkdir(filepath.Join(root, "administrator"), 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(user, unknown); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(unknown, user); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(user, filepath.Join(filepath.Dir(root), "outside")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(user, 0666); err != nil { // #nosec G302 -- deliberately unsafe fixture verifies refusal without mutation.
					t.Fatal(err)
				}
			case "race":
				hook = change
			}
			before, err := os.ReadFile(user) // #nosec G304 -- user is a fixed fixture path created below t.TempDir.
			if err != nil {
				t.Fatal(err)
			}
			if err := finalizeRetainedOperatorConfigurationAt(root, systemTestUID(t), systemTestGID(t), hook); err == nil {
				t.Fatal("ambiguous configuration accepted")
			}
			after, err := os.ReadFile(user) // #nosec G304 -- user is a fixed fixture path created below t.TempDir.
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("operator bytes changed on refusal", err)
			}
			for _, relative := range []string{"lists", "tls", "config/modules"} {
				if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
					t.Fatal("mutation preceded inventory refusal", err)
				}
			}
		})
	}
}

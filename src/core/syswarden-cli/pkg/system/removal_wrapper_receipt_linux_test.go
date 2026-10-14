//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyWrapperReceiptRetirementPreservesUnresolvedEvidence(t *testing.T) {
	for _, kind := range []string{"empty", "owned", "pending", "legacy", "modified", "mode", "symlink", "hardlink", "guard"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			root := feedOriginTestRoot(t, directory)
			name := "firewall-wrappers.state"
			path := filepath.Join(directory, name)
			content := FirewallWrapperStateVersion + "\n"
			switch kind {
			case "owned", "pending":
				content += "firewalld\tport\t2222\tpublic\t" + kind + "\n"
			case "legacy":
				content = "syswarden-firewall-wrappers-v2\n"
			case "modified":
				content += "# administrator modification\n"
			}
			if err := root.WriteFile(name, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			outside := "administrator"
			var err error
			switch kind {
			case "mode":
				err = root.Chmod(name, 0640)
			case "hardlink":
				err = root.Link(name, outside)
			case "symlink":
				if err = root.Rename(name, outside); err == nil {
					err = root.Symlink(outside, name)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			guard := func() error {
				if kind == "guard" {
					return errors.New("product services were not stopped")
				}
				return nil
			}
			err = removeEmptyFirewallWrapperState(path, guard)
			if kind == "empty" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("empty receipt remains", err)
				}
				if err := removeEmptyFirewallWrapperState(path, guard); err != nil {
					t.Fatal("completed retirement is not resumable", err)
				}
			} else {
				if err == nil {
					t.Fatal("unresolved or unsafe receipt was accepted")
				}
				got, err := root.ReadFile(name)
				if err != nil || string(got) != content {
					t.Fatal("refusal changed original ownership evidence", err)
				}
			}
		})
	}
}

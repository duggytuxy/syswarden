package config

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type editOwnershipInfo struct {
	os.FileInfo
	stat any
}

func (info editOwnershipInfo) Sys() any { return info.stat }

func changedEditOwner(t *testing.T, original os.FileInfo, group bool) os.FileInfo {
	t.Helper()
	raw, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture stat unavailable")
	}
	changed := *raw
	if group {
		changed.Gid ^= 1
	} else {
		changed.Uid ^= 1
	}
	return editOwnershipInfo{FileInfo: original, stat: &changed}
}

func TestModuleEditOwnershipBindsEveryOriginalInput(t *testing.T) {
	for _, target := range []string{"root", "modules", "master", "user", "other", "unknown_metadata"} {
		t.Run(target, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			snapshot, _, err := captureModuleEdit(root, userTOMLTarget())
			if err != nil {
				t.Fatal(err)
			}
			if err := snapshot.requireEditOwnership(os.Geteuid()); err != nil {
				t.Fatal(err)
			}
			switch target {
			case "root":
				snapshot.configRootInfo = changedEditOwner(t, snapshot.configRootInfo, false)
			case "modules":
				snapshot.modulesRootInfo = changedEditOwner(t, snapshot.modulesRootInfo, false)
			case "master":
				snapshot.master.info = changedEditOwner(t, snapshot.master.info, false)
			case "user":
				snapshot.user.info = changedEditOwner(t, snapshot.user.info, false)
			case "other":
				snapshot.modules["40-integrations.toml"].info = changedEditOwner(t, snapshot.modules["40-integrations.toml"].info, false)
			case "unknown_metadata":
				snapshot.configRootInfo = editOwnershipInfo{FileInfo: snapshot.configRootInfo, stat: nil}
			}
			if err := snapshot.requireEditOwnership(os.Geteuid()); err == nil {
				t.Fatal("foreign or unknown ownership granted edit authority")
			}
		})
	}
}

func TestModuleDirectoryCASRejectsOwnerAndGroupChanges(t *testing.T) {
	root, _ := initializedUserModule(t)
	edit, err := BeginUserModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	original := edit.state.snapshot.configRootInfo
	for _, group := range []bool{false, true} {
		changed := changedEditOwner(t, original, group)
		if sameFileAndMode(original, changed) {
			t.Fatal("directory ownership change passed compare-and-swap")
		}
	}
	if !sameFileAndMode(original, original) {
		t.Fatal("unchanged directory rejected")
	}
}

func TestModuleEditOwnerRefusalDoesNotChangeLiveConfiguration(t *testing.T) {
	root, edit, before, info := proposalFixture(t)
	otherUID := os.Geteuid() ^ 1
	if err := edit.state.snapshot.requireEditOwnership(otherUID); err == nil {
		t.Fatal("another operator acquired edit authority")
	}
	assertUserUnchanged(t, root, before, info)
}

func TestModuleEditRefusesUnsupportedRecoveryMetadataBeforeApproval(t *testing.T) {
	for _, fault := range []string{"hardlink", "readonly", "executable"} {
		t.Run(fault, func(t *testing.T) {
			root, path := initializedUserModule(t)
			switch fault {
			case "hardlink":
				if err := os.Link(path, filepath.Join(root, "retained-user-link")); err != nil {
					t.Fatal(err)
				}
			case "readonly":
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
			case "executable":
				if err := os.Chmod(path, 0700); err != nil { // #nosec G302 -- Deliberately create an executable test TOML file to verify pre-approval refusal without changing its mode.
					t.Fatal(err)
				}
			}
			edit, err := BeginUserModuleEdit(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			before := intentFixtureFiles(t, root)
			if _, err := edit.Prepare(context.Background(), []byte("[user]\nprofile_name='Reviewed'\n")); err == nil {
				t.Fatal("unsupported input acquired approval")
			}
			after := intentFixtureFiles(t, root)
			if len(before) != len(after) {
				t.Fatal("refusal created recovery or staging data")
			}
			for path, raw := range before {
				if after[path] != raw {
					t.Fatal("refusal rewrote input")
				}
			}
		})
	}
}

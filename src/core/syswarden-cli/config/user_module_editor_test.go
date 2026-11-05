package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUserModuleEditorUsesPrivateCopyAndPreservesLiveFileUntilApproval(t *testing.T) {
	root, edit, before, info := proposalFixture(t)
	var stage string
	p, err := edit.PrepareWithEditor(context.Background(), func(path string) error {
		stage = path
		if path == filepath.Join(root, "modules", userModuleName) {
			t.Fatal("editor received live path")
		}
		directory, err := os.Stat(filepath.Dir(path))
		if err != nil {
			return err
		}
		file, err := os.Stat(path)
		if err != nil {
			return err
		}
		if directory.Mode().Perm() != 0700 || file.Mode().Perm() != 0600 {
			t.Fatal("private editor permissions are not restrictive")
		}
		contents, err := readSecureFileByPathBounded(path, maximumUserModuleSize)
		if err != nil {
			return err
		}
		if !bytes.Equal(contents, before) {
			t.Fatal("editor copy differs from captured user file")
		}
		return writeSecureFileAtomically(filepath.Dir(path), userModuleName, []byte("[user]\nprofile_name='Edited'\n"))
	})
	if err != nil {
		t.Fatal(err)
	}
	assertUserUnchanged(t, root, before, info)
	if _, err := os.Lstat(filepath.Dir(stage)); !os.IsNotExist(err) {
		t.Fatalf("private staging not removed: %v", err)
	}
	if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(root, "modules", userModuleName), "[user]\nprofile_name='Edited'\n")
}

func TestUserModuleEditorFailureNeverPublishes(t *testing.T) {
	for _, mutation := range []string{"editor_error", "invalid_toml", "symlink", "oversized", "unsafe_mode", "cancelled", "concurrent_live"} {
		t.Run(mutation, func(t *testing.T) {
			root, edit, before, info := proposalFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stage string
			_, err := edit.PrepareWithEditor(ctx, func(path string) error {
				stage = path
				switch mutation {
				case "editor_error":
					return errors.New("editor failed")
				case "invalid_toml":
					return writeSecureFileAtomically(filepath.Dir(path), userModuleName, []byte("[invalid\n"))
				case "oversized":
					return writeSecureFileAtomically(filepath.Dir(path), userModuleName, bytes.Repeat([]byte("x"), int(maximumUserModuleSize)+1))
				case "unsafe_mode":
					return os.Chmod(path, 0644) // #nosec G302 -- deliberate unsafe mode on the synthetic private editor copy; publication must refuse it
				case "cancelled":
					cancel()
					return nil
				case "concurrent_live":
					return writeSecureFileAtomically(filepath.Join(root, "modules"), userModuleName, []byte("# preserve concurrent edit\n"))
				case "symlink":
					if err := os.Remove(path); err != nil {
						return err
					}
					return os.Symlink(filepath.Join(root, "modules", userModuleName), path)
				}
				return nil
			})
			if err == nil {
				t.Fatal("unsafe editor result accepted")
			}
			if mutation == "concurrent_live" {
				assertFileContent(t, filepath.Join(root, "modules", userModuleName), "# preserve concurrent edit\n")
			} else {
				assertUserUnchanged(t, root, before, info)
			}
			if _, err := os.Lstat(filepath.Dir(stage)); !os.IsNotExist(err) {
				t.Fatalf("private working directory left after refusal: %v", err)
			}
		})
	}
}

func TestUserModuleEditorPreservesUnexpectedRecoveryFiles(t *testing.T) {
	root, edit, before, info := proposalFixture(t)
	var directory string
	_, err := edit.PrepareWithEditor(context.Background(), func(path string) error {
		directory = filepath.Dir(path)
		return writeSecureFileAtomically(directory, "editor-recovery", []byte("private recovery bytes\n"))
	})
	if err == nil {
		t.Fatal("unexpected recovery file silently removed or ignored")
	}
	assertUserUnchanged(t, root, before, info)
	assertFileContent(t, filepath.Join(directory, "editor-recovery"), "private recovery bytes\n")
	// These exact synthetic files belong to this test, not to an operator editor.
	if err := os.Remove(filepath.Join(directory, "editor-recovery")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
}

func TestUserModuleImportAndProfileOnlyPrepareValidatedProposal(t *testing.T) {
	for _, operation := range []string{"profile", "import"} {
		t.Run(operation, func(t *testing.T) {
			root, edit, before, info := proposalFixture(t)
			var p *UserModuleProposal
			var err error
			if operation == "profile" {
				p, err = edit.PrepareProfileName(context.Background(), "Reviewed")
			} else {
				source := t.TempDir()
				if err := writeSecureFileAtomically(source, "import.toml", []byte("[user]\nprofile_name='Reviewed'\n")); err != nil {
					t.Fatal(err)
				}
				p, err = edit.PrepareImport(context.Background(), filepath.Join(source, "import.toml"))
			}
			if err != nil {
				t.Fatal(err)
			}
			assertUserUnchanged(t, root, before, info)
			if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			value, found, err := GetValidatedModularValue(root, "user.profile_name")
			if err != nil || !found || value != "Reviewed" {
				t.Fatalf("published profile=%q found=%v err=%v", value, found, err)
			}
		})
	}
}

func TestUserModuleProfilePreservesSimilarlyNamedAdministratorKeys(t *testing.T) {
	root, path := initializedUserModule(t)
	const original = "[user]\nprofile_name = 'Original'\nprofile_name_backup = 'retain exactly'\nprofile_name_suffix = 42\n"
	if err := writeSecureFileAtomically(filepath.Dir(path), userModuleName, []byte(original)); err != nil {
		t.Fatal(err)
	}
	edit, err := BeginUserModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := edit.PrepareProfileName(context.Background(), "Reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if err := proposal.Publish(context.Background(), proposal.Review().ApprovalID, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, path, "[user]\nprofile_name = \"Reviewed\"\nprofile_name_backup = 'retain exactly'\nprofile_name_suffix = 42\n")
}

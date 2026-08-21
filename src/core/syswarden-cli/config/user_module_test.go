package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func initializedUserModule(t *testing.T) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(root, "modules", userModuleName)
}

func TestValidatedUserModuleRejectsInvalidCandidateWithoutChangingInode_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	before, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(userPath) // #nosec G304 -- userPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	invalid := []byte("[core]\nssh_port = \"70000\"\n")
	if err := WriteValidatedUserModule(root, invalid); err == nil {
		t.Fatal("invalid merged user configuration was accepted")
	}
	after, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("failed validation replaced the operator inode")
	}
	assertFileContent(t, userPath, string(content))
}

func TestValidatedUserModulePublishFailureLeavesOldInodeAndContent_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	before, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(userPath) // #nosec G304 -- userPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	previous := publishValidatedUserModule
	publishValidatedUserModule = func(string, string, []byte, *secureFileIdentity, func() error, func() error, func() error) error {
		return errors.New("injected atomic publish failure")
	}
	t.Cleanup(func() { publishValidatedUserModule = previous })
	err = WriteValidatedUserModule(root, []byte("[user]\nprofile_name = \"replacement\"\n"))
	if err == nil || !strings.Contains(err.Error(), "injected atomic publish failure") {
		t.Fatalf("publish error = %v", err)
	}
	after, statErr := os.Lstat(userPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !os.SameFile(before, after) {
		t.Fatal("failed publish replaced the operator inode")
	}
	assertFileContent(t, userPath, string(content))
}

func TestValidatedProfileRejectsConcurrentUserModuleMutation_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	const concurrent = "# concurrent operator update\n[user]\nprofile_name = \"must-survive\"\n"
	previous := publishValidatedUserModule
	publishValidatedUserModule = func(directory, name string, content []byte, expected *secureFileIdentity, preCommit, prePublish, postCommit func() error) error {
		if err := writeSecureFileAtomically(directory, name, []byte(concurrent)); err != nil {
			return err
		}
		return replaceSecureFileAtomicallyIfUnchangedValidated(directory, name, content, expected, preCommit, prePublish, postCommit)
	}
	t.Cleanup(func() { publishValidatedUserModule = previous })

	err := SetValidatedProfileName(root, "must_not_overwrite")
	if err == nil || !strings.Contains(err.Error(), "changed before publish") {
		t.Fatalf("concurrent profile update error = %v", err)
	}
	assertFileContent(t, userPath, concurrent)
}

func TestValidatedUserModuleCASIncludesMasterEveryReadModuleAndInventory_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name       string
		targetName string
		targetDir  func(string) string
		create     bool
	}{
		{name: "master", targetName: "config.toml", targetDir: func(root string) string { return root }},
		{name: "existing module", targetName: "40-integrations.toml", targetDir: func(root string) string { return filepath.Join(root, "modules") }},
		{name: "module inventory", targetName: "41-concurrent.toml", targetDir: func(root string) string { return filepath.Join(root, "modules") }, create: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, userPath := initializedUserModule(t)
			userBefore, err := os.Lstat(userPath)
			if err != nil {
				t.Fatal(err)
			}
			userContent, err := ReadUserModule(root)
			if err != nil {
				t.Fatal(err)
			}
			directory := test.targetDir(root)
			mutation := []byte("# concurrent module inventory change\n")
			if !test.create {
				targetRoot, openErr := os.OpenRoot(directory)
				if openErr != nil {
					t.Fatal(openErr)
				}
				original, readErr := targetRoot.ReadFile(test.targetName)
				_ = targetRoot.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				mutation = append(original, mutation...)
			}

			previous := publishValidatedUserModule
			publishValidatedUserModule = func(moduleDirectory, name string, content []byte, expected *secureFileIdentity, preCommit, prePublish, postCommit func() error) error {
				if err := writeSecureFileAtomically(directory, test.targetName, mutation); err != nil {
					return err
				}
				return replaceSecureFileAtomicallyIfUnchangedValidated(moduleDirectory, name, content, expected, preCommit, prePublish, postCommit)
			}
			t.Cleanup(func() { publishValidatedUserModule = previous })

			err = WriteValidatedUserModule(root, []byte("[user]\nprofile_name = \"candidate\"\n"))
			if err == nil || !strings.Contains(err.Error(), "configuration CAS") {
				t.Fatalf("concurrent %s mutation error = %v", test.name, err)
			}
			userAfter, statErr := os.Lstat(userPath)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if !os.SameFile(userBefore, userAfter) {
				t.Fatal("rejected merged-config mutation replaced the user-module inode")
			}
			assertFileContent(t, userPath, string(userContent))
		})
	}
}

func TestValidatedUserModuleCASIncludesMigrationMarkerThroughPublication_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name              string
		immediatelyBefore bool
	}{
		{name: "before full configuration CAS"},
		{name: "immediately before no-replace publication", immediatelyBefore: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, userPath := initializedUserModule(t)
			before, err := os.Lstat(userPath)
			if err != nil {
				t.Fatal(err)
			}
			beforeContent, err := ReadUserModule(root)
			if err != nil {
				t.Fatal(err)
			}

			previous := publishValidatedUserModule
			publishValidatedUserModule = func(
				directory, name string,
				content []byte,
				expected *secureFileIdentity,
				preCommit, prePublish, postCommit func() error,
			) error {
				publishMarker := func() error {
					return writeMissingSecureFile(root, migrationMarkerName, []byte("{}\n"))
				}
				if test.immediatelyBefore {
					originalPrePublish := prePublish
					prePublish = func() error {
						if err := publishMarker(); err != nil {
							return err
						}
						return originalPrePublish()
					}
				} else if err := publishMarker(); err != nil {
					return err
				}
				return replaceSecureFileAtomicallyIfUnchangedValidated(
					directory,
					name,
					content,
					expected,
					preCommit,
					prePublish,
					postCommit,
				)
			}
			t.Cleanup(func() { publishValidatedUserModule = previous })

			err = WriteValidatedUserModule(root, []byte("[user]\nprofile_name = \"candidate\"\n"))
			if err == nil || !strings.Contains(err.Error(), "configuration CAS") {
				t.Fatalf("migration-marker interleaving error = %v", err)
			}
			after, statErr := os.Lstat(userPath)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if !os.SameFile(before, after) {
				t.Fatal("migration-marker CAS failure did not preserve the previous operator inode")
			}
			assertFileContent(t, userPath, string(beforeContent))
			if _, err := os.Lstat(filepath.Join(root, migrationMarkerName)); err != nil {
				t.Fatalf("test migration marker disappeared: %v", err)
			}
		})
	}
}

func TestValidatedUserModuleRestoresPreviousInodeWhenMigrationWinsAfterPrePublish_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	const previousUser = "# authoritative operator state\n[user]\nprofile_name = \"must-remain-effective\"\n"
	if err := WriteValidatedUserModule(root, []byte(previousUser)); err != nil {
		t.Fatal(err)
	}
	previousInfo, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}

	migrationRoot := t.TempDir()
	source := filepath.Join(migrationRoot, "legacy.conf")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	var migrationUserInfo os.FileInfo
	previousPublisher := publishValidatedUserModule
	publishValidatedUserModule = func(
		directory, name string,
		content []byte,
		expected *secureFileIdentity,
		preCommit, prePublish, postCommit func() error,
	) error {
		originalPrePublish := prePublish
		prePublish = func() error {
			if err := originalPrePublish(); err != nil {
				return err
			}
			// The real migrator runs after the writer's final marker CAS and
			// publishes its generated no-replace user module while the previous
			// inode is quarantined. It also completes quickly enough to remove its
			// marker before the writer observes the publication conflict.
			if err := (&Migrator{SourcePath: source, OutputDir: root}).Run(); err != nil {
				return err
			}
			var err error
			migrationUserInfo, err = os.Lstat(userPath)
			return err
		}
		return replaceSecureFileAtomicallyIfUnchangedValidated(
			directory,
			name,
			content,
			expected,
			preCommit,
			prePublish,
			postCommit,
		)
	}
	t.Cleanup(func() { publishValidatedUserModule = previousPublisher })

	err = WriteValidatedUserModule(root, []byte("[user]\nprofile_name = \"candidate\"\n"))
	if err == nil || !strings.Contains(err.Error(), "publish operator module without replacement") {
		t.Fatalf("writer/migration publication conflict error = %v", err)
	}
	if migrationUserInfo == nil || os.SameFile(previousInfo, migrationUserInfo) {
		t.Fatal("test migration did not publish a competing user-module inode")
	}
	restoredInfo, statErr := os.Lstat(userPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !os.SameFile(previousInfo, restoredInfo) {
		t.Fatal("migration winner displaced the previous operator inode")
	}
	assertFileContent(t, userPath, previousUser)
	if _, err := os.Lstat(filepath.Join(root, migrationMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("completed interleaved migration left a marker: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "modules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+userModuleName+".") {
			t.Fatalf("writer/migration conflict left hidden operator state %s", entry.Name())
		}
	}
}

func TestValidatedUserModulePostCommitMutationRollsBackPublishedInode_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	modulesDir := filepath.Join(root, "modules")
	userBefore, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	userContent, err := ReadUserModule(root)
	if err != nil {
		t.Fatal(err)
	}
	modulesRoot, err := os.OpenRoot(modulesDir)
	if err != nil {
		t.Fatal(err)
	}
	integrations, err := modulesRoot.ReadFile("40-integrations.toml")
	_ = modulesRoot.Close()
	if err != nil {
		t.Fatal(err)
	}
	mutatedIntegrations := append(integrations, []byte("\n# concurrent post-commit mutation\n")...)

	previous := publishValidatedUserModule
	publishValidatedUserModule = func(directory, name string, content []byte, expected *secureFileIdentity, preCommit, prePublish, postCommit func() error) error {
		mutatingPostCommit := func() error {
			if err := writeSecureFileAtomically(directory, "40-integrations.toml", mutatedIntegrations); err != nil {
				return err
			}
			return postCommit()
		}
		return replaceSecureFileAtomicallyIfUnchangedValidated(directory, name, content, expected, preCommit, prePublish, mutatingPostCommit)
	}
	t.Cleanup(func() { publishValidatedUserModule = previous })

	err = WriteValidatedUserModule(root, []byte("[user]\nprofile_name = \"candidate\"\n"))
	if err == nil || !strings.Contains(err.Error(), "post-commit configuration CAS") {
		t.Fatalf("post-commit mutation error = %v", err)
	}
	userAfter, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(userBefore, userAfter) {
		t.Fatal("post-commit CAS failure did not restore the previous user-module inode")
	}
	assertFileContent(t, userPath, string(userContent))
}

func TestValidatedUserModuleDetectsSameBytePostCommitInodeSubstitution_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	const candidate = "[user]\nprofile_name = \"same-bytes-new-inode\"\n"
	var concurrentInfo os.FileInfo
	previous := publishValidatedUserModule
	publishValidatedUserModule = func(directory, name string, content []byte, expected *secureFileIdentity, preCommit, prePublish, postCommit func() error) error {
		mutatingPostCommit := func() error {
			if err := writeSecureFileAtomically(directory, name, content); err != nil {
				return err
			}
			var err error
			concurrentInfo, err = os.Lstat(userPath)
			if err != nil {
				return err
			}
			return postCommit()
		}
		return replaceSecureFileAtomicallyIfUnchangedValidated(directory, name, content, expected, preCommit, prePublish, mutatingPostCommit)
	}
	t.Cleanup(func() { publishValidatedUserModule = previous })

	err := WriteValidatedUserModule(root, []byte(candidate))
	if err == nil || !strings.Contains(err.Error(), "post-commit inode CAS") {
		t.Fatalf("same-byte inode substitution error = %v", err)
	}
	after, statErr := os.Lstat(userPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if concurrentInfo == nil || !os.SameFile(concurrentInfo, after) {
		t.Fatal("failed inode CAS overwrote the concurrent same-byte replacement")
	}
	assertFileContent(t, userPath, candidate)
}

func TestValidatedUserModuleRejectsDestinationAndImportSymlinks_SW_CFG_002(t *testing.T) {
	t.Run("destination", func(t *testing.T) {
		root, userPath := initializedUserModule(t)
		victim := filepath.Join(t.TempDir(), "victim.toml")
		if err := os.WriteFile(victim, []byte("preserve\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(userPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, userPath); err != nil {
			t.Fatal(err)
		}
		if err := WriteValidatedUserModule(root, []byte("[user]\nprofile_name = \"replacement\"\n")); err == nil {
			t.Fatal("symlinked user module was accepted")
		}
		assertFileContent(t, victim, "preserve\n")
	})

	t.Run("import source", func(t *testing.T) {
		root, userPath := initializedUserModule(t)
		before, err := os.ReadFile(userPath) // #nosec G304 -- userPath is rooted in t.TempDir
		if err != nil {
			t.Fatal(err)
		}
		realSource := filepath.Join(t.TempDir(), "real.toml")
		if err := os.WriteFile(realSource, []byte("[user]\nprofile_name = \"imported\"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		symlink := filepath.Join(filepath.Dir(realSource), "source-link.toml")
		if err := os.Symlink(realSource, symlink); err != nil {
			t.Fatal(err)
		}
		if err := ImportValidatedUserModule(root, symlink); err == nil {
			t.Fatal("symlinked import source was accepted")
		}
		assertFileContent(t, userPath, string(before))
	})
}

func TestValidatedProfileAndImportUseAtomicMergedValidation_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	before, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetValidatedProfileName(root, "production_1"); err != nil {
		t.Fatalf("SetValidatedProfileName() error = %v", err)
	}
	afterProfile, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, afterProfile) {
		t.Fatal("successful profile update did not atomically replace the inode")
	}
	profileContent, err := os.ReadFile(userPath) // #nosec G304 -- userPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profileContent), `profile_name = "production_1"`) {
		t.Fatalf("profile update missing from user module: %s", profileContent)
	}

	source := filepath.Join(t.TempDir(), "import.toml")
	const imported = "# imported operator bytes\n[user]\nprofile_name = \"import-profile\"\n"
	if err := os.WriteFile(source, []byte(imported), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ImportValidatedUserModule(root, source); err != nil {
		t.Fatalf("ImportValidatedUserModule() error = %v", err)
	}
	assertFileContent(t, userPath, imported)
	info, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("imported user module mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestAtomicSecureReplacementPreservesOwnerGroupAndMode_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	if err := os.Chmod(userPath, 0640); err != nil { // #nosec G302 -- deliberate fixture mode verifies exact owner/group preservation
		t.Fatal(err)
	}
	before, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	wantUID, wantGID, ok := fileOwnerUIDGID(before)
	if !ok {
		t.Fatal("file ownership is unavailable")
	}

	if err := SetValidatedProfileName(root, "ownership"); err != nil {
		t.Fatalf("SetValidatedProfileName() error = %v", err)
	}
	after, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	gotUID, gotGID, ok := fileOwnerUIDGID(after)
	if !ok {
		t.Fatal("replacement ownership is unavailable")
	}
	if gotUID != wantUID || gotGID != wantGID || after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("replacement identity = uid %d gid %d mode %#o, want uid %d gid %d mode %#o", gotUID, gotGID, after.Mode().Perm(), wantUID, wantGID, before.Mode().Perm())
	}
}

func TestAtomicSecureReplacementFailsClosedWhenOwnershipCannotBePreserved_SW_CFG_002(t *testing.T) {
	root, userPath := initializedUserModule(t)
	before, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeContent, err := os.ReadFile(userPath) // #nosec G304 -- userPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}

	original := applySecureFileOwnership
	applySecureFileOwnership = func(*os.File, int, int) error { return errors.New("injected ownership failure") }
	t.Cleanup(func() { applySecureFileOwnership = original })
	if err := SetValidatedProfileName(root, "rejected"); err == nil || !strings.Contains(err.Error(), "preserve existing secure file ownership") {
		t.Fatalf("SetValidatedProfileName() error = %v, want ownership failure", err)
	}
	after, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("ownership failure replaced the destination inode")
	}
	afterContent, err := os.ReadFile(userPath) // #nosec G304 -- userPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(afterContent) != string(beforeContent) {
		t.Fatal("ownership failure changed the destination content")
	}
}

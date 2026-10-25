package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var ordinaryEditTargets = []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml", "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml"}

func TestOrdinaryModuleCandidatePublishesOnlyTheReviewedTarget(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			original := edit.Content()
			candidate := append(bytes.Clone(original), []byte("\n# reviewed candidate\n")...)
			p, err := edit.Prepare(context.Background(), candidate)
			if err != nil {
				t.Fatal(err)
			}
			if p.Review().Target != relative {
				t.Fatalf("reviewed target=%q", p.Review().Target)
			}
			if err := edit.state.snapshot.revalidate(root, false, nil); err != nil {
				t.Fatal("preparation changed live configuration:", err)
			}
			if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := edit.state.snapshot.revalidateTarget(root, edit.state.target, candidate); err != nil {
				t.Fatal("publication changed unrelated configuration:", err)
			}
			if _, err := ValidateModularConfig(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOrdinaryModuleCandidateRepairsInvalidTargetWithoutLiveInvalidEdit(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			target, err := ordinaryTOMLTarget(relative)
			if err != nil {
				t.Fatal(err)
			}
			original, err := readSecureFileByPathBounded(filepath.Join(root, relative), maximumUserModuleSize)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSecureFileAtomically(target.directory(root), target.name, []byte("[broken\n")); err != nil {
				t.Fatal(err)
			}
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			p, err := edit.Prepare(context.Background(), original)
			if err != nil {
				t.Fatal(err)
			}
			assertFileContent(t, filepath.Join(root, relative), "[broken\n")
			if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			assertFileContent(t, filepath.Join(root, relative), string(original))
		})
	}
}

func TestOrdinaryModuleCandidateRejectsEveryStaleTargetAndRetainsConcurrentBytes(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			p, err := edit.Prepare(context.Background(), append(edit.Content(), []byte("\n# reviewed\n")...))
			if err != nil {
				t.Fatal(err)
			}
			target := edit.state.target
			if err := writeSecureFileAtomically(target.directory(root), target.name, []byte("# concurrent administrator bytes\n")); err != nil {
				t.Fatal(err)
			}
			if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err == nil {
				t.Fatal("stale target was overwritten")
			}
			assertFileContent(t, filepath.Join(root, relative), "# concurrent administrator bytes\n")
		})
	}
}

func TestOrdinaryModuleCandidateRestoresOriginalInodeAfterLateRefusal(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(filepath.Join(root, relative))
			if err != nil {
				t.Fatal(err)
			}
			candidate := append(edit.Content(), []byte("\n# late-refusal-candidate\n")...)
			p, err := edit.Prepare(context.Background(), candidate)
			if err != nil {
				t.Fatal(err)
			}
			guard := func() error {
				current, err := readSecureFileByPathBounded(filepath.Join(root, relative), maximumUserModuleSize)
				if err != nil {
					return err
				}
				if bytes.Equal(current, candidate) {
					return errors.New("pending lifecycle recovery")
				}
				return nil
			}
			if err := p.Publish(context.Background(), p.Review().ApprovalID, guard); err == nil {
				t.Fatal("late refusal accepted")
			}
			after, err := os.Lstat(filepath.Join(root, relative))
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) {
				t.Fatal("original inode not restored")
			}
			if err := edit.state.snapshot.revalidate(root, false, nil); err != nil {
				t.Fatal("refused publication changed configuration:", err)
			}
		})
	}
}

func TestOrdinaryModuleEditorRejectsUnsupportedAndDedicatedTargets(t *testing.T) {
	root, _ := initializedUserModule(t)
	for _, target := range []string{"", "../config.toml", "/etc/ssh/sshd_config", "modules/../config.toml", "modules/05-ssh.toml", "modules/98-arbitrary.toml", "modules/99-user.toml/child", "modules\\99-user.toml"} {
		if _, err := BeginModuleEdit(context.Background(), root, target); err == nil {
			t.Fatalf("unsupported target accepted: %q", target)
		}
	}
}

func TestOrdinaryModuleCannotImportOrRenameUserProfileThroughAnotherTarget(t *testing.T) {
	root, _ := initializedUserModule(t)
	edit, err := BeginModuleEdit(context.Background(), root, "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edit.PrepareProfileName(context.Background(), "WrongTarget"); err == nil {
		t.Fatal("profile helper selected another target")
	}
	if _, err := edit.PrepareImport(context.Background(), filepath.Join(root, "modules", userModuleName)); err == nil {
		t.Fatal("import helper selected another target")
	}
}

func TestOrdinaryModuleCandidateCannotCreateMissingFreshInventory(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			before, err := readSecureFileByPathBounded(filepath.Join(root, relative), maximumUserModuleSize)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, relative)); err != nil {
				t.Fatal(err)
			}
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := edit.Prepare(context.Background(), before); err == nil {
				t.Fatal("candidate erased incomplete fresh-install barrier")
			}
			if _, err := os.Lstat(filepath.Join(root, relative)); !os.IsNotExist(err) {
				t.Fatal("missing file was published")
			}
		})
	}
}

func TestOrdinaryModuleCandidateKeepsLexicalOverridesAndHistoricalMissingFileRules(t *testing.T) {
	root := historicalOrdinaryEditRoot(t)
	userPath := filepath.Join(root, "modules", userModuleName)
	if err := os.Remove(userPath); err != nil {
		t.Fatal(err)
	}
	if err := writeSecureFileAtomically(filepath.Dir(userPath), "zz-admin.toml", []byte("[network.blocklists]\nlist_choice='2'\n")); err != nil {
		t.Fatal(err)
	}
	edit, err := BeginUserModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	p, err := edit.Prepare(context.Background(), []byte("[network.blocklists]\nlist_choice='1'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Review().ModulePlan, "\n"), "Threat list choice: 2") {
		t.Fatal("preview merged a new user module after a later administrator override")
	}
	if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	value, found, err := GetValidatedModularValue(root, "network.blocklists.list_choice")
	if err != nil || !found || value != "2" {
		t.Fatalf("effective choice=%q found=%v err=%v", value, found, err)
	}
}

func TestOrdinaryModuleCandidateCannotAddRetiredWhitelistInAnyTarget(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			content := edit.Content()
			if bytes.Contains(content, []byte("whitelist_ips =")) {
				lines := strings.Split(string(content), "\n")
				for i, line := range lines {
					if strings.HasPrefix(strings.TrimSpace(line), "whitelist_ips =") {
						lines[i] = `whitelist_ips = ["0.0.0.0"]`
					}
				}
				content = []byte(strings.Join(lines, "\n"))
			} else {
				content = append(content, []byte("\n[network]\nwhitelist_ips=['0.0.0.0']\n")...)
			}
			if _, err := edit.Prepare(context.Background(), content); err == nil {
				t.Fatal("retired whitelist value added")
			}
			if err := edit.state.snapshot.revalidate(root, false, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func historicalOrdinaryEditRoot(t *testing.T) string {
	t.Helper()
	root, _ := initializedUserModule(t)
	for _, relative := range []string{"config.toml", "modules/00-core.toml"} {
		target, err := ordinaryTOMLTarget(relative)
		if err != nil {
			t.Fatal(err)
		}
		content, err := readSecureFileByPathBounded(filepath.Join(root, relative), maximumUserModuleSize)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "install_profile =") {
				lines[i] = "install_profile = ''"
			}
		}
		if err := writeSecureFileAtomically(target.directory(root), target.name, []byte(strings.Join(lines, "\n"))); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestOrdinaryModuleCandidateCreatesOnlyExplicitMissingHistoricalTarget(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root := historicalOrdinaryEditRoot(t)
			original, err := readSecureFileByPathBounded(filepath.Join(root, relative), maximumUserModuleSize)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, relative)); err != nil {
				t.Fatal(err)
			}
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			if len(edit.Content()) != 0 {
				t.Fatal("absent file gained implicit defaults")
			}
			p, err := edit.Prepare(context.Background(), original)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := edit.state.snapshot.revalidateTarget(root, edit.state.target, original); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateModularConfig(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOrdinaryModuleLateConcurrentOtherFileIsRetainedDuringRollback(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			original := edit.Content()
			p, err := edit.Prepare(context.Background(), append(bytes.Clone(original), []byte("\n# reviewed-late\n")...))
			if err != nil {
				t.Fatal(err)
			}
			other := userTOMLTarget()
			if other.relative == relative {
				other, _ = ordinaryTOMLTarget("config.toml")
			}
			changed := false
			guard := func() error {
				current, err := readSecureFileByPathBounded(filepath.Join(root, relative), maximumUserModuleSize)
				if err != nil {
					return err
				}
				if !changed && bytes.HasSuffix(current, []byte("# reviewed-late\n")) {
					changed = true
					return writeSecureFileAtomically(other.directory(root), other.name, []byte("# independent administrator update\n"))
				}
				return nil
			}
			if err := p.Publish(context.Background(), p.Review().ApprovalID, guard); err == nil {
				t.Fatal("concurrent file bypassed snapshot revalidation")
			}
			if !changed {
				t.Fatal("late concurrent update was not exercised")
			}
			assertFileContent(t, filepath.Join(root, relative), string(original))
			assertFileContent(t, filepath.Join(root, other.relative), "# independent administrator update\n")
		})
	}
}

func TestOrdinaryModuleCaptureAndPrivateEditAreSizeBounded(t *testing.T) {
	for _, relative := range ordinaryEditTargets {
		t.Run(relative, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			edit, err := BeginModuleEdit(context.Background(), root, relative)
			if err != nil {
				t.Fatal(err)
			}
			oversized := bytes.Repeat([]byte("x"), int(maximumUserModuleSize)+1)
			_, err = edit.PrepareWithEditor(context.Background(), func(path string) error {
				return writeSecureFileAtomically(filepath.Dir(path), filepath.Base(path), oversized)
			})
			if err == nil {
				t.Fatal("oversized private editor result accepted")
			}
			if err := edit.state.snapshot.revalidate(root, false, nil); err != nil {
				t.Fatal(err)
			}
			target := edit.state.target
			if err := writeSecureFileAtomically(target.directory(root), target.name, oversized); err != nil {
				t.Fatal(err)
			}
			if _, err := BeginModuleEdit(context.Background(), root, relative); err == nil {
				t.Fatal("oversized original configuration captured")
			}
		})
	}
}

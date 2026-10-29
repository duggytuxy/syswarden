package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUnconfiguredPublicationMissingFilesNeverBecomeUsable(t *testing.T) {
	for _, missing := range []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml", "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml"} {
		t.Run(missing, func(t *testing.T) {
			preserveOperatorPolicyGlobals(t)
			root := filepath.Join(t.TempDir(), "config")
			if err := EnsureDefaults(root); err != nil {
				t.Fatal(err)
			}
			if err := ParseConfig(root); err != nil {
				t.Fatal(err)
			}
			before := GlobalConfig
			if err := os.Remove(filepath.Join(root, missing)); err != nil {
				t.Fatal(err)
			}
			files := directoryDigest(t, root)
			for _, load := range []func() error{
				func() error { _, err := ValidateModularConfig(root); return err },
				func() error { _, _, err := GetValidatedModularValue(root, "core.install_profile"); return err },
				func() error { return ParseConfig(root) },
			} {
				if err := load(); err == nil || !strings.Contains(err.Error(), "incomplete unconfigured-v1 publication") {
					t.Fatal("incomplete profile was usable", err)
				}
				if GlobalConfig != before {
					t.Fatal("incomplete profile replaced validated configuration")
				}
				if got := directoryDigest(t, root); !reflect.DeepEqual(got, files) {
					t.Fatal("validation changed partial files")
				}
			}
			if !CurrentLoadState().Degraded {
				t.Fatal("partial runtime load did not degrade state")
			}
		})
	}
}

func TestUnpublishedUnconfiguredProfileResumesBeforeItCanBeLoaded(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	root := filepath.Join(t.TempDir(), "config")
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	complete := directoryDigest(t, root)
	for _, name := range []string{"config.toml", "modules/10-network.toml", "modules/99-user.toml"} {
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ValidateModularConfig(root); err == nil {
		t.Fatal("unpublished partial configuration accepted")
	}
	if err := EnsureDefaults(root); err != nil {
		t.Fatal("exact fresh retry refused", err)
	}
	if got := directoryDigest(t, root); !reflect.DeepEqual(got, complete) {
		t.Fatal("retry changed exact defaults")
	}
	if _, err := ValidateModularConfig(root); err != nil {
		t.Fatal(err)
	}
	if err := ParseConfig(root); err != nil {
		t.Fatal(err)
	}
}

func TestUnconfiguredPublicationRejectsUnsafeReplacementAndProfileShadowing(t *testing.T) {
	for _, mutation := range []string{"symlink", "directory", "missing-marker", "truncated", "shadow-standard", "shadow-historical"} {
		t.Run(mutation, func(t *testing.T) {
			preserveOperatorPolicyGlobals(t)
			root := filepath.Join(t.TempDir(), "config")
			if err := EnsureDefaults(root); err != nil {
				t.Fatal(err)
			}
			core := filepath.Join(root, "modules/00-core.toml")
			switch mutation {
			case "symlink":
				if err := os.Remove(core); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "config.toml"), core); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(core); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(core, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing-marker", "truncated":
				content := "[core]\nlog_level='INFO'\n"
				if mutation == "truncated" {
					content = "[core\n"
				}
				if err := os.WriteFile(core, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				profile := StandardInstallProfile
				if mutation == "shadow-historical" {
					profile = ""
				}
				if err := os.WriteFile(filepath.Join(root, "modules/99-user.toml"), []byte("[core]\ninstall_profile='"+profile+"'\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, load := range []func() error{
				func() error { _, err := ValidateModularConfig(root); return err },
				func() error { _, _, err := GetValidatedModularValue(root, "core.install_profile"); return err },
				func() error { return ParseConfig(root) },
			} {
				if err := load(); err == nil {
					t.Fatal("unsafe or contradictory publication accepted")
				}
			}
		})
	}
}

func TestUnconfiguredPublicationRetainsCompleteAdministratorPolicyAndHistoricalMasters(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	root := filepath.Join(t.TempDir(), "config")
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	override := "[network.blocklists]\nlist_choice='2'\n[waap]\nenabled=true\n"
	if err := os.WriteFile(filepath.Join(root, "modules/99-user.toml"), []byte(override), 0600); err != nil {
		t.Fatal(err)
	}
	before := directoryDigest(t, root)
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateModularConfig(root); err != nil {
		t.Fatal(err)
	}
	if err := ParseConfig(root); err != nil {
		t.Fatal(err)
	}
	if GlobalConfig.ListChoice != "2" || !GlobalConfig.WAAPEnabled {
		t.Fatal("explicit policy lost")
	}
	if got := directoryDigest(t, root); !reflect.DeepEqual(got, before) {
		t.Fatal("administrator policy rewritten")
	}
	for _, profile := range []string{"", StandardInstallProfile} {
		models, err := (&Migrator{OutputDir: root}).masterConfigContent(map[string]string{"SYSWARDEN_INSTALL_PROFILE": profile})
		if err != nil || strings.Contains(models, "install_profile") {
			t.Fatal("historical master bytes gained publication marker", profile, err)
		}
	}
}

func TestUserPublicationUsesTheSameModuleConsentAndCompletenessGuards(t *testing.T) {
	for _, scenario := range []string{"bridge-without-waap", "environment-module", "environment-list", "profile-shadow", "missing-master", "missing-network", "missing-user"} {
		t.Run(scenario, func(t *testing.T) {
			root, userPath := initializedUserModule(t)
			content := []byte("[user]\nprofile_name='candidate'\n")
			switch scenario {
			case "bridge-without-waap":
				content = []byte("[waap]\nenabled=false\nlog_bridge_enabled=true\n")
			case "environment-module":
				t.Setenv("SYSWARDEN_WAAP_ENABLED", "true")
			case "environment-list":
				t.Setenv("SYSWARDEN_NETWORK_BLOCKLISTS_LIST_CHOICE", "1")
			case "profile-shadow":
				content = []byte("[core]\ninstall_profile='standard-v1'\n")
			case "missing-master", "missing-network", "missing-user":
				name := "config.toml"
				if scenario == "missing-network" {
					name = "modules/10-network.toml"
				}
				if scenario == "missing-user" {
					name = "modules/99-user.toml"
				}
				if err := os.Remove(filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
			}
			before := directoryDigest(t, root)
			inode, err := os.Lstat(userPath)
			if err != nil && scenario != "missing-user" {
				t.Fatal(err)
			}
			if err := WriteValidatedUserModule(root, content); err == nil {
				t.Fatal("invalid candidate published")
			}
			if got := directoryDigest(t, root); !reflect.DeepEqual(got, before) {
				t.Fatal("rejected candidate changed bytes or inventory")
			}
			if inode != nil {
				after, err := os.Lstat(userPath)
				if err != nil || !os.SameFile(inode, after) {
					t.Fatal("rejected candidate replaced user inode", err)
				}
			}
		})
	}
}

func TestNewUserModuleCannotIntroduceUnpublishedUnconfiguredProfile(t *testing.T) {
	for _, profile := range []string{"", StandardInstallProfile} {
		t.Run("historical-"+profile, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := os.MkdirAll(filepath.Join(root, "modules"), 0750); err != nil {
				t.Fatal(err)
			}
			models, err := defaultModularFileModels(root, true)
			if err != nil {
				t.Fatal(err)
			}
			for name, content := range models {
				if name == "modules/99-user.toml" {
					continue
				}
				if profile == "" && name == "modules/00-core.toml" {
					content = strings.ReplaceAll(content, StandardInstallProfile, "")
				}
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ValidateModularConfig(root); err != nil {
				t.Fatal("historical starting layout is invalid", err)
			}
			before := directoryDigest(t, root)
			candidate := []byte("[core]\ninstall_profile='unconfigured-v1'\n")
			if err := WriteValidatedUserModule(root, candidate); err == nil {
				t.Fatal("new user module introduced an unpublished profile")
			}
			if got := directoryDigest(t, root); !reflect.DeepEqual(got, before) {
				t.Fatal("refused profile conversion changed existing files")
			}
			if _, err := os.Lstat(filepath.Join(root, "modules/99-user.toml")); !os.IsNotExist(err) {
				t.Fatal("refused profile conversion published the new user file", err)
			}
		})
	}
}

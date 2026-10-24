package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIncompleteInstalledPolicyIsNotReplacedByFreshDefaults(t *testing.T) {
	for _, scenario := range []string{"user-only", "extra-module-only", "missing-network", "missing-user", "partial-with-user", "partial-with-extra"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := EnsureDefaults(root); err != nil {
				t.Fatal(err)
			}
			files, err := DefaultModularFileModels(root)
			if err != nil {
				t.Fatal(err)
			}
			for relative := range files {
				remove := false
				switch scenario {
				case "user-only", "extra-module-only":
					remove = true
				case "missing-network":
					remove = relative == "modules/10-network.toml"
				case "missing-user":
					remove = relative == "modules/99-user.toml"
				case "partial-with-user", "partial-with-extra":
					remove = relative == "config.toml" || relative == "modules/10-network.toml"
				}
				if remove {
					if err := os.Remove(filepath.Join(root, relative)); err != nil {
						t.Fatal(err)
					}
				}
			}
			name := "modules/99-user.toml"
			if strings.Contains(scenario, "extra") {
				name = "modules/98-local.toml"
			}
			if scenario != "missing-user" {
				if err := os.WriteFile(filepath.Join(root, name), []byte("[network.geo]\nenabled=true\nallowed_countries=[\"fr\"]\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := directoryDigest(t, root)
			for attempt := 0; attempt < 2; attempt++ {
				if err := EnsureDefaults(root); err == nil || !strings.Contains(err.Error(), "incomplete existing configuration") {
					t.Errorf("attempt %d inferred fresh defaults for an incomplete installed policy: %v", attempt, err)
				}
				if got := directoryDigest(t, root); !reflect.DeepEqual(got, before) {
					t.Error("refused repair changed configuration bytes or inventory")
				}
			}
		})
	}
}

func TestUnpublishedExactFreshTemplatesCanResume(t *testing.T) {
	for _, name := range []string{"modules/00-core.toml", "modules/99-user.toml"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := EnsureDefaults(root); err != nil {
				t.Fatal(err)
			}
			before := directoryDigest(t, root)
			for _, relative := range []string{"config.toml", name} {
				if err := os.Remove(filepath.Join(root, relative)); err != nil {
					t.Fatal(err)
				}
			}
			if err := EnsureDefaults(root); err != nil {
				t.Fatal(err)
			}
			if got := directoryDigest(t, root); !reflect.DeepEqual(got, before) {
				t.Fatal("fresh retry did not restore the exact initial profile")
			}
		})
	}
}

func TestUnsafeUserModuleRefusesBeforeCreatingAnyDefaults(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(filepath.Join(root, "modules"), 0750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "external.toml")
	if err := os.WriteFile(outside, []byte("[core]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "modules/99-user.toml")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDefaults(root); err == nil {
		t.Fatal("unsafe user module accepted")
	}
	entries, err := os.ReadDir(filepath.Join(root, "modules"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "99-user.toml" {
		t.Fatal("refused unsafe policy created defaults", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "config.toml")); !os.IsNotExist(err) {
		t.Fatal("refused unsafe policy published the master", err)
	}
	assertFileContent(t, outside, "[core]\n")
}

func TestIncompletePolicyRepairKeepsLastValidatedSnapshot(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	root := filepath.Join(t.TempDir(), "config")
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	if err := ParseConfig(root); err != nil {
		t.Fatal(err)
	}
	before := GlobalConfig
	if err := os.Remove(filepath.Join(root, "modules/99-user.toml")); err != nil {
		t.Fatal(err)
	}
	files := directoryDigest(t, root)
	if err := PrepareInstallationConfiguration(root); err == nil {
		t.Error("missing administrator policy was silently recreated")
	}
	if GlobalConfig != before {
		t.Error("failed repair replaced the last validated configuration")
	}
	state := CurrentLoadState()
	if !state.Degraded || state.Source != root {
		t.Errorf("missing policy not reported as degraded: %+v", state)
	}
	if got := directoryDigest(t, root); !reflect.DeepEqual(got, files) {
		t.Error("failed repair changed the retained configuration")
	}
}

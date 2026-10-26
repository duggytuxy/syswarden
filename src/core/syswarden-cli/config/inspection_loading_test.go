package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func preserveInspectionLoadState(t *testing.T) {
	t.Helper()
	previous, state := GlobalConfig, CurrentLoadState()
	t.Cleanup(func() { GlobalConfig = previous; loadStateMu.Lock(); loadState = state; loadStateMu.Unlock() })
}

func inspectionFixture(t *testing.T, modular, historical bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	if modular {
		root = filepath.Join(root, "config")
		if err := InitializeDefaults(root); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "modules", "40-integrations.toml")
		if historical {
			if err := os.WriteFile(path, readImmutableFixture(t, "40-integrations.toml", v4028ModularFixtureSHA256), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return root, path
	}
	path := filepath.Join(root, "syswarden-auto.conf")
	data := []byte(DefaultConfig)
	if historical {
		data = readImmutableFixture(t, "legacy-ha-default.conf", v4028LegacyFixtureSHA256)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, path
}

func TestInspectionLoadingPreservesHistoricalAndCurrentFiles(t *testing.T) {
	preserveInspectionLoadState(t)
	for _, modular := range []bool{false, true} {
		for _, historical := range []bool{false, true} {
			name := "legacy"
			if modular {
				name = "modular"
			}
			if historical {
				name += "_historical"
			} else {
				name += "_current"
			}
			t.Run(name, func(t *testing.T) {
				source, path := inspectionFixture(t, modular, historical)
				root := source
				if !modular {
					root = filepath.Dir(source)
				}
				before := directoryDigest(t, root)
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				for attempt := 0; attempt < 2; attempt++ {
					if err := ParseConfigForInspection(source); err != nil {
						t.Fatal(err)
					}
					if GlobalConfig == nil || GlobalConfig.HAEnabled || GlobalConfig.BunkerWebEnabled {
						t.Fatal("inspection changed safe historical interpretation")
					}
					if state := CurrentLoadState(); state.Degraded || state.Source != source {
						t.Fatal("inspection did not publish validated process snapshot")
					}
					if !reflect.DeepEqual(before, directoryDigest(t, root)) {
						t.Fatal("inspection rewrote configuration")
					}
					after, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if !os.SameFile(info, after) || info.Mode() != after.Mode() || !info.ModTime().Equal(after.ModTime()) {
						t.Fatal("inspection replaced or changed input metadata")
					}
				}
			})
		}
	}
}

func TestInspectionLoadingRefusesAmbiguityWithoutDiscardingValidSnapshot(t *testing.T) {
	preserveInspectionLoadState(t)
	for _, kind := range []string{"invalid_modular", "partial_ha", "user_ha_override", "environment_ha_override", "symlink", "pending_edit", "invalid_legacy"} {
		t.Run(kind, func(t *testing.T) {
			source, path := inspectionFixture(t, kind != "invalid_legacy", true)
			fixtureRoot, err := os.OpenRoot(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := fixtureRoot.Close(); err != nil {
					t.Error(err)
				}
			})
			if kind == "invalid_legacy" {
				data, err := fixtureRoot.ReadFile(filepath.Base(path))
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, []byte("\nSYSWARDEN_FIREWALL_BACKEND=invalid\n")...)
				if err := fixtureRoot.WriteFile(filepath.Base(path), data, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				switch kind {
				case "invalid_modular":
					if err := os.WriteFile(filepath.Join(source, "modules", "99-user.toml"), []byte("[invalid\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "partial_ha":
					data, err := fixtureRoot.ReadFile(filepath.Base(path))
					if err != nil {
						t.Fatal(err)
					}
					data = []byte(strings.Replace(string(data), `token = ""`, `token = "partial-token"`, 1))
					if err := fixtureRoot.WriteFile(filepath.Base(path), data, 0600); err != nil {
						t.Fatal(err)
					}
				case "user_ha_override":
					if err := os.WriteFile(filepath.Join(source, "modules", "99-user.toml"), []byte("[integrations.ha]\nenabled = true\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "environment_ha_override":
					t.Setenv("SYSWARDEN_INTEGRATIONS_HA_ENABLED", "true")
				case "pending_edit":
					if err := os.WriteFile(filepath.Join(source, ".config-edit-intent.json"), []byte("pending\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					link := filepath.Join(t.TempDir(), "config")
					if err := os.Symlink(source, link); err != nil {
						t.Fatal(err)
					}
					source = link
				}
			}
			root := source
			if kind == "invalid_legacy" {
				root = filepath.Dir(source)
			}
			if kind == "symlink" {
				root = filepath.Dir(filepath.Dir(path))
			}
			before := directoryDigest(t, root)
			previous := &Config{SSHPort: "2222", FirewallBackend: "keep"}
			GlobalConfig = previous
			if err := ParseConfigForInspection(source); err == nil {
				t.Fatal("ambiguous inspection accepted")
			}
			if GlobalConfig != previous || !CurrentLoadState().Degraded {
				t.Fatal("refusal discarded prior validated state")
			}
			if !reflect.DeepEqual(before, directoryDigest(t, root)) {
				t.Fatal("refused inspection changed configuration")
			}
		})
	}
}

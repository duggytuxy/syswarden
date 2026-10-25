package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

func TestFreshNativePackageOnlyStagesConfiguration(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "stage", true: "refuse"}[failure], func(t *testing.T) {
			t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
			t.Setenv("SYSWARDEN_NATIVE_INSTALL_PHASE", "fresh")
			t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
			oldInspect, oldPrepare, oldLoad, oldRecover, oldLegacy, oldDeps, oldStage := inspectRemovalTombstone, prepareNativeServicesForInstall, initConfigHook, recoverPendingFirewallTransactionHook, preflightLegacyWireGuardForInstall, installDependenciesForInstall, stageFreshNativeConfiguration
			t.Cleanup(func() {
				inspectRemovalTombstone = oldInspect
				prepareNativeServicesForInstall = oldPrepare
				initConfigHook = oldLoad
				recoverPendingFirewallTransactionHook = oldRecover
				preflightLegacyWireGuardForInstall = oldLegacy
				installDependenciesForInstall = oldDeps
				stageFreshNativeConfiguration = oldStage
			})
			inspectRemovalTombstone = func() (bool, error) { return false, nil }
			prepareNativeServicesForInstall = func() (*system.NativeServiceInstallation, error) {
				t.Fatal("fresh package observed/prepared services")
				return nil, nil
			}
			initConfigHook = func() { t.Fatal("fresh package entered mutating configuration loading") }
			unexpected := func() error { t.Fatal("fresh package entered activation pipeline"); return nil }
			recoverPendingFirewallTransactionHook = unexpected
			preflightLegacyWireGuardForInstall = unexpected
			installDependenciesForInstall = unexpected
			calls := 0
			want := errors.New("unsafe existing configuration")
			stageFreshNativeConfiguration = func(root string) error {
				calls++
				if root != "/etc/syswarden/config" {
					t.Fatal(root)
				}
				if failure {
					return want
				}
				return nil
			}
			command := &cobra.Command{Use: "install"}
			parent := &cobra.Command{Use: "syswarden"}
			parent.AddCommand(command)
			var output bytes.Buffer
			command.SetOut(&output)
			if err := rootCmd.PersistentPreRunE(command, nil); err != nil {
				t.Fatal(err)
			}
			if calls != 0 {
				t.Fatal("pre-run staged configuration")
			}
			err := installCmd.RunE(command, nil)
			if (err != nil) != failure || calls != 1 {
				t.Fatal("incorrect staging result", calls, err)
			}
			if failure && !errors.Is(err, want) {
				t.Fatal("staging refusal lost", err)
			}
			if !failure && !strings.Contains(output.String(), "without activating lists") {
				t.Fatal("missing inactive disposition")
			}
		})
	}
}

func TestFreshNativePhaseNeverInferredFromListOrExistingProfile(t *testing.T) {
	for _, entry := range []struct {
		packaged, phase string
		fresh           bool
	}{{"1", "fresh", true}, {"1", "upgrade", false}, {"1", "unknown", false}, {"", "fresh", false}, {"1", "", false}} {
		t.Setenv("SYSWARDEN_PKG_INSTALL", entry.packaged)
		t.Setenv("SYSWARDEN_NATIVE_INSTALL_PHASE", entry.phase)
		if freshNativePackageInstallation() != entry.fresh {
			t.Fatal("incorrect native phase", entry)
		}
	}
}

func TestFreshPackageConfigurationStagingPreservesExistingPolicy(t *testing.T) {
	directory := t.TempDir()
	root := filepath.Join(directory, "config")
	legacy := filepath.Join(directory, "legacy", "syswarden-auto.conf")
	if err := stageFreshNativeConfigurationAt(root, legacy); err != nil {
		t.Fatal(err)
	}
	value, _, err := config.GetValidatedModularValue(root, "network.blocklists.list_choice")
	if err != nil || value != "4" {
		t.Fatal("fresh package selected a feed", value, err)
	}
	override := filepath.Join(root, "modules", "99-user.toml")
	chosen := []byte("[network.blocklists]\nlist_choice='1'\n[waap]\nenabled=true\n")
	if err := os.WriteFile(override, chosen, 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageFreshNativeConfigurationAt(root, legacy); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(override) // #nosec G304 -- exact administrator fixture under the test-owned temporary root
	if err != nil || !bytes.Equal(actual, chosen) {
		t.Fatal("staging changed administrator choices", err)
	}
	if err := os.Remove(filepath.Join(root, "modules", "10-network.toml")); err != nil {
		t.Fatal(err)
	}
	if err := stageFreshNativeConfigurationAt(root, legacy); err == nil {
		t.Fatal("staging repaired an incomplete installed policy")
	}
	if _, err := os.Stat(filepath.Join(root, "modules", "10-network.toml")); !os.IsNotExist(err) {
		t.Fatal("refused staging recreated missing policy")
	}
}

func TestFreshNativeStagingRefusesRetainedFlatPolicyBeforeCreatingDirectories(t *testing.T) {
	for _, suffix := range []string{"", ".migration_backup", ".migrated", ".migration_backup.migrated", ".bak"} {
		for _, kind := range []string{"file", "directory", "symlink", "dangling-symlink"} {
			t.Run(suffix+"/"+kind, func(t *testing.T) {
				directory := t.TempDir()
				root := filepath.Join(directory, "config")
				legacy := filepath.Join(directory, "syswarden-auto.conf")
				retained := legacy + suffix
				target := filepath.Join(directory, "administrator-policy")
				policy := []byte("SYSWARDEN_LIST_CHOICE=2\nSYSWARDEN_ENABLE_GEO=y\n")
				if err := os.WriteFile(target, policy, 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "file":
					err = os.WriteFile(retained, policy, 0600)
				case "directory":
					err = os.Mkdir(retained, 0700)
				case "symlink":
					err = os.Symlink(target, retained)
				case "dangling-symlink":
					err = os.Symlink(filepath.Join(directory, "missing-policy"), retained)
				}
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.Lstat(retained)
				if err != nil {
					t.Fatal(err)
				}
				if err := stageFreshNativeConfigurationAt(root, legacy); err == nil || !strings.Contains(err.Error(), "retained legacy configuration") {
					t.Fatal("retained policy did not refuse first modular staging", err)
				}
				if _, err := os.Lstat(root); !os.IsNotExist(err) {
					t.Fatal("refused staging created a modular directory", err)
				}
				after, err := os.Lstat(retained)
				if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
					t.Fatal("retained source was replaced or changed", err)
				}
				actual, err := os.ReadFile(target) // #nosec G304 -- fixed administrator fixture in this test-owned temporary directory
				if err != nil || !bytes.Equal(actual, policy) {
					t.Fatal("administrator source changed", err)
				}
				if kind == "file" {
					actual, err := os.ReadFile(retained) // #nosec G304 -- one exact fixed legacy suffix in this test-owned temporary directory
					if err != nil || !bytes.Equal(actual, policy) {
						t.Fatal("retained flat policy changed", err)
					}
				}
			})
		}
	}
}

func TestFreshNativeStagingRefusesAmbiguousLegacyParent(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "dangling-symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			root := filepath.Join(directory, "config")
			parent := filepath.Join(directory, "legacy")
			target := filepath.Join(directory, "target")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(parent, []byte("retained parent"), 0600)
			case "symlink":
				err = os.Symlink(target, parent)
			case "dangling-symlink":
				err = os.Symlink(filepath.Join(directory, "missing-parent"), parent)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := stageFreshNativeConfigurationAt(root, filepath.Join(parent, "syswarden-auto.conf")); err == nil {
				t.Fatal("ambiguous legacy parent allowed fresh staging")
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatal("ambiguous legacy parent caused modular directory creation", err)
			}
		})
	}
}

func TestFreshNativeStagingRetainsAuthoritativeModularPolicyWithLegacyCopies(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "invalid"}[valid], func(t *testing.T) {
			directory := t.TempDir()
			root := filepath.Join(directory, "config")
			legacy := filepath.Join(directory, "syswarden-auto.conf")
			if err := config.EnsureDefaults(root); err != nil {
				t.Fatal(err)
			}
			chosen := []byte("[network.blocklists]\nlist_choice='2'\n[waap]\nenabled=true\n")
			if !valid {
				chosen = []byte("[waap]\nenabled='invalid'\n")
			}
			if err := os.WriteFile(filepath.Join(root, "modules", "99-user.toml"), chosen, 0600); err != nil {
				t.Fatal(err)
			}
			// A complete valid modular policy is already authoritative, even when
			// the old flat pathname is an ambiguous, untouched recovery artifact.
			if err := os.Symlink(filepath.Join(directory, "missing-retained-source"), legacy); err != nil {
				t.Fatal(err)
			}
			before := make(map[string][]byte)
			identities := make(map[string]os.FileInfo)
			for _, relative := range []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml", "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml"} {
				path := filepath.Join(root, relative)
				content, err := os.ReadFile(path) // #nosec G304 -- closed modular fixture inventory beneath this test-owned root
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path], identities[path] = content, info
			}
			if err := stageFreshNativeConfigurationAt(root, legacy); (err == nil) != valid {
				t.Fatal("incorrect existing modular validation result", err)
			}
			for path, expected := range before {
				actual, err := os.ReadFile(path) // #nosec G304 -- previously captured closed modular fixture inventory
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("staging changed installed modular bytes", path, err)
				}
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(identities[path], after) || identities[path].Mode() != after.Mode() {
					t.Fatal("staging replaced installed modular file", path, err)
				}
			}
			if target, err := os.Readlink(legacy); err != nil || target != filepath.Join(directory, "missing-retained-source") {
				t.Fatal("staging changed retained legacy path", err)
			}
		})
	}
}

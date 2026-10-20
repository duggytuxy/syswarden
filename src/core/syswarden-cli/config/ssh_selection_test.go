package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"syswarden-cli/pkg/sshselection"
)

func TestSSHSelectionValidatedWithoutMutatingLegacyDefaults(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	before := directoryDigest(t, root)
	value, present, err := GetValidatedModularValue(root, "ssh.hardening")
	if err != nil || present || value != "" {
		t.Fatal("legacy defaults invented SSH consent", value, present, err)
	}
	if after := directoryDigest(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("inspection changed legacy defaults")
	}
	for _, choice := range []string{"disabled", "forwarding", "cis"} {
		if err := os.WriteFile(filepath.Join(root, sshselection.ModulePath), []byte("[ssh]\nhardening = \""+choice+"\"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		report, err := ValidateModularConfig(root)
		if err != nil || len(report.UnknownKeys) != 0 {
			t.Fatal("valid dedicated selection rejected", report, err)
		}
		value, present, err := GetValidatedModularValue(root, "ssh.hardening")
		if err != nil || !present || value != choice {
			t.Fatal("wrong dedicated selection", value, present, err)
		}
	}
}

func TestSSHSelectionRejectsMisplacementAndCoercionAcrossLoaders(t *testing.T) {
	for _, scenario := range []struct{ file, content string }{
		{"modules/99-user.toml", "[ssh]\nhardening = \"cis\"\n"},
		{"modules/05-ssh.toml", "[ssh]\nhardening = true\n"},
		{"modules/05-ssh.toml", "[SSH]\nhardening = \"cis\"\n"},
		{"modules/05-ssh.toml", "[core]\ncis_l2_hardening = true\n"},
	} {
		t.Run(scenario.file+scenario.content, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, scenario.file), []byte(scenario.content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateModularConfig(root); err == nil {
				t.Fatal("validation accepted ambiguous selection")
			}
			if _, _, err := GetValidatedModularValue(root, "ssh.hardening"); err == nil {
				t.Fatal("config-get accepted ambiguous selection")
			}
			if err := loadModularConfig(root); err == nil {
				t.Fatal("loader accepted ambiguous selection")
			}
		})
	}
}

func TestSSHSelectionEnvironmentRejectedByEveryModularEntryPoint(t *testing.T) {
	t.Setenv("SYSWARDEN_SSH_HARDENING", "cis")
	root := filepath.Join(t.TempDir(), "absent")
	if _, err := ValidateModularConfig(root); err == nil {
		t.Fatal("validation accepted environment selection")
	}
	if _, _, err := GetValidatedModularValue(root, "ssh.hardening"); err == nil {
		t.Fatal("config-get accepted environment selection")
	}
	if err := loadModularConfig(root); err == nil {
		t.Fatal("loader accepted environment selection")
	}
}

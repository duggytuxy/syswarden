package sshselection

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestSelectionRequiresExplicitMatchingConsent(t *testing.T) {
	for _, choice := range []string{"", "disabled", "forwarding", "cis", "true", "CIS"} {
		for _, intent := range []struct{ owner, profile string }{
			{"syswarden", "forwarding"}, {"syswarden", "cis"},
			{"external", "observe"}, {"external", "cis"}, {"", "cis"}, {"syswarden", ""},
		} {
			t.Run(choice+"/"+intent.owner+"/"+intent.profile, func(t *testing.T) {
				want := intent.owner == "syswarden" && (choice == "forwarding" || choice == "cis") && choice == intent.profile
				want = want || (intent.owner == "external" && intent.profile == "observe" && (choice == "" || choice == "disabled"))
				if err := (Config{choice}).Authorize(intent.owner, intent.profile); (err == nil) != want {
					t.Fatalf("authorization = %v, expected allowed=%t", err, want)
				}
			})
		}
	}
}

func TestSelectionRejectsCoercionAndAmbiguity(t *testing.T) {
	for _, input := range []string{
		`[ssh]` + "\nhardening = true", `[ssh]` + "\nhardening = 1",
		`[ssh]` + "\nhardening = []", `[ssh]` + "\nhardening = {}", `[ssh]` + "\nhardening = \"\"",
		`[SSH]` + "\nhardening = \"cis\"", `[ssh]` + "\nHardening = \"cis\"",
		`[ssh]` + "\nhardening = \"CIS\"", `[ssh]` + "\nhardening = \" cis\"",
		`[ssh]` + "\nhardening = \"cis\"\nhardening = \"disabled\"",
		`[ssh]` + "\nhardening = \"cis\"\nenabled = true", `ssh = "cis"`,
		"[[ssh]]\nhardening = \"cis\"", "[ssh.hardening]\nenabled = true",
		"[core]\ncis_l2_hardening = true", "[user]\npassword = \"private-fixture\"",
		"[ssh]\nhardening = \"private-fixture", strings.Repeat("#", MaxBytes+1),
	} {
		t.Run(input[:min(len(input), 50)], func(t *testing.T) {
			_, err := ParseModule([]byte(input))
			if err == nil || strings.Contains(err.Error(), "private-fixture") {
				t.Fatal("accepted invalid selection or exposed its contents", err)
			}
		})
	}
}

func TestSelectionMissingAndValidValues(t *testing.T) {
	for input, want := range map[string]string{
		"": "", "# operator has not selected SSH hardening\n": "", "[ssh]\n": "",
		"[ssh]\nhardening = \"disabled\"\n":   "disabled",
		"[ssh]\nhardening = \"forwarding\"\n": "forwarding",
		"[ssh]\nhardening = \"cis\"\n":        "cis",
		"ssh.hardening = \"cis\"\n":           "cis",
	} {
		selection, err := ParseModule([]byte(input))
		if err != nil || selection.Hardening != want {
			t.Fatal("wrong selection", selection, err)
		}
	}
}

func TestSelectionCannotBeMergedFromAnotherModule(t *testing.T) {
	for _, file := range []string{"config.toml", "modules/00-core.toml", "modules/99-user.toml", "modules/05-SSH.toml", "modules/./05-ssh.toml"} {
		for _, table := range []string{"ssh", "SSH", "Ssh", `"ssh.hardening"`} {
			var document map[string]any
			if err := toml.Unmarshal([]byte("["+table+"]\nhardening = \"cis\"\n"), &document); err != nil {
				t.Fatal(err)
			}
			if err := ValidateDocument(file, document); err == nil {
				t.Fatal("accepted selection outside its exact module", file)
			}
		}
	}
	if err := ValidateDocument("modules/00-core.toml", map[string]any{"core": map[string]any{"cis_l2_hardening": true}}); err != nil {
		t.Fatal("legacy core configuration should remain independently readable", err)
	}
}

func TestSelectionEnvironmentCannotGrantOrRevokeConsent(t *testing.T) {
	for _, name := range []string{"SYSWARDEN_SSH", "SYSWARDEN_SSH_HARDENING", "syswarden_ssh_hardening", "SYSWARDEN-SSH-HARDENING", "SYSWARDEN_SSH_HARDENING_ENABLED"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "private-fixture")
			err := RejectEnvironment()
			if err == nil || strings.Contains(err.Error(), "private-fixture") {
				t.Fatal("accepted environment selection or exposed its value", err)
			}
		})
	}
}

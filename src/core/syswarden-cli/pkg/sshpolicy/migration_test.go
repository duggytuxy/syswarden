package sshpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyIntentRefusesAmbiguousAttribution(t *testing.T) {
	changes := map[string]func(*legacyIntent){
		"missing attribution": func(v *legacyIntent) { v.Attribution = "" },
		"marker attribution":  func(v *legacyIntent) { v.Attribution = "marker" },
		"uppercase hash":      func(v *legacyIntent) { v.MainSHA256 = strings.Repeat("A", 64) },
		"short hash":          func(v *legacyIntent) { v.MainSHA256 = "abc" },
		"no edits":            func(v *legacyIntent) { v.Edits = nil },
		"zero line":           func(v *legacyIntent) { v.Edits[0].Line = 0 },
		"negative line":       func(v *legacyIntent) { v.Edits[0].Line = -1 },
		"duplicate line":      func(v *legacyIntent) { v.Edits = append(v.Edits, v.Edits[0]) },
		"unsorted":            func(v *legacyIntent) { v.Edits = []legacyEdit{{2, "remove"}, {1, "remove"}} },
		"freeform action":     func(v *legacyIntent) { v.Edits[0].Action = "replace" },
		"too many":            func(v *legacyIntent) { v.Edits = make([]legacyEdit, MaxLegacyEdits+1) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			value, err := parseIntent([]byte(validIntentJSON))
			if err != nil {
				t.Fatal(err)
			}
			value.Legacy = &legacyIntent{Attribution: "operator-reviewed", MainSHA256: strings.Repeat("a", 64), Edits: []legacyEdit{{1, "remove"}}}
			change(value.Legacy)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseIntent(raw); err == nil {
				t.Fatal("accepted ambiguous legacy declaration")
			}
		})
	}
}

func TestLegacySelectedLinesPreserveAllOtherBytes(t *testing.T) {
	main := "# original comment\nAllowTcpForwarding no\n# SYSWARDEN OVERRIDE:   X11Forwarding no\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User backup\n  ForceCommand internal-sftp\n"
	declaration := &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes([]byte(main)), Edits: []legacyEdit{{2, "remove"}, {3, "restore"}}}
	got, err := migrateMain([]byte(main), declaration)
	if err != nil {
		t.Fatal(err)
	}
	want := "# original comment\n  X11Forwarding no\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User backup\n  ForceCommand internal-sftp\n"
	if string(got) != want {
		t.Fatalf("unexpected transformation: %q", got)
	}
	if _, err := Prepare(CIS, map[string][]byte{MainPath: got}); err != nil {
		t.Fatal(err)
	}
	copy, err := migrateMain([]byte(main), nil)
	if err != nil {
		t.Fatal(err)
	}
	copy[0] = '!'
	if main[0] != '#' {
		t.Fatal("mutated original bytes")
	}
}

func TestLegacyEditsCannotRewriteUnrelatedSettings(t *testing.T) {
	for _, line := range []string{"Port 22", "PasswordAuthentication no", "Include /etc/ssh/sshd_config.d/*.conf", "Match User backup", "AllowTcpForwarding yes", "  AllowTcpForwarding no", "# administrator comment", "# SYSWARDEN OVERRIDE: Port 22"} {
		t.Run(line, func(t *testing.T) {
			main := line + "\n" + includeDropIns
			for _, action := range []string{"remove", "restore"} {
				declaration := &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes([]byte(main)), Edits: []legacyEdit{{1, action}}}
				if _, err := migrateMain([]byte(main), declaration); err == nil {
					t.Fatalf("accepted %s on unrelated line", action)
				}
			}
		})
	}
}

func TestLegacyRestoreDoesNotSilentlyOverrideBastionPolicy(t *testing.T) {
	main := "AllowTcpForwarding no\n# SYSWARDEN OVERRIDE: AllowTcpForwarding yes\n" + includeDropIns
	declaration := &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes([]byte(main)), Edits: []legacyEdit{{1, "remove"}, {2, "restore"}}}
	got, err := migrateMain([]byte(main), declaration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Forwarding, map[string][]byte{MainPath: got}); err == nil {
		t.Fatal("overrode restored forwarding requirement")
	}
}

func TestLegacyCISBlockIsIndivisibleAndExact(t *testing.T) {
	for _, changed := range []bool{false, true} {
		main := strings.Join(legacyCISBlock, "\n") + "\n" + includeDropIns
		if changed {
			main = strings.Replace(main, "MaxAuthTries 4", "MaxAuthTries 2", 1)
		}
		for omitted := 0; omitted <= len(legacyCISBlock); omitted++ {
			declaration := &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes([]byte(main))}
			for line := 1; line <= len(legacyCISBlock); line++ {
				if line != omitted {
					declaration.Edits = append(declaration.Edits, legacyEdit{line, "remove"})
				}
			}
			got, err := migrateMain([]byte(main), declaration)
			if omitted == 0 && !changed {
				if err != nil || string(got) != includeDropIns {
					t.Fatal("exact block did not migrate")
				}
				continue
			}
			if err == nil {
				t.Fatalf("accepted changed=%v omitted=%d", changed, omitted)
			}
		}
	}
}

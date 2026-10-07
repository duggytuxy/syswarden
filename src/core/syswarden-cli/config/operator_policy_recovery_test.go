package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const recoveryOperatorModule = `# Administrator source remains intact.
[user]
custom_metadata = "preserved"
[[operator_policy.rules]]
id = "maintenance"
family = "ipv4"
direction = "ingress"
protocol = "tcp"
destination_port = 8443
source = "192.0.2.0/24"
action = "accept"
`

func TestOperatorPolicyRecoveryInspectionIsIndependentAndReadOnly(t *testing.T) {
	dir := operatorPolicyFixture(t, recoveryOperatorModule)
	path := filepath.Join(dir, "modules", "99-user.toml")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	before, err := root.ReadFile("modules/99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	global, state := GlobalConfig, CurrentLoadState()
	candidate, err := InspectOperatorPolicyForRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.OperatorPolicy.Rules) != 1 || candidate.OperatorPolicy.Rules[0].DestinationPort != 8443 {
		t.Fatal("typed source was not preserved")
	}
	resolved, err := OperatorPolicySourcePath(candidate)
	if err != nil || resolved != path {
		t.Fatal(resolved, err)
	}
	after, err := root.ReadFile("modules/99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	final, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !os.SameFile(info, final) || info.Mode() != final.Mode() || GlobalConfig != global || !reflect.DeepEqual(CurrentLoadState(), state) {
		t.Fatal("recovery inspection changed administrator source or global configuration")
	}
	if err := root.WriteFile("modules/99-user.toml", append(before, []byte("\n# Changed after review\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OperatorPolicySourcePath(candidate); err == nil {
		t.Fatal("source change was accepted after inspection")
	}
}

func TestOperatorPolicyRecoveryRejectsMissingAmbiguousOrOverriddenSource(t *testing.T) {
	for _, kind := range []string{"empty", "unknown-field", "coerced-port", "symlink", "environment", "policy-mutation"} {
		t.Run(kind, func(t *testing.T) {
			dir := operatorPolicyFixture(t, recoveryOperatorModule)
			path := filepath.Join(dir, "modules", "99-user.toml")
			switch kind {
			case "empty":
				if err := os.WriteFile(path, []byte("[user]\ncustom_metadata = \"keep\"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-field":
				if err := os.WriteFile(path, append([]byte(recoveryOperatorModule), []byte("raw_nft = \"accept\"\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "coerced-port":
				content := bytes.Replace([]byte(recoveryOperatorModule), []byte("destination_port = 8443"), []byte("destination_port = \"8443\""), 1)
				if err := os.WriteFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "environment":
				t.Setenv("SYSWARDEN_OPERATOR_POLICY_RULES", "[]")
			}
			candidate, err := InspectOperatorPolicyForRecovery(dir)
			if kind == "policy-mutation" {
				if err != nil {
					t.Fatal(err)
				}
				candidate.OperatorPolicy.Rules[0].Source = "192.0.3.0/24"
				_, err = OperatorPolicySourcePath(candidate)
			}
			if err == nil {
				t.Fatal("unbound operator source accepted", kind)
			}
		})
	}
}

//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func planFixture(t *testing.T, main string) *inventoryFixture {
	t.Helper()
	fixture := newInventoryFixture(t, main)
	fixture.write(IntentPath, validIntentJSON)
	return fixture
}

func (fixture *inventoryFixture) plan() migrationPlan {
	fixture.t.Helper()
	plan, err := inspectPlan(fixture.root, os.Geteuid())
	if err != nil {
		fixture.t.Fatal(err)
	}
	return plan
}

func (fixture *inventoryFixture) intent(value intent) {
	fixture.t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.write(IntentPath, string(content))
}

func TestPlanFreshPublicationIsReadOnlyAndPrivate(t *testing.T) {
	fixture := planFixture(t, includeDropIns+"PasswordAuthentication no\nSubsystem sftp internal-sftp\n")
	before, err := collectPlanInventory(fixture.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	plan := fixture.plan()
	after, err := collectPlanInventory(fixture.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("inspection changed protected inputs")
	}
	if plan.summary.Operation != "publish" || plan.summary.ApplyAvailable || plan.summary.ContextCount != 1 ||
		plan.summary.MainBeforeSHA256 != plan.summary.MainAfterSHA256 || plan.summary.DropInSHA256 == "" || plan.summary.PlanSHA256 == "" {
		t.Fatalf("invalid summary: %+v", plan.summary)
	}
	output, err := json.Marshal(plan.summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"controller.example", "192.0.2.", "administrator", "PasswordAuthentication", "internal-sftp"} {
		if bytes.Contains(output, []byte(private)) {
			t.Fatal("summary exposed configuration")
		}
	}
	if fixture.plan().summary.PlanSHA256 != plan.summary.PlanSHA256 {
		t.Fatal("stable inspection changed digest")
	}
	if _, err := os.Lstat(fixture.path(DropInPath)); !os.IsNotExist(err) {
		t.Fatal("inspection created drop-in")
	}
	if _, err := os.Lstat(fixture.path("/var")); !os.IsNotExist(err) {
		t.Fatal("inspection created persistent state")
	}
}

func TestPlanRejectsUnprotectedOrMissingIntent(t *testing.T) {
	for _, mode := range []os.FileMode{0644, 0620, 0604, 0700, 0660, 0666} {
		t.Run(mode.String(), func(t *testing.T) {
			fixture := planFixture(t, includeDropIns)
			if err := fixture.chmod(IntentPath, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
				t.Fatal("accepted nonprivate intent")
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns)
		if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
			t.Fatal("inferred intent")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		fixture := planFixture(t, includeDropIns)
		if err := os.Remove(fixture.path(IntentPath)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fixture.path(MainPath), fixture.path(IntentPath)); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
			t.Fatal("followed intent symlink")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		fixture := planFixture(t, includeDropIns)
		if err := os.Link(fixture.path(IntentPath), fixture.path("/etc/syswarden/alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
			t.Fatal("accepted intent hardlink")
		}
	})
	t.Run("unsafe parent", func(t *testing.T) {
		fixture := planFixture(t, includeDropIns)
		if err := fixture.chmod("/etc/syswarden", 0777); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
			t.Fatal("accepted writable parent")
		}
	})
	t.Run("nil root", func(t *testing.T) {
		if _, err := inspectPlan(nil, 0); err == nil {
			t.Fatal("accepted nil root")
		}
	})
}

func TestPlanExternalOwnershipAndReservedPath(t *testing.T) {
	fixture := planFixture(t, includeDropIns+"AllowTcpForwarding local\nPermitOpen backend.example:22\n")
	value, err := parseIntent([]byte(validIntentJSON))
	if err != nil {
		t.Fatal(err)
	}
	value.Owner = "external"
	value.Profile = "observe"
	value.Role = "jump-host"
	value.Contexts[0].Route = "bastion"
	fixture.intent(value)
	plan := fixture.plan()
	if plan.summary.Operation != "observe" || len(plan.candidate.Bytes()) != 0 || plan.summary.DropInSHA256 != "" {
		t.Fatal("external owner acquired a policy")
	}
	fixture.write(MainPath, includeDropIns+"# SYSWARDEN OVERRIDE: AllowTcpForwarding yes\n")
	if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
		t.Fatal("ignored unresolved legacy edits")
	}
	fixture.write(MainPath, includeDropIns)
	fixture.write(DropInPath, "# administrator file\n")
	if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
		t.Fatal("adopted reserved administrator path")
	}
}

func TestPlanExplicitLegacyMigration(t *testing.T) {
	main := "AllowTcpForwarding no\n" + strings.Join(legacyCISBlock, "\n") + "\n" + includeDropIns + "PasswordAuthentication no\n# preserved comment\n"
	fixture := planFixture(t, main)
	if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
		t.Fatal("inferred legacy ownership")
	}
	value, err := parseIntent([]byte(validIntentJSON))
	if err != nil {
		t.Fatal(err)
	}
	value.Profile = "cis"
	value.Legacy = &legacyIntent{Attribution: "operator-reviewed", MainSHA256: digestBytes([]byte(main))}
	for line := 1; line <= 7; line++ {
		value.Legacy.Edits = append(value.Legacy.Edits, legacyEdit{line, "remove"})
	}
	fixture.intent(value)
	plan := fixture.plan()
	if plan.summary.Operation != "migrate" || plan.summary.LegacyEditCount != 7 || string(plan.main) != includeDropIns+"PasswordAuthentication no\n# preserved comment\n" {
		t.Fatal("incorrect bounded migration")
	}
	unchanged, err := collectPlanInventory(fixture.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged.files[MainPath]) != main {
		t.Fatal("planning applied migration")
	}
	fixture.write(MainPath, main+"# later administrator edit\n")
	if _, err := inspectPlan(fixture.root, os.Geteuid()); err == nil {
		t.Fatal("accepted stale attribution")
	}
}

func TestPlanDigestBindsCompleteObservations(t *testing.T) {
	fixture := planFixture(t, includeDropIns+"Include /etc/ssh/missing.conf\n")
	plan := fixture.plan()
	tests := map[string]func(*migrationPlan){
		"metadata": func(p *migrationPlan) {
			v := p.inventory.nodes[MainPath]
			v.mode ^= 040
			p.inventory.nodes[MainPath] = v
		},
		"inode": func(p *migrationPlan) { v := p.inventory.nodes[MainPath]; v.ino++; p.inventory.nodes[MainPath] = v },
		"ctime": func(p *migrationPlan) {
			v := p.inventory.nodes[MainPath]
			v.changed.Nsec++
			p.inventory.nodes[MainPath] = v
		},
		"negative lookup":  func(p *migrationPlan) { delete(p.inventory.nodes, "/etc/ssh/missing.conf") },
		"directory member": func(p *migrationPlan) { p.inventory.entries["/etc/ssh/sshd_config.d"] = []string{"nonmatching.txt"} },
		"alias": func(p *migrationPlan) {
			p.inventory.links["/etc/crypto-policies/back-ends/opensshserver.config"] = "/usr/share/crypto-policies/FIPS/opensshserver.txt"
		},
		"intent":        func(p *migrationPlan) { p.inventory.files[IntentPath] = []byte(validIntentJSON + "\n") },
		"main proposal": func(p *migrationPlan) { p.main = append(p.main, []byte("# new\n")...) },
		"operation":     func(p *migrationPlan) { p.summary.Operation = "observe" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			other := fixture.plan()
			change(&other)
			if planDigest(other) == plan.summary.PlanSHA256 {
				t.Fatal("plan digest did not bind change")
			}
		})
	}
}

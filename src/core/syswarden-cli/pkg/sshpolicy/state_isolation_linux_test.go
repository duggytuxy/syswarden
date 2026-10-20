//go:build linux

package sshpolicy

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSSHStateWritesRefuseAllReachablePrivateStorageIncludes(t *testing.T) {
	for _, include := range []string{
		"/var/lib/syswarden/*", "/var/lib/syswarden/*.json",
		"/var/lib/syswarden/.ssh-policy-create-*/ownership.json",
		"/var/lib/syswarden/ssh-policy-v1/prepared.json",
		"/var/lib/syswarden/.ssh-policy-retired-*/ownership.json",
		"/var/lib/syswarden/does-not-exist", "/var/lib/syswarden",
		"/var/lib/*/ssh-policy-owner-v1.json",
	} {
		for _, nested := range []bool{false, true} {
			t.Run(include+map[bool]string{true: "-nested", false: "-main"}[nested], func(t *testing.T) {
				f, instance := orphanFixture(t, true)
				line := "Match User automation\nInclude \"" + include + "\"\n"
				if nested {
					f.write("/etc/ssh/sshd_config.d/70-automation.conf", line)
				} else {
					f.write(MainPath, includeDropIns+line)
				}
				before, err := os.ReadDir(f.path(sshStateParent))
				if err != nil {
					t.Fatal(err)
				}
				main := fixtureMainImage(t, f)
				if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
					t.Fatal("wrote state reachable by Include")
				}
				if _, err := inspectSSHStateRetirement(f.root, os.Geteuid(), instance); err == nil {
					t.Fatal("accepted reachable retirement state")
				}
				if err := retireSSHState(f.root, os.Geteuid(), instance, strings.Repeat("a", 64), sshProvisionDefaults()); err == nil {
					t.Fatal("retired reachable state")
				}
				after, err := os.ReadDir(f.path(sshStateParent))
				if err != nil || len(before) != len(after) || !reflect.DeepEqual(main, fixtureMainImage(t, f)) {
					t.Fatal("changed evidence or SSH input", err)
				}
			})
		}
	}
}

func TestSSHStateProvisionRequiresIsolationBeforeAnyNamedCreation(t *testing.T) {
	f := stateFixture(t)
	f.write(MainPath, includeDropIns+"Include /var/lib/syswarden/not-present-yet\n")
	if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
		t.Fatal("ignored a negative Include")
	}
	entries, err := os.ReadDir(f.path(sshStateParent))
	if err != nil || len(entries) != 0 {
		t.Fatal("created state before isolation check", err)
	}
}

func TestSSHStateIsolationAllowsExternalPoliciesAndDetectsLaterEdits(t *testing.T) {
	f, instance := orphanFixture(t, true)
	f.write("/etc/ssh/sshd_config.d/60-ansible.conf", "Include /etc/ssh/automation/*.conf\n")
	f.write("/etc/ssh/automation/bastion.conf", "AllowTcpForwarding yes\n")
	plan := orphanPlan(t, f, instance)
	f.write("/etc/ssh/automation/bastion.conf", "AllowTcpForwarding yes\nInclude /var/lib/syswarden/missing.json\n")
	if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), sshProvisionDefaults()); err == nil {
		t.Fatal("used stale Include isolation")
	}
	if _, err := os.Lstat(f.path(sshStateParent + "/" + plan.record.receiptName())); !os.IsNotExist(err) {
		t.Fatal("wrote retirement receipt after input change", err)
	}
}

func TestSSHPlanRejectsReachableStorageWithoutChangingExternalOwnership(t *testing.T) {
	for _, include := range []string{"/var/lib/syswarden/future.json", "/var/lib/syswarden*", "/var/lib/syswarde?"} {
		t.Run(include, func(t *testing.T) {
			f := planFixture(t, includeDropIns+"Include "+include+"\n")
			if _, err := inspectPlan(f.root, os.Geteuid()); err == nil {
				t.Fatal("planned a write with reachable private storage")
			}
			value, err := parseIntent([]byte(validIntentJSON))
			if err != nil {
				t.Fatal(err)
			}
			value.Owner, value.Profile = "external", "observe"
			f.intent(value)
			plan := f.plan()
			if plan.summary.Operation != "observe" || plan.summary.ApplyAvailable {
				t.Fatal("changed external observation into publication")
			}
			if _, err := os.Lstat(f.path("/var")); !os.IsNotExist(err) {
				t.Fatal("read-only planning created state", err)
			}
		})
	}
}

func TestSSHProvisionRechecksIncludesBeforePublishingOwnership(t *testing.T) {
	f := stateFixture(t)
	ops := sshProvisionDefaults()
	calls := 0
	ops.sync = func(file *os.File) error {
		calls++
		if calls == 2 {
			f.write(MainPath, includeDropIns+"Include /var/lib/syswarden/future.json\n")
		}
		return file.Sync()
	}
	if err := provisionSSHState(f.root, os.Geteuid(), ops); err == nil {
		t.Fatal("accepted changed Include graph")
	}
	if calls != 2 {
		t.Fatal("did not reach pre-receipt interruption")
	}
	if _, err := os.Lstat(f.path(sshStateParent + "/" + sshOwnerName)); !os.IsNotExist(err) {
		t.Fatal("published ownership after configuration change", err)
	}
}

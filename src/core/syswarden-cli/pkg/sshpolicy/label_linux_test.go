//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

func TestSSHTargetLabelRejectsAmbiguousOutput(t *testing.T) {
	for _, value := range []string{"", "system_u:object_r:sshd_config_t", "<<none>>\n",
		"system_u::sshd_config_t:s0\n", " system_u:object_r:sshd_config_t:s0\n",
		"system_u:object_r:sshd_config_t:s0\nextra\n", "system_u:object_r:sshd_config_t:s0\x00\n",
		"system_u:object_r:sshd_config_t:s0\r\n", strings.Repeat("a", 4097) + "\n"} {
		if _, err := parseSSHTargetLabel([]byte(value)); err == nil {
			t.Fatal("accepted ambiguous policy context")
		}
	}
	for _, value := range []string{"system_u:object_r:sshd_config_t\n", "system_u:object_r:sshd_config_t:s0\n",
		"system_u:object_r:sshd_config_t:s0-s0:c0.c1023\n"} {
		got, err := parseSSHTargetLabel([]byte(value))
		if err != nil || !bytes.Equal(got, append([]byte(strings.TrimSuffix(value, "\n")), 0)) {
			t.Fatal("lost untranslated label", err)
		}
	}
}

func TestSSHTargetLabelRefusesHiddenSELinuxAndFakeMount(t *testing.T) {
	f := planFixture(t, includeDropIns)
	snapshot := f.plan().inventory
	snapshot.attributes[MainPath]["security.selinux"] = []byte("system_u:object_r:sshd_config_t:s0\x00")
	if _, err := resolveSSHTargetLabel(context.Background(), f.root, os.Geteuid(), snapshot); err == nil {
		t.Fatal("guessed target policy with unavailable selinuxfs")
	}
	if err := os.MkdirAll(f.path("/sys/fs/selinux"), 0700); err != nil {
		t.Fatal(err)
	}
	f.write("/sys/fs/selinux/enforce", "1")
	if _, err := readSSHSELinuxState(f.root, os.Geteuid()); err == nil {
		t.Fatal("accepted a regular directory as selinuxfs")
	}
}

func TestSSHTargetLabelInstalledOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_ORACLE_TEST=1 for installed label-tool verification")
	}
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	state, err := readSSHSELinuxState(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !state.present {
		t.Skip("SELinux is not active on the parser-oracle host")
	}
	label, err := resolveSSHTargetLabel(context.Background(), root, 0, inventorySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = label.close() }()
	if len(label.attributes["security.selinux"]) == 0 || label.recheck(context.Background()) != nil {
		t.Fatal("target-policy label could not be revalidated")
	}
	after, err := readSSHSELinuxState(root, 0)
	if err != nil || after != state {
		t.Fatal("read-only label resolution changed enforcement", err)
	}
}

func TestSSHLabelExecutableRequiresProtectedIdentity(t *testing.T) {
	const header = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00"
	for _, scenario := range []string{"usr-bin", "usr-sbin", "missing", "symlink", "hardlink", "writable", "script", "replacement", "shadow"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			target := "/usr/bin/matchpathcon"
			if scenario == "usr-sbin" || scenario == "shadow" {
				target = "/usr/sbin/matchpathcon"
			}
			if scenario != "missing" {
				f.write(target, header+"fixture")
				if err := f.chmod(target, 0755); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "symlink":
				if err := os.Rename(f.path(target), f.path(target+"-original")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("matchpathcon-original", f.path(target)); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(target), f.path(target+"-alias")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := f.chmod(target, 0775); err != nil {
					t.Fatal(err)
				}
			case "script":
				f.write(target, "#!/bin/sh\nexit 0\n")
				if err := f.chmod(target, 0755); err != nil {
					t.Fatal(err)
				}
			}
			tool, err := openSSHLabelExecutable(f.root, os.Geteuid())
			valid := scenario == "usr-bin" || scenario == "usr-sbin" || scenario == "replacement" || scenario == "shadow"
			if !valid {
				if err == nil {
					_ = tool.file.Close()
					t.Fatal("accepted an unsafe target-label helper")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer tool.file.Close()
			if err := tool.recheck(f.root, os.Geteuid()); err != nil {
				t.Fatal(err)
			}
			if scenario == "replacement" {
				f.write(target+"-replacement", header+"fixture")
				if err := f.chmod(target+"-replacement", 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.path(target+"-replacement"), f.path(target)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "shadow" {
				f.write("/usr/bin/matchpathcon", header+"fixture")
				if err := f.chmod("/usr/bin/matchpathcon", 0755); err != nil {
					t.Fatal(err)
				}
			}
			if (scenario == "replacement" || scenario == "shadow") && tool.recheck(f.root, os.Geteuid()) == nil {
				t.Fatal("accepted a different helper with identical contents")
			}
		})
	}
}

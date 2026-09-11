//go:build linux

package integration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const appArmorRsyslogFixture = `#include <tunables/global>
profile rsyslogd /usr/sbin/rsyslogd flags=(attach_disconnected) {
  #include <abstractions/base>
  /var/log/** rw,
  include if exists <rsyslog.d>
  #include <local/usr.sbin.rsyslogd>
}
`

func appArmorSocketFixture(t *testing.T) (string, string, uint32, uint32) {
	t.Helper()
	parent, _, uid, gid := newOwnedArtifactRemovalFixture(t)
	directory := filepath.Join(parent, rsyslogAppArmorDirectory)
	for _, path := range []string{directory, filepath.Join(directory, "local"), filepath.Join(directory, "rsyslog.d")} {
		if err := os.Mkdir(path, 0750); err != nil {
			t.Fatal(err)
		}
	}
	writeOwnedArtifactFixture(t, filepath.Join(directory, rsyslogAppArmorProfile), []byte(appArmorRsyslogFixture), 0644)
	writeOwnedArtifactFixture(t, filepath.Join(directory, "local", rsyslogAppArmorProfile), []byte("# Operator settings remain intact.\n"), 0644)
	return parent, filepath.Join(directory, "rsyslog.d", rsyslogAppArmorSnippet), uid, gid
}

func appArmorFixtureMode(mode string) func(string) (string, error) {
	return func(string) (string, error) { return mode, nil }
}

func readAppArmorFixture(parent, path string) ([]byte, error) {
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	relative, err := filepath.Rel(parent, path)
	if err != nil {
		return nil, err
	}
	return root.ReadFile(relative)
}

func TestRsyslogAppArmorSocketInstallAndRemovalPreserveConfinement(t *testing.T) {
	for _, mode := range []string{"enforce", "complain", "unloaded"} {
		t.Run(mode, func(t *testing.T) {
			parent, snippet, uid, gid := appArmorSocketFixture(t)
			var calls [][]string
			run := func(name string, args ...string) ([]byte, error) {
				if name != trustedAppArmorParser {
					t.Fatalf("unexpected privileged executable %q", name)
				}
				calls = append(calls, slices.Clone(args))
				if !slices.Contains(args, "--skip-cache") || slices.Contains(args, "--remove") {
					t.Fatalf("unsafe parser command %v", args)
				}
				if mode == "unloaded" && !slices.Contains(args, "--skip-kernel-load") {
					t.Fatal("installation enabled an unloaded profile")
				}
				if mode == "complain" && !slices.Contains(args, "--skip-kernel-load") && !slices.Contains(args, "--Complain") {
					t.Fatal("complain mode was not preserved")
				}
				return nil, nil
			}
			actions := 0
			action := func() error {
				actions++
				wire, err := readAppArmorFixture(parent, snippet)
				if err != nil || string(wire) != rsyslogAppArmorPolicy {
					t.Fatalf("bridge activated without its exact socket policy: %q %v", wire, err)
				}
				return nil
			}
			for range 2 {
				if err := withRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode(mode), run, func() error { return nil }, action); err != nil {
					t.Fatal(err)
				}
			}
			if actions != 2 || len(calls) < 2 {
				t.Fatalf("reconciliation was not idempotent: actions=%d commands=%v", actions, calls)
			}
			if err := attestRsyslogAppArmorSocketPolicyAbsent(parent, uid, gid); err == nil {
				t.Fatal("offline retry accepted a live socket policy")
			}
			if err := removeRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode(mode), run); err != nil {
				t.Fatal(err)
			}
			if err := attestRsyslogAppArmorSocketPolicyAbsent(parent, uid, gid); err != nil {
				t.Fatal(err)
			}
			before := len(calls)
			if err := removeRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode(mode), run); err != nil || len(calls) != before {
				t.Fatalf("already removed policy invoked a mutator: %v", err)
			}
			for path, expected := range map[string]string{
				filepath.Join(parent, rsyslogAppArmorDirectory, rsyslogAppArmorProfile):          appArmorRsyslogFixture,
				filepath.Join(parent, rsyslogAppArmorDirectory, "local", rsyslogAppArmorProfile): "# Operator settings remain intact.\n",
			} {
				wire, err := readAppArmorFixture(parent, path)
				if err != nil || string(wire) != expected {
					t.Fatalf("non-product profile changed: %s %v", path, err)
				}
			}
		})
	}
}

func TestRsyslogAppArmorRejectsUnsafeOrOperatorOwnedSnippet(t *testing.T) {
	for _, variant := range []string{"modified", "symlink", "hardlink", "directory", "group-writable", "wrong-mode"} {
		t.Run(variant, func(t *testing.T) {
			parent, snippet, uid, gid := appArmorSocketFixture(t)
			writeOwnedArtifactFixture(t, snippet, []byte(rsyslogAppArmorPolicy), 0600)
			switch variant {
			case "modified":
				writeOwnedArtifactFixture(t, snippet, []byte("# Operator override\n/run/other.sock w,\n"), 0600)
			case "symlink", "directory":
				if err := os.Remove(snippet); err != nil {
					t.Fatal(err)
				}
				if variant == "directory" {
					if err := os.Mkdir(snippet, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink(filepath.Join(parent, rsyslogAppArmorDirectory, rsyslogAppArmorProfile), snippet); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(snippet, filepath.Join(parent, "operator-copy")); err != nil {
					t.Fatal(err)
				}
			case "group-writable", "wrong-mode":
				mode := os.FileMode(0644)
				if variant == "group-writable" {
					mode = 0660
				}
				if err := os.Chmod(snippet, mode); err != nil {
					t.Fatal(err)
				}
			}
			mutations := 0
			run := func(string, ...string) ([]byte, error) { mutations++; return nil, nil }
			action := func() error { mutations++; return nil }
			if err := withRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("enforce"), run, func() error { return nil }, action); err == nil {
				t.Fatal("unsafe snippet accepted during installation")
			}
			if err := removeRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("enforce"), run); err == nil {
				t.Fatal("unsafe snippet accepted during removal")
			}
			if _, err := os.Lstat(snippet); err != nil || mutations != 0 {
				t.Fatalf("ambiguous policy was modified: %v commands=%d", err, mutations)
			}
		})
	}
}

func TestRsyslogAppArmorRollsBackNewPolicyAfterActivationOrBridgeFailure(t *testing.T) {
	for _, failure := range []string{"syntax", "load", "bridge", "barrier"} {
		t.Run(failure, func(t *testing.T) {
			parent, snippet, uid, gid := appArmorSocketFixture(t)
			sentinel := errors.New("controlled " + failure + " failure")
			failed, activated := false, false
			run := func(_ string, args ...string) ([]byte, error) {
				if !failed && (failure == "syntax" || failure == "load" && !slices.Contains(args, "--skip-kernel-load")) {
					failed = true
					return nil, sentinel
				}
				return nil, nil
			}
			barrier := func() error {
				if failure == "barrier" {
					return sentinel
				}
				return nil
			}
			err := withRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("enforce"), run, barrier, func() error {
				activated = true
				return sentinel
			})
			if !errors.Is(err, sentinel) || activated != (failure == "bridge") {
				t.Fatalf("failure contract: %v activated=%t", err, activated)
			}
			if _, err := os.Lstat(snippet); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed setup retained new permission: %v", err)
			}
			if err := attestRsyslogAppArmorSocketPolicyAbsent(parent, uid, gid); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRsyslogAppArmorRemovalFailureRestoresExactPolicyAndRetries(t *testing.T) {
	parent, snippet, uid, gid := appArmorSocketFixture(t)
	writeOwnedArtifactFixture(t, snippet, []byte(rsyslogAppArmorPolicy), 0600)
	sentinel := errors.New("controlled parser failure")
	calls := 0
	run := func(string, ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			if _, err := os.Lstat(snippet); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("policy was not quarantined before profile reload")
			}
			return nil, sentinel
		}
		return nil, nil
	}
	if err := removeRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("enforce"), run); !errors.Is(err, sentinel) {
		t.Fatalf("lost reload failure: %v", err)
	}
	wire, err := readAppArmorFixture(parent, snippet)
	if err != nil || string(wire) != rsyslogAppArmorPolicy || calls != 3 {
		t.Fatalf("policy and reload were not restored: %v calls=%d", err, calls)
	}
	if err := os.Rename(snippet, filepath.Join(filepath.Dir(snippet), exactArtifactQuarantineName(rsyslogAppArmorSnippet))); err != nil {
		t.Fatal(err)
	}
	if err := removeRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("enforce"), run); err != nil {
		t.Fatal(err)
	}
	if err := attestRsyslogAppArmorSocketPolicyAbsent(parent, uid, gid); err != nil {
		t.Fatal(err)
	}
}

func TestRsyslogAppArmorProfileScopeAndModeAreExplicit(t *testing.T) {
	for _, content := range []string{
		appArmorRsyslogFixture,
		strings.Replace(appArmorRsyslogFixture, "profile rsyslogd /usr/sbin/rsyslogd", "/usr/sbin/rsyslogd", 1),
		strings.Replace(appArmorRsyslogFixture, "include if exists <rsyslog.d>", "#include <rsyslog.d>", 1),
	} {
		if _, err := rsyslogAppArmorProfileName([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for _, content := range []string{
		strings.Replace(appArmorRsyslogFixture, "include if exists <rsyslog.d>", "# include is intentionally disabled", 1),
		strings.Replace(appArmorRsyslogFixture, "include if exists <rsyslog.d>", "profile other {\n include if exists <rsyslog.d>\n}", 1),
		strings.Replace(appArmorRsyslogFixture, "  include if exists <rsyslog.d>\n", "", 1) + "include if exists <rsyslog.d>\n",
		appArmorRsyslogFixture + appArmorRsyslogFixture,
		appArmorRsyslogFixture + "profile other /usr/bin/other {\n}\n",
		"#include <other-profile>\n" + appArmorRsyslogFixture,
		strings.Replace(appArmorRsyslogFixture, "profile rsyslogd", "profile operator", 1),
	} {
		if _, err := rsyslogAppArmorProfileName([]byte(content)); err == nil {
			t.Fatalf("unsafe include scope accepted: %q", content)
		}
	}
	for _, row := range []struct {
		enabled, profiles, mode string
		fail                    bool
	}{
		{"N", "", "unloaded", false}, {"Y", "rsyslogd (enforce)\n", "enforce", false},
		{"Y", "rsyslogd (complain)\n", "complain", false}, {"Y", "other (enforce)\n", "unloaded", false},
		{"?", "", "", true}, {"Y", "rsyslogd (kill)\n", "", true},
		{"Y", "rsyslogd (enforce)\nrsyslogd (complain)\n", "", true},
	} {
		mode, err := rsyslogAppArmorModeUsing("rsyslogd", func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/enabled") {
				return []byte(row.enabled), nil
			}
			return []byte(row.profiles), nil
		})
		if mode != row.mode || (err != nil) != row.fail {
			t.Fatalf("runtime mode=%q error=%v for %+v", mode, err, row)
		}
	}
}

func TestRsyslogAppArmorPreservesExistingPolicyAndRejectsVendorMutation(t *testing.T) {
	parent, snippet, uid, gid := appArmorSocketFixture(t)
	writeOwnedArtifactFixture(t, snippet, []byte(rsyslogAppArmorPolicy), 0600)
	sentinel := errors.New("bridge failure with existing policy")
	run := func(string, ...string) ([]byte, error) { return nil, nil }
	if err := withRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("enforce"), run, func() error { return nil }, func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	before, err := readAppArmorFixture(parent, snippet)
	if err != nil || string(before) != rsyslogAppArmorPolicy {
		t.Fatalf("existing exact policy was removed: %v", err)
	}
	profile, err := captureRsyslogAppArmorProfile(parent, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.directory.Close()
	writeOwnedArtifactFixture(t, filepath.Join(parent, rsyslogAppArmorDirectory, rsyslogAppArmorProfile), []byte(appArmorRsyslogFixture+"# Operator changed the profile.\n"), 0644)
	if err := reloadRsyslogAppArmorProfile(profile, uid, gid, "enforce", appArmorFixtureMode("enforce"), run); err == nil {
		t.Fatal("changed vendor profile accepted")
	}
	after, err := readAppArmorFixture(parent, snippet)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("vendor refusal changed socket policy: %v", err)
	}
}

func TestRsyslogAppArmorAbsentProfileDoesNotInvokePolicyCommands(t *testing.T) {
	parent, _, uid, gid := newOwnedArtifactRemovalFixture(t)
	commands, actions := 0, 0
	run := func(string, ...string) ([]byte, error) { commands++; return nil, nil }
	if err := withRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("unloaded"), run, func() error { return nil }, func() error { actions++; return nil }); err != nil {
		t.Fatal(err)
	}
	if commands != 0 || actions != 1 {
		t.Fatalf("unexpected no-AppArmor behavior: commands=%d actions=%d", commands, actions)
	}
}

func TestRsyslogAppArmorPackageRemovalRequiresProducerQuiescence(t *testing.T) {
	sentinel := errors.New("producer or policy failure")
	for _, row := range []struct {
		outcome RsyslogPackageRemovalOutcome
		prior   error
		cleanup error
		calls   int
		fail    bool
	}{
		{RsyslogPackageRemovalActiveQuiesced, nil, nil, 1, false},
		{RsyslogPackageRemovalActiveQuiesced, sentinel, nil, 0, true},
		{RsyslogPackageRemovalActiveQuiesced, nil, sentinel, 1, true},
		{RsyslogPackageRemovalOfflineAlreadyComplete, nil, nil, 0, false},
		{RsyslogPackageRemovalOutcomeUnknown, nil, nil, 0, true},
	} {
		calls := 0
		_, err := finishRsyslogPackageRemovalAppArmor(row.outcome, row.prior, func() error { calls++; return row.cleanup })
		if calls != row.calls || (err != nil) != row.fail {
			t.Fatalf("outcome=%d prior=%v: calls=%d error=%v", row.outcome, row.prior, calls, err)
		}
	}
}

func TestRsyslogAppArmorPublicationRejectsConcurrentOperatorReplacement(t *testing.T) {
	parent, snippet, uid, gid := appArmorSocketFixture(t)
	operator := []byte("# Operator replacement\n/run/operator.sock w,\n")
	run := func(string, ...string) ([]byte, error) {
		writeOwnedArtifactFixture(t, snippet, operator, 0600)
		return nil, nil
	}
	activated := false
	err := withRsyslogAppArmorSocketPolicyAtUsing(parent, uid, gid, appArmorFixtureMode("enforce"), run, func() error { return nil }, func() error { activated = true; return nil })
	if err == nil || activated {
		t.Fatalf("concurrent operator replacement accepted: %v", err)
	}
	actual, err := readAppArmorFixture(parent, snippet)
	if err != nil || !bytes.Equal(actual, operator) {
		t.Fatalf("operator replacement was overwritten: %q %v", actual, err)
	}
}

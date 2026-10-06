//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const legacyPlanTarget = "/etc/fail2ban/jail.d/syswarden-portscan.conf"

var fixtureLegacyFail2banParserSHA256 = sha256.Sum256([]byte("synthetic parser fixture"))

func fixtureLegacyFail2banPlanProbe(t *testing.T) legacyFail2banConfigurationProbe {
	t.Helper()
	before, after, _ := fixtureLegacyFail2banEffective(t, "historical")
	return func(_ legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
		content := before
		if len(retiring) > 0 {
			content = after
		}
		return legacyFail2banConfigurationView{enabled: content, allJails: content, parserSHA256: fixtureLegacyFail2banParserSHA256}, nil
	}
}

func assertEmptyLegacyFail2banPlan(t *testing.T, plan legacyFail2banRetirementPlan, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(plan, legacyFail2banRetirementPlan{}) {
		t.Fatal("failed preparation returned an approved or partial plan", err)
	}
}

func TestLegacyFail2banPlanBindsOwnedFilesAndRetainedConfiguration(t *testing.T) {
	root, host := fixtureLegacyFail2banInventory(t)
	action := "/etc/fail2ban/action.d/syswarden-webhook.conf"
	writeNFTPersistenceFixture(t, root, action, string(readLegacyFail2banFixture(t, "syswarden-webhook.conf")))
	probe := fixtureLegacyFail2banPlanProbe(t)
	paths := []string{legacyPlanTarget, action}
	plan, err := prepareLegacyFail2banRetirement(host, paths, probe)
	if err != nil || !validLegacyRetirementDigest(plan.sha256) || len(plan.records) != 2 {
		t.Fatal("complete plan preparation failed", err)
	}
	if !reflect.DeepEqual(paths, []string{legacyPlanTarget, action}) {
		t.Fatal("planner reordered caller input")
	}
	again, err := prepareLegacyFail2banRetirement(host, []string{action, legacyPlanTarget}, probe)
	if err != nil || again.sha256 != plan.sha256 {
		t.Fatal("equivalent target ordering changed the plan digest", err)
	}
	for _, record := range plan.records {
		if record.PlanSHA256 != plan.sha256 {
			t.Fatal("file intent lost its enclosing plan binding")
		}
		snapshot, err := host.snapshot(record.Source.Path)
		if err != nil || !matchesLegacyRetirementSource(record, snapshot) {
			t.Fatal("read-only planning changed or failed to bind the source", err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "var/backups")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only preparation created backup state")
	}
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/.private-copy", "# changed private inactive copy\n")
	changed, err := prepareLegacyFail2banRetirement(host, paths, probe)
	if err != nil || changed.sha256 == plan.sha256 {
		t.Fatal("plan digest did not bind an inactive retained source", err)
	}
	if err := os.Mkdir(filepath.Join(root, "etc/fail2ban/new-empty.d"), 0700); err != nil {
		t.Fatal(err)
	}
	withDirectory, err := prepareLegacyFail2banRetirement(host, paths, probe)
	if err != nil || withDirectory.sha256 == changed.sha256 {
		t.Fatal("plan digest did not bind complete directory membership", err)
	}
}

func TestLegacyFail2banPlanPreservesDormantActionOverlays(t *testing.T) {
	for _, name := range []string{"custom.conf", "custom.local", ".private.conf", "notes.txt"} {
		t.Run(name, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			path := "/etc/fail2ban/action.d/syswarden-webhook.conf"
			writeNFTPersistenceFixture(t, root, path, string(readLegacyFail2banFixture(t, "syswarden-webhook.conf")))
			overlayDir := "/etc/fail2ban/action.d/syswarden-webhook.d"
			if err := os.Mkdir(filepath.Join(root, overlayDir), 0700); err != nil {
				t.Fatal(err)
			}
			writeNFTPersistenceFixture(t, root, overlayDir+"/"+name, "[Definition]\nactionban = custom-action <ip>\n")
			_, after, _ := fixtureLegacyFail2banEffective(t, "historical")
			called := false
			probe := func(legacyFail2banInventory, []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
				called = true
				return legacyFail2banConfigurationView{enabled: after, allJails: after, parserSHA256: fixtureLegacyFail2banParserSHA256}, nil
			}
			plan, err := prepareLegacyFail2banRetirement(host, []string{path}, probe)
			if name == "custom.conf" || name == "custom.local" {
				assertEmptyLegacyFail2banPlan(t, plan, err)
				if called || !strings.Contains(err.Error(), "retained option overlay") {
					t.Fatal("dormant option overlay was not preserved before probing", err)
				}
			} else if err != nil {
				t.Fatal("inactive notes were mistaken for a reader overlay", err)
			}
		})
	}
}

func TestLegacyFail2banPlanFeedsDurableFileRetirementWithWholeInventoryGuard(t *testing.T) {
	root, host := fixtureLegacyFail2banInventory(t)
	plan, err := prepareLegacyFail2banRetirement(host, []string{legacyPlanTarget}, fixtureLegacyFail2banPlanProbe(t))
	if err != nil {
		t.Fatal(err)
	}
	record := plan.records[0]
	if err := os.MkdirAll(filepath.Join(root, legacyRetirementBackupDirectory(record)), 0700); err != nil {
		t.Fatal(err)
	}
	guard := func(retired bool) error {
		current, err := inspectLegacyFail2banInventory(host)
		if err != nil {
			return err
		}
		var targets []nftPersistenceRetiredSource
		if retired {
			targets = plan.retiring
		}
		return verifyLegacyFail2banInventoryRetirement(plan.baseline, current, targets)
	}
	if err := retireLegacyConfigurationFileUsing(host, record, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	retired, err := legacyRetirementSourceState(host, record)
	if err != nil || !retired {
		t.Fatal("planned original file was not safely retired", err)
	}
	intent, err := readLegacyRetirementFileRecord(host, legacyRetirementBackupDirectory(record))
	if err != nil || intent != record {
		t.Fatal("durable file intent differs from the prepared plan", err)
	}
	if err := guard(true); err != nil {
		t.Fatal("administrator configuration changed during planned retirement", err)
	}
}

func TestLegacyFail2banPlanRejectsUnknownOrAmbiguousOwnershipBeforeProbe(t *testing.T) {
	for _, kind := range []string{"empty", "duplicate", "missing", "custom", "modified", "local_override", "dormant_include", "no_probe"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			paths := []string{legacyPlanTarget}
			called := false
			probe := legacyFail2banConfigurationProbe(func(legacyFail2banInventory, []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
				called = true
				return legacyFail2banConfigurationView{}, nil
			})
			switch kind {
			case "empty":
				paths = nil
			case "duplicate":
				paths = append(paths, paths[0])
			case "missing":
				paths = []string{"/etc/fail2ban/action.d/absent.conf"}
			case "custom":
				paths = []string{"/etc/fail2ban/jail.d/administrator.local"}
			case "modified":
				writeNFTPersistenceFixture(t, root, legacyPlanTarget, "[syswarden-portscan]\nenabled = true\naction = custom\n")
			case "local_override":
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/syswarden-portscan.local", "[syswarden-portscan]\naction = custom\n")
			case "dormant_include":
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/filter.d/disabled.conf", "[INCLUDES]\nbefore = ../jail.d/syswarden-portscan.conf\n")
			case "no_probe":
				probe = nil
			}
			plan, err := prepareLegacyFail2banRetirement(host, paths, probe)
			assertEmptyLegacyFail2banPlan(t, plan, err)
			if called {
				t.Fatal("invoked parser before proving file ownership and includes")
			}
		})
	}
}

func TestLegacyFail2banPlanRequiresEnabledAndDormantProtection(t *testing.T) {
	for _, kind := range []string{"probe_before", "probe_after", "enabled_changed", "dormant_changed", "missing_all_view", "target_remains", "missing_forced_target", "incomplete_disabled_target"} {
		t.Run(kind, func(t *testing.T) {
			_, host := fixtureLegacyFail2banInventory(t)
			base := fixtureLegacyFail2banPlanProbe(t)
			probe := func(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
				view, _ := base(inventory, retiring)
				staged := len(retiring) != 0
				if kind == "probe_before" && !staged || kind == "probe_after" && staged {
					return view, errors.New("synthetic parser failure")
				}
				if staged {
					switch kind {
					case "enabled_changed":
						view.enabled = bytes.ReplaceAll(view.enabled, []byte("'administrator-web', 'maxretry', 1"), []byte("'administrator-web', 'maxretry', 99"))
					case "dormant_changed":
						view.allJails = bytes.ReplaceAll(view.allJails, []byte("'administrator-web', 'maxretry', 1"), []byte("'administrator-web', 'maxretry', 99"))
					case "missing_all_view":
						view.allJails = nil
					case "target_remains":
						view, _ = base(inventory, nil)
					}
				} else {
					switch kind {
					case "missing_forced_target":
						view, _ = base(inventory, []nftPersistenceRetiredSource{{}})
					case "incomplete_disabled_target":
						view.enabled = bytes.ReplaceAll(view.enabled, []byte("['start', 'syswarden-portscan']\n"), nil)
					}
				}
				return view, nil
			}
			plan, err := prepareLegacyFail2banRetirement(host, []string{legacyPlanTarget}, probe)
			assertEmptyLegacyFail2banPlan(t, plan, err)
		})
	}
}

func TestLegacyFail2banPlanAllowsDisabledTargetAndUnusedAction(t *testing.T) {
	for _, onlyAction := range []bool{false, true} {
		root, host := fixtureLegacyFail2banInventory(t)
		paths := []string{legacyPlanTarget}
		before, after, _ := fixtureLegacyFail2banEffective(t, "historical")
		if onlyAction {
			paths = []string{"/etc/fail2ban/action.d/syswarden-webhook.conf"}
			writeNFTPersistenceFixture(t, root, paths[0], string(readLegacyFail2banFixture(t, "syswarden-webhook.conf")))
		}
		probe := func(_ legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
			all := before
			if len(retiring) != 0 && !onlyAction {
				all = after
			}
			return legacyFail2banConfigurationView{enabled: after, allJails: all, parserSHA256: fixtureLegacyFail2banParserSHA256}, nil
		}
		if _, err := prepareLegacyFail2banRetirement(host, paths, probe); err != nil {
			t.Fatal("safe read-only plan was refused", err)
		}
	}
}

func TestLegacyFail2banPlanDetectsSourceChangesDuringEitherProbe(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		root, host := fixtureLegacyFail2banInventory(t)
		base := fixtureLegacyFail2banPlanProbe(t)
		probe := func(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
			if (len(retiring) == 0) == (phase == "before") {
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/new.local", "[administrator-web]\naction = new\n")
			}
			return base(inventory, retiring)
		}
		plan, err := prepareLegacyFail2banRetirement(host, []string{legacyPlanTarget}, probe)
		assertEmptyLegacyFail2banPlan(t, plan, err)
		if !strings.Contains(err.Error(), "changed during retirement planning") {
			t.Fatal("unexpected refusal", err)
		}
	}
}

func TestLegacyFail2banPlanProbeCannotOverwriteOriginalEvidence(t *testing.T) {
	_, host := fixtureLegacyFail2banInventory(t)
	base := fixtureLegacyFail2banPlanProbe(t)
	probe := func(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
		clear(inventory.sources[0].snapshot.content)
		inventory.sources[0].path = "/etc/fail2ban/changed.conf"
		if len(retiring) != 0 {
			retiring[0].path = "/etc/fail2ban/changed.conf"
		}
		return base(inventory, retiring)
	}
	plan, err := prepareLegacyFail2banRetirement(host, []string{legacyPlanTarget}, probe)
	if err != nil || plan.records[0].Source.Path != legacyPlanTarget {
		t.Fatal("callback scratch space corrupted original evidence", err)
	}
	if err := reattestLegacyFail2banPlanInventory(host, plan.baseline); err != nil {
		t.Fatal("callback mutated the saved inventory", err)
	}
}

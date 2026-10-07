//go:build linux

package firewall

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type legacyFail2banUnusedFixture struct {
	host    nftPersistenceFilesystem
	plan    legacyFail2banRetirementPlan
	live    legacyFail2banRuntimeSnapshot
	adapter legacyFail2banUnusedAdapter
	failure error
}

func fixtureLegacyFail2banUnused(t *testing.T) *legacyFail2banUnusedFixture {
	t.Helper()
	root, host, initial := fixtureLegacyFail2banVerifiedFilePlan(t)
	filter := "/etc/fail2ban/filter.d/syswarden-portscan.conf"
	writeNFTPersistenceFixture(t, root, filter, string(readLegacyFail2banFixture(t, "syswarden-portscan-filter.conf")))
	probe, err := newLegacyFail2banConfigurationProbe(host)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareLegacyFail2banRetirement(host, append(initial.binding.Targets, filter), probe)
	if err != nil {
		t.Fatal(err)
	}
	view, err := probe(plan.baseline, nil)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := decodeLegacyFail2banConfiguredActions(view.actionsEnabled)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &legacyFail2banUnusedFixture{host: host, plan: plan, live: legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail)}}
	for name, values := range actions {
		fixture.live.jails[name] = legacyFail2banRuntimeJail{actions: values, bans: []string{"127.0.0.4 \tfixture expiration"}}
	}
	original := fixtureLegacyFail2banOriginalPaths(plan)
	fixture.adapter = legacyFail2banUnusedAdapter{
		actions: actions,
		guard: func(ctx context.Context, published bool) error {
			if fixture.failure != nil {
				return fixture.failure
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if published {
				_, _, err := legacyFail2banRetirementProcessPaths(host, plan.binding, original)
				return err
			}
			return reattestLegacyFail2banPlanInventory(host, plan.baseline)
		},
		read: func(context.Context, bool) (legacyFail2banRuntimeSnapshot, error) {
			return cloneLegacyFail2banRuntimeFixture(fixture.live), nil
		},
	}
	return fixture
}

func TestLegacyFail2banUnusedRetirementPreservesAllJailsAndPrivateOriginals(t *testing.T) {
	fixture := fixtureLegacyFail2banUnused(t)
	before := cloneLegacyFail2banRuntimeFixture(fixture.live)
	for attempt := 0; attempt < 2; attempt++ {
		if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, defaultLegacyRetirementFileOps()); err != nil {
			t.Fatal("exact unused definitions could not be retired or resumed", err)
		}
		assertLegacyFail2banJournalComplete(t, fixture.host, fixture.plan)
		if !reflect.DeepEqual(before, fixture.live) {
			t.Fatal("file-only retirement changed runtime protection")
		}
	}
}

func TestLegacyFail2banUnusedRetirementResumesEveryFileBoundary(t *testing.T) {
	for _, phase := range []string{"plan-published", "unused-runtime-staged", "unused-runtime-durable", "intent-published", "source-retired", "retirement-durable", "plan-complete"} {
		t.Run(phase, func(t *testing.T) {
			fixture := fixtureLegacyFail2banUnused(t)
			interrupted := errors.New("synthetic unused-definition interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(current string) error {
				if current == phase {
					return interrupted
				}
				return nil
			}
			if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, ops); !errors.Is(err, interrupted) {
				t.Fatal("expected interruption was not reached", err)
			}
			// Recovery uses only the durable record, not an old inventory cache.
			record, err := readLegacyFail2banPlan(fixture.host, fixture.plan.sha256)
			if err != nil {
				t.Fatal(err)
			}
			fresh := legacyFail2banRetirementPlan{sha256: fixture.plan.sha256, binding: record}
			if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fresh, fresh.sha256, fixture.adapter, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("durable unused-definition plan could not resume", err)
			}
			assertLegacyFail2banJournalComplete(t, fixture.host, fixture.plan)
		})
	}
}

func TestLegacyFail2banUnusedRetirementRefusesLostProtection(t *testing.T) {
	for _, mutation := range []string{"guard", "ban", "action", "admin-source", "parser", "journal", "reappeared"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := fixtureLegacyFail2banUnused(t)
			ops := defaultLegacyRetirementFileOps()
			moved := 0
			retiredPath := ""
			ops.checkpoint = func(phase string) error {
				if phase != "source-retired" {
					return nil
				}
				moved++
				if moved != 1 {
					t.Fatal("retirement continued after loss of evidence or protection")
				}
				state, err := inspectLegacyFail2banPlanState(fixture.host, fixture.plan.binding)
				if err != nil || len(state.retired) != 1 {
					t.Fatal("intermediate retirement is not exactly one file", err)
				}
				for path := range state.retired {
					retiredPath = path
				}
				switch mutation {
				case "guard":
					fixture.failure = errors.New("independent producer guard failed")
				case "ban":
					jail := fixture.live.jails["administrator-active"]
					jail.bans = nil
					fixture.live.jails["administrator-active"] = jail
				case "action":
					fixture.live.jails["administrator-active"].actions["noop"]["actionban"] = fixtureLegacyFail2banRuntimeString("changed")
				case "admin-source":
					return fixture.host.root.WriteFile("etc/fail2ban/jail.d/admin.conf", []byte("[administrator-active]\nenabled=false\n"), 0600)
				case "parser":
					return fixture.host.root.WriteFile(strings.TrimPrefix(legacyFail2banLibrary, "/")+"/version.py", []byte("version='changed'\n"), 0600)
				case "journal":
					return fixture.host.root.Remove(strings.TrimPrefix(legacyFail2banPlanPath(fixture.plan.sha256), "/") + "/plan.json")
				case "reappeared":
					return fixture.host.root.WriteFile(strings.TrimPrefix(retiredPath, "/"), []byte("new administrator content"), 0600)
				}
				return nil
			}
			if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, ops); err == nil || moved != 1 {
				t.Fatal("changed protection was not refused immediately", err, moved)
			}
			if mutation != "reappeared" {
				if _, err := fixture.host.snapshot(retiredPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("first retired original was lost or recreated", err)
				}
			}
			for _, path := range fixture.plan.binding.Targets {
				if path != retiredPath {
					if _, err := fixture.host.snapshot(path); err != nil {
						t.Fatal("another active target changed after refusal", err)
					}
				}
			}
		})
	}
}

func TestLegacyFail2banUnusedRetirementRequiresExactPlanAndGuards(t *testing.T) {
	fixture := fixtureLegacyFail2banUnused(t)
	for _, mutation := range []string{"digest", "guard", "read", "actions", "ops", "views", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			adapter, plan, digest := fixture.adapter, fixture.plan, fixture.plan.sha256
			ops := defaultLegacyRetirementFileOps()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mutation {
			case "digest":
				digest = strings.Repeat("0", 64)
			case "guard":
				adapter.guard = nil
			case "read":
				adapter.read = nil
			case "actions":
				adapter.actions = nil
			case "ops":
				ops.checkpoint = nil
			case "views":
				plan.binding.Views[2][0] ^= 1
				_, plan.sha256, _ = encodeLegacyFail2banPlan(plan.binding, fixture.host.expectedUID, fixture.host.expectedGID)
				digest = plan.sha256
			case "canceled":
				cancel()
			}
			if err := retireUnusedLegacyFail2banFiles(ctx, fixture.host, plan, digest, adapter, ops); err == nil {
				t.Fatal("incomplete authorization or protection accepted")
			}
			if err := reattestLegacyFail2banPlanInventory(fixture.host, fixture.plan.baseline); err != nil {
				t.Fatal("refused inspection changed active sources", err)
			}
			if _, err := readLegacyFail2banPlan(fixture.host, digest); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused inspection published a durable plan", err)
			}
		})
	}
	if _, err := newLegacyFail2banUnusedAdapter(fixture.host, fixture.plan.binding, nil, nil); err == nil {
		t.Fatal("uninspected service accepted")
	}
	_, jailHost, jailPlan := fixtureLegacyFail2banJournal(t)
	// Even forged equal views cannot admit jail files into this file-only path.
	jailPlan.binding.Views[2], jailPlan.binding.Views[3] = jailPlan.binding.Views[0], jailPlan.binding.Views[1]
	if _, err := inspectUnusedLegacyFail2banPlan(jailHost, jailPlan.binding); err == nil {
		t.Fatal("jail retirement bypassed the runtime coordinator")
	}
}

func TestLegacyFail2banUnusedRetirementRejectsLostBanAcrossInvocations(t *testing.T) {
	for _, mutation := range []string{"lost-ban", "changed-expiration", "missing-evidence", "changed-evidence", "readable-evidence", "symlink-evidence"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := fixtureLegacyFail2banUnused(t)
			interrupted := errors.New("interrupted after one file")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(phase string) error {
				if phase == "source-retired" {
					return interrupted
				}
				return nil
			}
			if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, ops); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			path := strings.TrimPrefix(legacyFail2banPlanPath(fixture.plan.sha256), "/") + "/unused-runtime.json"
			var err error
			jail := fixture.live.jails["administrator-active"]
			switch mutation {
			case "lost-ban":
				jail.bans = nil
			case "changed-expiration":
				jail.bans = []string{"127.0.0.4 \tchanged expiration"}
			case "missing-evidence":
				err = fixture.host.root.Remove(path)
			case "changed-evidence":
				err = fixture.host.root.WriteFile(path, []byte("{}"), 0600)
			case "readable-evidence":
				err = fixture.host.root.Chmod(path, 0644)
			case "symlink-evidence":
				if err = fixture.host.root.Remove(path); err == nil {
					err = fixture.host.root.Symlink("plan.json", path)
				}
			}
			fixture.live.jails["administrator-active"] = jail
			if err != nil {
				t.Fatal(err)
			}
			if err := retireUnusedLegacyFail2banFiles(context.Background(), fixture.host, fixture.plan, fixture.plan.sha256, fixture.adapter, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("recovery accepted lost protection or changed runtime evidence")
			}
			state, err := inspectLegacyFail2banPlanState(fixture.host, fixture.plan.binding)
			if err != nil || len(state.retired) != 1 {
				t.Fatal("recovery moved more files after losing original protection evidence", err)
			}
			if mutation == "missing-evidence" {
				if _, err := fixture.host.root.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recovery recreated missing runtime evidence", err)
				}
			}
		})
	}
}

func TestLegacyFail2banUnusedRuntimeEvidenceIsPrivateAndBounded(t *testing.T) {
	live := legacyFail2banRuntimeSnapshot{jails: map[string]legacyFail2banRuntimeJail{
		"administrator": {bans: []string{"127.0.0.3 \texpiration two", "127.0.0.2 \texpiration one"}},
	}}
	digest := strings.Repeat("1", 64)
	content, err := encodeUnusedLegacyFail2banRuntime(digest, live)
	if err != nil || len(content) > 512 || strings.Contains(string(content), "127.0.0.") || strings.Contains(string(content), "administrator") {
		t.Fatal("private runtime evidence exposed source data or exceeded its bound", err)
	}
	jail := live.jails["administrator"]
	jail.bans[0], jail.bans[1] = jail.bans[1], jail.bans[0]
	again, err := encodeUnusedLegacyFail2banRuntime(digest, live)
	if err != nil || string(content) != string(again) {
		t.Fatal("runtime fingerprint depends on observation ordering", err)
	}
	for _, mutation := range []string{"digest", "duplicates", "oversized-ban", "newline", "nil"} {
		state := cloneLegacyFail2banRuntimeFixture(live)
		selected := digest
		jail := state.jails["administrator"]
		switch mutation {
		case "digest":
			selected = "../invalid"
		case "duplicates":
			jail.bans = append(jail.bans, jail.bans[0])
		case "oversized-ban":
			jail.bans = []string{strings.Repeat("x", 257) + "\ttime"}
		case "newline":
			jail.bans = []string{"127.0.0.2\tinvalid\ntime"}
		case "nil":
			state.jails = nil
		}
		if state.jails != nil {
			state.jails["administrator"] = jail
		}
		if _, err := encodeUnusedLegacyFail2banRuntime(selected, state); err == nil {
			t.Fatal("invalid runtime evidence was accepted", mutation)
		}
	}
}

// This opt-in integration fixture uses a real server, parser and kernel in a
// separate single-user network namespace. Its process/socket guard is a test
// adapter, not permission to retire files from the host service.
func TestLegacyFail2banUnusedLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_FAIL2BAN_UNUSED_LIVE") != "1" {
		t.Skip("requires the isolated unused-definition live fixture")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("live fixture requires a distinct single-user network namespace")
	}
	client := fixtureLegacyFail2banRuntimeClient(t)
	host := client.host
	parser, err := captureLegacyFail2banParser(host)
	if err != nil {
		t.Fatal(err)
	}
	probe := legacyFail2banConfigurationProbeUsingParser(host, parser)
	var plan legacyFail2banRetirementPlan
	digest, err := host.root.ReadFile("unused-plan.sha256")
	if errors.Is(err, os.ErrNotExist) {
		paths := []string{"/etc/fail2ban/action.d/syswarden-nft.conf", "/etc/fail2ban/action.d/syswarden-persistence.conf", "/etc/fail2ban/action.d/syswarden-webhook.conf", "/etc/fail2ban/filter.d/syswarden-portscan.conf"}
		plan, err = prepareLegacyFail2banRetirement(host, paths, probe)
		if err != nil {
			t.Fatal(err)
		}
		if err := host.root.WriteFile("unused-plan.sha256", []byte(plan.sha256), 0600); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	} else {
		record, err := readLegacyFail2banPlan(host, string(digest))
		if err != nil {
			t.Fatal(err)
		}
		plan = legacyFail2banRetirementPlan{sha256: string(digest), binding: record}
	}
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal(err)
	}
	view, err := probe(inventory, nil)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := decodeLegacyFail2banConfiguredActions(view.actionsEnabled)
	if err != nil {
		t.Fatal(err)
	}
	expected := fixtureLegacyFail2banOriginalPaths(legacyFail2banRetirementPlan{baseline: inventory})
	adapter := legacyFail2banUnusedAdapter{
		actions: actions,
		guard: func(ctx context.Context, published bool) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := client.guard(); err != nil {
				return err
			}
			if published {
				_, _, err := legacyFail2banRetirementProcessPaths(host, plan.binding, expected)
				return err
			}
			return reattestLegacyFail2banPlanInventory(host, inventory)
		},
		read: func(ctx context.Context, _ bool) (legacyFail2banRuntimeSnapshot, error) {
			return inspectLegacyFail2banRuntime(ctx, func(ctx context.Context, args []string) (legacyFail2banValue, error) {
				child, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				return client.query(child, args)
			})
		},
	}
	ops := defaultLegacyRetirementFileOps()
	if os.Getenv("SYSWARDEN_TEST_FAIL2BAN_UNUSED_EXIT") == "source-retired" {
		ops.checkpoint = func(phase string) error {
			if phase == "source-retired" {
				os.Exit(78)
			}
			return nil
		}
	}
	if err := retireUnusedLegacyFail2banFiles(context.Background(), host, plan, plan.sha256, adapter, ops); err != nil {
		t.Fatal(err)
	}
	state, err := inspectLegacyFail2banPlanState(host, plan.binding)
	if err != nil || len(state.retired) != 4 {
		t.Fatal("unused-definition retirement remains incomplete", err)
	}
	t.Log("Exact unused definitions retired with private originals and unchanged live administrator actions and bans.")
}

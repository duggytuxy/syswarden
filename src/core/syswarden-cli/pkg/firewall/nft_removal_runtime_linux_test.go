//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type nftRemovalFixtureRunner struct{ tables map[nftTableTarget][]byte }

func TestNFTRuntimeRetirementPinnedObserverScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nft-fixture")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\"\n"), 0700); err != nil { // #nosec G306 -- Owner-only inert executable fixture.
		t.Fatal(err)
	}
	fixtureLegacyFail2banNFTExecutable(t, path)
	runner, err := newExecNFTCommandRunner()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range syswardenNFTTables {
		args := []string{"-j", "list", "table", target.family, target.name}
		out, err := runner.Run(context.Background(), nil, args...)
		if err != nil || string(out) != strings.Join(args, " ")+"\n" {
			t.Fatal("bounded JSON observation failed", err)
		}
	}
	for _, args := range [][]string{
		{"-j", "list", "table", "inet", "administrator"},
		{"-j", "list", "table", "inet", "syswarden_wg"},
		{"-j", "delete", "table", "inet", "syswarden"},
		{"-j", "list", "table", "inet", "syswarden", "extra"},
	} {
		if _, err := runner.Run(context.Background(), nil, args...); err == nil {
			t.Fatal("unbound observer command accepted")
		}
	}
}

func (runner *nftRemovalFixtureRunner) Run(_ context.Context, input []byte, arguments ...string) ([]byte, error) {
	if len(input) != 0 {
		return nil, fmt.Errorf("fixture observer received mutation input")
	}
	if reflect.DeepEqual(arguments, []string{"-j", "list", "tables"}) {
		objects := []any{}
		for target := range runner.tables {
			objects = append(objects, map[string]any{"table": map[string]any{"family": target.family, "name": target.name}})
		}
		return json.Marshal(map[string]any{"nftables": objects})
	}
	if len(arguments) == 5 && arguments[0] == "-j" && arguments[1] == "list" && arguments[2] == "table" {
		wire, found := runner.tables[nftTableTarget{family: arguments[3], name: arguments[4]}]
		if !found {
			return nil, fmt.Errorf("fixture table absent")
		}
		return bytes.Clone(wire), nil
	}
	return nil, fmt.Errorf("fixture observer received an unexpected command")
}

type nftRemovalFixtureFence struct {
	run    func(context.Context, func() error) error
	closed bool
}

func (f *nftRemovalFixtureFence) apply(ctx context.Context, guard func() error) error {
	return f.run(ctx, guard)
}
func (f *nftRemovalFixtureFence) close() { f.closed = true }

func fixtureNFTCurrentRuntimePlan(t *testing.T, fixture nftCurrentFileFixture, retire bool) (nftPersistenceFilesystem, nftHistoricalPersistencePlan, func(string, string) error) {
	t.Helper()
	host, _, _ := fixtureNFTPersistenceGraphRecord(t)
	if err := host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.Source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	origins, producers := strings.Repeat("a", 64), strings.Repeat("b", 64)
	plan, err := prepareNFTCurrentPersistencePlan(host, []string{nftSharedFixturePath}, fixture.inputs(), origins, producers)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic authorities bind only these captured fixture inputs.
	guard := func(a, b string) error {
		if a != origins || b != producers {
			return fmt.Errorf("fixture authority changed")
		}
		return nil
	}
	if retire {
		if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
			t.Fatal(err)
		}
	}
	return host, plan, guard
}

func fixtureNFTCurrentRuntimeRunner(fixture nftCurrentFileFixture) *nftRemovalFixtureRunner {
	runner := &nftRemovalFixtureRunner{tables: map[nftTableTarget][]byte{
		{family: "inet", name: "syswarden"}:           fixture.InetJSON,
		{family: "netdev", name: "syswarden_hw_drop"}: fixture.NetdevJSON,
		{family: "inet", name: "administrator"}:       []byte(`{"nftables":[]}`),
	}}
	if fixture.ARP {
		runner.tables[nftTableTarget{family: "arp", name: "syswarden_arp"}] = fixture.ARPJSON
	}
	return runner
}

func TestNFTRuntimeRetirementOrdersDurableIntentAndResumes(t *testing.T) {
	for _, phase := range []string{"none", "kernel-retirement-intent-durable", "kernel-retirement-applied", "unconfirmed-kernel-outcome"} {
		t.Run(phase, func(t *testing.T) {
			fixture := fixtureNFTCurrentFiles(t)[7]
			host, plan, guard := fixtureNFTCurrentRuntimePlan(t, fixture, true)
			runner := fixtureNFTCurrentRuntimeRunner(fixture)
			applies := 0
			sentinel := errors.New("synthetic interruption")
			factory := func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
				targets, err := inspect(ctx)
				if err != nil {
					return nil, err
				}
				return &nftRemovalFixtureFence{run: func(_ context.Context, check func() error) error {
					if err := check(); err != nil {
						return err
					}
					journal, err := host.snapshot(legacyFail2banPlanPath(plan.sha256) + "/kernel-retirement.json")
					if err != nil || journal.identity.Mode().Perm() != 0600 {
						t.Fatal("kernel action preceded its durable private intent", err)
					}
					applies++
					for _, target := range targets {
						delete(runner.tables, target)
					}
					if phase == "unconfirmed-kernel-outcome" {
						return sentinel
					}
					return nil
				}}, nil
			}
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(current string) error {
				if current == phase {
					return sentinel
				}
				return nil
			}
			err := retireNFTCurrentRuntimeUsing(context.Background(), host, plan, plan.sha256, guard, runner, ops, factory)
			if phase == "none" && err != nil || phase != "none" && !errors.Is(err, sentinel) {
				t.Fatal("unexpected interruption result", err)
			}
			recovered, err := readNFTHistoricalPersistencePlan(host, plan.sha256)
			if err != nil {
				t.Fatal(err)
			}
			if err := retireNFTCurrentRuntimeUsing(context.Background(), host, recovered, recovered.sha256, guard, runner, defaultLegacyRetirementFileOps(), factory); err != nil {
				t.Fatal("runtime recovery failed", err)
			}
			if applies != 1 || len(runner.tables) != 1 || runner.tables[nftTableTarget{family: "inet", name: "administrator"}] == nil {
				t.Fatal("retirement touched unrelated state or repeated an already completed mutation")
			}
			if phase == "none" {
				if err := host.root.WriteFile((legacyFail2banPlanPath(plan.sha256) + "/kernel-retirement.json")[1:], []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := retireNFTCurrentRuntimeUsing(context.Background(), host, recovered, recovered.sha256, guard, runner, defaultLegacyRetirementFileOps(), factory); err == nil {
					t.Fatal("corrupt durable evidence was accepted after apparent completion")
				}
			}
		})
	}
}

func TestNFTRuntimeRetirementRefusesUnprovenStateBeforeMutation(t *testing.T) {
	for _, change := range []string{"active-source", "extra-table", "missing-table", "extra-address", "authority", "wrong-review", "source-change", "journal-change", "sync-failure"} {
		t.Run(change, func(t *testing.T) {
			fixture := fixtureNFTCurrentFiles(t)[7]
			host, plan, guard := fixtureNFTCurrentRuntimePlan(t, fixture, change != "active-source")
			runner := fixtureNFTCurrentRuntimeRunner(fixture)
			ops := defaultLegacyRetirementFileOps()
			reviewed := plan.sha256
			switch change {
			case "extra-table":
				runner.tables[nftTableTarget{family: "inet", name: "syswarden_table"}] = []byte(`{}`)
			case "missing-table":
				delete(runner.tables, nftTableTarget{family: "inet", name: "syswarden"})
			case "extra-address":
				runner.tables[nftTableTarget{family: "inet", name: "syswarden"}] = mutateNFTCurrentSet(t, fixture.InetJSON, "syswarden_whitelist", func(s map[string]any) { s["elem"] = append(s["elem"].([]any), "203.0.113.99") })
			case "authority":
				guard = func(string, string) error { return fmt.Errorf("producer changed") }
			case "wrong-review":
				reviewed = strings.Repeat("f", 64)
			case "source-change":
				ops.checkpoint = func(phase string) error {
					if phase == "kernel-retirement-intent-durable" {
						return host.root.WriteFile(legacyNFTIncludePath[1:], []byte(fixture.Source), 0600)
					}
					return nil
				}
			case "journal-change":
				ops.checkpoint = func(phase string) error {
					if phase == "kernel-retirement-intent-durable" {
						return host.root.WriteFile((legacyFail2banPlanPath(plan.sha256) + "/kernel-retirement.json")[1:], []byte(`{}`), 0600)
					}
					return nil
				}
			case "sync-failure":
				ops.sync = func(*os.File) error { return fmt.Errorf("synthetic synchronization failure") }
			}
			initial := len(runner.tables)
			factory := func(ctx context.Context, inspect func(context.Context) ([]nftTableTarget, error)) (nftRemovalFence, error) {
				if _, err := inspect(ctx); err != nil {
					return nil, err
				}
				return &nftRemovalFixtureFence{run: func(_ context.Context, check func() error) error {
					if err := check(); err != nil {
						return err
					}
					t.Fatal("unproven state crossed the kernel mutation boundary")
					return nil
				}}, nil
			}
			if err := retireNFTCurrentRuntimeUsing(context.Background(), host, plan, reviewed, guard, runner, ops, factory); err == nil {
				t.Fatal("unproven runtime accepted")
			}
			if len(runner.tables) != initial {
				t.Fatal("refusal changed runtime")
			}
		})
	}
}

func TestNFTRuntimeRetirementLiveFixture(t *testing.T) {
	runNFTRuntimeRetirementLiveFixture(t, false, false)
}

func TestNFTOwnedPolicyLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_OWNED_POLICY_LIVE") != "1" {
		t.Skip("requires a disposable owned-policy retirement namespace")
	}
	runNFTRuntimeRetirementLiveFixture(t, true, false)
}

func TestNFTRemovalSessionLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_REMOVAL_SESSION_LIVE") != "1" {
		t.Skip("requires a disposable removal-session namespace")
	}
	runNFTRuntimeRetirementLiveFixture(t, true, true)
}

func runNFTRuntimeRetirementLiveFixture(t *testing.T, owned, sessionMode bool) {
	if os.Getenv("SYSWARDEN_TEST_NFT_RUNTIME_RETIREMENT_LIVE") != "1" {
		t.Skip("requires a disposable runtime-retirement namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := func(binary string, input []byte, args ...string) []byte {
		t.Helper()
		if binary != "/usr/bin/nft" && binary != "/usr/bin/ip" {
			t.Fatal("unsupported fixture executable")
		}
		cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- Fixed fixture binaries in a verified disposable network namespace.
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command failed: %v: %s", err, out)
		}
		return out
	}
	nft := func(input []byte, args ...string) []byte { return command("/usr/bin/nft", input, args...) }
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), `"table"`) {
		t.Fatal("fixture namespace is not empty")
	}
	command("/usr/bin/ip", nil, "link", "set", "lo", "up")
	command("/usr/bin/ip", nil, "link", "add", "swv0", "type", "veth", "peer", "name", "swv1")
	allowed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = allowed.Close() }()
	blocked, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocked.Close() }()
	admin := fmt.Sprintf("table inet administrator {\n chain input {\n type filter hook input priority -50; policy accept;\n tcp dport %d drop\n }\n}\n", blocked.Addr().(*net.TCPAddr).Port)
	nft([]byte(admin), "-f", "-")
	traffic := func() {
		t.Helper()
		connection, err := net.DialTimeout("tcp4", allowed.Addr().String(), time.Second)
		if err != nil {
			t.Fatal("allowed administrator traffic failed", err)
		}
		_ = connection.Close()
		connection, err = net.DialTimeout("tcp4", blocked.Addr().String(), 150*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			t.Fatal("administrator protection was lost")
		}
	}
	// A private exact copy gives the installed executable the fixture UID in
	// this single-user mapping. Production executable validation is unchanged.
	binary, err := os.ReadFile("/usr/bin/nft")
	if err != nil {
		t.Fatal(err)
	}
	binaryDirectory := t.TempDir()
	binaryRoot, err := os.OpenRoot(binaryDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = binaryRoot.Close() }()
	binaryPath := filepath.Join(binaryDirectory, "nft-fixture")
	if err := binaryRoot.WriteFile("nft-fixture", binary, 0700); err != nil { // #nosec G306 -- Owner-only executable fixture copied from the installed nft binary.
		t.Fatal(err)
	}
	fixtureLegacyFail2banNFTExecutable(t, binaryPath)
	runner, err := newExecNFTCommandRunner()
	if err != nil {
		t.Fatal(err)
	}
	replay := []byte(admin)
	for index, fixture := range fixtureNFTCurrentFiles(t) {
		var host nftPersistenceFilesystem
		var plan nftHistoricalPersistencePlan
		var guard func(string, string) error
		var session *nftRemovalSession
		if sessionMode {
			host, _, _ = fixtureNFTOwnedPolicyPlan(t, fixture, "include", admin)
			installNFTPersistenceLoaderFixture(t, host)
			producers, err := inspectNFTRemovalProducersUsing(ctx, host, inspectNFTPersistenceLoader, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			session, err = prepareNFTRemovalSession(ctx, host, producers)
			if err != nil {
				t.Fatal(err)
			}
			plan, guard = session.plan, session.guard(ctx)
		} else if owned {
			host, plan, guard = fixtureNFTOwnedPolicyPlan(t, fixture, "include", admin)
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			preserved, err := host.root.ReadFile("etc/nftables.d/administrator.nft")
			if err != nil || string(preserved) != admin {
				t.Fatal("retirement changed the administrator's persistent protection", err)
			}
			replay = preserved
		} else {
			host, plan, guard = fixtureNFTCurrentRuntimePlan(t, fixture, true)
		}
		nft([]byte(fixture.Source), "-f", "-")
		traffic()
		if sessionMode {
			if err := session.inspectRuntime(ctx, runner); err != nil {
				t.Fatal("read-only session runtime inspection", err)
			}
			if err := applyNFTOwnedRemovalSources(host, plan, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			// Reopen the selected plan through a fresh session before mutation.
			session, err = prepareNFTRemovalSession(ctx, host, session.producers)
			if err != nil {
				t.Fatal(err)
			}
			plan, guard = session.plan, session.guard(ctx)
			preserved, err := host.root.ReadFile("etc/nftables.d/administrator.nft")
			if err != nil || string(preserved) != admin {
				t.Fatal("administrator persistence changed", err)
			}
			replay = preserved
		}
		ops := defaultLegacyRetirementFileOps()
		if index == 7 {
			// A real administrator change after live inspection must invalidate
			// the kernel generation instead of being deleted with the table.
			ops.checkpoint = func(phase string) error {
				if phase == "kernel-retirement-inspected" {
					nft(nil, "add", "rule", "inet", "syswarden", "docker_protect", "counter")
				}
				return nil
			}
			if err := retireNFTCurrentRuntime(ctx, host, plan, plan.sha256, guard, runner, ops, nil); err == nil {
				t.Fatal("concurrent administrator transaction did not invalidate the generation")
			}
			traffic()
			if err := retireNFTCurrentRuntime(ctx, host, plan, plan.sha256, guard, runner, defaultLegacyRetirementFileOps(), nil); err == nil {
				t.Fatal("subsequent inspection adopted the administrator rule")
			}
			if !strings.Contains(string(nft(nil, "list", "table", "inet", "syswarden")), "counter packets") {
				t.Fatal("administrator addition was removed")
			}
			// Explicit fixture teardown is confined to this disposable namespace.
			nft(nil, "delete", "table", "inet", "syswarden")
			nft(nil, "delete", "table", "netdev", "syswarden_hw_drop")
			if fixture.ARP {
				nft(nil, "delete", "table", "arp", "syswarden_arp")
			}
		} else {
			if err := retireNFTCurrentRuntime(ctx, host, plan, plan.sha256, guard, runner, ops, nil); err != nil {
				t.Fatal(err)
			}
			traffic()
			if err := retireNFTCurrentRuntime(ctx, host, plan, plan.sha256, guard, runner, ops, nil); err != nil {
				t.Fatal("completed runtime could not be reconciled", err)
			}
		}
	}
	traffic()
	nft(nil, "delete", "table", "inet", "administrator")
	nft(replay, "-f", "-")
	traffic()
	if strings.Contains(string(nft(nil, "-j", "list", "tables")), "syswarden") {
		t.Fatal("retired product state reappeared")
	}
	t.Log("Durable source and kernel retirement preserve allowed and blocked administrator traffic. Concurrent rules invalidate the atomic deletion and survive fresh inspection. Persistence replay does not recreate product tables; no host reboot qualification is claimed.")
	if owned {
		t.Log("The private writer receipt authorizes the dedicated product source. Replay uses the exact retained administrator file. Product-loader quiescence remains a synthetic fixture authority.")
	}
}

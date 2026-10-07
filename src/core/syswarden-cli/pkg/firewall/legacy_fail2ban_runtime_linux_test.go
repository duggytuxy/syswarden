//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixtureLegacyFail2banRuntimeString(value string) legacyFail2banValue {
	return legacyFail2banValue{kind: 's', text: value}
}

func fixtureLegacyFail2banRuntimeList(values ...string) legacyFail2banValue {
	result := legacyFail2banValue{kind: 'l'}
	for _, value := range values {
		result.items = append(result.items, fixtureLegacyFail2banRuntimeString(value))
	}
	return result
}

func fixtureLegacyFail2banRuntimeStatus(names ...string) legacyFail2banValue {
	return legacyFail2banValue{kind: 'l', items: []legacyFail2banValue{
		{kind: 't', items: []legacyFail2banValue{fixtureLegacyFail2banRuntimeString("Number of jail"), {kind: 'i', number: int64(len(names))}}},
		{kind: 't', items: []legacyFail2banValue{fixtureLegacyFail2banRuntimeString("Jail list"), fixtureLegacyFail2banRuntimeString(strings.Join(names, ", "))}},
	}}
}

func fixtureLegacyFail2banRuntimeQuery(_ context.Context, args []string) (legacyFail2banValue, error) {
	switch strings.Join(args, " ") {
	case "version":
		return fixtureLegacyFail2banRuntimeString("1.1.0"), nil
	case "status":
		return fixtureLegacyFail2banRuntimeStatus("administrator-web", "syswarden-portscan"), nil
	}
	if len(args) >= 3 && args[0] == "get" {
		switch args[2] {
		case "banip":
			return fixtureLegacyFail2banRuntimeList("192.0.2.1 \t2026-01-01 00:00:00 + 3600 = 2026-01-01 01:00:00"), nil
		case "actions":
			return fixtureLegacyFail2banRuntimeList("syswarden-nft"), nil
		case "actionproperties":
			return fixtureLegacyFail2banRuntimeList("actionstop", "name"), nil
		case "action":
			if args[4] == "__module__" {
				return fixtureLegacyFail2banRuntimeString("fail2ban.server.action"), nil
			}
			if args[4] == "name" {
				return fixtureLegacyFail2banRuntimeString(args[1]), nil
			}
			return fixtureLegacyFail2banRuntimeString("nft delete chain inet fixture " + args[1]), nil
		}
	}
	return legacyFail2banValue{}, fmt.Errorf("unexpected fixture query")
}

func TestLegacyFail2banRuntimePreservesSharedAdministratorActionsAndBans(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before, err := inspectLegacyFail2banRuntime(ctx, fixtureLegacyFail2banRuntimeQuery)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"none", "retired", "ban", "action", "new-action", "missing-admin", "new-jail", "target-remains"} {
		t.Run(change, func(t *testing.T) {
			after, err := inspectLegacyFail2banRuntime(ctx, fixtureLegacyFail2banRuntimeQuery)
			if err != nil {
				t.Fatal(err)
			}
			retired := map[string]bool{}
			admin := after.jails["administrator-web"]
			switch change {
			case "retired":
				delete(after.jails, "syswarden-portscan")
				retired["syswarden-portscan"] = true
			case "ban":
				admin.bans = nil
			case "action":
				admin.actions["syswarden-nft"]["actionstop"] = fixtureLegacyFail2banRuntimeString("changed")
			case "new-action":
				admin.actions["unexpected-action"] = nil
			case "new-jail":
				after.jails["new-admin"] = admin
			case "target-remains":
				retired["syswarden-portscan"] = true
			}
			after.jails["administrator-web"] = admin
			if change == "missing-admin" {
				delete(after.jails, "administrator-web")
			}
			err = verifyLegacyFail2banRuntimePreservation(before, after, retired)
			if (err == nil) != (change == "none" || change == "retired") {
				t.Fatal("unexpected preservation outcome", change, err)
			}
		})
	}
}

func TestLegacyFail2banRuntimeRejectsUnstableOrUnsupportedObservations(t *testing.T) {
	for _, kind := range []string{"version", "membership", "duplicate-actions", "invalid-ban", "count", "query-failure", "custom-action", "duplicate-properties", "private-property", "query-limit"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			statuses := 0
			query := func(ctx context.Context, args []string) (legacyFail2banValue, error) {
				value, err := fixtureLegacyFail2banRuntimeQuery(ctx, args)
				if err != nil {
					return value, err
				}
				if args[0] == "status" {
					statuses++
					if kind == "membership" && statuses == 2 {
						return fixtureLegacyFail2banRuntimeStatus("administrator-web"), nil
					}
					if kind == "count" {
						value.items[0].items[1].number = 3
					}
					if kind == "query-limit" {
						names := make([]string, 128)
						for i := range names {
							names[i] = fmt.Sprintf("admin%d", i)
						}
						return fixtureLegacyFail2banRuntimeStatus(names...), nil
					}
				}
				if kind == "version" && args[0] == "version" {
					value.text = "2.0.0"
				}
				if len(args) > 2 {
					switch {
					case kind == "duplicate-actions" && args[2] == "actions":
						value = fixtureLegacyFail2banRuntimeList("nft", "nft")
					case kind == "invalid-ban" && args[2] == "banip":
						value = fixtureLegacyFail2banRuntimeList("not-an-address")
					case kind == "custom-action" && args[2] == "action" && args[4] == "__module__":
						value = fixtureLegacyFail2banRuntimeString("administrator_plugin")
					case kind == "query-failure" && args[2] == "action":
						return legacyFail2banValue{}, fmt.Errorf("fixture server unavailable")
					case kind == "duplicate-properties" && args[2] == "actionproperties":
						value = fixtureLegacyFail2banRuntimeList("name", "name")
					case kind == "private-property" && args[2] == "actionproperties":
						value = fixtureLegacyFail2banRuntimeList("__class__")
					case kind == "query-limit" && args[2] == "actionproperties":
						keys := make([]string, 128)
						for i := range keys {
							keys[i] = fmt.Sprintf("property%d", i)
						}
						value = fixtureLegacyFail2banRuntimeList(keys...)
					}
				}
				return value, nil
			}
			snapshot, err := inspectLegacyFail2banRuntime(ctx, query)
			if err == nil || snapshot.jails != nil {
				t.Fatal("unsafe or partial runtime observation accepted")
			}
		})
	}
}

// This optional fixture connects only to a separate test instance. The caller
// supplies its private filesystem root and PID; it is not a production service
// attestor and must never be used as permission to change host protections.
func fixtureLegacyFail2banRuntimeClient(t *testing.T) legacyFail2banReadOnlySocket {
	t.Helper()
	path := os.Getenv("SYSWARDEN_FAIL2BAN_RUNTIME_FIXTURE_ROOT")
	if path == "" {
		t.Skip("set an isolated Fail2ban fixture root and PID")
	}
	pid, err := strconv.ParseInt(os.Getenv("SYSWARDEN_FAIL2BAN_RUNTIME_FIXTURE_PID"), 10, 32)
	if err != nil || pid <= 0 {
		t.Fatal("invalid fixture PID")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	host := fixtureNFTPersistencePinnedRoot(t, root)
	peer := syscall.Ucred{Pid: int32(pid), Uid: host.expectedUID, Gid: host.expectedGID}
	var arguments []string
	if err := json.Unmarshal([]byte(os.Getenv("SYSWARDEN_FAIL2BAN_RUNTIME_PROCESS_ARGUMENTS")), &arguments); err != nil || len(arguments) < 2 {
		t.Fatal("the isolated launcher must provide its exact fixture process arguments")
	}
	proc, err := os.OpenRoot("/proc/" + strconv.FormatInt(pid, 10))
	if err != nil {
		t.Fatal(err)
	}
	cgroup, err := readLegacyFail2banProcessFile(proc, "cgroup", 16384)
	_ = proc.Close()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Stat(arguments[0])
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.Stat(arguments[1])
	if err != nil {
		t.Fatal(err)
	}
	process, err := bindLegacyFail2banProcess(peer, legacyFail2banProcessExpectation{
		executable: executable, arguments: arguments, cgroup: cgroup,
		paths: map[string]os.FileInfo{arguments[0]: executable, arguments[1]: script},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Close() })
	return legacyFail2banReadOnlySocket{host: host, path: "/control.sock", peer: peer, guard: process.verify}
}

func TestLegacyFail2banRuntimeLiveFixture(t *testing.T) {
	client := fixtureLegacyFail2banRuntimeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	query := func(ctx context.Context, args []string) (legacyFail2banValue, error) {
		value, err := client.query(ctx, args)
		if err != nil {
			t.Logf("Isolated fixture query failed: %q", args)
		}
		return value, err
	}
	before, err := inspectLegacyFail2banRuntime(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	after, err := inspectLegacyFail2banRuntime(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyFail2banRuntimePreservation(before, after, nil); err != nil {
		t.Fatal(err)
	}
	if _, found := after.jails["administrator-web"]; !found {
		t.Fatal("administrator fixture absent")
	}
	if len(after.jails["administrator-web"].bans) != 1 {
		t.Fatal("administrator fixture ban absent")
	}
	if os.Getenv("SYSWARDEN_FAIL2BAN_RUNTIME_EXPECT_RETIRED") == "1" {
		if _, found := after.jails["syswarden-portscan"]; found {
			t.Fatal("retired target remains active")
		}
	} else if _, found := after.jails["syswarden-portscan"]; !found {
		t.Fatal("historical target fixture absent")
	}
	t.Log("Authenticated non-executing runtime inspection and repeated administrator-state comparison passed.")
}

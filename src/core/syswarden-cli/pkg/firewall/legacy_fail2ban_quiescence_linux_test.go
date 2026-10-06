//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestLegacyFail2banRetirementTransportCannotIssueGlobalOrExecutableCommands(t *testing.T) {
	for _, command := range [][]string{
		{"stop"}, {"stop", "--all"}, {"stop", "-invalid"}, {"reload"}, {"unban", "--all"},
		{"set", "target", "idle", "off"}, {"set", "target", "unbanip", "192.0.2.1"},
		{"set", "target", "action", "nft", "actionstop", "nft flush ruleset"},
		{"set", "target", "action", "nft", "stop", ""},
		{"set", "target", "action", "nft", "__class__", ""},
		{"set", "target", "action", "nft", "actionstop?family=unknown", ""},
		{"set", "target", "action", "nft", "actionstart_on_demand", ""},
		{"set", "target;sh", "idle", "on"},
	} {
		if encoded, err := encodeLegacyFail2banRetirementCommand(command); err == nil || encoded != nil {
			t.Fatal("unsafe transition could be encoded", command)
		}
	}
	for _, command := range [][]string{
		{"stop", "target"}, {"set", "target", "idle", "on"},
		{"set", "target", "action", "nft", "actionstop", ""},
		{"set", "target", "action", "nft", "actionstop?family=inet6", ""},
	} {
		if _, err := encodeLegacyFail2banRetirementCommand(command); err != nil {
			t.Fatal(err)
		}
		if _, err := encodeLegacyFail2banQuery(command); err == nil {
			t.Fatal("read-only transport accepted a retirement command")
		}
	}
}

func TestLegacyFail2banRetirementSocketRequiresRepeatedDurableAuthorization(t *testing.T) {
	command := []string{"stop", "target"}
	encoded, err := encodeLegacyFail2banRetirementCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"valid", "nil", "deny-before", "deny-send", "deny-after", "wrong-peer", "wrong-ack"} {
		t.Run(kind, func(t *testing.T) {
			reply := []byte("\x80\x02K\x00N\x86." + legacyFail2banEnd)
			if kind == "wrong-ack" {
				reply = []byte("\x80\x02K\x00\x88\x86." + legacyFail2banEnd)
			}
			client, received := fixtureLegacyFail2banSocketRequest(t, encoded, reply, nil, false)
			checks := 0
			authorize := func(_ context.Context, actual []string) error {
				checks++
				if !reflect.DeepEqual(command, actual) {
					return fmt.Errorf("transition differs from fixture intent")
				}
				if kind == "deny-before" || kind == "deny-send" && checks == 2 || kind == "deny-after" && checks == 3 {
					return fmt.Errorf("fixture durable intent unavailable")
				}
				return nil
			}
			if kind == "nil" {
				authorize = nil
			}
			if kind == "wrong-peer" {
				client.peer.Pid++
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := (legacyFail2banRetirementSocket{client: client, authorize: authorize}).command(ctx, command)
			if kind == "valid" {
				if err != nil || received.Load() != 1 || checks != 3 {
					t.Fatal("authorized targeted transition failed", err, checks)
				}
			} else if err == nil {
				t.Fatal("unconfirmed transition accepted")
			} else if kind != "deny-after" && kind != "wrong-ack" && received.Load() != 0 {
				t.Fatal("unauthorized transition was sent")
			}
		})
	}
}

func fixtureLegacyFail2banQuiescenceState() legacyFail2banRuntimeSnapshot {
	properties := make(map[string]legacyFail2banValue)
	for _, hook := range []string{"actionstart", "actionban", "actionreban", "actionunban", "actioncheck", "actionrepair", "actionflush", "actionstop", "actionreload", "actionstop?family=inet6", "actionprolong"} {
		properties[hook] = fixtureLegacyFail2banRuntimeString("must never execute")
	}
	properties["actionstart_on_demand"] = legacyFail2banValue{kind: 0x88}
	return legacyFail2banRuntimeSnapshot{jails: map[string]legacyFail2banRuntimeJail{
		"target":        {actions: map[string]map[string]legacyFail2banValue{"nft": properties}},
		"administrator": {actions: map[string]map[string]legacyFail2banValue{"custom": {"actionstop": fixtureLegacyFail2banRuntimeString("preserve")}}},
	}}
}

func TestLegacyFail2banQuiescencePlansOnlyTargetHooksBeforeStop(t *testing.T) {
	live := fixtureLegacyFail2banQuiescenceState()
	commands, err := planLegacyFail2banQuiescence(live, map[string]bool{"target": true, "inactive-owned": true})
	if err != nil || len(commands) != 13 || !reflect.DeepEqual(commands[0], []string{"set", "target", "idle", "on"}) || !reflect.DeepEqual(commands[len(commands)-1], []string{"stop", "target"}) {
		t.Fatal("invalid targeted phase ordering", commands, err)
	}
	for _, command := range commands {
		if command[1] != "target" {
			t.Fatal("administrator or inactive jail included")
		}
		encoded, err := encodeLegacyFail2banRetirementCommand(command)
		if err != nil || bytes.Contains(encoded, []byte("must never execute")) {
			t.Fatal("plan contains executable hook bytes", err)
		}
	}
	if live.jails["administrator"].actions["custom"]["actionstop"].text != "preserve" {
		t.Fatal("planning changed administrator state")
	}
	for _, kind := range []string{"missing", "method", "conditional", "too-many", "empty-target", "global-target"} {
		t.Run(kind, func(t *testing.T) {
			live := fixtureLegacyFail2banQuiescenceState()
			targets := map[string]bool{"target": true}
			properties := live.jails["target"].actions["nft"]
			switch kind {
			case "missing":
				delete(properties, "actionunban")
			case "method":
				properties["actionstop"] = legacyFail2banValue{kind: 'N'}
			case "conditional":
				properties["actionstop?family=unknown"] = fixtureLegacyFail2banRuntimeString("unsafe")
			case "too-many":
				for i := 0; i < 129; i++ {
					properties[fmt.Sprintf("value%d", i)] = fixtureLegacyFail2banRuntimeString("")
				}
			case "empty-target":
				targets = nil
			case "global-target":
				targets = map[string]bool{"--all": true}
			}
			if commands, err := planLegacyFail2banQuiescence(live, targets); err == nil || commands != nil {
				t.Fatal("incomplete or unsupported evidence accepted", kind)
			}
		})
	}
}

// Fixture-only authorization is deliberately separate from production
// ownership and journal recovery. The isolated harness supplies the process,
// synthetic jail and private directory. This test changes no host service.
func TestLegacyFail2banQuiescenceLiveFixture(t *testing.T) {
	client := fixtureLegacyFail2banRuntimeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	query := func(ctx context.Context, args []string) (legacyFail2banValue, error) {
		child, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		return client.query(child, args)
	}
	before, err := inspectLegacyFail2banRuntime(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]bool{"syswarden-portscan": true}
	if _, present := before.jails["syswarden-portscan"]; !present {
		t.Fatal("fixture target is not active")
	}
	commands, err := planLegacyFail2banQuiescence(before, targets)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := json.Marshal(commands)
	if err != nil {
		t.Fatal(err)
	}
	path := "/private-backup/quiescence-fixture.json"
	file, err := client.host.root.OpenFile(path[1:], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if _, err := file.Write(intent); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		directory, err := client.host.root.Open("private-backup")
		if err != nil {
			t.Fatal(err)
		}
		if err := directory.Sync(); err != nil {
			t.Fatal(err)
		}
		_ = directory.Close()
	} else if !os.IsExist(err) {
		t.Fatal(err)
	}
	expected, err := client.host.snapshot(path)
	if err != nil || !bytes.Equal(expected.content, intent) {
		t.Fatal("fixture intent differs from its original transitions", err)
	}
	index := 0
	writer := legacyFail2banRetirementSocket{client: client, authorize: func(_ context.Context, command []string) error {
		current, err := client.host.snapshot(path)
		if err != nil || !sameLegacyFail2banSource(expected, current) || sha256.Sum256(current.content) != sha256.Sum256(intent) || !reflect.DeepEqual(command, commands[index]) {
			return fmt.Errorf("fixture durable transition evidence changed")
		}
		return nil
	}}
	for ; index < len(commands); index++ {
		command := commands[index]
		if command[0] == "stop" {
			current, err := inspectLegacyFail2banRuntime(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			for _, properties := range current.jails["syswarden-portscan"].actions {
				for key, value := range properties {
					if legacyFail2banHookProperty(key) && (value.kind != 's' || value.text != "") {
						t.Fatal("target hook remains executable before stop")
					}
				}
			}
		}
		child, done := context.WithTimeout(ctx, 5*time.Second)
		err := writer.command(child, command)
		done()
		if err != nil {
			t.Fatal(err)
		}
		if len(command) == 6 && os.Getenv("SYSWARDEN_FAIL2BAN_QUIESCENCE_EXIT") == "hook-cleared" {
			os.Exit(75)
		}
	}
	after, err := inspectLegacyFail2banRuntime(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyFail2banRuntimePreservation(before, after, targets); err != nil {
		t.Fatal(err)
	}
	t.Log("Target hooks cleared before targeted stop; administrator actions and bans preserved; kernel cleanup remains separate")
}

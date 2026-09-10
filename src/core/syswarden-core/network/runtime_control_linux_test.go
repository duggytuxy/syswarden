//go:build linux

package network

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runtimeControlTestDirectory(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("", "sw-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	return path
}

func callRuntimeControlFixture(t *testing.T, path, request string) []byte {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	wire, err := io.ReadAll(io.LimitReader(connection, 4096))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestRuntimeControlAuthenticatesAndCommitsNativeDeletion(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	if err := manager.Ban("192.0.2.60"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runtimeControlTestDirectory(t), "control.sock")
	server, err := startRuntimeControlServerAt(path, os.Geteuid(), manager)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	for _, action := range []string{"preflight", "unban"} {
		wire := callRuntimeControlFixture(t, path, `{"version":1,"action":"`+action+`","entry":"192.0.2.60"}`)
		var response runtimeControlResponse
		if err := json.Unmarshal(wire, &response); err != nil || !response.OK || response.Version != 1 {
			t.Fatalf("authenticated control failed: %s, %v", wire, err)
		}
	}
	if native.entries["192.0.2.60"].Present {
		t.Fatal("control operation did not remove native enforcement")
	}
	snapshot, err := manager.RuntimeLifecycleStateSnapshot(1024)
	if err != nil || snapshot.Deleted != 1 {
		t.Fatalf("control deletion was not linked to durable history: %+v, %v", snapshot, err)
	}
	server.Stop()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket remained after shutdown: %v", err)
	}
}

func TestRuntimeControlRejectsMalformedRequestsBeforeMutation(t *testing.T) {
	manager, _ := lifecycleManagerFixture(t)
	path := filepath.Join(runtimeControlTestDirectory(t), "control.sock")
	server, err := startRuntimeControlServerAt(path, os.Geteuid(), manager)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	for name, request := range map[string]string{
		"duplicate":        `{"version":1,"version":1,"action":"unban","entry":"192.0.2.60"}`,
		"unknown":          `{"version":1,"action":"unban","entry":"192.0.2.60","extra":true}`,
		"wrong-action":     `{"version":1,"action":"ban","entry":"192.0.2.60"}`,
		"mapped-address":   `{"version":1,"action":"unban","entry":"::ffff:192.0.2.60"}`,
		"trailing-command": `{"version":1,"action":"unban","entry":"192.0.2.60"} {"version":1}`,
		"oversized":        strings.Repeat(" ", 2049),
	} {
		t.Run(name, func(t *testing.T) {
			if wire := callRuntimeControlFixture(t, path, request); len(wire) != 0 {
				t.Fatalf("malformed command received a success-capable response: %s", wire)
			}
		})
	}
	model, pending, err := manager.store.load()
	if err != nil || pending != nil || model.Sequence != 1 {
		t.Fatalf("malformed request mutated durable state: %+v, %v", model, err)
	}
}

func TestRuntimeControlRefusesLiveOrNonSocketReplacement(t *testing.T) {
	manager, _ := lifecycleManagerFixture(t)
	directory := runtimeControlTestDirectory(t)
	path := filepath.Join(directory, "control.sock")
	server, err := startRuntimeControlServerAt(path, os.Geteuid(), manager)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	if second, err := startRuntimeControlServerAt(path, os.Geteuid(), manager); err == nil {
		second.Stop()
		t.Fatal("live control socket was replaced")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("operator-file", []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := startRuntimeControlServerAt(filepath.Join(directory, "operator-file"), os.Geteuid(), manager); err == nil {
		other.Stop()
		t.Fatal("non-socket operator file was replaced")
	}
	wire, err := root.ReadFile("operator-file")
	if err != nil || string(wire) != "preserve" {
		t.Fatal("unrelated operator file changed")
	}
}

func TestRuntimeControlRejectsActualPeerWithUnexpectedUID(t *testing.T) {
	manager, _ := lifecycleManagerFixture(t)
	path := filepath.Join(runtimeControlTestDirectory(t), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, err := io.WriteString(client, `{"version":1,"action":"unban","entry":"192.0.2.60"}`); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	server := &RuntimeControlServer{ownerUID: os.Geteuid() + 1, manager: manager}
	server.handle(accepted)
	_ = accepted.Close()
	wire, _ := io.ReadAll(io.LimitReader(client, 4096))
	if len(wire) != 0 {
		t.Fatalf("unexpected peer UID received a response: %s", wire)
	}
	model, pending, err := manager.store.load()
	if err != nil || pending != nil || model.Sequence != 1 {
		t.Fatal("unexpected peer UID changed durable state")
	}
}

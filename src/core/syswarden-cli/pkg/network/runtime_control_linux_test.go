//go:build linux

package network

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runtimeControlClientFixture(t *testing.T, response string) (string, <-chan string) {
	t.Helper()
	directory, err := os.MkdirTemp("", "sw-client-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod("control.sock", 0600); err != nil {
		t.Fatal(err)
	}
	_ = root.Close()
	requests := make(chan string, 1)
	go func() {
		defer close(requests)
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		wire, err := io.ReadAll(io.LimitReader(connection, 2049))
		if err != nil {
			return
		}
		requests <- string(wire)
		_, _ = io.WriteString(connection, response)
	}()
	return path, requests
}

func TestRuntimeControlClientUsesAuthenticatedBoundedProtocol(t *testing.T) {
	path, requests := runtimeControlClientFixture(t, "{\"version\":1,\"ok\":true}\n")
	if err := requestRuntimeControlAt(context.Background(), path, os.Geteuid(), "unban", "192.0.2.90"); err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(<-requests), &request); err != nil {
		t.Fatal(err)
	}
	if len(request) != 3 || request["action"] != "unban" || request["entry"] != "192.0.2.90" || request["version"] != float64(1) {
		t.Fatalf("unexpected core command: %v", request)
	}
}

func TestRuntimeControlClientRefusesAmbiguousOrMalformedReplies(t *testing.T) {
	for name, response := range map[string]string{
		"empty":          "",
		"missing-result": `{"version":1}`,
		"wrong-version":  `{"version":2,"ok":true}`,
		"duplicate":      `{"version":1,"ok":false,"ok":true}`,
		"unknown-field":  `{"version":1,"ok":true,"other":1}`,
		"contradictory":  `{"version":1,"ok":true,"error":"failed"}`,
		"refusal":        `{"version":1,"ok":false,"error":"fenced"}`,
		"trailing":       `{"version":1,"ok":true} {}`,
		"oversized":      strings.Repeat("x", 2049),
	} {
		t.Run(name, func(t *testing.T) {
			path, _ := runtimeControlClientFixture(t, response)
			if err := requestRuntimeControlAt(context.Background(), path, os.Geteuid(), "unban", "192.0.2.90"); err == nil {
				t.Fatal("invalid or ambiguous core result became success")
			}
		})
	}
}

func TestRuntimeControlClientRejectsEndpointLookalikesAndInvalidTargets(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("control.sock", []byte("operator file"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	if err := requestRuntimeControlAt(context.Background(), path, os.Geteuid(), "unban", "192.0.2.90"); err == nil {
		t.Fatal("regular file was used as a control endpoint")
	}
	for _, entry := range []string{"192.0.2.1/24", "::ffff:192.0.2.90", "fe80::1%eth0", "192.0.2.90\n"} {
		if err := requestRuntimeControlAt(context.Background(), path, os.Geteuid(), "unban", entry); err == nil {
			t.Fatalf("noncanonical target accepted: %q", entry)
		}
	}
	wire, err := root.ReadFile("control.sock")
	if err != nil || string(wire) != "operator file" {
		t.Fatal("control endpoint lookalike was modified")
	}
}

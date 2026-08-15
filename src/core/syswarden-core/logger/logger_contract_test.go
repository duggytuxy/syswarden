package logger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func readLoggerTestFile(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	wire, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestPersistentBlocklistWriterIsAtomicCanonicalAndFailClosed_SW_HA_003(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden_blacklist.ipv4")
	for _, entry := range []string{"198.51.100.9", "198.51.100.7", "198.51.100.9", "203.0.113.9/24"} {
		if err := UpdatePersistentBlocklist(path, entry, true); err != nil {
			t.Fatal(err)
		}
	}
	wire := readLoggerTestFile(t, path)
	if string(wire) != "198.51.100.7\n198.51.100.9\n203.0.113.0/24\n" {
		t.Fatalf("canonical deduplicated blocklist = %q", wire)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("published blocklist info=%v err=%v", info, err)
	}
	if err := UpdatePersistentBlocklist(path, "198.51.100.9", false); err != nil {
		t.Fatal(err)
	}
	wire = readLoggerTestFile(t, path)
	if string(wire) != "198.51.100.7\n203.0.113.0/24\n" {
		t.Fatalf("atomic removal = %q", wire)
	}

	const workers = 64
	var wait sync.WaitGroup
	for index := 1; index <= workers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := UpdatePersistentBlocklist(path, "192.0.2."+strconv.Itoa(index), true); err != nil {
				t.Errorf("concurrent persistence: %v", err)
			}
		}()
	}
	wait.Wait()
	wire = readLoggerTestFile(t, path)
	if got := len(strings.Fields(string(wire))); got != workers+2 {
		t.Fatalf("concurrent atomic writer retained %d entries, want %d", got, workers+2)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "operator-target")
	if err := os.WriteFile(target, []byte("operator data\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := UpdatePersistentBlocklist(path, "198.51.100.100", true); err == nil {
		t.Fatal("persistent blocklist writer accepted a symlink destination")
	}
	targetWire := readLoggerTestFile(t, target)
	if !reflect.DeepEqual(targetWire, []byte("operator data\n")) {
		t.Fatalf("symlink target changed: %q", targetWire)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	insecureRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer insecureRoot.Close()
	insecureFile, err := insecureRoot.OpenFile(filepath.Base(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insecureFile.Write([]byte("198.51.100.11\n")); err != nil {
		_ = insecureFile.Close()
		t.Fatal(err)
	}
	if err := insecureFile.Chmod(0644); err != nil {
		_ = insecureFile.Close()
		t.Fatal(err)
	}
	if err := insecureFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := UpdatePersistentBlocklist(path, "198.51.100.12", true); err == nil {
		t.Fatal("persistent blocklist writer accepted an insecure destination mode")
	}
	if wire := readLoggerTestFile(t, path); string(wire) != "198.51.100.11\n" {
		t.Fatalf("insecure destination changed despite rejection: %q", wire)
	}

	realParent := t.TempDir()
	realChild := filepath.Join(realParent, "real-child")
	if err := os.Mkdir(realChild, 0700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked-ancestor")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if err := UpdatePersistentBlocklist(filepath.Join(linkedParent, "real-child", "syswarden_blacklist.ipv4"), "198.51.100.12", true); err == nil {
		t.Fatal("persistent blocklist writer accepted a symbolic-link ancestor")
	}
	if _, err := os.Lstat(filepath.Join(realChild, "syswarden_blacklist.ipv4")); !os.IsNotExist(err) {
		t.Fatalf("symbolic-link ancestor target was mutated: %v", err)
	}
	if err := UpdatePersistentBlocklist(directory+"/./syswarden_blacklist.ipv4", "198.51.100.12", true); err == nil {
		t.Fatal("persistent blocklist writer accepted a non-canonical path")
	}
}

func TestLocalCheckTelemetryPreservesStructuredCompatibility_SW_DOC_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	l := NewLogger(path)
	l.LogComplianceDrift("selected local check observed a deviation")
	l.LogComplianceOK("selected local checks found no deviation")
	l.Close()

	content, err := os.ReadFile(path) // #nosec G304 -- path is a test-owned temporary file
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("telemetry event count = %d, want 2", len(lines))
	}
	for index, wantAction := range []string{"COMPLIANCE-DRIFT", "COMPLIANCE-OK"} {
		var event TelemetryEvent
		if err := json.Unmarshal([]byte(lines[index]), &event); err != nil {
			t.Fatal(err)
		}
		if event.Action != wantAction || event.Jail != "NIS2-AUDIT" {
			t.Fatalf("structured compatibility changed: %#v", event)
		}
		for _, forbidden := range []string{"NIS2", "ISO27001", "compliant"} {
			if strings.Contains(strings.ToLower(event.Payload), strings.ToLower(forbidden)) {
				t.Fatalf("payload retains unsupported claim %q: %s", forbidden, event.Payload)
			}
		}
	}
}

func TestWAFEventNDJSONProducerSchemaContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", "waf-events-v4.02.8.ndjson")
	fixture, err := os.Open(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	var actions []string
	scanner := bufio.NewScanner(fixture)
	for scanner.Scan() {
		var event TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("logger event schema rejected fixture: %v", err)
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"action", "timestamp", "ip", "jail", "payload"} {
			if _, ok := fields[required]; !ok {
				t.Fatalf("producer omitted required field %q from %s", required, encoded)
			}
		}
		actions = append(actions, event.Action)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(actions, ",") != "BANNED,ALLOWED,DETECTED,SHADOW-ALERT,SIMULATED-BAN,COMPLIANCE-DRIFT" {
		t.Fatalf("producer actions = %v", actions)
	}
}

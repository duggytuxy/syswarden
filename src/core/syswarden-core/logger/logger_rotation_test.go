package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func loggerRotationFixture(index int) TelemetryEvent {
	return TelemetryEvent{
		Action:    "DETECTED",
		Timestamp: "2026-08-28T12:00:00Z",
		IP:        fmt.Sprintf("198.51.100.%d", index),
		Jail:      "rotation-test",
		Payload:   fmt.Sprintf("record-%d", index),
		Severity:  7,
	}
}

func loggerRotationWire(t *testing.T, event TelemetryEvent) []byte {
	t.Helper()
	wire, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return append(wire, '\n')
}

func readLoggerRotationFile(t *testing.T, path string) []byte {
	t.Helper()
	wire, err := os.ReadFile(path) // #nosec G304 -- path is owned by the test
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func loggerRotationDirectoryNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestTelemetryLoggerRotationRetainsTriggeringRecordAndOneGeneration_SW_KPI_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "waf.json")
	lines := make([][]byte, 5)
	for index := range lines {
		lines[index] = loggerRotationWire(t, loggerRotationFixture(index+1))
	}
	if len(lines[0]) != len(lines[1]) || len(lines[1]) != len(lines[2]) ||
		len(lines[2]) != len(lines[3]) || len(lines[3]) != len(lines[4]) {
		t.Fatal("rotation fixtures must have equal encoded sizes")
	}
	limit := int64(len(lines[0]) + len(lines[1]))
	eventLogger := newLoggerWithRotationLimit(path, limit)
	if eventLogger.file == nil {
		t.Fatal("logger did not open its active file")
	}

	for index := 0; index < 3; index++ {
		eventLogger.writeTelemetry(loggerRotationFixture(index + 1))
	}
	if got, want := readLoggerRotationFile(t, path+".1"), bytes.Join(lines[:2], nil); !bytes.Equal(got, want) {
		t.Fatalf("first rotated generation = %q, want %q", got, want)
	}
	if got, want := readLoggerRotationFile(t, path), lines[2]; !bytes.Equal(got, want) {
		t.Fatalf("triggering record was not written to the new active file: got %q want %q", got, want)
	}

	eventLogger.writeTelemetry(loggerRotationFixture(4))
	eventLogger.writeTelemetry(loggerRotationFixture(5))
	openedFile := eventLogger.file
	eventLogger.Close()
	if eventLogger.file != nil {
		t.Fatal("logger retained its file after close")
	}
	if _, err := openedFile.Write([]byte("late\n")); err == nil {
		t.Fatal("logger close did not close the active file descriptor")
	}
	eventLogger.writeTelemetry(loggerRotationFixture(1))
	eventLogger.Close()

	if got, want := readLoggerRotationFile(t, path+".1"), bytes.Join(lines[2:4], nil); !bytes.Equal(got, want) {
		t.Fatalf("second rotated generation = %q, want %q", got, want)
	}
	if got, want := readLoggerRotationFile(t, path), lines[4]; !bytes.Equal(got, want) {
		t.Fatalf("active generation after second rotation = %q, want %q", got, want)
	}
	for _, candidate := range []string{path, path + ".1"} {
		info, err := os.Lstat(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %v, want regular 0600", candidate, info.Mode())
		}
		if info.Size() > limit {
			t.Fatalf("%s size = %d, limit = %d", candidate, info.Size(), limit)
		}
	}
	names := loggerRotationDirectoryNames(t, directory)
	if want := []string{"waf.json", "waf.json.1"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("telemetry generations = %v, want %v", names, want)
	}
}

func TestTelemetryLoggerFirstRotationBoundsOversizedLegacyActiveTail_SW_KPI_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "waf.json")
	lines := make([][]byte, 4)
	for index := range lines {
		lines[index] = loggerRotationWire(t, loggerRotationFixture(index+1))
	}
	if len(lines[0]) != len(lines[1]) || len(lines[1]) != len(lines[2]) || len(lines[2]) != len(lines[3]) {
		t.Fatal("legacy rotation fixtures must have equal encoded sizes")
	}
	legacy := bytes.Join(lines[:3], nil)
	limit := int64(2*len(lines[0]) + len(lines[0])/2)
	if int64(len(legacy)) <= limit {
		t.Fatal("legacy active fixture is not oversized")
	}
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}

	eventLogger := newLoggerWithRotationLimit(path, limit)
	if eventLogger.file == nil {
		t.Fatal("logger did not open the oversized legacy active file")
	}
	eventLogger.writeTelemetry(loggerRotationFixture(4))
	eventLogger.Close()

	if got, want := readLoggerRotationFile(t, path+".1"), bytes.Join(lines[1:3], nil); !bytes.Equal(got, want) {
		t.Fatalf("bounded legacy generation = %q, want %q", got, want)
	}
	if got, want := readLoggerRotationFile(t, path), lines[3]; !bytes.Equal(got, want) {
		t.Fatalf("active generation after legacy compaction = %q, want %q", got, want)
	}
	for _, candidate := range []string{path, path + ".1"} {
		info, err := os.Lstat(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
			t.Fatalf("bounded generation %s = mode:%v size:%d limit:%d", candidate, info.Mode(), info.Size(), limit)
		}
	}
	if got, want := loggerRotationDirectoryNames(t, directory), []string{"waf.json", "waf.json.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy compaction files = %v, want %v", got, want)
	}
}

func TestTelemetryLoggerStartupBoundsOversizedRetainedGeneration_SW_KPI_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "waf.json")
	lines := make([][]byte, 4)
	for index := range lines {
		lines[index] = loggerRotationWire(t, loggerRotationFixture(index+1))
	}
	if len(lines[0]) != len(lines[1]) || len(lines[1]) != len(lines[2]) || len(lines[2]) != len(lines[3]) {
		t.Fatal("retained rotation fixtures must have equal encoded sizes")
	}
	legacyRetained := bytes.Join(lines[:3], nil)
	limit := int64(2*len(lines[0]) + len(lines[0])/2)
	if err := os.WriteFile(path+".1", legacyRetained, 0644); err != nil { // #nosec G306 -- deliberately migrate a legacy over-permissive generation
		t.Fatal(err)
	}
	if err := os.WriteFile(path, lines[3], 0600); err != nil {
		t.Fatal(err)
	}

	eventLogger := newLoggerWithRotationLimit(path, limit)
	if eventLogger.file == nil {
		t.Fatal("logger refused a successfully compacted retained generation")
	}
	if got, want := readLoggerRotationFile(t, path+".1"), bytes.Join(lines[1:3], nil); !bytes.Equal(got, want) {
		eventLogger.Close()
		t.Fatalf("startup-bounded retained generation = %q, want %q", got, want)
	}
	retainedInfo, err := os.Lstat(path + ".1")
	if err != nil {
		eventLogger.Close()
		t.Fatal(err)
	}
	if !retainedInfo.Mode().IsRegular() || retainedInfo.Mode().Perm() != 0600 || retainedInfo.Size() > limit {
		eventLogger.Close()
		t.Fatalf("startup-bounded retained generation = mode:%v size:%d limit:%d", retainedInfo.Mode(), retainedInfo.Size(), limit)
	}
	eventLogger.Close()
	if got, want := loggerRotationDirectoryNames(t, directory), []string{"waf.json", "waf.json.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("startup compaction files = %v, want %v", got, want)
	}
}

func TestTelemetryLoggerRejectsSingleRecordLargerThanRotationLimit_SW_KPI_001(t *testing.T) {
	wire := loggerRotationWire(t, loggerRotationFixture(1))
	limit := int64(len(wire) - 1)
	for _, test := range []struct {
		name    string
		initial []byte
	}{
		{name: "empty active"},
		{name: "non-empty active", initial: []byte("{}\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "waf.json")
			if test.initial != nil {
				if err := os.WriteFile(path, test.initial, 0600); err != nil {
					t.Fatal(err)
				}
			}
			eventLogger := newLoggerWithRotationLimit(path, limit)
			if eventLogger.file == nil {
				t.Fatal("logger did not open the active file")
			}
			eventLogger.mu.Lock()
			rotationErr := eventLogger.rotateBeforeWriteLocked(int64(len(wire)))
			eventLogger.mu.Unlock()
			if !errors.Is(rotationErr, errTelemetryRecordExceedsRotationLimit) {
				eventLogger.Close()
				t.Fatalf("oversized pending record error = %v", rotationErr)
			}
			eventLogger.writeTelemetry(loggerRotationFixture(1))
			eventLogger.Close()

			if got := readLoggerRotationFile(t, path); !bytes.Equal(got, test.initial) {
				t.Fatalf("oversized record changed active generation: got %q want %q", got, test.initial)
			}
			if got, want := loggerRotationDirectoryNames(t, directory), []string{"waf.json"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("oversized record created rotation files = %v, want %v", got, want)
			}
		})
	}
}

func TestTelemetryGenerationCompactionSyncFailureKeepsPublishedBoundedTail_SW_KPI_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "waf.json.1")
	lines := make([][]byte, 3)
	for index := range lines {
		lines[index] = loggerRotationWire(t, loggerRotationFixture(index+1))
	}
	if len(lines[0]) != len(lines[1]) || len(lines[1]) != len(lines[2]) {
		t.Fatal("sync-failure rotation fixtures must have equal encoded sizes")
	}
	if err := os.WriteFile(path, bytes.Join(lines, nil), 0644); err != nil { // #nosec G306 -- deliberately migrate a legacy over-permissive active journal
		t.Fatal(err)
	}
	limit := int64(2*len(lines[0]) + len(lines[0])/2)
	syncCalls := 0
	injected := errors.New("injected telemetry directory sync failure")
	err := compactTelemetryGenerationTailWithSync(path, limit, func(string) error {
		syncCalls++
		return injected
	})
	if !errors.Is(err, injected) || syncCalls != 1 {
		t.Fatalf("post-publication sync result = err:%v calls:%d", err, syncCalls)
	}
	if got, want := readLoggerRotationFile(t, path), bytes.Join(lines[1:], nil); !bytes.Equal(got, want) {
		t.Fatalf("post-sync-failure bounded tail = %q, want %q", got, want)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		t.Fatalf("post-sync-failure generation = mode:%v size:%d limit:%d", info.Mode(), info.Size(), limit)
	}
	if got, want := loggerRotationDirectoryNames(t, directory), []string{"waf.json.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("post-sync-failure files = %v, want %v", got, want)
	}
}

func TestTelemetryLoggerRotationCreationFailureRollsBackAndWrites_SW_KPI_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "waf.json")
	first := loggerRotationWire(t, loggerRotationFixture(1))
	second := loggerRotationWire(t, loggerRotationFixture(2))
	eventLogger := newLoggerWithRotationLimit(path, int64(len(first)))
	eventLogger.writeTelemetry(loggerRotationFixture(1))
	createCalls := 0
	eventLogger.createRotationLogFile = func(string) (*os.File, error) {
		createCalls++
		return nil, errors.New("injected active-file creation failure")
	}
	eventLogger.writeTelemetry(loggerRotationFixture(2))
	if createCalls != 1 {
		t.Fatalf("new active file creation calls = %d, want 1", createCalls)
	}
	if eventLogger.file == nil {
		t.Fatal("logger did not reopen the rolled-back active file")
	}
	eventLogger.Close()

	if got, want := readLoggerRotationFile(t, path), append(append([]byte(nil), first...), second...); !bytes.Equal(got, want) {
		t.Fatalf("rolled-back active file = %q, want %q", got, want)
	}
	if _, err := os.Lstat(path + ".1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed rotation retained an unexpected generation: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("rolled-back active file mode = %v, want regular 0600", info.Mode())
	}
	if got, want := loggerRotationDirectoryNames(t, directory), []string{"waf.json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback left residual rotation files = %v, want %v", got, want)
	}
}

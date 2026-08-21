package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testHAFenceEpoch            = "7f67f63c-3f70-47b5-8b37-42f5827614a3"
	testHAFenceMembershipDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHAFenceWriterDigest     = "f9bfe56aeb4a03ff07607c64e982dd075c84d1414be7d2e952bef41817e80119"
)

func newHAFenceTombstoneTestController(t *testing.T, directory string) *haFenceController {
	t.Helper()
	controller, err := newHAFenceController(directory, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	controller.now = func() time.Time { return time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC) }
	controller.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 1024))
	return controller
}

func testHAFenceEngagementEvent() haFenceEpochEvent {
	return haFenceEpochEvent{
		Event: "engaged", Epoch: testHAFenceEpoch,
		MembershipSHA256:            testHAFenceMembershipDigest,
		LegacyWriterInventorySHA256: testHAFenceWriterDigest,
		RecordedAt:                  "2026-08-20T13:00:00Z",
	}
}

func testHAFenceRetirementEvent(t *testing.T) haFenceEpochEvent {
	t.Helper()
	closure := &haFenceWriterClosure{
		SchemaVersion: haFenceWriterClosureVersion, Epoch: testHAFenceEpoch,
		MembershipSHA256:            testHAFenceMembershipDigest,
		LegacyWriterInventorySHA256: testHAFenceWriterDigest,
		LegacyRetryQueueDrained:     true, Writers: []haFenceWriterClosureEntry{},
	}
	wire, err := canonicalHAFenceWriterClosureBytes(*closure)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	return haFenceEpochEvent{
		Event: "retired", Epoch: testHAFenceEpoch,
		MembershipSHA256:            testHAFenceMembershipDigest,
		LegacyWriterInventorySHA256: testHAFenceWriterDigest,
		RecordedAt:                  "2026-08-20T13:05:00Z",
		WriterClosureSHA256:         hex.EncodeToString(digest[:]), WriterClosure: closure,
	}
}

func publishHAFenceTestTombstones(t *testing.T, controller *haFenceController, events []haFenceEpochEvent) {
	t.Helper()
	tombstones := haFenceEpochTombstones{Version: haFenceTombstonesVersion, Events: events}
	wire, err := json.Marshal(tombstones)
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, '\n')
	if err := controller.withLock(true, true, func(root *os.Root) error {
		return publishHAFileAtomically(root, haFenceTombstonesName, wire)
	}); err != nil {
		t.Fatal(err)
	}
}

func publishHAFenceTestState(t *testing.T, controller *haFenceController, state haFenceDiskState) {
	t.Helper()
	if err := controller.withLock(true, true, func(root *os.Root) error {
		return publishHAFenceState(root, state)
	}); err != nil {
		t.Fatal(err)
	}
}

func readHAFenceTestState(t *testing.T, controller *haFenceController) haFenceDiskState {
	t.Helper()
	var state haFenceDiskState
	if err := controller.withLock(false, false, func(root *os.Root) error {
		var err error
		state, err = readHAFenceState(root, controller.expectedOwnerUID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

func activeHAFenceTestState(generation uint64) haFenceDiskState {
	drainedAt := "2026-08-20T13:00:00Z"
	condition := "sw-fence-v1-" + "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
	return haFenceDiskState{
		Version: haFenceVersion, State: haFenceStateActiveDrained,
		Epoch: testHAFenceEpoch, MembershipSHA256: testHAFenceMembershipDigest,
		LegacyWriterInventorySHA256: testHAFenceWriterDigest,
		Generation:                  generation, Condition: condition, DrainedAt: &drainedAt,
	}
}

func TestHAFenceRestartRecoversCrashWindowAndInactiveRollback(t *testing.T) {
	for _, rollbackAfterActivation := range []bool{false, true} {
		name := "crash_after_engagement_tombstone"
		if rollbackAfterActivation {
			name = "rollback_active_state_to_inactive"
		}
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "fence")
			controller := newHAFenceTombstoneTestController(t, directory)
			if err := controller.prepareForServer(); err != nil {
				t.Fatal(err)
			}
			publishHAFenceTestTombstones(t, controller, []haFenceEpochEvent{testHAFenceEngagementEvent()})
			if rollbackAfterActivation {
				publishHAFenceTestState(t, controller, activeHAFenceTestState(3))
			}
			publishHAFenceTestState(t, controller, haFenceDiskState{
				Version: haFenceVersion, State: haFenceStateInactive, Generation: 1,
			})

			restarted := newHAFenceTombstoneTestController(t, directory)
			if err := restarted.prepareForServer(); err != nil {
				t.Fatal(err)
			}
			state := readHAFenceTestState(t, restarted)
			if state.State != haFenceStateActiveDrained || state.Epoch != testHAFenceEpoch || state.Generation != 3 ||
				!validHAFenceCondition(state.Condition) {
				t.Fatalf("recovered state = %+v", state)
			}
			mutated := false
			err := restarted.withLegacyMutation("POST", nil, func() { mutated = true })
			var protocolError *haFenceHTTPError
			if err == nil || !errors.As(err, &protocolError) || protocolError.Status != 423 || mutated {
				t.Fatalf("legacy writer after recovery: err=%v, mutated=%t", err, mutated)
			}
		})
	}
}

func TestHAFenceRestartRotatesOpenCampaignProof(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "fence")
	controller := newHAFenceTombstoneTestController(t, directory)
	if err := controller.prepareForServer(); err != nil {
		t.Fatal(err)
	}
	publishHAFenceTestTombstones(t, controller, []haFenceEpochEvent{testHAFenceEngagementEvent()})
	publishHAFenceTestState(t, controller, activeHAFenceTestState(3))
	before := readHAFenceTestState(t, controller)

	restarted := newHAFenceTombstoneTestController(t, directory)
	restarted.random = bytes.NewReader(bytes.Repeat([]byte{0x6b}, 64))
	if err := restarted.prepareForServer(); err != nil {
		t.Fatal(err)
	}
	after := readHAFenceTestState(t, restarted)
	if after.State != haFenceStateActiveDrained || after.Generation != 5 || after.Condition == before.Condition {
		t.Fatalf("restart proof was not rotated: before=%+v after=%+v", before, after)
	}
}

func TestHAFenceRestartCompletesRetiredEpochRollback(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "fence")
	controller := newHAFenceTombstoneTestController(t, directory)
	if err := controller.prepareForServer(); err != nil {
		t.Fatal(err)
	}
	publishHAFenceTestTombstones(t, controller, []haFenceEpochEvent{
		testHAFenceEngagementEvent(), testHAFenceRetirementEvent(t),
	})
	publishHAFenceTestState(t, controller, activeHAFenceTestState(3))

	restarted := newHAFenceTombstoneTestController(t, directory)
	if err := restarted.prepareForServer(); err != nil {
		t.Fatal(err)
	}
	state := readHAFenceTestState(t, restarted)
	if state.State != haFenceStateInactive || state.Generation != 4 || state.Epoch != "" || state.Condition != "" {
		t.Fatalf("retired rollback state = %+v", state)
	}
	secondRestart := newHAFenceTombstoneTestController(t, directory)
	if err := secondRestart.prepareForServer(); err != nil {
		t.Fatal(err)
	}
	if next := readHAFenceTestState(t, secondRestart); next != state {
		t.Fatalf("retired state changed on another restart: before=%+v after=%+v", state, next)
	}
}

func TestHAFenceRestartRejectsMissingIncoherentTombstones(t *testing.T) {
	for _, state := range []haFenceDiskState{
		activeHAFenceTestState(3),
		{Version: haFenceVersion, State: haFenceStateInactive, Generation: 4},
	} {
		directory := filepath.Join(t.TempDir(), "fence")
		controller := newHAFenceTombstoneTestController(t, directory)
		if err := controller.prepareForServer(); err != nil {
			t.Fatal(err)
		}
		publishHAFenceTestState(t, controller, state)
		restarted := newHAFenceTombstoneTestController(t, directory)
		if err := restarted.prepareForServer(); err == nil || !strings.Contains(err.Error(), "no durable epoch tombstones") {
			t.Fatalf("missing tombstone restart error = %v", err)
		}
	}
}

func TestHAFenceRestartRejectsCorruptUnsafeAndNoncanonicalTombstones(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		mode os.FileMode
	}{
		{name: "malformed", wire: []byte("{\n"), mode: 0600},
		{name: "duplicate", wire: []byte(`{"version":1,"version":1,"events":[]}` + "\n"), mode: 0600},
		{name: "unknown", wire: []byte(`{"version":1,"events":[],"unknown":true}` + "\n"), mode: 0600},
		{name: "noncanonical", wire: []byte("{\n  \"version\": 1,\n  \"events\": []\n}\n"), mode: 0600},
		{name: "unsafe_mode", wire: []byte(`{"version":1,"events":[]}` + "\n"), mode: 0644},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "fence")
			controller := newHAFenceTombstoneTestController(t, directory)
			if err := controller.prepareForServer(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, haFenceTombstonesName)
			if err := os.WriteFile(path, test.wire, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			restarted := newHAFenceTombstoneTestController(t, directory)
			if err := restarted.prepareForServer(); err == nil {
				t.Fatal("unsafe or corrupt HA fence tombstone was accepted")
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "fence")
		controller := newHAFenceTombstoneTestController(t, directory)
		if err := controller.prepareForServer(); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte(`{"version":1,"events":[]}`+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, haFenceTombstonesName)); err != nil {
			t.Fatal(err)
		}
		restarted := newHAFenceTombstoneTestController(t, directory)
		if err := restarted.prepareForServer(); err == nil {
			t.Fatal("symbolic-link HA fence tombstone was accepted")
		}
	})
}

package network

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type haTwoNodeHarness struct {
	a, b        *haReplicationCoordinator
	partitioned bool
	queued      [][]byte
}

func newHATwoNodeHarness(t *testing.T) *haTwoNodeHarness {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	modelA, _ := newHAReplicationModel("cluster-a")
	modelB, _ := newHAReplicationModel("cluster-a")
	a, err := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", secret, modelA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, modelB)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.activate(); err != nil {
		t.Fatal(err)
	}
	if err := b.activate(); err != nil {
		t.Fatal(err)
	}
	return &haTwoNodeHarness{a: a, b: b}
}

func (h *haTwoNodeHarness) send(t *testing.T, from, to *haReplicationCoordinator, operation haReplicationOperation) []byte {
	t.Helper()
	wire, err := from.envelope(operation, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if h.partitioned {
		h.queued = append(h.queued, wire)
		from.markPeerUnavailable("deterministic partition")
		to.markPeerUnavailable("deterministic partition")
		return wire
	}
	if _, err := to.receive(wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestHACoordinationTwoNodeConvergencePartitionRecoveryAndReplay(t *testing.T) {
	h := newHATwoNodeHarness(t)
	opA := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	opB := testHAReplicationOperation(t, "node-b", 1, "192.0.2.20", "waap", "upsert")
	if _, err := h.a.model.enqueue(opA); err != nil {
		t.Fatal(err)
	}
	if _, err := h.b.model.enqueue(opB); err != nil {
		t.Fatal(err)
	}
	h.send(t, h.a, h.b, opA)
	h.send(t, h.b, h.a, opB)
	if !reflect.DeepEqual(h.a.model.snapshot(), h.b.model.snapshot()) {
		t.Fatal("initial convergence failed")
	}

	h.partitioned = true
	deleted := testHAReplicationOperation(t, "node-a", 2, "192.0.2.10", "ssh", "delete")
	if _, err := h.a.model.enqueue(deleted); err != nil {
		t.Fatal(err)
	}
	wire := h.send(t, h.a, h.b, deleted)
	if h.a.state != haCoordinationDegraded || h.b.state != haCoordinationDegraded {
		t.Fatal("partition was not detected")
	}
	h.partitioned = false
	if _, err := h.b.receive(wire); err != nil {
		t.Fatal(err)
	}
	if h.b.state != haCoordinationRecovering {
		t.Fatalf("peer return did not require recovery: %s", h.b.state)
	}
	digest, _ := h.b.stateDigest()
	if err := h.b.beginRecovery("node-a", digest); err != nil {
		t.Fatal(err)
	}
	if err := h.b.activate(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.b.receive(wire); !errors.Is(err, errHACoordinationReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestHACoordinationRestartRetainsAntiReplay(t *testing.T) {
	h := newHATwoNodeHarness(t)
	op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "delete")
	if _, err := h.a.model.enqueue(op); err != nil {
		t.Fatal(err)
	}
	wire := h.send(t, h.a, h.b, op)
	state := h.b.model.persistentState()
	restartedModel, err := validateHAReplicationPersistentState(state)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", []byte("0123456789abcdef0123456789abcdef"), restartedModel)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.activate(); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.receive(wire); !errors.Is(err, errHACoordinationReplay) {
		t.Fatalf("restart replay accepted: %v", err)
	}
}

func TestHACoordinationIntegrityIdentityAndDivergenceFence(t *testing.T) {
	t.Run("tamper", func(t *testing.T) {
		h := newHATwoNodeHarness(t)
		op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
		wire, _ := h.a.envelope(op, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
		wire = []byte(strings.Replace(string(wire), "192.0.2.10", "192.0.2.11", 1))
		if _, err := h.b.receive(wire); err == nil || h.b.state != haCoordinationFenced {
			t.Fatal("tamper did not fence")
		}
	})
	t.Run("identity", func(t *testing.T) {
		h := newHATwoNodeHarness(t)
		op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
		wire, _ := h.a.envelope(op, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
		var envelope haCoordinationEnvelope
		if err := json.Unmarshal(wire, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.SenderID = "node-c"
		envelope.MAC, _ = haCoordinationMAC(h.a.secret, envelope)
		wire, _ = json.Marshal(envelope)
		if _, err := h.b.receive(wire); err == nil || h.b.state != haCoordinationFenced {
			t.Fatal("identity conflict did not fence")
		}
	})
	t.Run("sequence divergence", func(t *testing.T) {
		h := newHATwoNodeHarness(t)
		known := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
		if _, err := h.b.model.apply(known); err != nil {
			t.Fatal(err)
		}
		conflict := testHAReplicationOperation(t, "node-a", 1, "192.0.2.11", "ssh", "upsert")
		wire, _ := h.a.envelope(conflict, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
		if _, err := h.b.receive(wire); err == nil || h.b.state != haCoordinationFenced {
			t.Fatal("divergence did not fence")
		}
	})
}

func TestHACoordinationExplicitRecoveryIsCheckpointBound(t *testing.T) {
	h := newHATwoNodeHarness(t)
	h.a.fence("test split brain")
	if err := h.a.beginRecovery("node-c", strings.Repeat("0", 64)); err == nil || h.a.state != haCoordinationFenced {
		t.Fatal("invalid recovery evidence accepted")
	}
	digest, _ := h.a.stateDigest()
	if err := h.a.beginRecovery("node-b", digest); err != nil {
		t.Fatal(err)
	}
	if h.a.state != haCoordinationRecovering {
		t.Fatal("recovery did not enter recovering")
	}
	if _, err := h.a.envelope(testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert"), time.Now()); err == nil {
		t.Fatal("recovering coordinator emitted traffic before activation")
	}
}

func TestHACoordinationEnvelopeBoundsStrictJSONAndSecretLifecycle(t *testing.T) {
	h := newHATwoNodeHarness(t)
	op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	wire, _ := h.a.envelope(op, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	cases := [][]byte{
		make([]byte, maxHACoordinationEnvelopeBytes+1),
		append(wire, []byte(` {}`)...),
		append(wire[:len(wire)-1], []byte(`,"unknown":true}`)...),
		[]byte(strings.Replace(string(wire), `"version":1`, `"version":1,"version":1`, 1)),
	}
	for index, candidate := range cases {
		if _, err := decodeHACoordinationEnvelope(candidate); err == nil {
			t.Fatalf("invalid envelope %d accepted", index)
		}
	}
	coordinator, err := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), h.a.model)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.close()
	if len(coordinator.secret) != 0 {
		t.Fatal("secret retained after close")
	}
	if _, err := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("short"), h.a.model); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestHACoordinationRejectsPersistedThirdNodeMembership(t *testing.T) {
	model, _ := newHAReplicationModel("cluster-a")
	operation := testHAReplicationOperation(t, "node-c", 1, "192.0.2.30", "ssh", "upsert")
	if _, err := model.apply(operation); err != nil {
		t.Fatal(err)
	}
	if _, err := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model); err == nil {
		t.Fatal("persisted third-node membership was accepted")
	}
}

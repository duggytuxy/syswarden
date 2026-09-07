package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testHAReplicationOperation(t *testing.T, node string, sequence uint64, ip, source, action string) haReplicationOperation {
	return testHAReplicationOperationAtEpoch(t, 1, node, sequence, ip, source, action)
}

func testHAReplicationOperationAtEpoch(t *testing.T, epoch uint64, node string, sequence uint64, ip, source, action string) haReplicationOperation {
	t.Helper()
	op := haReplicationOperation{
		SchemaVersion: haReplicationSchemaVersion, ClusterID: "cluster-a", Epoch: epoch, NodeID: node,
		Sequence: sequence, Owner: node, Source: source, IP: ip, Action: action,
		IssuedAt: "2026-09-03T08:00:00Z",
	}
	if action == "upsert" {
		op.ExpiresAt = "2026-09-03T10:00:00Z"
	} else {
		op.TombstoneUntil = "2026-10-03T08:00:00Z"
	}
	digest, err := haReplicationOperationDigest(op)
	if err != nil {
		t.Fatal(err)
	}
	op.OperationID = digest
	return op
}

func TestHAReplicationValidationFailsClosed(t *testing.T) {
	valid := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	wire, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHAReplicationOperation(wire); err != nil {
		t.Fatalf("valid operation rejected: %v", err)
	}
	cases := map[string][]byte{
		"unknown field": append(wire[:len(wire)-1], []byte(`,"extra":true}`)...),
		"duplicate key": []byte(strings.Replace(string(wire), `"sequence":1`, `"sequence":1,"sequence":1`, 1)),
		"trailing JSON": append(append([]byte(nil), wire...), []byte(` {}`)...),
		"oversized":     make([]byte, maxHAReplicationWireBytes+1),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeHAReplicationOperation(candidate); err == nil {
				t.Fatal("malformed operation accepted")
			}
		})
	}

	mutations := map[string]func(*haReplicationOperation){
		"cluster":          func(op *haReplicationOperation) { op.ClusterID = "UPPER" },
		"epoch":            func(op *haReplicationOperation) { op.Epoch = 0 },
		"owner":            func(op *haReplicationOperation) { op.Owner = "node-b" },
		"sequence":         func(op *haReplicationOperation) { op.Sequence = 0 },
		"address":          func(op *haReplicationOperation) { op.IP = "::ffff:192.0.2.10" },
		"source":           func(op *haReplicationOperation) { op.Source = "bad source" },
		"action":           func(op *haReplicationOperation) { op.Action = "replace" },
		"time":             func(op *haReplicationOperation) { op.IssuedAt = "2026-09-03T08:00:00+00:00" },
		"digest":           func(op *haReplicationOperation) { op.OperationID = strings.Repeat("0", 64) },
		"upsert tombstone": func(op *haReplicationOperation) { op.TombstoneUntil = "2026-10-03T08:00:00Z" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateHAReplicationOperation(candidate); err == nil {
				t.Fatal("invalid operation accepted")
			}
		})
	}
}

func TestHAReplicationRejectsOperationsFromAnotherEpochWithoutMutation(t *testing.T) {
	model, err := newHAReplicationModel("cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := model.setEpoch(2); err != nil {
		t.Fatal(err)
	}
	operation := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	if changed, err := model.apply(operation); err == nil || changed {
		t.Fatalf("foreign epoch operation changed=%t err=%v", changed, err)
	}
	if len(model.snapshot()) != 0 || len(model.seen) != 0 || len(model.highWater) != 0 {
		t.Fatalf("foreign epoch operation mutated state: %#v", model.persistentState())
	}
}

func TestHAReplicationLifetimeBoundsArePartOfTheSignedOperation(t *testing.T) {
	tooLong := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	tooLong.ExpiresAt = "2026-10-04T08:00:00Z"
	tooLong.OperationID, _ = haReplicationOperationDigest(tooLong)
	if err := validateHAReplicationOperation(tooLong); err == nil {
		t.Fatal("overlong replicated lease accepted")
	}
	wrongTombstone := testHAReplicationOperation(t, "node-a", 2, "192.0.2.10", "ssh", "delete")
	wrongTombstone.TombstoneUntil = "2026-10-02T08:00:00Z"
	wrongTombstone.OperationID, _ = haReplicationOperationDigest(wrongTombstone)
	if err := validateHAReplicationOperation(wrongTombstone); err == nil {
		t.Fatal("noncanonical tombstone retention accepted")
	}
}

func TestHAReplicationIdempotenceSequenceConflictAndClusterIdentity(t *testing.T) {
	model, err := newHAReplicationModel("cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	changed, err := model.apply(op)
	if err != nil || !changed {
		t.Fatalf("first apply = %v, %v", changed, err)
	}
	changed, err = model.apply(op)
	if err != nil || changed {
		t.Fatalf("duplicate apply = %v, %v", changed, err)
	}
	conflict := testHAReplicationOperation(t, "node-a", 1, "192.0.2.11", "ssh", "upsert")
	if _, err := model.apply(conflict); err == nil {
		t.Fatal("sequence conflict accepted")
	}
	foreign := testHAReplicationOperation(t, "node-b", 1, "192.0.2.10", "ssh", "upsert")
	foreign.ClusterID = "cluster-b"
	foreign.OperationID, _ = haReplicationOperationDigest(foreign)
	if _, err := model.apply(foreign); err == nil {
		t.Fatal("foreign cluster accepted")
	}
}

func TestHAReplicationConvergesAcrossOrderAndDuplicates(t *testing.T) {
	operations := []haReplicationOperation{
		testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert"),
		testHAReplicationOperation(t, "node-a", 2, "192.0.2.10", "ssh", "delete"),
		testHAReplicationOperation(t, "node-b", 1, "192.0.2.10", "ssh", "upsert"),
		testHAReplicationOperation(t, "node-a", 3, "192.0.2.20", "waap", "upsert"),
	}
	var orders [][]int
	var permute func([]int, int)
	permute = func(order []int, cursor int) {
		if cursor == len(order) {
			orders = append(orders, append([]int(nil), order...))
			return
		}
		for index := cursor; index < len(order); index++ {
			order[cursor], order[index] = order[index], order[cursor]
			permute(order, cursor+1)
			order[cursor], order[index] = order[index], order[cursor]
		}
	}
	permute([]int{0, 1, 2, 3}, 0)
	// Replays in the same delivery stream must remain no-ops.
	orders = append(orders, []int{0, 0, 2, 1, 3, 1})
	var expected []haReplicationClaim
	for index, order := range orders {
		model, _ := newHAReplicationModel("cluster-a")
		for _, operationIndex := range order {
			if _, err := model.apply(operations[operationIndex]); err != nil {
				t.Fatal(err)
			}
		}
		got := model.snapshot()
		if index == 0 {
			expected = got
			continue
		}
		if !reflect.DeepEqual(expected, got) {
			t.Fatalf("order %d diverged\nwant %#v\ngot  %#v", index, expected, got)
		}
	}
}

func TestHAReplicationDeleteExpiryDominanceAndOwnerIsolation(t *testing.T) {
	model, _ := newHAReplicationModel("cluster-a")
	oldUpsert := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	deleteOp := testHAReplicationOperation(t, "node-a", 2, "192.0.2.10", "ssh", "delete")
	otherOwner := testHAReplicationOperation(t, "node-b", 1, "192.0.2.10", "ssh", "upsert")
	for _, op := range []haReplicationOperation{deleteOp, oldUpsert, otherOwner} {
		if _, err := model.apply(op); err != nil {
			t.Fatal(err)
		}
	}
	active := model.activeClaims(time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC))
	if len(active) != 1 || active[0].Owner != "node-b" {
		t.Fatalf("owner isolation failed: %#v", active)
	}

	expiry := testHAReplicationOperation(t, "node-b", 2, "192.0.2.10", "ssh", "expiry")
	if _, err := model.apply(expiry); err != nil {
		t.Fatal(err)
	}
	if got := model.activeClaims(time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)); len(got) != 0 {
		t.Fatalf("expiry did not dominate: %#v", got)
	}
	if _, err := model.apply(otherOwner); err != nil {
		t.Fatal(err)
	}
	if got := model.activeClaims(time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)); len(got) != 0 {
		t.Fatalf("old upsert resurrected after expiry: %#v", got)
	}
}

func TestHAReplicationNaturalTTLAndQuota(t *testing.T) {
	model, _ := newHAReplicationModel("cluster-a")
	op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	if _, err := model.apply(op); err != nil {
		t.Fatal(err)
	}
	if got := model.activeClaims(time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)); len(got) != 0 {
		t.Fatalf("expired claim remains active: %#v", got)
	}
	model.seen = make(map[string]struct{}, maxHAReplicationOperations)
	for index := 0; index < maxHAReplicationOperations; index++ {
		model.seen[fmt.Sprintf("%064x", index)] = struct{}{}
	}
	quotaOp := testHAReplicationOperation(t, "node-b", 1, "192.0.2.20", "ssh", "upsert")
	if _, err := model.apply(quotaOp); err == nil {
		t.Fatal("quota overflow accepted")
	}
	outboxModel, _ := newHAReplicationModel("cluster-a")
	for index := 0; index < maxHAReplicationOutbox; index++ {
		outboxModel.outbox[fmt.Sprintf("%064x", index)] = haReplicationOperation{}
	}
	if _, err := outboxModel.enqueue(quotaOp); err == nil {
		t.Fatal("outbox quota overflow accepted")
	}
}

func TestHAReplicationPersistenceRestartAndOutbox(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only persistence fixture directory requires execute permission
		t.Fatal(err)
	}
	path := filepath.Join(directory, "replication-state.json")
	model, _ := newHAReplicationModel("cluster-a")
	first := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	second := testHAReplicationOperation(t, "node-a", 2, "192.0.2.10", "ssh", "delete")
	if _, err := model.enqueue(first); err != nil {
		t.Fatal(err)
	}
	if _, err := model.enqueue(second); err != nil {
		t.Fatal(err)
	}
	if err := model.acknowledge(first.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := saveHAReplicationModel(path, os.Geteuid(), model); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		t.Fatalf("unsafe persistent mode: %v, %v", info, err)
	}
	restarted, err := loadHAReplicationModel(path, os.Geteuid(), "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(model.persistentState(), restarted.persistentState()) {
		t.Fatalf("restart changed state\nwant %#v\ngot  %#v", model.persistentState(), restarted.persistentState())
	}
	if len(restarted.outbox) != 1 || restarted.outbox[second.OperationID].Action != "delete" {
		t.Fatalf("outbox was not recovered: %#v", restarted.outbox)
	}
	if _, err := restarted.apply(first); err != nil {
		t.Fatal(err)
	}
	if got := restarted.snapshot(); len(got) != 1 || got[0].Action != "delete" {
		t.Fatalf("replay resurrected state: %#v", got)
	}
}

func TestHAReplicationPersistenceRejectsCorruptionAndUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only persistence fixture directory requires execute permission
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	model, _ := newHAReplicationModel("cluster-a")
	op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	if _, err := model.enqueue(op); err != nil {
		t.Fatal(err)
	}
	if err := saveHAReplicationModel(path, os.Geteuid(), model); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path) // #nosec G304 -- path is a fixed state filename beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"truncated":  original[:len(original)/2],
		"unknown":    append(original[:len(original)-1], []byte(`,"unknown":true}`)...),
		"duplicate":  []byte(strings.Replace(string(original), `"version":1`, `"version":1,"version":1`, 1)),
		"trailing":   append(append([]byte(nil), original...), []byte(` {}`)...),
		"whitespace": append([]byte("\n"), original...),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, wire, 0600); err != nil { // #nosec G703 -- path is a fixed state filename beneath t.TempDir
				t.Fatal(err)
			}
			if _, err := loadHAReplicationModel(path, os.Geteuid(), "cluster-a"); err == nil {
				t.Fatal("corrupt state accepted")
			}
		})
	}
	if err := os.WriteFile(path, original, 0600); err != nil { // #nosec G703 -- path is a fixed state filename beneath t.TempDir
		t.Fatal(err)
	}
	if _, err := loadHAReplicationModel(path, os.Geteuid(), "cluster-b"); err == nil {
		t.Fatal("wrong cluster accepted")
	}
	if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- this adversarial fixture deliberately makes state world-readable
		t.Fatal(err)
	}
	if err := saveHAReplicationModel(path, os.Geteuid(), model); err == nil {
		t.Fatal("unsafe existing state mode accepted for publication")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil { // #nosec G302 -- this adversarial fixture deliberately makes the state directory non-private
		t.Fatal(err)
	}
	if _, err := loadHAReplicationModel(path, os.Geteuid(), "cluster-a"); err == nil {
		t.Fatal("non-owner-only directory accepted")
	}
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- this restores the owner-only fixture directory and requires execute permission
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked-state")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHAReplicationModel(link, os.Geteuid(), "cluster-a"); err == nil {
		t.Fatal("symlink state accepted")
	}
}

func TestHAReplicationInterruptedPublicationPreservesLastSnapshot(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only persistence fixture directory requires execute permission
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	model, _ := newHAReplicationModel("cluster-a")
	op := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	if _, err := model.enqueue(op); err != nil {
		t.Fatal(err)
	}
	if err := saveHAReplicationModel(path, os.Geteuid(), model); err != nil {
		t.Fatal(err)
	}
	// A staging file left by an interrupted writer is never selected as state.
	if err := os.WriteFile(filepath.Join(directory, ".state.json.syswarden-interrupted.tmp"), []byte(`{"partial":`), 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := loadHAReplicationModel(path, os.Geteuid(), "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.snapshot(); len(got) != 1 || got[0].OperationID != op.OperationID {
		t.Fatalf("last committed snapshot not recovered: %#v", got)
	}
}

func TestHAReplicationCompactionHighWaterPreventsResurrection(t *testing.T) {
	model, _ := newHAReplicationModel("cluster-a")
	upsert := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	deleted := testHAReplicationOperation(t, "node-a", 2, "192.0.2.10", "ssh", "delete")
	for _, operation := range []haReplicationOperation{deleted, upsert} {
		if _, err := model.apply(operation); err != nil {
			t.Fatal(err)
		}
	}
	model.compact(time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC))
	if model.highWater["node-a"] != 2 || len(model.claims) != 0 || len(model.seen) != 0 {
		t.Fatalf("unexpected compacted state: %#v", model.persistentState())
	}
	if changed, err := model.apply(upsert); err != nil || changed {
		t.Fatalf("compacted replay accepted: changed=%v err=%v", changed, err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only persistence fixture directory requires execute permission
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	if err := saveHAReplicationModel(path, os.Geteuid(), model); err != nil {
		t.Fatal(err)
	}
	restarted, err := loadHAReplicationModel(path, os.Geteuid(), "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := restarted.apply(upsert); err != nil || changed || len(restarted.activeClaims(time.Now())) != 0 {
		t.Fatalf("restart resurrected compacted operation: changed=%v err=%v", changed, err)
	}
}

func TestHAReplicationCompactionDoesNotCrossSequenceGap(t *testing.T) {
	model, _ := newHAReplicationModel("cluster-a")
	third := testHAReplicationOperation(t, "node-a", 3, "192.0.2.30", "ssh", "delete")
	if _, err := model.apply(third); err != nil {
		t.Fatal(err)
	}
	model.compact(time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC))
	if model.highWater["node-a"] != 0 || len(model.claims) != 1 {
		t.Fatalf("compaction crossed missing sequence: %#v", model.persistentState())
	}
}

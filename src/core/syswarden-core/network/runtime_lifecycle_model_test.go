package network

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func lifecycleModelFixture() (runtimeLifecycleModel, time.Time) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	return runtimeLifecycleModel{SchemaVersion: 1, Identity: strings.Repeat("ab", 32),
		Sequence: 1, UpdatedAt: now.Format(time.RFC3339Nano), Records: []runtimeLifecycleRecord{}}, now
}

func TestRuntimeLifecycleRequiresVerifiedDeletionAndLaterAbsence(t *testing.T) {
	initial, now := lifecycleModelFixture()
	present := runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true}
	absent := runtimeLifecycleWitness{Complete: true}
	active, err := initial.verifiedBan("192.0.2.8", now, present)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := active.observeAbsence("192.0.2.8", now.Add(time.Second), absent); err == nil {
		t.Fatal("unexplained disappearance became an authoritative lifecycle transition")
	}
	deleted, err := active.verifiedDeletion("192.0.2.8", now.Add(time.Second), present, absent)
	if err != nil || deleted.Records[0].State != "deleted" {
		t.Fatalf("verified deletion: %v, %v", deleted, err)
	}
	stillDeleted, err := deleted.observeAbsence("192.0.2.8", now.Add(30*time.Second), absent)
	if err != nil || !reflect.DeepEqual(stillDeleted, deleted) {
		t.Fatalf("absence was confirmed too early: %v, %v", stillDeleted, err)
	}
	tombstoned, err := deleted.observeAbsence("192.0.2.8", now.Add(31*time.Second), absent)
	if err != nil || tombstoned.Records[0].State != "tombstoned" || tombstoned.Records[0].Cause != "verified-deletion" {
		t.Fatalf("terminal absence: %v, %v", tombstoned, err)
	}
	if _, err := tombstoned.verifiedDeletion("192.0.2.8", now.Add(32*time.Second), present, absent); err == nil {
		t.Fatal("unexplained reappearance reused a completed claim")
	}
	rebanned, err := tombstoned.verifiedBan("192.0.2.8", now.Add(32*time.Second), present)
	if err != nil || rebanned.Records[0].Generation != 2 || rebanned.Records[0].State != "active" {
		t.Fatalf("new verified generation: %v, %v", rebanned, err)
	}
	if len(initial.Records) != 0 || active.Records[0].State != "active" || deleted.Records[0].State != "deleted" {
		t.Fatal("transition mutated a prior immutable model")
	}
}

func TestRuntimeLifecycleNativeExpiryCannotBeGuessed(t *testing.T) {
	model, now := lifecycleModelFixture()
	witness := runtimeLifecycleWitness{Complete: true, Present: true, ExpiresAt: now.Add(time.Minute)}
	model, err := model.verifiedBan("2001:db8::1", now, witness)
	if err != nil {
		t.Fatal(err)
	}
	absent := runtimeLifecycleWitness{Complete: true}
	if _, err := model.observeAbsence("2001:db8::1", now.Add(59*time.Second), absent); err == nil {
		t.Fatal("early disappearance was reported as native expiry")
	}
	expired, err := model.verifiedDeletion("2001:db8::1", now.Add(time.Minute), absent, absent)
	if err != nil || expired.Records[0].State != "expired" || expired.Records[0].Cause != "native-expiry" {
		t.Fatalf("already elapsed absence was falsely attributed to operator: %v, %v", expired, err)
	}
	if _, err := expired.observeAbsence("2001:db8::1", now.Add(90*time.Second), runtimeLifecycleWitness{}); err == nil {
		t.Fatal("incomplete kernel read confirmed a tombstone")
	}
	tombstone, err := expired.observeAbsence("2001:db8::1", now.Add(90*time.Second), absent)
	if err != nil || tombstone.Records[0].State != "tombstoned" || tombstone.Records[0].Cause != "native-expiry" {
		t.Fatalf("native expiry cause was lost: %v, %v", tombstone, err)
	}
}

func TestRuntimeLifecycleRejectsInvalidWitnessesAndNoOpInputs(t *testing.T) {
	model, now := lifecycleModelFixture()
	for name, witness := range map[string]runtimeLifecycleWitness{
		"incomplete":    {Present: true, Permanent: true},
		"absent":        {Complete: true},
		"expired":       {Complete: true, Present: true, ExpiresAt: now},
		"contradictory": {Complete: true, Present: true, Permanent: true, ExpiresAt: now.Add(time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := model.verifiedBan("192.0.2.1", now, witness); err == nil {
				t.Fatal("unverified active state accepted")
			}
		})
	}
	absent := runtimeLifecycleWitness{Complete: true}
	for _, entry := range []string{"not-an-address", "192.0.2.1/24", "::ffff:192.0.2.1", "fe80::1%eth0"} {
		if _, err := model.verifiedDeletion(entry, now, absent, absent); err == nil {
			t.Fatalf("invalid no-op entry accepted: %q", entry)
		}
	}
	if _, err := model.verifiedDeletion("192.0.2.1", now.Add(-time.Second), absent, absent); err == nil {
		t.Fatal("clock rollback accepted on a no-op path")
	}
	model.Sequence = 0
	if _, err := model.verifiedDeletion("192.0.2.1", now, absent, absent); err == nil {
		t.Fatal("corrupt model accepted on a no-op path")
	}
}

func TestRuntimeLifecycleCanonicalWireAndTampering(t *testing.T) {
	model, now := lifecycleModelFixture()
	model, err := model.verifiedBan("192.0.2.0/24", now, runtimeLifecycleWitness{Complete: true, Present: true, Permanent: true})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := model.digest()
	if err != nil || len(digest) != 64 {
		t.Fatalf("model digest: %q, %v", digest, err)
	}
	for name, corrupt := range map[string]func(*runtimeLifecycleModel){
		"nil-inventory": func(m *runtimeLifecycleModel) { m.Records = nil },
		"duplicate":     func(m *runtimeLifecycleModel) { m.Records = append(m.Records, m.Records[0]) },
		"false-cause":   func(m *runtimeLifecycleModel) { m.Records[0].Cause = "native-expiry" },
		"future-transition": func(m *runtimeLifecycleModel) {
			m.Records[0].TransitionAt = now.Add(time.Second).Format(time.RFC3339Nano)
		},
		"false-confirmation": func(m *runtimeLifecycleModel) { m.Records[0].ConfirmedAt = now.Format(time.RFC3339Nano) },
		"uppercase-identity": func(m *runtimeLifecycleModel) { m.Identity = strings.ToUpper(m.Identity) },
	} {
		t.Run(name, func(t *testing.T) {
			copyModel := model
			copyModel.Records = append([]runtimeLifecycleRecord{}, model.Records...)
			corrupt(&copyModel)
			if _, err := copyModel.wire(); err == nil {
				t.Fatal("corrupt model was serializable as evidence")
			}
		})
	}
}

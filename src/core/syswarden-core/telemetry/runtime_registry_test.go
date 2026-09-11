package telemetry

import (
	"fmt"
	"reflect"
	"testing"
)

func TestActiveRuntimeClaimAppearsWithoutAnAttackRecord(t *testing.T) {
	view, err := collectRuntimeEnforcementView(localRuntimeReporterFixture{snapshot: localRuntimeSnapshotFixture()})
	if err != nil {
		t.Fatal(err)
	}
	entries := appendActiveRuntimeRegistryEntries(nil, view)
	if len(entries) != 1 || entries[0].IP != "192.0.2.10" || entries[0].EnforcementState != "active" ||
		entries[0].Action != "BANNED" || entries[0].Jail != "native-runtime" || entries[0].Mitre != "-" ||
		entries[0].Timestamp != view.capturedAt {
		t.Fatalf("active native claim missing or misattributed: %+v", entries)
	}
	if !reflect.DeepEqual(*view.localSnapshot, localRuntimeSnapshotFixture()) {
		t.Fatal("registry projection modified native lifecycle history")
	}
}

func TestRuntimeRegistryPreservesAttackEvidenceAndBound(t *testing.T) {
	view := runtimeEnforcementView{linked: true, complete: true, capturedAt: "2026-09-11T19:00:00Z", byIP: map[string]string{
		"192.0.2.10": "active", "192.0.2.11": "deleted", "192.0.2.12": "expired", "192.0.2.13": "tombstoned",
		"192.0.2.14": "active", "2001:db8::/64": "active",
	}}
	original := []BannedIP{{IP: "192.0.2.10", Jail: "ssh-auth", Action: "BANNED", EnforcementState: "active", Payload: "original evidence"}}
	entries := appendActiveRuntimeRegistryEntries(append([]BannedIP{}, original...), view)
	if len(entries) != 3 || entries[0] != original[0] || entries[1].IP != "192.0.2.14" || entries[2].IP != "2001:db8::/64" {
		t.Fatalf("registry duplicated or altered attack evidence: %+v", entries)
	}
	for _, fault := range []string{"unlinked", "incomplete", "truncated"} {
		t.Run(fault, func(t *testing.T) {
			unsafe := view
			switch fault {
			case "unlinked":
				unsafe.linked = false
			case "incomplete":
				unsafe.complete = false
			case "truncated":
				unsafe.truncated = true
			}
			if got := appendActiveRuntimeRegistryEntries(nil, unsafe); len(got) != 0 {
				t.Fatalf("unverified runtime claims entered the registry: %+v", got)
			}
		})
	}
	view.byIP = make(map[string]string)
	for index := 1; index <= 60; index++ {
		view.byIP[fmt.Sprintf("192.0.2.%d", index)] = "active"
	}
	first := appendActiveRuntimeRegistryEntries(nil, view)
	second := appendActiveRuntimeRegistryEntries(nil, view)
	if len(first) != 50 || !reflect.DeepEqual(first, second) {
		t.Fatal("registry bound or deterministic ordering was lost")
	}
}

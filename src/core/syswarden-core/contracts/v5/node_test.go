package v5

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func nodeFixture(t testing.TB, name string) NodeSnapshot {
	t.Helper()
	snapshot, err := DecodeNodeSnapshot(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func readContext() NodeReadContext {
	return NodeReadContext{
		ExpectedIdentity: NodeIdentity{ClusterID: "cluster.fixture.1", NodeID: "node.fixture.1", Epoch: "generation.fixture.1"},
		Now:              time.Date(2026, time.January, 1, 0, 0, 30, 0, time.UTC),
		MaxAge:           time.Minute,
	}
}

func TestNodeSnapshotGolden(t *testing.T) {
	for _, name := range []string{"node-reachable.json", "node-unreachable.json", "node-unknown.json"} {
		t.Run(name, func(t *testing.T) {
			data := fixture(t, name)
			snapshot, err := DecodeNodeSnapshot(data)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := EncodeNodeSnapshot(snapshot)
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("node canonical bytes changed", err)
			}
			if err := CheckCurrentNodeSnapshot(snapshot, readContext()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeIdentityCannotBeReplacedByAnAddressOrDifferentEpoch(t *testing.T) {
	base := nodeFixture(t, "node-reachable.json")
	cases := map[string]func(*NodeSnapshot){
		"different cluster":   func(s *NodeSnapshot) { s.Identity.ClusterID = "cluster.fixture.2" },
		"different node":      func(s *NodeSnapshot) { s.Identity.NodeID = "node.fixture.2" },
		"old epoch":           func(s *NodeSnapshot) { s.Identity.Epoch = "generation.fixture.0" },
		"future epoch":        func(s *NodeSnapshot) { s.Identity.Epoch = "generation.fixture.999" },
		"case alias":          func(s *NodeSnapshot) { s.Identity.NodeID = "NODE.fixture.1" },
		"address as identity": func(s *NodeSnapshot) { s.Identity.NodeID = "192.0.2.10" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := base
			change(&s)
			// Valid syntax must never silently replace expected registry identity.
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := CheckCurrentNodeSnapshot(s, readContext()); !errors.Is(err, ErrNodeIdentityMismatch) {
				t.Fatal("identity substitution accepted", err)
			}
		})
	}
	context := readContext()
	context.ExpectedIdentity.Epoch = "generation.fixture.2"
	if err := CheckCurrentNodeSnapshot(base, context); !errors.Is(err, ErrNodeIdentityMismatch) {
		t.Fatal("revoked generation accepted", err)
	}
	base.Identity = context.ExpectedIdentity
	if err := CheckCurrentNodeSnapshot(base, context); err != nil {
		t.Fatal("exact replacement identity rejected", err)
	}
}

func TestNodeSnapshotFreshnessUsesCollectorTimeAndCallerPolicy(t *testing.T) {
	s := nodeFixture(t, "node-reachable.json")
	collected := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name           string
		offset, maxAge time.Duration
		want           error
	}{
		{"before collection", -time.Nanosecond, time.Minute, ErrNodeSnapshotNotCurrent},
		{"exact collection", 0, time.Minute, nil},
		{"before expiry", time.Minute - time.Nanosecond, time.Minute, nil},
		{"exact expiry", time.Minute, time.Minute, ErrNodeSnapshotNotCurrent},
		{"expired", 2 * time.Minute, time.Minute, ErrNodeSnapshotNotCurrent},
		{"shorter policy still current", 5 * time.Second, 10 * time.Second, nil},
		{"exact local deadline", 10 * time.Second, 10 * time.Second, ErrNodeSnapshotNotCurrent},
		{"local deadline exceeded", 20 * time.Second, 10 * time.Second, ErrNodeSnapshotNotCurrent},
		{"broader policy cannot extend expiry", time.Minute, 2 * time.Minute, ErrNodeSnapshotNotCurrent},
		{"zero policy", 0, 0, ErrInvalidNodeReadContext},
		{"negative policy", 0, -time.Second, ErrInvalidNodeReadContext},
		{"unbounded policy", 0, MaxSnapshotLifetime + time.Nanosecond, ErrInvalidNodeReadContext},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			context := readContext()
			context.Now = collected.Add(test.offset)
			context.MaxAge = test.maxAge
			if err := CheckCurrentNodeSnapshot(s, context); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	// A remote clock cannot extend the collector's freshness window.
	s.ObservedAt = Field{State: Present, Value: "2027-01-01T00:00:00Z"}
	s.ClockQuality = Field{State: Present, Value: "unsynchronized"}
	if err := CheckCurrentNodeSnapshot(s, readContext()); err != nil {
		t.Fatal(err)
	}
	context := readContext()
	context.Now = collected.Add(time.Minute)
	if err := CheckCurrentNodeSnapshot(s, context); !errors.Is(err, ErrNodeSnapshotNotCurrent) {
		t.Fatal("source clock extended freshness", err)
	}
	context.Now = time.Time{}
	if err := CheckCurrentNodeSnapshot(s, context); !errors.Is(err, ErrInvalidNodeReadContext) {
		t.Fatal("zero caller time accepted", err)
	}
	context = readContext()
	context.ExpectedIdentity = NodeIdentity{}
	if err := CheckCurrentNodeSnapshot(s, context); !errors.Is(err, ErrInvalidNodeReadContext) {
		t.Fatal("empty expected membership accepted", err)
	}
}

func TestDisconnectDoesNotInventProtectionOrLoseIntegrationHistory(t *testing.T) {
	online := nodeFixture(t, "node-reachable.json")
	offline := nodeFixture(t, "node-unreachable.json")
	if online.ControlRef.Value != offline.ControlRef.Value || online.IntegrationRef.Value != offline.IntegrationRef.Value {
		t.Fatal("cached protection or integration reference was lost")
	}
	if offline.ControlRef.State != Stale || offline.IntegrationRef.State != Stale {
		t.Fatal("outage hides stale evidence")
	}
	if err := CheckCurrentNodeSnapshot(offline, readContext()); err != nil {
		t.Fatal("fresh outage report rejected", err)
	}
	for _, reachability := range []string{"unreachable", "unknown"} {
		for _, state := range []string{Present, Partial} {
			for _, field := range []string{"observed_at", "clock_quality", "agent_version", "policy_ref", "control_ref", "integration_ref"} {
				t.Run(reachability+"/"+state+"/"+field, func(t *testing.T) {
					s := offline
					s.Reachability = reachability
					fields := map[string]*Field{"observed_at": &s.ObservedAt, "clock_quality": &s.ClockQuality,
						"agent_version": &s.AgentVersion, "policy_ref": &s.PolicyRef,
						"control_ref": &s.ControlRef, "integration_ref": &s.IntegrationRef}
					fields[field].State = state
					if err := s.Validate(); !errors.Is(err, ErrInvalidNodeDocument) {
						t.Fatal("cached fact became current", err)
					}
				})
			}
		}
	}
	// A successful transport exchange does not fill a missing protection proof.
	online.ControlRef = Field{State: Unavailable}
	online.PolicyRef = Field{State: Rejected}
	if err := CheckCurrentNodeSnapshot(online, readContext()); err != nil {
		t.Fatal(err)
	}
	if online.ControlRef.State != Unavailable || online.PolicyRef.State != Rejected {
		t.Fatal("link health became a policy verdict")
	}
}

func TestNodeSnapshotRejectsIncoherentConstructedValues(t *testing.T) {
	base := nodeFixture(t, "node-reachable.json")
	cases := map[string]func(*NodeSnapshot){
		"empty identity":                   func(s *NodeSnapshot) { s.Identity = NodeIdentity{} },
		"empty epoch":                      func(s *NodeSnapshot) { s.Identity.Epoch = "" },
		"empty collector":                  func(s *NodeSnapshot) { s.CollectorID = "" },
		"empty snapshot":                   func(s *NodeSnapshot) { s.SnapshotID = "" },
		"bad identifier":                   func(s *NodeSnapshot) { s.SnapshotID = "../../fixture" },
		"invalid utf8":                     func(s *NodeSnapshot) { s.Identity.NodeID = "\xff" },
		"oversized identifier":             func(s *NodeSnapshot) { s.Identity.NodeID = strings.Repeat("a", MaxIdentifierBytes+1) },
		"zero lifetime":                    func(s *NodeSnapshot) { s.ValidUntil = s.CollectedAt },
		"negative lifetime":                func(s *NodeSnapshot) { s.ValidUntil = "2025-12-31T23:59:59Z" },
		"excessive lifetime":               func(s *NodeSnapshot) { s.ValidUntil = "2026-01-02T00:00:00.000000001Z" },
		"invalid timestamp":                func(s *NodeSnapshot) { s.CollectedAt = "2026-02-30T00:00:00Z" },
		"noncanonical timestamp":           func(s *NodeSnapshot) { s.ValidUntil = "2026-01-01T01:01:00+01:00" },
		"unknown reachability":             func(s *NodeSnapshot) { s.Reachability = "protected" },
		"contact in future":                func(s *NodeSnapshot) { s.LastSuccessfulContact.Value = "2026-01-01T00:00:01Z" },
		"old contact called reachable":     func(s *NodeSnapshot) { s.LastSuccessfulContact.Value = "2025-12-31T23:59:59Z" },
		"missing contact called reachable": func(s *NodeSnapshot) { s.LastSuccessfulContact = Field{State: Missing} },
		"invalid clock":                    func(s *NodeSnapshot) { s.ClockQuality.Value = "healthy" },
		"unavailable with value":           func(s *NodeSnapshot) { s.ControlRef.State = Unavailable },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := base
			mutate(&s)
			if data, err := EncodeNodeSnapshot(s); !errors.Is(err, ErrInvalidNodeDocument) || data != nil {
				t.Fatal("incoherent snapshot encoded", err)
			}
			if err := CheckCurrentNodeSnapshot(s, readContext()); !errors.Is(err, ErrInvalidNodeDocument) {
				t.Fatal("incoherent snapshot considered current", err)
			}
		})
	}
	base.ValidUntil = "2026-01-02T00:00:00Z"
	base.Identity.NodeID = strings.Repeat("a", MaxIdentifierBytes)
	if _, err := EncodeNodeSnapshot(base); err != nil {
		t.Fatal("exact lifetime/identifier bound rejected", err)
	}
}

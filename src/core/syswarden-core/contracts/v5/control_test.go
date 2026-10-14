package v5

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func controlFixture(t testing.TB, name string) ControlSnapshot {
	t.Helper()
	s, err := DecodeControlSnapshot(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func controlContext(t testing.TB) ControlReadContext {
	t.Helper()
	return ControlReadContext{ExpectedIdentity: readContext().ExpectedIdentity, ExpectedScope: controlScopeFixture(t),
		Now: time.Date(2026, time.January, 1, 0, 0, 20, 0, time.UTC), MaxAge: time.Minute}
}

func TestControlSnapshotGolden(t *testing.T) {
	for _, name := range []string{"control-effective.json", "control-absent.json", "control-cached.json", "control-unavailable.json"} {
		t.Run(name, func(t *testing.T) {
			s := controlFixture(t, name)
			encoded, err := EncodeControlSnapshot(s)
			if err != nil || !bytes.Equal(encoded, fixture(t, name)) {
				t.Fatal("control golden bytes changed", err)
			}
			want := error(nil)
			if name == "control-cached.json" || name == "control-unavailable.json" {
				want = ErrControlNotCurrent
			}
			if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, want) {
				t.Fatal("unexpected current-state classification", err)
			}
		})
	}
}

func TestActionSuccessCannotRenewControlEvidence(t *testing.T) {
	a := actionFixture(t, "action-verified.json")
	if err := CheckActionOutcomeBinding(a, actionContext(t)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"control-cached.json", "control-unavailable.json"} {
		s := controlFixture(t, name)
		if s.ActionRef != (Field{Present, a.OutcomeID}) {
			t.Fatal("fixture does not retain the historical action link")
		}
		if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, ErrControlNotCurrent) {
			t.Fatal("historical success became current protection", err)
		}
	}
	// Even a new live report cannot give an old observation a new lifetime.
	s := controlFixture(t, "control-effective.json")
	s.ObservedAt.Value = "2025-12-31T23:00:00Z"
	if err := s.Validate(); err != nil {
		t.Fatal("old observation must remain available for historical review", err)
	}
	if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, ErrControlNotCurrent) {
		t.Fatal("new collection time renewed old measurement", err)
	}
}

func TestControlPresenceAndAbsenceAreScopedToOneOwner(t *testing.T) {
	for _, name := range []string{"control-effective.json", "control-absent.json"} {
		s := controlFixture(t, name)
		context := controlContext(t)
		if err := CheckCurrentControlSnapshot(s, context); err != nil {
			t.Fatal(err)
		}
		context.ExpectedScope.OwnerID = "owner.administrator"
		if err := CheckCurrentControlSnapshot(s, context); !errors.Is(err, ErrControlScopeMismatch) {
			t.Fatal("one source's claim established another owner's state", err)
		}
	}
	// Transport reachability is a separate statement from enforcement evidence.
	node := nodeFixture(t, "node-reachable.json")
	if err := CheckCurrentNodeSnapshot(node, readContext()); err != nil {
		t.Fatal(err)
	}
	s := controlFixture(t, "control-unavailable.json")
	if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, ErrControlNotCurrent) {
		t.Fatal("healthy transport filled missing verification", err)
	}
}

func TestControlCurrencyUsesObservationAndExactExpiry(t *testing.T) {
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		now, maxAge time.Duration
		until       string
		want        error
	}{
		{"before collection", 9 * time.Second, time.Minute, "2026-01-01T00:01:10Z", ErrControlNotCurrent},
		{"at collection", 10 * time.Second, time.Minute, "2026-01-01T00:01:10Z", nil},
		{"before observation age limit", 68*time.Second - time.Nanosecond, time.Minute, "2026-01-01T00:01:10Z", nil},
		{"exact observation age limit", 68 * time.Second, time.Minute, "2026-01-01T00:01:10Z", ErrControlNotCurrent},
		{"short policy", 18 * time.Second, 10 * time.Second, "2026-01-01T00:01:10Z", ErrControlNotCurrent},
		{"before document expiry", 15*time.Second - time.Nanosecond, time.Minute, "2026-01-01T00:00:15Z", nil},
		{"exact document expiry", 15 * time.Second, time.Minute, "2026-01-01T00:00:15Z", ErrControlNotCurrent},
		{"broader policy cannot extend expiry", 70 * time.Second, 2 * time.Minute, "2026-01-01T00:01:10Z", ErrControlNotCurrent},
		{"zero budget", 20 * time.Second, 0, "2026-01-01T00:01:10Z", ErrInvalidControlContext},
		{"negative budget", 20 * time.Second, -time.Second, "2026-01-01T00:01:10Z", ErrInvalidControlContext},
		{"excessive budget", 20 * time.Second, MaxSnapshotLifetime + time.Nanosecond, "2026-01-01T00:01:10Z", ErrInvalidControlContext},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s := controlFixture(t, "control-effective.json")
			s.ValidUntil = test.until
			context := controlContext(t)
			context.Now, context.MaxAge = base.Add(test.now), test.maxAge
			if err := CheckCurrentControlSnapshot(s, context); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	for _, clock := range []string{"unknown", "unsynchronized", "synchronized"} {
		s := controlFixture(t, "control-effective.json")
		s.ObservedAt.Value, s.ClockQuality = "2027-01-01T00:00:00Z", clock
		if err := s.Validate(); err != nil {
			t.Fatal("skewed historical data discarded", err)
		}
		if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, ErrControlNotCurrent) {
			t.Fatal("future observation accepted", err)
		}
	}
	for _, clock := range []string{"unknown", "unsynchronized"} {
		s := controlFixture(t, "control-effective.json")
		s.ClockQuality = clock
		if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, ErrControlNotCurrent) {
			t.Fatal("unestablished clock accepted for currency", err)
		}
	}
}

func TestControlSnapshotRejectsSubstitutedScope(t *testing.T) {
	cases := map[string]func(*ControlReadContext){
		"cluster":      func(c *ControlReadContext) { c.ExpectedIdentity.ClusterID = "cluster.other" },
		"node":         func(c *ControlReadContext) { c.ExpectedIdentity.NodeID = "node.other" },
		"old epoch":    func(c *ControlReadContext) { c.ExpectedIdentity.Epoch = "generation.fixture.0" },
		"new epoch":    func(c *ControlReadContext) { c.ExpectedIdentity.Epoch = "generation.fixture.999" },
		"control":      func(c *ControlReadContext) { c.ExpectedScope.ControlID = "control.other" },
		"target":       func(c *ControlReadContext) { c.ExpectedScope.TargetRef = "target.other" },
		"target bytes": func(c *ControlReadContext) { c.ExpectedScope.TargetSHA256 = strings.Repeat("0", 64) },
		"owner":        func(c *ControlReadContext) { c.ExpectedScope.OwnerID = "owner.other" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			context := controlContext(t)
			change(&context)
			if err := CheckCurrentControlSnapshot(controlFixture(t, "control-effective.json"), context); !errors.Is(err, ErrControlScopeMismatch) {
				t.Fatal("scope substitution accepted", err)
			}
		})
	}
}

func TestControlReportCannotOutliveEffectTTL(t *testing.T) {
	s := controlFixture(t, "control-effective.json")
	s.EffectExpiresAt = Field{Present, "2026-01-01T00:00:20Z"}
	context := controlContext(t)
	context.Now = context.Now.Add(-time.Nanosecond)
	if err := CheckCurrentControlSnapshot(s, context); err != nil {
		t.Fatal("unexpired control rejected", err)
	}
	context.Now = context.Now.Add(time.Nanosecond)
	if err := CheckCurrentControlSnapshot(s, context); !errors.Is(err, ErrControlNotCurrent) {
		t.Fatal("exact TTL expiry was extended by snapshot lifetime", err)
	}
	s.EffectExpiresAt.Value = s.ObservedAt.Value
	if err := CheckCurrentControlSnapshot(s, context); !errors.Is(err, ErrControlNotCurrent) {
		t.Fatal("effect already expired when observed accepted", err)
	}
	for _, state := range []string{Missing, Unavailable, Rejected, Partial, Stale} {
		t.Run(state, func(t *testing.T) {
			s.EffectExpiresAt = Field{State: state}
			if s.EffectExpiresAt.hasValue() {
				s.EffectExpiresAt.Value = "2026-01-02T00:00:00Z"
			}
			if err := s.Validate(); err != nil {
				t.Fatal("incomplete lifetime should remain visible", err)
			}
			if err := CheckCurrentControlSnapshot(s, context); !errors.Is(err, ErrControlNotCurrent) {
				t.Fatal("unknown lifetime became a permanent control", err)
			}
		})
	}
	s.EffectExpiresAt = Field{State: NotApplicable}
	if err := CheckCurrentControlSnapshot(s, context); err != nil {
		t.Fatal("explicitly non-expiring control rejected", err)
	}
}

func TestIncompleteControlEvidenceNeverBecomesCurrent(t *testing.T) {
	for _, state := range []string{Missing, Unavailable, Stale, Partial, Rejected, NotApplicable} {
		t.Run(state, func(t *testing.T) {
			s := controlFixture(t, "control-effective.json")
			s.State.State = state
			if !s.State.hasValue() {
				s.State.Value = ""
			}
			encoded, err := EncodeControlSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeControlSnapshot(encoded)
			if err != nil || again != s {
				t.Fatal("availability changed", err)
			}
			if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, ErrControlNotCurrent) {
				t.Fatal("incomplete state became current", err)
			}
		})
	}
	for _, field := range []string{"state", "observed_at", "effect_expires_at", "evidence_ref"} {
		for _, state := range []string{Present, Partial} {
			s := controlFixture(t, "control-cached.json")
			fields := map[string]*Field{"state": &s.State, "observed_at": &s.ObservedAt, "effect_expires_at": &s.EffectExpiresAt, "evidence_ref": &s.EvidenceRef}
			fields[field].State = state
			if err := s.Validate(); !errors.Is(err, ErrInvalidControlDocument) {
				t.Fatal("cache value promoted", field, err)
			}
		}
	}
}

func TestControlRejectsInvalidConstructedValues(t *testing.T) {
	cases := map[string]func(*ControlSnapshot){
		"identity":             func(s *ControlSnapshot) { s.Identity.NodeID = "" },
		"scope":                func(s *ControlSnapshot) { s.Scope.TargetSHA256 = strings.Repeat("A", 64) },
		"identifier":           func(s *ControlSnapshot) { s.ObserverID = "../../observer" },
		"oversized identifier": func(s *ControlSnapshot) { s.SnapshotID = strings.Repeat("a", MaxIdentifierBytes+1) },
		"zero lifetime":        func(s *ControlSnapshot) { s.ValidUntil = s.CollectedAt },
		"negative lifetime":    func(s *ControlSnapshot) { s.ValidUntil = "2025-01-01T00:00:00Z" },
		"excessive lifetime":   func(s *ControlSnapshot) { s.ValidUntil = "2026-01-02T00:00:10.000000001Z" },
		"noncanonical time":    func(s *ControlSnapshot) { s.CollectedAt = "2026-01-01T01:00:10+01:00" },
		"observation":          func(s *ControlSnapshot) { s.ObservedAt.Value = "invalid" },
		"clock":                func(s *ControlSnapshot) { s.ClockQuality = "trusted" },
		"basis":                func(s *ControlSnapshot) { s.Basis = "action_succeeded" },
		"value":                func(s *ControlSnapshot) { s.State.Value = "allowed" },
		"expiry timestamp":     func(s *ControlSnapshot) { s.EffectExpiresAt = Field{Present, "invalid"} },
		"absent with active TTL": func(s *ControlSnapshot) {
			s.State.Value = "absent"
			s.EffectExpiresAt = Field{Present, "2026-01-01T00:00:30Z"}
		},
		"no observation":          func(s *ControlSnapshot) { s.ObservedAt = Field{State: Unavailable} },
		"no evidence":             func(s *ControlSnapshot) { s.EvidenceRef = Field{State: Missing} },
		"partial evidence":        func(s *ControlSnapshot) { s.EvidenceRef.State = Partial },
		"action reference":        func(s *ControlSnapshot) { s.ActionRef = Field{Present, ""} },
		"unavailable with values": func(s *ControlSnapshot) { s.Basis = "unavailable"; s.State.State = Stale },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := controlFixture(t, "control-effective.json")
			change(&s)
			if data, err := EncodeControlSnapshot(s); !errors.Is(err, ErrInvalidControlDocument) || data != nil {
				t.Fatal("invalid snapshot encoded", err)
			}
			if err := CheckCurrentControlSnapshot(s, controlContext(t)); !errors.Is(err, ErrInvalidControlDocument) {
				t.Fatal("invalid snapshot considered current", err)
			}
		})
	}
	s := controlFixture(t, "control-effective.json")
	s.ValidUntil = "2026-01-02T00:00:10Z"
	s.SnapshotID = strings.Repeat("a", MaxIdentifierBytes)
	if _, err := EncodeControlSnapshot(s); err != nil {
		t.Fatal("exact lifetime or identifier boundary rejected", err)
	}
	contexts := []ControlReadContext{controlContext(t), controlContext(t), controlContext(t)}
	contexts[0].Now = time.Time{}
	contexts[1].ExpectedIdentity.Epoch = ""
	contexts[2].ExpectedScope.OwnerID = ""
	for _, context := range contexts {
		if err := CheckCurrentControlSnapshot(s, context); !errors.Is(err, ErrInvalidControlContext) {
			t.Fatal("invalid read context accepted", err)
		}
	}
}

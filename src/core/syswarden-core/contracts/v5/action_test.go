package v5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func inputFixtureDigest(t testing.TB, name string) string {
	t.Helper()
	data, err := goldenFixtures.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func controlScopeFixture(t testing.TB) ControlScope {
	t.Helper()
	return ControlScope{ControlID: "control.fixture.1", TargetRef: "target.fixture.1",
		TargetSHA256: inputFixtureDigest(t, "control-target-input.txt"), OwnerID: "owner.fixture.1"}
}

func actionContext(t testing.TB) ActionReadContext {
	t.Helper()
	return ActionReadContext{ExpectedIdentity: readContext().ExpectedIdentity,
		ExpectedScope: controlScopeFixture(t), ActionID: "action.fixture.1", AttemptID: "attempt.fixture.1",
		PlanRef: "plan.fixture.1", PlanSHA256: inputFixtureDigest(t, "action-plan-input.txt")}
}

func actionFixture(t testing.TB, name string) ActionOutcome {
	t.Helper()
	a, err := DecodeActionOutcome(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestActionOutcomeGolden(t *testing.T) {
	for _, name := range []string{"action-verified.json", "action-failed.json", "action-unknown.json"} {
		t.Run(name, func(t *testing.T) {
			a := actionFixture(t, name)
			encoded, err := EncodeActionOutcome(a)
			if err != nil || !bytes.Equal(encoded, fixture(t, name)) {
				t.Fatal("action golden bytes changed", err)
			}
			// Exact historical binding is possible for a failed or unknown result.
			if err := CheckActionOutcomeBinding(a, actionContext(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActionStatesRemainDistinctHistoricalReports(t *testing.T) {
	for _, state := range []string{"pending", "applied", "verified", "expired", "rolled_back", "failed", "partial", "unknown"} {
		t.Run(state, func(t *testing.T) {
			a := actionFixture(t, "action-verified.json")
			a.State = state
			if state != "verified" && state != "rolled_back" {
				a.VerificationRef = Field{State: Unavailable}
			}
			if member("pending", "expired", "failed", "unknown")(state) {
				a.AuthorityRef = Field{State: Unavailable}
			}
			if state == "unknown" {
				a.ReasonCode, a.EvidenceRef = Field{State: Unavailable}, Field{State: Unavailable}
			}
			encoded, err := EncodeActionOutcome(a)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeActionOutcome(encoded)
			if err != nil || decoded != a {
				t.Fatal("outcome was promoted or erased", err)
			}
			if err := CheckActionOutcomeBinding(a, actionContext(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A timestamp does not establish current enforcement or retry ordering.
	a := actionFixture(t, "action-verified.json")
	for _, when := range []string{"2025-01-01T00:00:00Z", "2027-01-01T00:00:00Z"} {
		a.RecordedAt, a.ClockQuality = when, "unsynchronized"
		if err := CheckActionOutcomeBinding(a, actionContext(t)); err != nil {
			t.Fatal("historical clock metadata became execution authority", err)
		}
	}
}

func TestActionBindingRejectsSubstitution(t *testing.T) {
	cases := map[string]func(*ActionReadContext){
		"cluster":      func(c *ActionReadContext) { c.ExpectedIdentity.ClusterID = "cluster.other" },
		"node":         func(c *ActionReadContext) { c.ExpectedIdentity.NodeID = "node.other" },
		"epoch":        func(c *ActionReadContext) { c.ExpectedIdentity.Epoch = "generation.fixture.999" },
		"control":      func(c *ActionReadContext) { c.ExpectedScope.ControlID = "control.other" },
		"target":       func(c *ActionReadContext) { c.ExpectedScope.TargetRef = "target.other" },
		"target bytes": func(c *ActionReadContext) { c.ExpectedScope.TargetSHA256 = strings.Repeat("0", 64) },
		"owner":        func(c *ActionReadContext) { c.ExpectedScope.OwnerID = "owner.other" },
		"action":       func(c *ActionReadContext) { c.ActionID = "action.other" },
		"retry":        func(c *ActionReadContext) { c.AttemptID = "attempt.fixture.2" },
		"plan":         func(c *ActionReadContext) { c.PlanRef = "plan.other" },
		"plan bytes":   func(c *ActionReadContext) { c.PlanSHA256 = strings.Repeat("0", 64) },
	}
	a := actionFixture(t, "action-verified.json")
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			context := actionContext(t)
			change(&context)
			if err := CheckActionOutcomeBinding(a, context); !errors.Is(err, ErrActionBindingMismatch) {
				t.Fatal("different action scope or plan accepted", err)
			}
		})
	}
}

func TestActionClaimsRequireIdentifiedAuthorityAndEvidence(t *testing.T) {
	for _, state := range []string{Missing, Unavailable, Stale, Partial, Rejected, NotApplicable} {
		for _, field := range []string{"authority", "reason", "evidence", "verification"} {
			for _, outcome := range []string{"verified", "rolled_back"} {
				t.Run(outcome+"/"+field+"/"+state, func(t *testing.T) {
					a := actionFixture(t, "action-verified.json")
					a.State = outcome
					fields := map[string]*Field{"authority": &a.AuthorityRef, "reason": &a.ReasonCode,
						"evidence": &a.EvidenceRef, "verification": &a.VerificationRef}
					f := fields[field]
					f.State = state
					if !f.hasValue() {
						f.Value = ""
					}
					if encoded, err := EncodeActionOutcome(a); !errors.Is(err, ErrInvalidActionDocument) || encoded != nil {
						t.Fatal("unsupported success claim accepted", err)
					}
				})
			}
		}
	}
	for _, state := range []string{"applied", "partial"} {
		a := actionFixture(t, "action-verified.json")
		a.State, a.AuthorityRef = state, Field{State: Unavailable}
		if err := a.Validate(); !errors.Is(err, ErrInvalidActionDocument) {
			t.Fatal("effect claimed without identified authority", err)
		}
	}
}

func TestActionRejectsInvalidConstructedRecordsAndContext(t *testing.T) {
	cases := map[string]func(*ActionOutcome){
		"identity":        func(a *ActionOutcome) { a.Identity = NodeIdentity{} },
		"scope":           func(a *ActionOutcome) { a.Scope.OwnerID = "" },
		"outcome":         func(a *ActionOutcome) { a.OutcomeID = "" },
		"attempt":         func(a *ActionOutcome) { a.AttemptID = "" },
		"action":          func(a *ActionOutcome) { a.ActionID = "../../other" },
		"size":            func(a *ActionOutcome) { a.ReporterID = strings.Repeat("a", MaxIdentifierBytes+1) },
		"plan":            func(a *ActionOutcome) { a.PlanRef = "https://example.invalid/plan" },
		"plan digest":     func(a *ActionOutcome) { a.PlanSHA256 = strings.Repeat("A", 64) },
		"time":            func(a *ActionOutcome) { a.RecordedAt = "2026-01-01T01:00:01+01:00" },
		"clock":           func(a *ActionOutcome) { a.ClockQuality = "trusted" },
		"state":           func(a *ActionOutcome) { a.State = "protected" },
		"empty reference": func(a *ActionOutcome) { a.EvidenceRef.Value = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := actionFixture(t, "action-verified.json")
			change(&a)
			if data, err := EncodeActionOutcome(a); !errors.Is(err, ErrInvalidActionDocument) || data != nil {
				t.Fatal("invalid record encoded", err)
			}
			if err := CheckActionOutcomeBinding(a, actionContext(t)); !errors.Is(err, ErrInvalidActionDocument) {
				t.Fatal("invalid record passed contextual check", err)
			}
		})
	}
	a := actionFixture(t, "action-verified.json")
	contexts := []ActionReadContext{actionContext(t), actionContext(t), actionContext(t), actionContext(t)}
	contexts[0].ExpectedIdentity.Epoch = ""
	contexts[1].ExpectedScope.TargetSHA256 = "invalid"
	contexts[2].AttemptID = ""
	contexts[3].PlanSHA256 = "invalid"
	for _, context := range contexts {
		if err := CheckActionOutcomeBinding(a, context); !errors.Is(err, ErrInvalidActionContext) {
			t.Fatal("invalid caller context accepted", err)
		}
	}
}

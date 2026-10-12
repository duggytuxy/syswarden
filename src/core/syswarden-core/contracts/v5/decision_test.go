package v5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func decisionFixture(t testing.TB, name string) PolicyDecision {
	t.Helper()
	d, err := DecodePolicyDecision(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func decisionContext(t testing.TB, eventFixture string) DecisionReadContext {
	t.Helper()
	event, err := DecodeEvent(fixture(t, eventFixture))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := goldenFixtures.ReadFile("testdata/decision-policy-input.txt")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(policy)
	return DecisionReadContext{
		EventIdentity: readContext().ExpectedIdentity,
		Event:         event,
		PolicyRef:     "policy.fixture.1",
		PolicySHA256:  hex.EncodeToString(sum[:]),
	}
}

func TestPolicyDecisionGolden(t *testing.T) {
	for _, name := range []string{"decision-block.json", "decision-allow.json", "decision-observe-l2.json", "decision-unavailable.json"} {
		t.Run(name, func(t *testing.T) {
			data := fixture(t, name)
			d := decisionFixture(t, name)
			encoded, err := EncodePolicyDecision(d)
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("decision golden bytes changed", err)
			}
			input := "native-ip.json"
			if name == "decision-observe-l2.json" {
				input = "native-l2.json"
			}
			want := error(nil)
			if name == "decision-unavailable.json" {
				want = ErrDecisionInputMismatch
			}
			if err := CheckPolicyDecisionBinding(d, decisionContext(t, input)); !errors.Is(err, want) {
				t.Fatal("unexpected decision input binding", err)
			}
		})
	}
}

func TestPolicyDecisionRejectsInputSubstitution(t *testing.T) {
	base := decisionFixture(t, "decision-block.json")
	cases := map[string]func(*PolicyDecision){
		"cluster":         func(d *PolicyDecision) { d.Identity.ClusterID = "cluster.other" },
		"node":            func(d *PolicyDecision) { d.Identity.NodeID = "node.other" },
		"previous epoch":  func(d *PolicyDecision) { d.Identity.Epoch = "generation.fixture.0" },
		"later epoch":     func(d *PolicyDecision) { d.Identity.Epoch = "generation.fixture.999" },
		"event reference": func(d *PolicyDecision) { d.Input.EventID = "event.other" },
		"event digest":    func(d *PolicyDecision) { d.Input.EventSHA256 = strings.Repeat("0", 64) },
		"policy reference": func(d *PolicyDecision) {
			d.PolicyRef.Value = "policy.other"
		},
		"same policy name new bytes": func(d *PolicyDecision) { d.PolicySHA256.Value = strings.Repeat("0", 64) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			change(&d)
			if err := d.Validate(); err != nil {
				t.Fatal("expected syntactically valid substituted statement", err)
			}
			if err := CheckPolicyDecisionBinding(d, decisionContext(t, "native-ip.json")); !errors.Is(err, ErrDecisionInputMismatch) {
				t.Fatal("substitution accepted", err)
			}
		})
	}
}

func TestDecisionBindingCoversWholeEvent(t *testing.T) {
	d := decisionFixture(t, "decision-block.json")
	cases := map[string]func(*Event){
		"address":           func(e *Event) { e.Subject.Address.Value = "192.0.2.11" },
		"layer":             func(e *Event) { e.Layer.Value = "L7" },
		"observation":       func(e *Event) { e.ObservationCode.Value = "other_observation" },
		"observed time":     func(e *Event) { e.ObservedAt.Value = "2027-01-01T00:00:00Z" },
		"receipt time":      func(e *Event) { e.ReceivedAt = "2026-01-01T00:00:02Z" },
		"clock":             func(e *Event) { e.ClockQuality = "synchronized" },
		"source":            func(e *Event) { e.Provenance.SourceID.Value = "source.other" },
		"severity":          func(e *Event) { e.Severity = Field{Present, "critical"} },
		"evidence":          func(e *Event) { e.EvidenceRef = Field{Present, "evidence.other"} },
		"policy":            func(e *Event) { e.PolicyRef = Field{Present, "policy.other"} },
		"historical action": func(e *Event) { e.ActionRef = Field{Present, "action.other"} },
		"current control":   func(e *Event) { e.ControlRef = Field{Present, "control.other"} },
		"reputation":        func(e *Event) { e.Context.Reputation = Field{Present, "reputation.other"} },
		"trust":             func(e *Event) { e.Context.Trust = Field{Present, "trust.other"} },
		"history":           func(e *Event) { e.Context.History = Field{Partial, "history.other"} },
		"attribution":       func(e *Event) { e.Context.Attribution = Field{Stale, "attribution.other"} },
		"original bytes":    func(e *Event) { e.Provenance.OriginalSHA256 = Field{Present, strings.Repeat("a", 64)} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			context := decisionContext(t, "native-ip.json")
			change(&context.Event)
			if err := context.Event.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := CheckPolicyDecisionBinding(d, context); !errors.Is(err, ErrDecisionInputMismatch) {
				t.Fatal("changed event retained previous decision binding", err)
			}
		})
	}
}

func TestPolicyDecisionAvailabilityNeverBecomesEnforcement(t *testing.T) {
	base := decisionFixture(t, "decision-block.json")
	context := decisionContext(t, "native-ip.json")
	before := context.Event
	for _, field := range []string{"verdict", "severity"} {
		for _, state := range []string{Present, Stale, Partial, Missing, Unavailable, Rejected, NotApplicable} {
			t.Run(field+"/"+state, func(t *testing.T) {
				d := base
				value := &d.Verdict
				if field == "severity" {
					value = &d.Severity
				}
				value.State = state
				if !value.hasValue() {
					value.Value = ""
				}
				encoded, err := EncodePolicyDecision(d)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := DecodePolicyDecision(encoded)
				if err != nil || decoded != d {
					t.Fatal("decision availability changed", err)
				}
				if err := CheckPolicyDecisionBinding(decoded, context); err != nil {
					t.Fatal("input binding incorrectly decided verdict availability", err)
				}
				if context.Event != before {
					t.Fatal("decision mutated observation or invented enforcement")
				}
			})
		}
	}
	// Evaluation time is historical, not an expiry window or causal proof.
	base.EvaluatedAt = "2025-01-01T00:00:00Z"
	base.ClockQuality = "unsynchronized"
	if err := CheckPolicyDecisionBinding(base, context); err != nil {
		t.Fatal("source clock caused an invented ordering", err)
	}
}

func TestPolicyClassificationRequiresPinnedPolicyAndExplanation(t *testing.T) {
	for _, classified := range []string{"verdict", "severity"} {
		for _, dependency := range []string{"policy", "reason", "evidence"} {
			for _, state := range []string{Missing, Unavailable, Stale, Partial, Rejected, NotApplicable} {
				t.Run(classified+"/"+dependency+"/"+state, func(t *testing.T) {
					d := decisionFixture(t, "decision-block.json")
					if classified == "verdict" {
						d.Severity = Field{State: Unavailable}
					} else {
						d.Verdict = Field{State: Unavailable}
					}
					fields := map[string][]*Field{"policy": {&d.PolicyRef, &d.PolicySHA256}, "reason": {&d.ReasonCode}, "evidence": {&d.EvidenceRef}}
					for _, field := range fields[dependency] {
						field.State = state
						if !field.hasValue() {
							field.Value = ""
						}
					}
					if _, err := EncodePolicyDecision(d); !errors.Is(err, ErrInvalidDecisionDocument) {
						t.Fatal("classification accepted without exact policy/explanation", err)
					}
				})
			}
		}
	}
}

func TestPolicyDecisionRejectsInvalidContext(t *testing.T) {
	d := decisionFixture(t, "decision-block.json")
	cases := map[string]func(*DecisionReadContext){
		"empty identity":                    func(c *DecisionReadContext) { c.EventIdentity = NodeIdentity{} },
		"empty policy":                      func(c *DecisionReadContext) { c.PolicyRef = "" },
		"invalid policy hash":               func(c *DecisionReadContext) { c.PolicySHA256 = strings.Repeat("A", 64) },
		"event node differs from ingestion": func(c *DecisionReadContext) { c.EventIdentity.NodeID = "node.other" },
		"empty event":                       func(c *DecisionReadContext) { c.Event = Event{} },
		"missing event identity":            func(c *DecisionReadContext) { c.Event.EventID = Field{State: Missing} },
		"stale event identity":              func(c *DecisionReadContext) { c.Event.EventID.State = Stale },
		"partial node identity":             func(c *DecisionReadContext) { c.Event.NodeID.State = Partial },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			context := decisionContext(t, "native-ip.json")
			change(&context)
			if err := CheckPolicyDecisionBinding(d, context); !errors.Is(err, ErrInvalidDecisionInput) {
				t.Fatal("invalid caller context accepted", err)
			}
		})
	}
	if value, err := DecisionEventSHA256(Event{}); !errors.Is(err, ErrInvalidDecisionInput) || value != "" {
		t.Fatal("invalid input returned a usable digest", err)
	}
}

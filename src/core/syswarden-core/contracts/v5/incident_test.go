package v5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func incidentFixture(t testing.TB, name string) IncidentRelation {
	t.Helper()
	r, err := DecodeIncidentRelation(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func incidentContext(t testing.TB, relationID string) IncidentReadContext {
	t.Helper()
	sum := sha256.Sum256(evidencePayload(t, "incident-rule.txt"))
	id := readContext().ExpectedIdentity
	return IncidentReadContext{ExpectedIdentity: id, RelationID: relationID, IncidentID: "incident.fixture.1",
		RuleRef: "rule.fixture.correlation", RuleSHA256: hex.EncodeToString(sum[:]),
		From:     ResolvedIncidentRecord{Identity: id, Schema: EventSchema, Data: fixture(t, "native-ip.json")},
		To:       ResolvedIncidentRecord{Identity: id, Schema: PolicyDecisionSchema, Data: fixture(t, "decision-block.json")},
		Evidence: evidenceFixture(t, "evidence-original.json")}
}

func TestIncidentRelationGolden(t *testing.T) {
	for _, name := range []string{"incident-association.json", "incident-contradicted.json", "incident-unresolved.json"} {
		t.Run(name, func(t *testing.T) {
			r := incidentFixture(t, name)
			data, err := EncodeIncidentRelation(r)
			if err != nil || !bytes.Equal(data, fixture(t, name)) {
				t.Fatal("incident golden bytes changed", err)
			}
			err = CheckIncidentRelationBinding(r, incidentContext(t, r.RelationID))
			if name == "incident-unresolved.json" {
				if !errors.Is(err, ErrIncidentInputsUnavailable) {
					t.Fatal("unresolved evidence interpreted", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIncidentReferencesPreserveCanonicalTypedRecords(t *testing.T) {
	for _, item := range []struct{ schema, name string }{
		{EventSchema, "native-ip.json"}, {EventSchema, "native-l2.json"},
		{NodeSnapshotSchema, "node-unreachable.json"}, {PolicyDecisionSchema, "decision-unavailable.json"},
		{ActionOutcomeSchema, "action-failed.json"}, {ControlSnapshotSchema, "control-cached.json"},
		{EvidenceDescriptorSchema, "evidence-unknown.json"},
	} {
		t.Run(item.name, func(t *testing.T) {
			input := ResolvedIncidentRecord{Identity: readContext().ExpectedIdentity, Schema: item.schema, Data: fixture(t, item.name)}
			ref, err := IncidentRecordReferenceFromJSON(input)
			if err != nil || !ref.validate() {
				t.Fatal("valid historical endpoint rejected", err)
			}
			sum := sha256.Sum256(input.Data)
			if ref.SHA256 != hex.EncodeToString(sum[:]) || ref.Schema != item.schema {
				t.Fatal("wrong endpoint digest domain")
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, input.Data, "", "  "); err != nil {
				t.Fatal(err)
			}
			input.Data = pretty.Bytes()
			again, err := IncidentRecordReferenceFromJSON(input)
			if err != nil || again != ref {
				t.Fatal("formatting changed endpoint identity", err)
			}
			input.Identity.NodeID = "node.other"
			if ref, err := IncidentRecordReferenceFromJSON(input); !errors.Is(err, ErrInvalidIncidentInput) || ref != (IncidentRecordReference{}) {
				t.Fatal("cross-node endpoint accepted", err)
			}
		})
	}
}

func TestIncidentBindingRejectsInputSubstitution(t *testing.T) {
	r := incidentFixture(t, "incident-association.json")
	cases := map[string]func(*IncidentReadContext){
		"incident":                func(c *IncidentReadContext) { c.IncidentID = "incident.other" },
		"relation":                func(c *IncidentReadContext) { c.RelationID = "relation.other" },
		"expected cluster":        func(c *IncidentReadContext) { c.ExpectedIdentity.ClusterID = "cluster.other" },
		"expected node":           func(c *IncidentReadContext) { c.ExpectedIdentity.NodeID = "node.other" },
		"expected epoch":          func(c *IncidentReadContext) { c.ExpectedIdentity.Epoch = "generation.other" },
		"event ingestion epoch":   func(c *IncidentReadContext) { c.From.Identity.Epoch = "generation.other" },
		"event ingestion cluster": func(c *IncidentReadContext) { c.From.Identity.ClusterID = "cluster.other" },
		"rule identity":           func(c *IncidentReadContext) { c.RuleRef = "rule.other" },
		"rule bytes":              func(c *IncidentReadContext) { c.RuleSHA256 = strings.Repeat("0", 64) },
		"reverse endpoints":       func(c *IncidentReadContext) { c.From, c.To = c.To, c.From },
		"event bytes with same ID": func(c *IncidentReadContext) {
			c.From.Data = bytes.Replace(c.From.Data, []byte("192.0.2.10"), []byte("192.0.2.11"), 1)
		},
		"evidence ID":     func(c *IncidentReadContext) { c.Evidence.EvidenceID = "evidence.other" },
		"evidence source": func(c *IncidentReadContext) { c.Evidence.SourceID = "source.other" },
		"evidence epoch":  func(c *IncidentReadContext) { c.Evidence.Identity.Epoch = "generation.other" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := incidentContext(t, r.RelationID)
			change(&c)
			if err := CheckIncidentRelationBinding(r, c); !errors.Is(err, ErrIncidentInputMismatch) {
				t.Fatal("substituted inputs accepted", err)
			}
		})
	}
}

func TestIncidentBindingDoesNotValidateClaimOrPayload(t *testing.T) {
	r := incidentFixture(t, "incident-contradicted.json")
	c := incidentContext(t, r.RelationID)
	// Missing payload bytes do not rewrite a known descriptor or assessment.
	c.Evidence = evidenceFixture(t, "evidence-unavailable.json")
	hash, err := EvidenceDescriptorSHA256(c.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	r.Evidence = EvidenceReference{Ref: Field{Present, c.Evidence.EvidenceID}, SHA256: Field{Present, hash}}
	if err := CheckIncidentRelationBinding(r, c); err != nil {
		t.Fatal("known unavailable descriptor cannot be linked", err)
	}
	if r.Support.Value != "contradicting" || c.Evidence.Content.Ref.State != Unavailable {
		t.Fatal("binding changed evidence meaning")
	}
	for _, state := range []string{Present, Stale, Partial, Missing, Unavailable, Rejected, NotApplicable} {
		t.Run(state, func(t *testing.T) {
			x := r
			x.Support.State = state
			if !x.Support.hasValue() {
				x.Support.Value = ""
			}
			data, err := EncodeIncidentRelation(x)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeIncidentRelation(data)
			if err != nil || again != x {
				t.Fatal("support availability lost", err)
			}
			if err := CheckIncidentRelationBinding(x, c); err != nil {
				t.Fatal("input equality incorrectly became support verdict", err)
			}
		})
	}
	// Collection times cannot establish causal order, even with a known clock.
	r.RecordedAt = "2099-01-01T00:00:00Z"
	r.ClockQuality = "unsynchronized"
	if err := CheckIncidentRelationBinding(r, c); err != nil {
		t.Fatal("historical skew destroyed a reference", err)
	}
}

func TestIncidentAssessmentDoesNotChooseRelationshipKind(t *testing.T) {
	for _, kind := range []string{"association", "causal_hypothesis"} {
		for _, support := range []string{"supporting", "contradicting", "inconclusive"} {
			t.Run(kind+"/"+support, func(t *testing.T) {
				r := incidentFixture(t, "incident-association.json")
				r.Kind, r.Support.Value = kind, support
				encoded, err := EncodeIncidentRelation(r)
				if err != nil {
					t.Fatal(err)
				}
				again, err := DecodeIncidentRelation(encoded)
				if err != nil || again != r {
					t.Fatal("assessment changed the claimed relationship", err)
				}
				if err := CheckIncidentRelationBinding(r, incidentContext(t, r.RelationID)); err != nil {
					t.Fatal("input equality was treated as a correlation verdict", err)
				}
			})
		}
	}
}

func TestIncidentRejectsInvalidClaimsAndSelfEdges(t *testing.T) {
	changes := map[string]func(*IncidentRelation){
		"identity":                func(r *IncidentRelation) { r.Identity.NodeID = "" },
		"id":                      func(r *IncidentRelation) { r.RelationID = "../../private" },
		"oversize":                func(r *IncidentRelation) { r.IncidentID = strings.Repeat("a", MaxIdentifierBytes+1) },
		"correlator":              func(r *IncidentRelation) { r.CorrelatorID = "" },
		"rule ID":                 func(r *IncidentRelation) { r.RuleRef = "" },
		"rule digest":             func(r *IncidentRelation) { r.RuleSHA256 = strings.Repeat("A", 64) },
		"time":                    func(r *IncidentRelation) { r.RecordedAt = "2026-01-01T00:00:00.000Z" },
		"clock":                   func(r *IncidentRelation) { r.ClockQuality = "verified" },
		"endpoint schema":         func(r *IncidentRelation) { r.From.Schema = "future" },
		"endpoint ID":             func(r *IncidentRelation) { r.To.RecordID = "" },
		"endpoint hash":           func(r *IncidentRelation) { r.To.SHA256 = "" },
		"self":                    func(r *IncidentRelation) { r.To = r.From },
		"self with forked digest": func(r *IncidentRelation) { r.To = r.From; r.To.SHA256 = strings.Repeat("0", 64) },
		"causality promotion":     func(r *IncidentRelation) { r.Kind = "caused" },
		"support promotion":       func(r *IncidentRelation) { r.Support.Value = "proven" },
		"missing evidence": func(r *IncidentRelation) {
			r.Evidence = EvidenceReference{Ref: Field{State: Missing}, SHA256: Field{State: Missing}}
		},
		"partial reason":          func(r *IncidentRelation) { r.ReasonCode.State = Partial },
		"missing reason":          func(r *IncidentRelation) { r.ReasonCode = Field{State: Unavailable} },
		"evidence state mismatch": func(r *IncidentRelation) { r.Evidence.SHA256.State = Stale },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			r := incidentFixture(t, "incident-association.json")
			change(&r)
			if data, err := EncodeIncidentRelation(r); !errors.Is(err, ErrInvalidIncidentDocument) || data != nil {
				t.Fatal("invalid relation encoded", err)
			}
			if err := CheckIncidentRelationBinding(r, incidentContext(t, r.RelationID)); !errors.Is(err, ErrInvalidIncidentDocument) {
				t.Fatal("invalid relation bound", err)
			}
		})
	}
}

func TestIncidentInputRequiresValidatedRecords(t *testing.T) {
	r := incidentFixture(t, "incident-association.json")
	for _, change := range []func(*IncidentReadContext){
		func(c *IncidentReadContext) { c.ExpectedIdentity.Epoch = "" }, func(c *IncidentReadContext) { c.IncidentID = "" },
		func(c *IncidentReadContext) { c.RelationID = "" }, func(c *IncidentReadContext) { c.RuleSHA256 = "" },
		func(c *IncidentReadContext) { c.From.Data = []byte("null") }, func(c *IncidentReadContext) { c.To.Data = []byte("null") },
		func(c *IncidentReadContext) { c.From.Schema = "future" }, func(c *IncidentReadContext) { c.Evidence = EvidenceDescriptor{} },
		func(c *IncidentReadContext) { c.To.Identity.Epoch = "generation.other" },
	} {
		c := incidentContext(t, r.RelationID)
		change(&c)
		if err := CheckIncidentRelationBinding(r, c); !errors.Is(err, ErrInvalidIncidentInput) {
			t.Fatal("invalid context accepted", err)
		}
	}
	for _, schema := range []string{EventSchema, NodeSnapshotSchema, PolicyDecisionSchema, ActionOutcomeSchema, ControlSnapshotSchema, EvidenceDescriptorSchema, IncidentRelationSchema, "future"} {
		for _, data := range [][]byte{nil, []byte("null"), fixture(t, "incident-association.json"), bytes.Repeat([]byte(" "), MaxDocumentBytes+1)} {
			ref, err := IncidentRecordReferenceFromJSON(ResolvedIncidentRecord{Identity: readContext().ExpectedIdentity, Schema: schema, Data: data})
			if !errors.Is(err, ErrInvalidIncidentInput) || ref != (IncidentRecordReference{}) {
				t.Fatal("unusable endpoint returned", err)
			}
		}
	}
	for _, data := range bytes.Split(bytes.TrimSpace(fixture(t, "legacy-projections.ndjson")), []byte("\n")) {
		if ref, err := IncidentRecordReferenceFromJSON(ResolvedIncidentRecord{Identity: readContext().ExpectedIdentity, Schema: EventSchema, Data: data}); err == nil || ref != (IncidentRecordReference{}) {
			t.Fatal("legacy projection gained fabricated identity")
		}
	}
}

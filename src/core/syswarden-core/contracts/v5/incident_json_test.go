package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestIncidentRelationStrictJSON(t *testing.T) {
	data := fixture(t, "incident-association.json")
	base := string(data)
	replace := func(old, new string) []byte {
		t.Helper()
		if !strings.Contains(base, old) {
			t.Fatal("mutation did not touch fixture", old)
		}
		return []byte(strings.Replace(base, old, new, 1))
	}
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"duplicate":           []byte(strings.Replace(base, "{", `{"schema":"ignored",`, 1)),
		"escaped duplicate":   []byte(strings.Replace(base, "{", `{"\u0073chema":"ignored",`, 1)),
		"alias":               replace(`"relation_id":`, `"Relation_ID":`),
		"unknown":             []byte(strings.Replace(base, "{", `{"extension":true,`, 1)),
		"missing epoch":       replace(`,"epoch":"generation.fixture.1"`, ""),
		"numeric relation":    replace(`"relation_id":"relation.fixture.1"`, `"relation_id":1`),
		"null endpoint":       replace(`"from":{`, `"from":null,"discarded":{`),
		"endpoint alias":      replace(`"record_id":`, `"Record_ID":`),
		"duplicate endpoint":  replace(`"record_id":"event.fixture.1"`, `"record_id":"other","record_id":"event.fixture.1"`),
		"missing endpoint ID": replace(`"record_id":"event.fixture.1",`, ""),
		"null support":        replace(`"support":{"state":"present","value":"supporting"}`, `"support":null`),
		"unpaired utf16":      replace("correlator.fixture.1", `\ud800`),
		"invalid utf8":        replace("correlator.fixture.1", string([]byte{0xff})),
		"terminal escape":     replace("correlator.fixture.1", `\u001b[31m`),
		"path injection":      replace("correlator.fixture.1", "private/payload/not-for-errors"),
		"trailing":            append([]byte(base), []byte(" {}")...),
		"oversized":           []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
		"deep":                []byte(strings.Repeat("[", 9) + strings.Repeat("]", 9)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := DecodeIncidentRelation(input)
			if !errors.Is(err, ErrInvalidIncidentDocument) || r != (IncidentRelation{}) {
				t.Fatal("ambiguous relation accepted", err)
			}
			if strings.Contains(err.Error(), "private/payload") {
				t.Fatal("input leaked in error")
			}
		})
	}
	if r, err := DecodeIncidentRelation(replace(IncidentRelationSchema, IncidentRelationSchema+".future")); !errors.Is(err, ErrUnsupportedIncidentSchema) || r != (IncidentRelation{}) {
		t.Fatal("unknown relation schema interpreted", err)
	}
	r := incidentFixture(t, "incident-association.json")
	r.Schema = "future"
	if data, err := EncodeIncidentRelation(r); !errors.Is(err, ErrUnsupportedIncidentSchema) || data != nil {
		t.Fatal("unknown schema encoded", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	r, err := DecodeIncidentRelation(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeIncidentRelation(r)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed relation bytes", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := DecodeIncidentRelation(input); err != nil {
		t.Fatal("exact document boundary rejected", err)
	}
	if r, err := DecodeIncidentRelation(append(input, ' ')); err == nil || r != (IncidentRelation{}) {
		t.Fatal("document limit bypassed", err)
	}
	r.RelationID = strings.Repeat("a", MaxIdentifierBytes)
	if _, err := EncodeIncidentRelation(r); err != nil {
		t.Fatal("identifier boundary rejected", err)
	}
}

func TestOtherRecordsDoNotCreateIncidentClaims(t *testing.T) {
	inputs := bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n"))
	inputs = append(inputs, bytes.Split(bytes.TrimSpace(fixture(t, "legacy-projections.ndjson")), []byte("\n"))...)
	for _, name := range []string{"native-ip.json", "native-l2.json", "node-reachable.json", "decision-block.json", "action-verified.json", "control-effective.json", "evidence-original.json"} {
		inputs = append(inputs, fixture(t, name))
	}
	for _, input := range inputs {
		if r, err := DecodeIncidentRelation(input); err == nil || r != (IncidentRelation{}) {
			t.Fatal("unrelated record manufactured an incident")
		}
	}
	data := fixture(t, "incident-association.json")
	if e, err := DecodeEvent(data); err == nil || e != (Event{}) {
		t.Fatal("incident became an observation")
	}
	if n, err := DecodeNodeSnapshot(data); err == nil || n != (NodeSnapshot{}) {
		t.Fatal("incident became node health")
	}
	if d, err := DecodePolicyDecision(data); err == nil || d != (PolicyDecision{}) {
		t.Fatal("incident became a decision")
	}
	if a, err := DecodeActionOutcome(data); err == nil || a != (ActionOutcome{}) {
		t.Fatal("incident became an action")
	}
	if c, err := DecodeControlSnapshot(data); err == nil || c != (ControlSnapshot{}) {
		t.Fatal("incident became current control")
	}
	if e, err := DecodeEvidenceDescriptor(data); err == nil || e != (EvidenceDescriptor{}) {
		t.Fatal("incident became evidence bytes")
	}
}

func FuzzIncidentRelationRoundTrip(f *testing.F) {
	fuzzEnforcementCodec(f, []string{"incident-association.json", "incident-contradicted.json", "incident-unresolved.json", "native-ip.json"}, DecodeIncidentRelation, EncodeIncidentRelation, func(t *testing.T, r IncidentRelation) {
		c := incidentContext(t, r.RelationID)
		c.ExpectedIdentity.Epoch = "generation.rejected.1"
		if r.Identity.Epoch == c.ExpectedIdentity.Epoch {
			c.ExpectedIdentity.Epoch = "generation.rejected.2"
		}
		if err := CheckIncidentRelationBinding(r, c); err == nil {
			t.Fatal("cross-epoch incident binding accepted")
		}
	})
}

func FuzzIncidentRecordReference(f *testing.F) {
	for _, item := range []struct{ schema, name string }{
		{EventSchema, "native-l2.json"}, {NodeSnapshotSchema, "node-unreachable.json"}, {PolicyDecisionSchema, "decision-block.json"},
		{ActionOutcomeSchema, "action-failed.json"}, {ControlSnapshotSchema, "control-cached.json"}, {EvidenceDescriptorSchema, "evidence-redacted.json"},
		{IncidentRelationSchema, "incident-association.json"},
	} {
		f.Add(item.schema, fixture(f, item.name))
	}
	f.Fuzz(func(t *testing.T, schema string, data []byte) {
		input := ResolvedIncidentRecord{Identity: readContext().ExpectedIdentity, Schema: schema, Data: data}
		ref, err := IncidentRecordReferenceFromJSON(input)
		if err != nil {
			if ref != (IncidentRecordReference{}) {
				t.Fatal("partial endpoint on error")
			}
			return
		}
		if !ref.validate() {
			t.Fatal("invalid endpoint result")
		}
		again, err := IncidentRecordReferenceFromJSON(input)
		if err != nil || again != ref {
			t.Fatal("nondeterministic endpoint", err)
		}
		input.Identity.NodeID = "node.rejected"
		if ref, err := IncidentRecordReferenceFromJSON(input); err == nil || ref != (IncidentRecordReference{}) {
			t.Fatal("cross-node endpoint accepted")
		}
	})
}

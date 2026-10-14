package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPolicyDecisionRejectsAmbiguousJSON(t *testing.T) {
	base := string(fixture(t, "decision-block.json"))
	replace := func(old, new string) []byte { return []byte(strings.Replace(base, old, new, 1)) }
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"duplicate":         []byte(strings.Replace(base, "{", `{"schema":"ignored",`, 1)),
		"escaped duplicate": []byte(strings.Replace(base, "{", `{"\u0073chema":"ignored",`, 1)),
		"case alias":        replace(`"schema":`, `"Schema":`),
		"unknown member":    []byte(strings.Replace(base, "{", `{"extension":true,`, 1)),
		"missing member":    replace(`"clock_quality":"unknown",`, ""),
		"null identity":     replace(`"identity":{"cluster_id":"cluster.fixture.1","node_id":"node.fixture.1","epoch":"generation.fixture.1"}`, `"identity":null`),
		"input alias":       replace(`"event_id":`, `"Event_ID":`),
		"input duplicate":   replace(`"event_id":"event.fixture.1"`, `"event_id":"other","event_id":"event.fixture.1"`),
		"null input":        replace(`"input":{`, `"input":null,"discarded":{`),
		"null verdict":      replace(`"verdict":{"state":"present","value":"block"}`, `"verdict":null`),
		"boolean verdict":   replace(`"value":"block"`, `"value":true`),
		"null value":        replace(`"value":"block"`, `"value":null`),
		"unknown state":     replace(`"state":"present"`, `"state":"safe"`),
		"execution claim":   replace(`"value":"block"`, `"value":"verified"`),
		"unpaired utf16":    replace("decision.fixture.1", `\ud800`),
		"invalid utf8":      replace("decision.fixture.1", string([]byte{0xff})),
		"terminal escape":   replace("decision.fixture.1", `\u001b[31m`),
		"trailing":          append([]byte(base), []byte(" {}")...),
		"oversized":         []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if d, err := DecodePolicyDecision(input); !errors.Is(err, ErrInvalidDecisionDocument) || d != (PolicyDecision{}) {
				t.Fatal("ambiguous decision accepted or returned partially", err)
			}
		})
	}
	if d, err := DecodePolicyDecision(replace(PolicyDecisionSchema, "syswarden.policy-decision.v2")); !errors.Is(err, ErrUnsupportedDecisionSchema) || d != (PolicyDecision{}) {
		t.Fatal("unknown decision schema interpreted", err)
	}
	secretInput := replace("decision.fixture.1", "private/payload/not-for-errors")
	if _, err := DecodePolicyDecision(secretInput); err == nil || strings.Contains(err.Error(), "private/payload") {
		t.Fatal("untrusted payload leaked in error")
	}
}

func TestPolicyDecisionRejectsInvalidConstructedValues(t *testing.T) {
	base := decisionFixture(t, "decision-block.json")
	cases := map[string]func(*PolicyDecision){
		"identity":                  func(d *PolicyDecision) { d.Identity.Epoch = "" },
		"decision identifier":       func(d *PolicyDecision) { d.DecisionID = "" },
		"evaluator":                 func(d *PolicyDecision) { d.EvaluatorID = "../../other" },
		"event identifier":          func(d *PolicyDecision) { d.Input.EventID = strings.Repeat("a", MaxIdentifierBytes+1) },
		"event digest":              func(d *PolicyDecision) { d.Input.EventSHA256 = strings.Repeat("A", 64) },
		"short event digest":        func(d *PolicyDecision) { d.Input.EventSHA256 = "abc" },
		"policy digest":             func(d *PolicyDecision) { d.PolicySHA256.Value = strings.Repeat("g", 64) },
		"policy state mismatch":     func(d *PolicyDecision) { d.PolicySHA256.State = Stale },
		"policy value with absence": func(d *PolicyDecision) { d.PolicyRef.State = Missing },
		"reason":                    func(d *PolicyDecision) { d.ReasonCode.Value = "free form explanation" },
		"evidence":                  func(d *PolicyDecision) { d.EvidenceRef.Value = "https://example.invalid/evidence" },
		"time":                      func(d *PolicyDecision) { d.EvaluatedAt = "2026-01-01T01:00:02+01:00" },
		"clock quality":             func(d *PolicyDecision) { d.ClockQuality = "trusted" },
		"verdict":                   func(d *PolicyDecision) { d.Verdict.Value = "ban_succeeded" },
		"severity":                  func(d *PolicyDecision) { d.Severity.Value = "100" },
		"missing with verdict":      func(d *PolicyDecision) { d.Verdict.State = Missing },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			change(&d)
			if data, err := EncodePolicyDecision(d); !errors.Is(err, ErrInvalidDecisionDocument) || data != nil {
				t.Fatal("invalid constructed decision encoded", err)
			}
			if err := CheckPolicyDecisionBinding(d, decisionContext(t, "native-ip.json")); !errors.Is(err, ErrInvalidDecisionDocument) {
				t.Fatal("invalid constructed decision binding accepted", err)
			}
		})
	}
	base.DecisionID = strings.Repeat("a", MaxIdentifierBytes)
	if _, err := EncodePolicyDecision(base); err != nil {
		t.Fatal("exact identifier bound rejected", err)
	}
	base.Schema = "syswarden.policy-decision.v2"
	if data, err := EncodePolicyDecision(base); !errors.Is(err, ErrUnsupportedDecisionSchema) || data != nil {
		t.Fatal("unknown constructed schema accepted", err)
	}
}

func TestPolicyDecisionFormattingAndInputDigest(t *testing.T) {
	data := fixture(t, "decision-block.json")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	d, err := DecodePolicyDecision(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodePolicyDecision(d)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed decision golden bytes", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := DecodePolicyDecision(input); err != nil {
		t.Fatal("exact document bound rejected", err)
	}
	if _, err := DecodePolicyDecision(append(input, ' ')); err == nil {
		t.Fatal("document byte limit bypassed")
	}
	pretty.Reset()
	if err := json.Indent(&pretty, fixture(t, "native-ip.json"), "", "  "); err != nil {
		t.Fatal(err)
	}
	context := decisionContext(t, "native-ip.json")
	context.Event, err = DecodeEvent(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPolicyDecisionBinding(d, context); err != nil {
		t.Fatal("event framing or formatting changed semantic input digest", err)
	}
}

func TestPolicyDecisionCannotBeInventedFromOtherSchemas(t *testing.T) {
	for _, line := range bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n")) {
		if d, err := DecodePolicyDecision(line); !errors.Is(err, ErrInvalidDecisionDocument) || d != (PolicyDecision{}) {
			t.Fatal("legacy observation became policy verdict", err)
		}
	}
	for _, name := range []string{"native-ip.json", "native-l2.json", "node-reachable.json"} {
		if d, err := DecodePolicyDecision(fixture(t, name)); !errors.Is(err, ErrInvalidDecisionDocument) || d != (PolicyDecision{}) {
			t.Fatal("read record became policy verdict", err)
		}
	}
	for _, line := range bytes.Split(bytes.TrimSpace(fixture(t, "legacy-projections.ndjson")), []byte("\n")) {
		if d, err := DecodePolicyDecision(line); err == nil || d != (PolicyDecision{}) {
			t.Fatal("legacy projection became decision")
		}
	}
	data := fixture(t, "decision-block.json")
	if e, err := DecodeEvent(data); err == nil || e != (Event{}) {
		t.Fatal("decision accepted as sensor observation")
	}
	if s, err := DecodeNodeSnapshot(data); err == nil || s != (NodeSnapshot{}) {
		t.Fatal("decision accepted as current node evidence")
	}
}

func FuzzPolicyDecisionRoundTrip(f *testing.F) {
	for _, name := range []string{"decision-block.json", "decision-allow.json", "decision-observe-l2.json", "decision-unavailable.json", "native-ip.json", "node-reachable.json"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := DecodePolicyDecision(data)
		if err != nil {
			if d != (PolicyDecision{}) {
				t.Fatal("partially usable decision on failure")
			}
			return
		}
		encoded, err := EncodePolicyDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodePolicyDecision(encoded)
		if err != nil || again != d {
			t.Fatal("decision round trip changed meaning", err)
		}
		second, err := EncodePolicyDecision(again)
		if err != nil || !bytes.Equal(second, encoded) {
			t.Fatal("unstable decision encoding", err)
		}
		context := decisionContext(t, "native-ip.json")
		context.EventIdentity.ClusterID = "cluster.always.different"
		if d.Identity.ClusterID == context.EventIdentity.ClusterID {
			context.EventIdentity.ClusterID = "cluster.other"
		}
		if err := CheckPolicyDecisionBinding(d, context); err == nil {
			t.Fatal("accepted unrelated identity binding")
		}
	})
}

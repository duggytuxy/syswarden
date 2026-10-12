package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func checkEnforcementCodec[T comparable](t *testing.T, name, schema string,
	decode func([]byte) (T, error), encode func(T) ([]byte, error), invalidError, schemaError error) {
	t.Helper()
	data := fixture(t, name)
	base := string(data)
	replace := func(old, new string) []byte { return []byte(strings.Replace(base, old, new, 1)) }
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"duplicate":         []byte(strings.Replace(base, "{", `{"schema":"ignored",`, 1)),
		"escaped duplicate": []byte(strings.Replace(base, "{", `{"\u0073chema":"ignored",`, 1)),
		"alias":             replace(`"schema":`, `"Schema":`),
		"unknown member":    []byte(strings.Replace(base, "{", `{"extension":true,`, 1)),
		"missing owner":     replace(`,"owner_id":"owner.fixture.1"`, ""),
		"owner alias":       replace(`"owner_id":`, `"Owner_ID":`),
		"duplicate owner":   replace(`"owner_id":"owner.fixture.1"`, `"owner_id":"other","owner_id":"owner.fixture.1"`),
		"numeric owner":     replace(`"owner_id":"owner.fixture.1"`, `"owner_id":1`),
		"null owner":        replace(`"owner_id":"owner.fixture.1"`, `"owner_id":null`),
		"null scope":        replace(`"scope":{`, `"scope":null,"discarded":{`),
		"missing epoch":     replace(`,"epoch":"generation.fixture.1"`, ""),
		"null identity":     replace(`"identity":{"cluster_id":"cluster.fixture.1","node_id":"node.fixture.1","epoch":"generation.fixture.1"}`, `"identity":null`),
		"unpaired utf16":    replace("owner.fixture.1", `\ud800`),
		"invalid utf8":      replace("owner.fixture.1", string([]byte{0xff})),
		"terminal escape":   replace("owner.fixture.1", `\u001b[31m`),
		"path injection":    replace("owner.fixture.1", "private/payload/not-for-errors"),
		"trailing":          append([]byte(base), []byte(" {}")...),
		"oversized":         []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
	}
	var zero T
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			value, err := decode(input)
			if !errors.Is(err, invalidError) || value != zero {
				t.Fatal("ambiguous record accepted or returned partially", err)
			}
			if strings.Contains(err.Error(), "private/payload") {
				t.Fatal("input leaked in error")
			}
		})
	}
	if value, err := decode(replace(schema, schema+".unknown")); !errors.Is(err, schemaError) || value != zero {
		t.Fatal("unknown schema interpreted", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	value, err := decode(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encode(value)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed golden bytes", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := decode(input); err != nil {
		t.Fatal("exact byte boundary rejected", err)
	}
	if value, err := decode(append(input, ' ')); !errors.Is(err, invalidError) || value != zero {
		t.Fatal("byte limit bypassed", err)
	}
}

func TestActionOutcomeStrictJSON(t *testing.T) {
	checkEnforcementCodec(t, "action-verified.json", ActionOutcomeSchema, DecodeActionOutcome, EncodeActionOutcome, ErrInvalidActionDocument, ErrUnsupportedActionSchema)
	a := actionFixture(t, "action-verified.json")
	a.Schema = "unknown"
	if data, err := EncodeActionOutcome(a); !errors.Is(err, ErrUnsupportedActionSchema) || data != nil {
		t.Fatal("unknown constructed action schema encoded", err)
	}
}

func TestControlSnapshotStrictJSON(t *testing.T) {
	checkEnforcementCodec(t, "control-effective.json", ControlSnapshotSchema, DecodeControlSnapshot, EncodeControlSnapshot, ErrInvalidControlDocument, ErrUnsupportedControlSchema)
	s := controlFixture(t, "control-effective.json")
	s.Schema = "unknown"
	if data, err := EncodeControlSnapshot(s); !errors.Is(err, ErrUnsupportedControlSchema) || data != nil {
		t.Fatal("unknown constructed control schema encoded", err)
	}
}

func TestOtherRecordsCannotBecomeActionOrControlEvidence(t *testing.T) {
	inputs := bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n"))
	inputs = append(inputs, bytes.Split(bytes.TrimSpace(fixture(t, "legacy-projections.ndjson")), []byte("\n"))...)
	for _, name := range []string{"native-ip.json", "native-l2.json", "node-reachable.json", "decision-block.json", "decision-allow.json"} {
		inputs = append(inputs, fixture(t, name))
	}
	for _, input := range inputs {
		if a, err := DecodeActionOutcome(input); err == nil || a != (ActionOutcome{}) {
			t.Fatal("observation or decision became action outcome")
		}
		if s, err := DecodeControlSnapshot(input); err == nil || s != (ControlSnapshot{}) {
			t.Fatal("observation or decision became control evidence")
		}
	}
	if a, err := DecodeActionOutcome(fixture(t, "control-effective.json")); err == nil || a != (ActionOutcome{}) {
		t.Fatal("control observation became action history")
	}
	if s, err := DecodeControlSnapshot(fixture(t, "action-verified.json")); err == nil || s != (ControlSnapshot{}) {
		t.Fatal("historical verification became current control")
	}
	for _, name := range []string{"action-verified.json", "control-effective.json"} {
		data := fixture(t, name)
		if e, err := DecodeEvent(data); err == nil || e != (Event{}) {
			t.Fatal("action/control record became an event")
		}
		if s, err := DecodeNodeSnapshot(data); err == nil || s != (NodeSnapshot{}) {
			t.Fatal("action/control record became node status")
		}
		if d, err := DecodePolicyDecision(data); err == nil || d != (PolicyDecision{}) {
			t.Fatal("action/control record became a policy decision")
		}
	}
}

func fuzzEnforcementCodec[T comparable](f *testing.F, names []string, decode func([]byte) (T, error), encode func(T) ([]byte, error), check func(*testing.T, T)) {
	for _, name := range names {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var zero T
		value, err := decode(data)
		if err != nil {
			if value != zero {
				t.Fatal("partially usable record on failure")
			}
			return
		}
		encoded, err := encode(value)
		if err != nil {
			t.Fatal(err)
		}
		again, err := decode(encoded)
		if err != nil || again != value {
			t.Fatal("round trip changed meaning", err)
		}
		second, err := encode(again)
		if err != nil || !bytes.Equal(second, encoded) {
			t.Fatal("unstable encoding", err)
		}
		check(t, value)
	})
}

func FuzzActionOutcomeRoundTrip(f *testing.F) {
	fuzzEnforcementCodec(f, []string{"action-verified.json", "action-failed.json", "action-unknown.json", "control-effective.json"}, DecodeActionOutcome, EncodeActionOutcome, func(t *testing.T, a ActionOutcome) {
		context := actionContext(t)
		context.ExpectedScope.OwnerID = "owner.rejected.1"
		if a.Scope.OwnerID == context.ExpectedScope.OwnerID {
			context.ExpectedScope.OwnerID = "owner.rejected.2"
		}
		if err := CheckActionOutcomeBinding(a, context); err == nil {
			t.Fatal("cross-owner action binding accepted")
		}
	})
}

func FuzzControlSnapshotRoundTrip(f *testing.F) {
	fuzzEnforcementCodec(f, []string{"control-effective.json", "control-absent.json", "control-cached.json", "control-unavailable.json", "action-verified.json"}, DecodeControlSnapshot, EncodeControlSnapshot, func(t *testing.T, s ControlSnapshot) {
		context := controlContext(t)
		context.ExpectedScope.OwnerID = "owner.rejected.1"
		if s.Scope.OwnerID == context.ExpectedScope.OwnerID {
			context.ExpectedScope.OwnerID = "owner.rejected.2"
		}
		if err := CheckCurrentControlSnapshot(s, context); err == nil {
			t.Fatal("cross-owner current state accepted")
		}
	})
}

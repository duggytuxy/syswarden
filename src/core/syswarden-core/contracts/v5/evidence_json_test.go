package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEvidenceStrictJSON(t *testing.T) {
	data := fixture(t, "evidence-original.json")
	base := string(data)
	replace := func(old, new string) []byte {
		t.Helper()
		if !strings.Contains(base, old) {
			t.Fatal("mutation does not touch fixture", old)
		}
		return []byte(strings.Replace(base, old, new, 1))
	}
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"duplicate":         []byte(strings.Replace(base, "{", `{"schema":"ignored",`, 1)),
		"escaped duplicate": []byte(strings.Replace(base, "{", `{"\u0073chema":"ignored",`, 1)),
		"alias":             replace(`"schema":`, `"Schema":`),
		"unknown":           []byte(strings.Replace(base, "{", `{"extension":true,`, 1)),
		"missing identity":  replace(`,"epoch":"generation.fixture.1"`, ""),
		"numeric size":      replace(`"value":"72"`, `"value":72`),
		"null content":      replace(`"content":{`, `"content":null,"discarded":{`),
		"nested duplicate":  replace(`"size_bytes":{`, `"size_bytes":null,"size_bytes":{`),
		"content alias":     replace(`"sha256":`, `"SHA256":`),
		"missing digest":    replace(`"sha256":{"state":"not_applicable","value":""}`, `"removed":{}`),
		"nested unknown":    replace(`"state":"not_applicable"`, `"extra":0,"state":"not_applicable"`),
		"unpaired utf16":    replace("source.fixture.1", `\ud800`),
		"invalid utf8":      replace("source.fixture.1", string([]byte{0xff})),
		"terminal escape":   replace("source.fixture.1", `\u001b[31m`),
		"path injection":    replace("source.fixture.1", "private/payload/not-for-errors"),
		"trailing":          append([]byte(base), []byte(" {}")...),
		"oversized":         []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
		"deep":              []byte(strings.Repeat("[", 9) + strings.Repeat("]", 9)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			e, err := DecodeEvidenceDescriptor(input)
			if !errors.Is(err, ErrInvalidEvidenceDocument) || e != (EvidenceDescriptor{}) {
				t.Fatal("ambiguous evidence accepted", err)
			}
			if strings.Contains(err.Error(), "private/payload") {
				t.Fatal("input leaked in error")
			}
		})
	}
	if e, err := DecodeEvidenceDescriptor(replace(EvidenceDescriptorSchema, EvidenceDescriptorSchema+".unknown")); !errors.Is(err, ErrUnsupportedEvidenceSchema) || e != (EvidenceDescriptor{}) {
		t.Fatal("unknown schema accepted", err)
	}
	e := evidenceFixture(t, "evidence-original.json")
	e.Schema = "unknown"
	if data, err := EncodeEvidenceDescriptor(e); !errors.Is(err, ErrUnsupportedEvidenceSchema) || data != nil {
		t.Fatal("unknown schema encoded", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	e, err := DecodeEvidenceDescriptor(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeEvidenceDescriptor(e)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed descriptor bytes", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := DecodeEvidenceDescriptor(input); err != nil {
		t.Fatal("exact byte boundary rejected", err)
	}
	if e, err := DecodeEvidenceDescriptor(append(input, ' ')); !errors.Is(err, ErrInvalidEvidenceDocument) || e != (EvidenceDescriptor{}) {
		t.Fatal("byte limit bypassed", err)
	}
}

func TestEvidenceCannotBeManufacturedFromOtherRecords(t *testing.T) {
	inputs := bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n"))
	inputs = append(inputs, bytes.Split(bytes.TrimSpace(fixture(t, "legacy-projections.ndjson")), []byte("\n"))...)
	for _, name := range []string{"native-ip.json", "native-l2.json", "node-reachable.json", "decision-block.json", "action-verified.json", "control-effective.json"} {
		inputs = append(inputs, fixture(t, name))
	}
	for _, input := range inputs {
		if e, err := DecodeEvidenceDescriptor(input); err == nil || e != (EvidenceDescriptor{}) {
			t.Fatal("unrelated record promoted into evidence")
		}
	}
	data := fixture(t, "evidence-original.json")
	if e, err := DecodeEvent(data); err == nil || e != (Event{}) {
		t.Fatal("evidence became observation")
	}
	if n, err := DecodeNodeSnapshot(data); err == nil || n != (NodeSnapshot{}) {
		t.Fatal("evidence became node health")
	}
	if d, err := DecodePolicyDecision(data); err == nil || d != (PolicyDecision{}) {
		t.Fatal("evidence became verdict")
	}
	if a, err := DecodeActionOutcome(data); err == nil || a != (ActionOutcome{}) {
		t.Fatal("evidence became action success")
	}
	if s, err := DecodeControlSnapshot(data); err == nil || s != (ControlSnapshot{}) {
		t.Fatal("evidence became protection")
	}
}

func FuzzEvidenceDescriptorRoundTrip(f *testing.F) {
	fuzzEnforcementCodec(f, []string{"evidence-original.json", "evidence-redacted.json", "evidence-derived.json", "evidence-unavailable.json", "evidence-unknown.json", "action-verified.json"}, DecodeEvidenceDescriptor, EncodeEvidenceDescriptor, func(t *testing.T, e EvidenceDescriptor) {
		context := evidenceContext(t, e)
		context.ExpectedIdentity.Epoch = "generation.rejected.1"
		if e.Identity.Epoch == context.ExpectedIdentity.Epoch {
			context.ExpectedIdentity.Epoch = "generation.rejected.2"
		}
		if err := CheckEvidencePayloadBinding(e, context, nil); !errors.Is(err, ErrEvidenceBindingMismatch) {
			t.Fatal("cross-epoch payload binding accepted", err)
		}
	})
}

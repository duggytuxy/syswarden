package v5

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

//go:embed testdata/*
var goldenFixtures embed.FS

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := goldenFixtures.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

func TestEventGolden(t *testing.T) {
	for _, name := range []string{"native-ip.json", "native-l2.json"} {
		t.Run(name, func(t *testing.T) {
			data := fixture(t, name)
			e, err := DecodeEvent(data)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := EncodeEvent(e)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical, data) {
				t.Fatal("canonical bytes changed")
			}
			// Accept formatting variation, then emit the same pinned bytes.
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, data, "", "  "); err != nil {
				t.Fatal(err)
			}
			again, err := DecodeEvent(pretty.Bytes())
			if err != nil || again != e {
				t.Fatal("formatting changed semantics", err)
			}
		})
	}
}

func TestEventRejectsAmbiguousOrInvalidDocuments(t *testing.T) {
	base := string(fixture(t, "native-ip.json"))
	replace := func(old, new string) []byte { return []byte(strings.Replace(base, old, new, 1)) }
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"unsupported":                  replace(EventSchema, "syswarden.event-envelope.v2"),
		"duplicate":                    []byte(strings.Replace(base, "{", `{"schema":"ignored",`, 1)),
		"escaped duplicate":            []byte(strings.Replace(base, "{", `{"\u0073chema":"ignored",`, 1)),
		"case alias":                   replace(`"schema":`, `"Schema":`),
		"unknown member":               []byte(strings.Replace(base, "{", `{"extension":true,`, 1)),
		"nested duplicate":             replace(`"state":"present"`, `"state":"missing","state":"present"`),
		"nested alias":                 replace(`"state":"present"`, `"State":"present"`),
		"missing member":               replace(`"clock_quality":"unknown",`, ""),
		"null member":                  replace(`"clock_quality":"unknown"`, `"clock_quality":null`),
		"null field":                   replace(`"event_id":{"state":"present","value":"event.fixture.1"}`, `"event_id":null`),
		"numeric string":               replace(`"value":"event.fixture.1"`, `"value":1`),
		"trailing":                     append([]byte(base), []byte(" {}")...),
		"invalid utf8":                 replace("event.fixture.1", string([]byte{0xff})),
		"high surrogate":               replace("event.fixture.1", `\ud800`),
		"low surrogate":                replace("event.fixture.1", `\udc00`),
		"unknown state":                replace(`"state":"present"`, `"state":"unknown"`),
		"missing with value":           replace(`"state":"present"`, `"state":"missing"`),
		"empty present":                replace("event.fixture.1", ""),
		"long identifier":              replace("event.fixture.1", strings.Repeat("a", MaxIdentifierBytes+1)),
		"terminal escape":              replace("event.fixture.1", `\u001b[31m`),
		"path reference":               replace("event.fixture.1", "../../secrets"),
		"offset time":                  replace("2026-01-01T00:00:00Z", "2026-01-01T01:00:00+01:00"),
		"redundant fraction":           replace("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000Z"),
		"invalid time":                 replace("2026-01-01T00:00:00Z", "2026-02-30T00:00:00Z"),
		"mapped ipv4":                  replace("192.0.2.10", "::ffff:192.0.2.10"),
		"zoned ipv6":                   replace("192.0.2.10", "fe80::1%eth0"),
		"noncanonical ipv6":            replace("192.0.2.10", "2001:0db8::1"),
		"unknown subject with address": replace(`"kind":"ip"`, `"kind":"unknown"`),
		"invalid layer":                replace(`"value":"L4"`, `"value":"L8"`),
		"oversized":                    []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			e, err := DecodeEvent(input)
			if err == nil {
				t.Fatal("invalid input accepted")
			}
			if e != (Event{}) {
				t.Fatal("partial event returned on error")
			}
			if !errors.Is(err, ErrInvalidDocument) && !errors.Is(err, ErrUnsupportedSchema) {
				t.Fatalf("unclassified error: %v", err)
			}
		})
	}
}

func TestAvailabilityIsNotAValueOrVerdict(t *testing.T) {
	base, err := DecodeEvent(fixture(t, "native-ip.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{Present, Stale, Partial, Missing, Unavailable, Rejected, NotApplicable} {
		t.Run(state, func(t *testing.T) {
			e := base
			e.Context.Trust = Field{State: state}
			if e.Context.Trust.hasValue() {
				e.Context.Trust.Value = "assessment.fixture.1"
			}
			data, err := EncodeEvent(e)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeEvent(data)
			if err != nil || decoded != e {
				t.Fatal("availability was lost", err)
			}
			if decoded.ActionRef != base.ActionRef || decoded.ControlRef != base.ControlRef {
				t.Fatal("source context changed action or control evidence")
			}
		})
	}
	// A clock ahead of receipt is representable. The codec must not invent a
	// global order or silently fix an unsynchronized source clock.
	base.ObservedAt.Value = "2027-01-01T00:00:00Z"
	base.ClockQuality = "unsynchronized"
	if _, err := EncodeEvent(base); err != nil {
		t.Fatal(err)
	}
}

func TestEncoderRejectsInvalidConstructedValues(t *testing.T) {
	base, err := DecodeEvent(fixture(t, "native-ip.json"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Event){
		func(e *Event) { e.Schema = "future" },
		func(e *Event) { e.EventID.Value = "\xff" },
		func(e *Event) { e.Provenance.OriginalSHA256 = Field{State: Present, Value: strings.Repeat("A", 64)} },
		func(e *Event) {
			e.Subject = Subject{Kind: "mac", Address: Field{State: Present, Value: "AA:00:00:00:00:01"}}
		},
		func(e *Event) { e.Severity = Field{State: Present, Value: "safe"} },
		func(e *Event) { e.ReceivedAt = "" },
	}
	for i, mutate := range mutations {
		e := base
		mutate(&e)
		if output, err := EncodeEvent(e); err == nil || output != nil {
			t.Fatalf("mutation %d was encoded", i)
		}
	}
}

func TestExactDocumentAndIdentifierLimits(t *testing.T) {
	base, err := DecodeEvent(fixture(t, "native-ip.json"))
	if err != nil {
		t.Fatal(err)
	}
	base.EventID.Value = strings.Repeat("a", MaxIdentifierBytes)
	data, err := EncodeEvent(base)
	if err != nil {
		t.Fatal("valid identifier boundary rejected", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if got, err := DecodeEvent(input); err != nil || got != base {
		t.Fatal("valid document boundary rejected", err)
	}
	if _, err := DecodeEvent(append(input, ' ')); err == nil {
		t.Fatal("document limit not enforced")
	}
	base.EventID.Value += "a"
	if _, err := EncodeEvent(base); err == nil {
		t.Fatal("identifier limit not enforced")
	}
}

func FuzzEventRoundTrip(f *testing.F) {
	f.Add(fixture(f, "native-ip.json"))
	f.Add(fixture(f, "native-l2.json"))
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := DecodeEvent(data)
		if err != nil {
			if e != (Event{}) {
				t.Fatal("partial event")
			}
			return
		}
		canonical, err := EncodeEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeEvent(canonical)
		if err != nil || again != e {
			t.Fatal("round trip changed meaning", err)
		}
		second, err := EncodeEvent(again)
		if err != nil || !bytes.Equal(second, canonical) {
			t.Fatal("unstable canonical encoding", err)
		}
	})
}

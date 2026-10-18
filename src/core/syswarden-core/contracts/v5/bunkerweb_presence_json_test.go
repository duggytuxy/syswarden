package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestBunkerWebPresenceStrictJSON(t *testing.T) {
	base := string(fixture(t, "bunkerweb-presence.json"))
	replace := func(old, new string) []byte { return []byte(strings.Replace(base, old, new, 1)) }
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"duplicate":            []byte(strings.Replace(base, "{", `{"schema":"other",`, 1)),
		"escaped duplicate":    []byte(strings.Replace(base, "{", `{"\u0073chema":"other",`, 1)),
		"case alias":           replace(`"schema":`, `"Schema":`),
		"nested duplicate":     replace(`"state":"present"`, `"state":"missing","state":"present"`),
		"nested alias":         replace(`"assessed_at":`, `"Assessed_at":`),
		"missing field":        replace(`,"clock_quality":"synchronized"`, ``),
		"null field":           replace(`"clock_quality":"synchronized"`, `"clock_quality":null`),
		"numeric field":        replace(`"clock_quality":"synchronized"`, `"clock_quality":1`),
		"missing nested field": replace(`,"value":"established"`, ``),
		"unknown nested field": replace(`"value":"established"`, `"value":"established","address":"192.0.2.1"`),
		"unknown field":        []byte(strings.Replace(base, "{", `{"extension":"ignored",`, 1)),
		"invalid utf8":         replace("node.fixture.1", string([]byte{0xff})),
		"surrogate":            replace("node.fixture.1", `\ud800`),
		"control":              replace("node.fixture.1", `\u001b[31m`),
		"trailing":             append([]byte(base), []byte(" {}")...),
		"oversized":            []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := DecodeBunkerWebPresenceSnapshot(data)
			if !errors.Is(err, ErrInvalidBunkerWebPresenceDocument) || s != (BunkerWebPresenceSnapshot{}) {
				t.Fatal("ambiguous report disclosed", err)
			}
			if strings.Contains(err.Error(), "192.0.2.1") || strings.Contains(err.Error(), "node.fixture.1") {
				t.Fatal("input leaked into error")
			}
		})
	}
	if s, err := DecodeBunkerWebPresenceSnapshot(replace(BunkerWebPresenceSnapshotSchema, "syswarden.bunkerweb-presence-snapshot.v2")); !errors.Is(err, ErrUnsupportedBunkerWebPresenceSchema) || s != (BunkerWebPresenceSnapshot{}) {
		t.Fatal("unknown schema accepted", err)
	}
}

func TestBunkerWebPresenceFormattingBoundsAndSchemaIsolation(t *testing.T) {
	data := fixture(t, "bunkerweb-presence.json")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	s, err := DecodeBunkerWebPresenceSnapshot(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeBunkerWebPresenceSnapshot(s)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed identity", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := DecodeBunkerWebPresenceSnapshot(input); err != nil {
		t.Fatal("exact bound rejected", err)
	}
	if _, err := DecodeBunkerWebPresenceSnapshot(append(input, ' ')); err == nil {
		t.Fatal("excess bound accepted")
	}
	for _, name := range []string{"node-reachable.json", "node-exposure.json", "native-ip.json"} {
		if out, err := DecodeBunkerWebPresenceSnapshot(fixture(t, name)); err == nil || out != (BunkerWebPresenceSnapshot{}) {
			t.Fatal("other schema became presence")
		}
	}
	if out, err := DecodeNodeSnapshot(data); err == nil || out != (NodeSnapshot{}) {
		t.Fatal("presence became node health")
	}
	if out, err := DecodeEvent(data); err == nil || out != (Event{}) {
		t.Fatal("presence became event")
	}
	for _, line := range bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n")) {
		if out, err := DecodeBunkerWebPresenceSnapshot(line); err == nil || out != (BunkerWebPresenceSnapshot{}) {
			t.Fatal("legacy event became presence")
		}
	}
}

func FuzzBunkerWebPresenceRoundTrip(f *testing.F) {
	for _, name := range []string{"bunkerweb-presence.json", "node-reachable.json", "node-exposure.json", "native-ip.json"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeBunkerWebPresenceSnapshot(data)
		if err != nil {
			if s != (BunkerWebPresenceSnapshot{}) {
				t.Fatal("partial presence")
			}
			return
		}
		encoded, err := EncodeBunkerWebPresenceSnapshot(s)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeBunkerWebPresenceSnapshot(encoded)
		if err != nil || again != s {
			t.Fatal("round trip changed meaning", err)
		}
		next, err := EncodeBunkerWebPresenceSnapshot(again)
		if err != nil || !bytes.Equal(next, encoded) {
			t.Fatal("unstable encoding", err)
		}
		c := presenceContext(t, s)
		c.ExpectedIdentity.NodeID = "deliberately.different"
		if c.ExpectedIdentity.NodeID == s.Identity.NodeID {
			c.ExpectedIdentity.NodeID = "different.again"
		}
		if view, err := ProjectBunkerWebPresenceSnapshot(s, c); !errors.Is(err, ErrBunkerWebPresenceBindingMismatch) || view != (BunkerWebPresenceView{}) {
			t.Fatal("wrong identity accepted", err)
		}
	})
}

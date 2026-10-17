package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestNodeExposureStrictJSON(t *testing.T) {
	base := string(fixture(t, "node-exposure.json"))
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
		"missing nested field": replace(`,"value":"internet_exposed"`, ``),
		"unknown nested field": replace(`"value":"internet_exposed"`, `"value":"internet_exposed","address":"192.0.2.1"`),
		"unknown field":        []byte(strings.Replace(base, "{", `{"extension":"ignored",`, 1)),
		"invalid utf8":         replace("node.fixture.1", string([]byte{0xff})),
		"surrogate":            replace("node.fixture.1", `\ud800`),
		"control":              replace("node.fixture.1", `\u001b[31m`),
		"trailing":             append([]byte(base), []byte(" {}")...),
		"oversized":            []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := DecodeNodeExposureSnapshot(data)
			if !errors.Is(err, ErrInvalidNodeExposureDocument) || s != (NodeExposureSnapshot{}) {
				t.Fatal("ambiguous report disclosed", err)
			}
			if strings.Contains(err.Error(), "192.0.2.1") || strings.Contains(err.Error(), "node.fixture.1") {
				t.Fatal("input leaked into error")
			}
		})
	}
	if s, err := DecodeNodeExposureSnapshot(replace(NodeExposureSnapshotSchema, "syswarden.node-exposure-snapshot.v2")); !errors.Is(err, ErrUnsupportedNodeExposureSchema) || s != (NodeExposureSnapshot{}) {
		t.Fatal("unknown schema accepted", err)
	}
}

func TestNodeExposureFormattingBoundsAndSchemaIsolation(t *testing.T) {
	data := fixture(t, "node-exposure.json")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	s, err := DecodeNodeExposureSnapshot(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeNodeExposureSnapshot(s)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed identity", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := DecodeNodeExposureSnapshot(input); err != nil {
		t.Fatal("exact bound rejected", err)
	}
	if _, err := DecodeNodeExposureSnapshot(append(input, ' ')); err == nil {
		t.Fatal("excess bound accepted")
	}
	for _, name := range []string{"node-reachable.json", "native-ip.json"} {
		if out, err := DecodeNodeExposureSnapshot(fixture(t, name)); err == nil || out != (NodeExposureSnapshot{}) {
			t.Fatal("other schema became exposure")
		}
	}
	if out, err := DecodeNodeSnapshot(data); err == nil || out != (NodeSnapshot{}) {
		t.Fatal("exposure became node health")
	}
	if out, err := DecodeEvent(data); err == nil || out != (Event{}) {
		t.Fatal("exposure became event")
	}
	for _, line := range bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n")) {
		if out, err := DecodeNodeExposureSnapshot(line); err == nil || out != (NodeExposureSnapshot{}) {
			t.Fatal("legacy event became exposure")
		}
	}
}

func FuzzNodeExposureRoundTrip(f *testing.F) {
	for _, name := range []string{"node-exposure.json", "node-reachable.json", "native-ip.json"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeNodeExposureSnapshot(data)
		if err != nil {
			if s != (NodeExposureSnapshot{}) {
				t.Fatal("partial exposure")
			}
			return
		}
		encoded, err := EncodeNodeExposureSnapshot(s)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeNodeExposureSnapshot(encoded)
		if err != nil || again != s {
			t.Fatal("round trip changed meaning", err)
		}
		next, err := EncodeNodeExposureSnapshot(again)
		if err != nil || !bytes.Equal(next, encoded) {
			t.Fatal("unstable encoding", err)
		}
		c := exposureContext(t, s)
		c.ExpectedIdentity.NodeID = "deliberately.different"
		if c.ExpectedIdentity.NodeID == s.Identity.NodeID {
			c.ExpectedIdentity.NodeID = "different.again"
		}
		if view, err := ProjectNodeExposureSnapshot(s, c); !errors.Is(err, ErrNodeExposureBindingMismatch) || view != (NodeExposureView{}) {
			t.Fatal("wrong identity accepted", err)
		}
	})
}

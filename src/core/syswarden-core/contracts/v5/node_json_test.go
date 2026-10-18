package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNodeSnapshotRejectsAmbiguousJSON(t *testing.T) {
	base := string(fixture(t, "node-reachable.json"))
	replace := func(old, new string) []byte { return []byte(strings.Replace(base, old, new, 1)) }
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"duplicate":          []byte(strings.Replace(base, "{", `{"schema":"ignored",`, 1)),
		"escaped duplicate":  []byte(strings.Replace(base, "{", `{"\u0073chema":"ignored",`, 1)),
		"case alias":         replace(`"schema":`, `"Schema":`),
		"nested duplicate":   replace(`"epoch":"generation.fixture.1"`, `"epoch":"old","epoch":"generation.fixture.1"`),
		"nested alias":       replace(`"epoch":`, `"Epoch":`),
		"missing generation": replace(`,"epoch":"generation.fixture.1"`, ""),
		"null identity":      replace(`"identity":{"cluster_id":"cluster.fixture.1","node_id":"node.fixture.1","epoch":"generation.fixture.1"}`, `"identity":null`),
		"numeric generation": replace(`"epoch":"generation.fixture.1"`, `"epoch":1`),
		"null field":         replace(`"clock_quality":{"state":"present","value":"unknown"}`, `"clock_quality":null`),
		"unknown member":     []byte(strings.Replace(base, "{", `{"extension":"ignored",`, 1)),
		"invalid utf8":       replace("node.fixture.1", string([]byte{0xff})),
		"unpaired surrogate": replace("node.fixture.1", `\ud800`),
		"terminal escape":    replace("node.fixture.1", `\u001b[31m`),
		"trailing value":     append([]byte(base), []byte(" {}")...),
		"oversized":          []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if s, err := DecodeNodeSnapshot(input); !errors.Is(err, ErrInvalidNodeDocument) || s != (NodeSnapshot{}) {
				t.Fatal("ambiguous data accepted or returned partially", err)
			}
		})
	}
	if s, err := DecodeNodeSnapshot(replace(NodeSnapshotSchema, "syswarden.node-snapshot.v2")); !errors.Is(err, ErrUnsupportedNodeSchema) || s != (NodeSnapshot{}) {
		t.Fatal("unknown schema interpreted", err)
	}
}

func TestNodeSnapshotFormattingAndByteLimit(t *testing.T) {
	data := fixture(t, "node-reachable.json")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	s, err := DecodeNodeSnapshot(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeNodeSnapshot(s)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed canonical bytes", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := DecodeNodeSnapshot(input); err != nil {
		t.Fatal("exact document boundary rejected", err)
	}
	if _, err := DecodeNodeSnapshot(append(input, ' ')); err == nil {
		t.Fatal("document bound not enforced")
	}
}

func TestNodeSnapshotRejectsLegacyRecordsWithoutInventingEnrollment(t *testing.T) {
	for _, line := range bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n")) {
		if s, err := DecodeNodeSnapshot(line); !errors.Is(err, ErrInvalidNodeDocument) || s != (NodeSnapshot{}) {
			t.Fatal("legacy event became enrolled node identity", err)
		}
	}
	for _, name := range []string{"native-ip.json", "native-l2.json"} {
		if s, err := DecodeNodeSnapshot(fixture(t, name)); !errors.Is(err, ErrInvalidNodeDocument) || s != (NodeSnapshot{}) {
			t.Fatal("event node reference became membership proof", err)
		}
	}
	if e, err := DecodeEvent(fixture(t, "node-reachable.json")); err == nil || e != (Event{}) {
		t.Fatal("node schema confused with event schema")
	}
}

func FuzzNodeSnapshotRoundTrip(f *testing.F) {
	for _, name := range []string{"node-reachable.json", "node-unreachable.json", "node-unknown.json", "native-ip.json"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeNodeSnapshot(data)
		if err != nil {
			if s != (NodeSnapshot{}) {
				t.Fatal("partial node snapshot")
			}
			return
		}
		encoded, err := EncodeNodeSnapshot(s)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeNodeSnapshot(encoded)
		if err != nil || again != s {
			t.Fatal("node round trip changed meaning", err)
		}
		second, err := EncodeNodeSnapshot(again)
		if err != nil || !bytes.Equal(second, encoded) {
			t.Fatal("unstable node encoding", err)
		}
		// Synthetic selection derived from fuzz input only, not production admission.
		context := nodeViewContext(t, s)
		context.ReadContext.ExpectedIdentity = s.Identity
		context.ReadContext.Now, _ = time.Parse(time.RFC3339Nano, s.CollectedAt)
		context.ReadContext.MaxAge = MaxSnapshotLifetime
		view, err := ProjectNodeSnapshot(s, context)
		if err != nil || view.ReportState != Present || view.CurrentReachability != s.Reachability {
			t.Fatal("valid report lost current projection", err)
		}
		checkNodeViewFields(t, s, view, false)
		context.ReadContext.Now, _ = time.Parse(time.RFC3339Nano, s.ValidUntil)
		view, err = ProjectNodeSnapshot(s, context)
		if err != nil || view.ReportState != Stale || view.CurrentReachability != "unknown" || view.Identity != s.Identity {
			t.Fatal("expired report lost identity or retained current transport", err)
		}
		checkNodeViewFields(t, s, view, true)
		if err := CheckCurrentNodeSnapshot(s, readContext()); err == nil && s.Identity != readContext().ExpectedIdentity {
			t.Fatal("accepted substituted identity")
		}
	})
}

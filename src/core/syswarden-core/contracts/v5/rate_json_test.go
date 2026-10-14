package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRateStrictJSON(t *testing.T) {
	data := fixture(t, "rate-mixed.json")
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
		"duplicate":         []byte(strings.Replace(base, "{", `{"schema":"ignored",`, 1)),
		"escaped duplicate": []byte(strings.Replace(base, "{", `{"\u0073chema":"ignored",`, 1)),
		"alias":             replace(`"snapshot_id":`, `"Snapshot_ID":`),
		"unknown":           []byte(strings.Replace(base, "{", `{"percentage":100,`, 1)),
		"missing input":     replace(`"ref":"scope.fixture.1",`, ""),
		"numeric count":     replace(`"eligible":"10"`, `"eligible":10`),
		"duplicate count":   replace(`"eligible":"10"`, `"eligible":"9","eligible":"10"`),
		"count alias":       replace(`"eligible":`, `"Eligible":`),
		"null count":        replace(`"eligible":"10"`, `"eligible":null`),
		"missing count":     replace(`"excluded":"2"`, `"discarded":"2"`),
		"nested count":      replace(`"eligible":"10"`, `"eligible":{"value":"10"}`),
		"null window":       replace(`"window":{`, `"window":null,"discarded":{`),
		"unpaired utf16":    replace("collector.fixture.1", `\ud800`),
		"invalid utf8":      replace("collector.fixture.1", string([]byte{0xff})),
		"terminal escape":   replace("collector.fixture.1", `\u001b[31m`),
		"private input":     replace("collector.fixture.1", "private/payload/not-for-errors"),
		"trailing":          append([]byte(base), []byte(" {}")...),
		"oversized":         []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
		"depth":             []byte(strings.Repeat("[", 9) + strings.Repeat("]", 9)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := DecodeRateSnapshot(input)
			if !errors.Is(err, ErrInvalidRateDocument) || s != (RateSnapshot{}) {
				t.Fatal("ambiguous rate accepted", err)
			}
			if strings.Contains(err.Error(), "private/payload") {
				t.Fatal("input leaked in error")
			}
		})
	}
	for _, test := range []struct {
		old, value string
		err        error
	}{
		{RateSnapshotSchema, RateSnapshotSchema + ".future", ErrUnsupportedRateSchema},
		{"verified_protection_coverage.v1", "verified_protection_coverage.v2", ErrUnsupportedRateDefinition},
	} {
		if s, err := DecodeRateSnapshot(replace(test.old, test.value)); !errors.Is(err, test.err) || s != (RateSnapshot{}) {
			t.Fatal("unsupported schema/formula interpreted", err)
		}
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	s, err := DecodeRateSnapshot(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRateSnapshot(s)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("formatting changed canonical rate", err)
	}
	input := append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(data)), data...)
	if _, err := DecodeRateSnapshot(input); err != nil {
		t.Fatal("byte boundary rejected", err)
	}
	if s, err := DecodeRateSnapshot(append(input, ' ')); err == nil || s != (RateSnapshot{}) {
		t.Fatal("byte bound bypassed")
	}
	s.SnapshotID = strings.Repeat("x", MaxIdentifierBytes)
	if _, err := EncodeRateSnapshot(s); err != nil {
		t.Fatal("ID boundary rejected", err)
	}
}

func TestRateReadBinding(t *testing.T) {
	s := rateFixture(t, "mixed")
	for name, change := range map[string]func(*RateReadContext){
		"snapshot":        func(c *RateReadContext) { c.SnapshotID = "snapshot.other" },
		"snapshot hash":   func(c *RateReadContext) { c.SnapshotSHA256 = strings.Repeat("1", 64) },
		"collector":       func(c *RateReadContext) { c.CollectorID = "collector.other" },
		"formula":         func(c *RateReadContext) { c.DefinitionID = "reporting_coverage.v1" },
		"category":        func(c *RateReadContext) { c.Category = "high" },
		"scope":           func(c *RateReadContext) { c.Inputs.Scope.Ref = "scope.other" },
		"scope hash":      func(c *RateReadContext) { c.Inputs.Scope.SHA256 = strings.Repeat("1", 64) },
		"population":      func(c *RateReadContext) { c.Inputs.Population.Ref = "population.other" },
		"population hash": func(c *RateReadContext) { c.Inputs.Population.SHA256 = strings.Repeat("1", 64) },
		"policy":          func(c *RateReadContext) { c.Inputs.Policy.Ref = "policy.other" },
		"policy hash":     func(c *RateReadContext) { c.Inputs.Policy.SHA256 = strings.Repeat("1", 64) },
		"window": func(c *RateReadContext) {
			c.Window.Start, c.Window.End = "2026-10-12T09:00:00Z", "2026-10-12T09:00:00Z"
		},
		"minimum": func(c *RateReadContext) { c.MinimumEligible = "11" },
	} {
		t.Run(name, func(t *testing.T) {
			c := rateContext(t, "mixed")
			change(&c)
			if err := CheckCurrentRateSnapshot(s, c); !errors.Is(err, ErrRateBindingMismatch) {
				t.Fatal("substituted rate input accepted", err)
			}
		})
	}
	c := rateContext(t, "mixed")
	for _, change := range []func(*RateSnapshot){
		func(s *RateSnapshot) { s.Counts.Matched, s.Counts.Other = "8", "0" },
		func(s *RateSnapshot) { s.Counts.Excluded = "3" },
		func(s *RateSnapshot) { s.Counts.State = Partial },
		func(s *RateSnapshot) { s.GeneratedAt = "2026-10-12T10:00:01Z" },
	} {
		changed := s
		change(&changed)
		if err := CheckCurrentRateSnapshot(changed, c); !errors.Is(err, ErrRateBindingMismatch) {
			t.Fatal("same-ID content replacement accepted", err)
		}
	}
}

func TestRateReadContextAndFreshness(t *testing.T) {
	s := rateFixture(t, "mixed")
	for name, change := range map[string]func(*RateReadContext){
		"empty snapshot":    func(c *RateReadContext) { c.SnapshotID = "" },
		"empty hash":        func(c *RateReadContext) { c.SnapshotSHA256 = "" },
		"empty collector":   func(c *RateReadContext) { c.CollectorID = "" },
		"unknown formula":   func(c *RateReadContext) { c.DefinitionID = "unknown.v1" },
		"bad scope":         func(c *RateReadContext) { c.Inputs.Scope.Ref = "" },
		"bad window":        func(c *RateReadContext) { c.Window.Start = "invalid" },
		"wrong window kind": func(c *RateReadContext) { c.Window.Kind = "interval"; c.Window.Start = "2026-10-12T09:00:00Z" },
		"zero minimum":      func(c *RateReadContext) { c.MinimumEligible = "0" },
		"zero age":          func(c *RateReadContext) { c.MaxAge = 0 },
		"negative age":      func(c *RateReadContext) { c.MaxAge = -1 },
		"overlong age":      func(c *RateReadContext) { c.MaxAge = MaxSnapshotLifetime + 1 },
		"zero now":          func(c *RateReadContext) { c.Now = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			c := rateContext(t, "mixed")
			change(&c)
			if err := CheckCurrentRateSnapshot(s, c); !errors.Is(err, ErrInvalidRateReadContext) {
				t.Fatal("bad context accepted", err)
			}
		})
	}
	for _, now := range []string{"2026-10-12T09:59:59.999999999Z", "2026-10-12T10:05:00Z", "2026-10-12T10:05:00.000000001Z"} {
		c := rateContext(t, "mixed")
		c.Now, _ = time.Parse(time.RFC3339Nano, now)
		if err := CheckCurrentRateSnapshot(s, c); !errors.Is(err, ErrRateSnapshotNotCurrent) {
			t.Fatal("time boundary accepted", now, err)
		}
	}
	c := rateContext(t, "mixed")
	c.MaxAge = time.Minute
	if err := CheckCurrentRateSnapshot(s, c); !errors.Is(err, ErrRateSnapshotNotCurrent) {
		t.Fatal("caller age ignored", err)
	}
	c.Now = c.Now.Add(-time.Nanosecond)
	if err := CheckCurrentRateSnapshot(s, c); err != nil {
		t.Fatal("inside age rejected", err)
	}
	for _, clock := range []string{"unknown", "unsynchronized"} {
		s.ClockQuality = clock
		c := rateContext(t, "mixed")
		c.SnapshotSHA256, _ = RateSnapshotSHA256(s)
		if err := CheckCurrentRateSnapshot(s, c); !errors.Is(err, ErrRateSnapshotNotCurrent) {
			t.Fatal("clock uncertainty hidden", err)
		}
	}
	// A fresh report can retain stale quantities, without promoting their state.
	s = rateFixture(t, "mixed")
	s.Counts.State = Stale
	c = rateContext(t, "mixed")
	c.SnapshotSHA256, _ = RateSnapshotSHA256(s)
	if err := CheckCurrentRateSnapshot(s, c); err != nil {
		t.Fatal("fresh stale-data report rejected", err)
	}
	r, err := ComputeRatePercentages(s)
	if err != nil || r.Matched.State != Stale {
		t.Fatal("stale data refreshed by new report", err)
	}
}

func TestOtherRecordsCannotBecomeRateSnapshots(t *testing.T) {
	inputs := bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n"))
	for _, name := range []string{"native-ip.json", "native-l2.json", "node-reachable.json", "decision-block.json", "action-verified.json", "control-effective.json", "evidence-original.json", "incident-association.json"} {
		inputs = append(inputs, fixture(t, name))
	}
	for _, input := range inputs {
		if s, err := DecodeRateSnapshot(input); err == nil || s != (RateSnapshot{}) {
			t.Fatal("other record manufactured a rate")
		}
	}
	data := fixture(t, "rate-mixed.json")
	if e, err := DecodeEvent(data); err == nil || e != (Event{}) {
		t.Fatal("rate became an event")
	}
	if c, err := DecodeControlSnapshot(data); err == nil || c != (ControlSnapshot{}) {
		t.Fatal("rate became current control")
	}
	if r, err := IncidentRecordReferenceFromJSON(ResolvedIncidentRecord{Identity: readContext().ExpectedIdentity, Schema: RateSnapshotSchema, Data: data}); err == nil || r != (IncidentRecordReference{}) {
		t.Fatal("fleet rate became a node-local incident endpoint")
	}
}

func FuzzRateSnapshotRoundTrip(f *testing.F) {
	context := rateContext(f, "mixed")
	fuzzEnforcementCodec(f, []string{"rate-mixed.json", "rate-empty.json", "rate-missing.json", "rate-partial.json", "rate-severity.json", "native-ip.json"}, DecodeRateSnapshot, EncodeRateSnapshot, func(t *testing.T, s RateSnapshot) {
		if _, err := ComputeRatePercentages(s); err != nil {
			t.Fatal("valid report failed arithmetic", err)
		}
		c := context
		c.Inputs.Scope.Ref = "scope.rejected.1"
		if s.Inputs.Scope.Ref == c.Inputs.Scope.Ref {
			c.Inputs.Scope.Ref = "scope.rejected.2"
		}
		if err := CheckCurrentRateSnapshot(s, c); err == nil {
			t.Fatal("cross-scope rate accepted")
		}
	})
}

package v5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

func rateFixture(t testing.TB, name string) RateSnapshot {
	t.Helper()
	s, err := DecodeRateSnapshot(fixture(t, "rate-"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rateContext(t testing.TB, name string) RateReadContext {
	t.Helper()
	s := rateFixture(t, name)
	hash, err := RateSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	inputs := s.Inputs
	for filename, ref := range map[string]*RateReference{
		"rate-scope.txt": &inputs.Scope, "rate-policy.txt": &inputs.Policy,
		"rate-population-" + name + ".txt": &inputs.Population,
	} {
		// Preserve exact source bytes, including the scope/policy final newline.
		data, err := goldenFixtures.ReadFile("testdata/" + filename)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		ref.SHA256 = hex.EncodeToString(sum[:])
	}
	return RateReadContext{SnapshotID: s.SnapshotID, SnapshotSHA256: hash, CollectorID: s.CollectorID,
		DefinitionID: s.DefinitionID, Category: s.Category, Inputs: inputs, Window: s.Window,
		MinimumEligible: "1", Now: time.Date(2026, 10, 12, 10, 1, 0, 0, time.UTC), MaxAge: 5 * time.Minute}
}

func TestRateCatalogGolden(t *testing.T) {
	lines := bytes.Split(bytes.TrimSpace(fixture(t, "rate-catalog.ndjson")), []byte("\n"))
	if len(lines) != 6 {
		t.Fatal("catalog fixture coverage changed")
	}
	seen := make(map[string]bool)
	for _, line := range lines {
		var expected RateDefinition
		if err := json.Unmarshal(line, &expected); err != nil {
			t.Fatal(err)
		}
		d, err := LookupRateDefinition(expected.ID)
		if err != nil || d != expected || seen[d.ID] {
			t.Fatal("catalog definition changed without new fixture/version", err)
		}
		seen[d.ID] = true
		if d.Unit != "percent" || d.Precision != "2" || d.Rounding != "half_up" || d.Catalog != RateCatalogSchema || d.Deduplication == "" {
			t.Fatal("incomplete percentage definition")
		}
		hash, err := RateDefinitionSHA256(d.ID)
		sum := sha256.Sum256(line)
		if err != nil || hash != hex.EncodeToString(sum[:]) {
			t.Fatal("catalog byte binding changed", err)
		}
		d.Numerator = "consumer override"
		again, err := LookupRateDefinition(d.ID)
		if err != nil || again != expected {
			t.Fatal("caller changed the catalog")
		}
		s := rateFixture(t, "mixed")
		s.DefinitionID, s.DefinitionSHA256, s.Window.Kind = expected.ID, hash, expected.WindowKind
		if s.Window.Kind == "interval" {
			s.Window.Start = "2026-10-12T09:00:00Z"
		}
		if expected.ID == "alert_severity_share.v1" {
			s.Category = "high"
		}
		if err := s.Validate(); err != nil {
			t.Fatal("catalog formula has no valid report", err)
		}
	}
	for _, id := range []string{"", "reporting_coverage.v2", "security_score.v1", "attacks_blocked.v1", "false_positive_rate.v1", "alert_outcome_share.v1"} {
		if d, err := LookupRateDefinition(id); !errors.Is(err, ErrUnsupportedRateDefinition) || d != (RateDefinition{}) {
			t.Fatal("unsupported formula interpreted", id)
		}
		if hash, err := RateDefinitionSHA256(id); !errors.Is(err, ErrUnsupportedRateDefinition) || hash != "" {
			t.Fatal("unsupported formula hashed")
		}
	}
}

func TestRateGoldenSnapshots(t *testing.T) {
	for _, test := range []struct{ name, state, matched, other, unknown, stale string }{
		{"mixed", Present, "70.00", "10.00", "10.00", "10.00"},
		{"empty", Unavailable, "", "", "", ""},
		{"missing", Missing, "", "", "", ""},
		{"partial", Partial, "33.33", "16.67", "33.33", "16.67"},
		{"severity", Present, "33.33", "33.33", "33.33", "0.00"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := rateFixture(t, test.name)
			data, err := EncodeRateSnapshot(s)
			if err != nil || !bytes.Equal(data, fixture(t, "rate-"+test.name+".json")) {
				t.Fatal("golden rate encoding changed", err)
			}
			if err := CheckCurrentRateSnapshot(s, rateContext(t, test.name)); err != nil {
				t.Fatal("synthetic report binding failed", err)
			}
			r, err := ComputeRatePercentages(s)
			want := RatePercentages{Field{test.state, test.matched}, Field{test.state, test.other}, Field{test.state, test.unknown}, Field{test.state, test.stale}}
			if err != nil || r != want {
				t.Fatal("rate semantics changed", r, err)
			}
		})
	}
}

func TestRateInvalidDeclarations(t *testing.T) {
	cases := map[string]func(*RateSnapshot){
		"schema":                     func(s *RateSnapshot) { s.Schema += ".future" },
		"formula":                    func(s *RateSnapshot) { s.DefinitionID += ".future" },
		"formula hash":               func(s *RateSnapshot) { s.DefinitionSHA256 = strings.Repeat("0", 64) },
		"snapshot ID":                func(s *RateSnapshot) { s.SnapshotID = "" },
		"collector ID":               func(s *RateSnapshot) { s.CollectorID = strings.Repeat("x", MaxIdentifierBytes+1) },
		"scope URL":                  func(s *RateSnapshot) { s.Inputs.Scope.Ref = "https://private.invalid" },
		"population hash":            func(s *RateSnapshot) { s.Inputs.Population.SHA256 = "" },
		"policy hash":                func(s *RateSnapshot) { s.Inputs.Policy.SHA256 = strings.Repeat("A", 64) },
		"category":                   func(s *RateSnapshot) { s.Category = "high" },
		"minimum zero":               func(s *RateSnapshot) { s.MinimumEligible = "0" },
		"minimum sign":               func(s *RateSnapshot) { s.MinimumEligible = "+1" },
		"window kind":                func(s *RateSnapshot) { s.Window.Kind = "interval" },
		"snapshot unequal bounds":    func(s *RateSnapshot) { s.Window.Start = "2026-10-12T09:00:00Z" },
		"window future":              func(s *RateSnapshot) { s.Window.Start, s.Window.End = "2026-10-12T11:00:00Z", "2026-10-12T11:00:00Z" },
		"timestamp alias":            func(s *RateSnapshot) { s.GeneratedAt = "2026-10-12T10:00:00+00:00" },
		"expiry equal":               func(s *RateSnapshot) { s.ValidUntil = s.GeneratedAt },
		"expiry too far":             func(s *RateSnapshot) { s.ValidUntil = "2026-10-13T10:00:00.000000001Z" },
		"clock":                      func(s *RateSnapshot) { s.ClockQuality = "good" },
		"state":                      func(s *RateSnapshot) { s.Counts.State = "complete" },
		"hidden numbers":             func(s *RateSnapshot) { s.Counts.State = Unavailable },
		"negative":                   func(s *RateSnapshot) { s.Counts.Other = "-1" },
		"leading zero":               func(s *RateSnapshot) { s.Counts.Eligible = "010" },
		"float":                      func(s *RateSnapshot) { s.Counts.Matched = "7.0" },
		"exponent":                   func(s *RateSnapshot) { s.Counts.Eligible = "1e1" },
		"whitespace":                 func(s *RateSnapshot) { s.Counts.Unknown = " 1" },
		"overflow":                   func(s *RateSnapshot) { s.Counts.Excluded = "9223372036854775808" },
		"numerator exceeds":          func(s *RateSnapshot) { s.Counts.Matched = "11" },
		"missing remainder":          func(s *RateSnapshot) { s.Counts.Other = "0" },
		"overlapping parts":          func(s *RateSnapshot) { s.Counts.Stale = "2" },
		"hidden unknown denominator": func(s *RateSnapshot) { s.Counts.Eligible = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := rateFixture(t, "mixed")
			change(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("invalid rate accepted")
			}
			if data, err := EncodeRateSnapshot(s); err == nil || data != nil {
				t.Fatal("invalid rate encoded")
			}
			if r, err := ComputeRatePercentages(s); err == nil || r != (RatePercentages{}) {
				t.Fatal("invalid rate produced partial percentages")
			}
			if h, err := RateSnapshotSHA256(s); err == nil || h != "" {
				t.Fatal("invalid rate hashed")
			}
		})
	}
	for _, change := range []func(*RateSnapshot){
		func(s *RateSnapshot) { s.Category = "unknown" },
		func(s *RateSnapshot) { s.Window.Start = s.Window.End },
		func(s *RateSnapshot) { s.Window.Start = "2026-10-12T11:00:00Z" },
	} {
		s := rateFixture(t, "severity")
		change(&s)
		if s.Validate() == nil {
			t.Fatal("invalid interval or overlapping severity category accepted")
		}
	}
}

func TestRateAvailabilityAndMinimum(t *testing.T) {
	for _, state := range []string{Present, Partial, Stale, Missing, Unavailable, Rejected, NotApplicable} {
		t.Run(state, func(t *testing.T) {
			s := rateFixture(t, "mixed")
			if member(Present, Partial, Stale)(state) {
				s.Counts.State = state
			} else {
				s.Counts = RateCounts{State: state}
			}
			r, err := ComputeRatePercentages(s)
			if err != nil || r.Matched.State != state || r.Unknown.State != state {
				t.Fatal("availability promoted or discarded", err)
			}
			if !member(Present, Partial, Stale)(state) && r.Matched.Value != "" {
				t.Fatal("unknown denominator became a number")
			}
		})
	}
	s := rateFixture(t, "mixed")
	s.MinimumEligible = "11"
	r, err := ComputeRatePercentages(s)
	if err != nil || r.Matched != (Field{State: Unavailable}) {
		t.Fatal("insufficient sample became a percentage", err)
	}
	s.MinimumEligible = "10"
	r, err = ComputeRatePercentages(s)
	if err != nil || r.Matched.Value != "70.00" {
		t.Fatal("exact minimum rejected", err)
	}
}

func TestRateArithmeticBoundaries(t *testing.T) {
	for _, test := range []struct {
		n, d uint64
		want string
	}{
		{0, 10, "0.00"}, {10, 10, "100.00"}, {1, 3, "33.33"}, {2, 3, "66.67"},
		{1, 20000, "0.01"}, {1, 20001, "0.00"}, {19999, 20000, "100.00"},
		{math.MaxInt64, math.MaxInt64, "100.00"}, {1, math.MaxInt64, "0.00"},
		{math.MaxInt64 / 2, math.MaxInt64, "50.00"}, {9007199254740993, 9007199254740994, "100.00"},
	} {
		t.Run(strconv.FormatUint(test.n, 10)+"/"+strconv.FormatUint(test.d, 10), func(t *testing.T) {
			s := rateFixture(t, "mixed")
			s.Counts = binaryRateCounts(test.n, test.d)
			r, err := ComputeRatePercentages(s)
			if err != nil || r.Matched.Value != test.want {
				t.Fatal("integer rounding or overflow error", r, err)
			}
		})
	}
	// A known disjoint population union has 1/10, not the mean of 1/1 and 0/9.
	// This fixture does not implement membership union or prove disjointness.
	s := rateFixture(t, "mixed")
	s.Counts = binaryRateCounts(1, 10)
	r, err := ComputeRatePercentages(s)
	if err != nil || r.Matched.Value != "10.00" {
		t.Fatal("weighted population arithmetic failed", err)
	}
}

func binaryRateCounts(n, d uint64) RateCounts {
	return RateCounts{State: Present, Eligible: strconv.FormatUint(d, 10), Matched: strconv.FormatUint(n, 10),
		Other: strconv.FormatUint(d-n, 10), Unknown: "0", Stale: "0", Excluded: "0"}
}

func FuzzRateArithmetic(f *testing.F) {
	for _, seed := range [][2]uint64{{0, 0}, {1, 20000}, {1, 3}, {math.MaxInt64, math.MaxInt64}, {math.MaxUint64, math.MaxUint64}} {
		f.Add(seed[0], seed[1])
	}
	base := rateFixture(f, "mixed")
	f.Fuzz(func(t *testing.T, n, d uint64) {
		d &= math.MaxInt64
		n %= d + 1
		s := base
		s.Counts = binaryRateCounts(n, d)
		r, err := ComputeRatePercentages(s)
		if err != nil {
			t.Fatal(err)
		}
		if d == 0 {
			if r.Matched != (Field{State: Unavailable}) {
				t.Fatal("empty denominator promoted")
			}
			return
		}
		// Independent arbitrary-precision rational oracle covers overflow/rounding.
		numerator := new(big.Int).Mul(new(big.Int).SetUint64(n), big.NewInt(100))
		want := new(big.Rat).SetFrac(numerator, new(big.Int).SetUint64(d)).FloatString(2)
		if r.Matched != (Field{State: Present, Value: want}) {
			t.Fatal("percentage disagrees with exact rational oracle", r.Matched, want)
		}
	})
}

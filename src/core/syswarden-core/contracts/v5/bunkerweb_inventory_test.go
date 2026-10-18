package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func inventoryFixture(t testing.TB) (BunkerWebInventoryContext, BunkerWebInventoryMember, BunkerWebInventoryReport) {
	t.Helper()
	s := presenceFixture(t)
	c := presenceContext(t, s)
	m := BunkerWebInventoryMember{Identity: s.Identity, KnownRegistration: RateReference{Ref: "registration.history.1", SHA256: strings.Repeat("e", 64)},
		Selection: BunkerWebPresenceSelection{SnapshotID: s.SnapshotID, SHA256: c.SnapshotSHA256, CollectorID: s.CollectorID}}
	return BunkerWebInventoryContext{Scope: s.Scope, Membership: RateReference{Ref: "membership.fixture.1", SHA256: strings.Repeat("f", 64)}, Policy: s.Policy,
			Now: c.Now, MaxReportAge: c.MaxReportAge, MaxRegistrationAge: c.MaxRegistrationAge, MaxModeAge: c.MaxModeAge}, m,
		BunkerWebInventoryReport{Identity: s.Identity, Document: fixture(t, "bunkerweb-presence.json")}
}

func selectInventoryReport(t testing.TB, m *BunkerWebInventoryMember, s BunkerWebPresenceSnapshot) BunkerWebInventoryReport {
	t.Helper()
	data, err := EncodeBunkerWebPresenceSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := BunkerWebPresenceSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	m.Selection = BunkerWebPresenceSelection{SnapshotID: s.SnapshotID, SHA256: hash, CollectorID: s.CollectorID}
	return BunkerWebInventoryReport{Identity: m.Identity, Document: data}
}

func assertInvalidInventory(t testing.TB, c BunkerWebInventoryContext, m []BunkerWebInventoryMember, r []BunkerWebInventoryReport) {
	t.Helper()
	out, err := ResolveBunkerWebInventory(c, m, r)
	if !errors.Is(err, ErrInvalidBunkerWebInventory) || out.Entries() != nil || out.Manifest() != nil || out.Relevance() != "" {
		t.Fatal("invalid inventory disclosed data", err)
	}
	if ref, err := out.Reference("rejected"); err == nil || ref != (RateReference{}) {
		t.Fatal("invalid inventory referenced")
	}
}

func TestBunkerWebInventoryGoldenAndCopies(t *testing.T) {
	c, m, r := inventoryFixture(t)
	out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Manifest(), fixture(t, "bunkerweb-inventory.json")) {
		t.Fatal("canonical inventory changed")
	}
	ref, err := out.Reference("inventory.fixture.1")
	if err != nil || ref.SHA256 != strings.TrimSpace(string(fixture(t, "bunkerweb-inventory-digest.txt"))) {
		t.Fatal("manifest digest changed", err)
	}
	entries := out.Entries()
	data := out.Manifest()
	entries[0].Identity.NodeID = "modified"
	data[0] = 'X'
	r.Document[0] = 'X'
	if out.Entries()[0].Identity != m.Identity || out.Manifest()[0] != '{' || out.Relevance() != "known" {
		t.Fatal("caller mutated result")
	}
	if ref, err := out.Reference(""); err == nil || ref != (RateReference{}) {
		t.Fatal("invalid reference accepted")
	}
}

func TestBunkerWebInventoryRetainsMissingKnownAndUnknown(t *testing.T) {
	c, m, _ := inventoryFixture(t)
	unknown := m
	unknown.Identity.NodeID = "node.unknown"
	unknown.KnownRegistration = RateReference{}
	unknown.Selection = BunkerWebPresenceSelection{}
	out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{unknown, m, m}, nil)
	if err != nil || len(out.Entries()) != 2 || out.Relevance() != "known" {
		t.Fatal("nonresponding members disappeared", err)
	}
	for _, entry := range out.Entries() {
		want := "unknown"
		if entry.Identity == m.Identity {
			want = "known"
		}
		if entry.Relevance != want || entry.ReportState != Missing || entry.CurrentMode != "unknown" || entry.Reason != "missing_report" {
			t.Fatal("missing report became absent or enabled", entry)
		}
	}
	empty, err := ResolveBunkerWebInventory(c, nil, nil)
	if err != nil || len(empty.Entries()) != 0 || empty.Relevance() != "absent" || !bytes.Contains(empty.Manifest(), []byte(`"entries":[]`)) {
		t.Fatal("explicit empty inventory failed", err)
	}
	onlyUnknown, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{unknown}, nil)
	if err != nil || onlyUnknown.Relevance() != "unknown" {
		t.Fatal("unknown inventory became absent", err)
	}
}

func TestBunkerWebInventoryModesAndHistory(t *testing.T) {
	for _, mode := range []string{"log_only", "sync_only", "combined", "disabled", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			c, m, _ := inventoryFixture(t)
			s := presenceFixture(t)
			s.Mode.Value = mode
			r := selectInventoryReport(t, &m, s)
			out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
			if err != nil || out.Relevance() != "known" || out.Entries()[0].CurrentMode != mode {
				t.Fatal("mode changed or integration hidden", err)
			}
		})
	}
	for _, known := range []bool{false, true} {
		t.Run(fmt.Sprintf("absence/history=%t", known), func(t *testing.T) {
			c, m, _ := inventoryFixture(t)
			s := presenceFixture(t)
			s.Registration.Value = "absent"
			s.Mode = InventoryClassification{State: Unavailable}
			if !known {
				m.KnownRegistration = RateReference{}
			}
			r := selectInventoryReport(t, &m, s)
			out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
			if err != nil {
				t.Fatal(err)
			}
			e := out.Entries()[0]
			if known {
				if out.Relevance() != "known" || e.ReportState != Rejected || e.Reason != "registration_conflict" || e.Registration.Value != "" || e.Mode.Value != "" {
					t.Fatal("report erased history", e)
				}
			} else if out.Relevance() != "absent" || e.ReportState != Present || e.Reason != "current_absence" {
				t.Fatal("explicit absence failed", e)
			}
		})
	}
}

func TestBunkerWebInventoryRetainsFreshnessAndDoesNotRenewHistory(t *testing.T) {
	for _, kind := range []string{"expired", "unverified clock", "stale registration", "stale mode", "absent stale", "unknown registration"} {
		t.Run(kind, func(t *testing.T) {
			c, m, _ := inventoryFixture(t)
			s := presenceFixture(t)
			switch kind {
			case "expired":
				c.Now = c.Now.Add(time.Hour)
			case "unverified clock":
				s.ClockQuality = "unknown"
			case "stale registration":
				s.Registration.State = Stale
			case "stale mode":
				s.Mode.State = Stale
			case "absent stale":
				s.Registration.Value = "absent"
				s.Registration.State = Stale
				s.Mode = InventoryClassification{State: Unavailable}
			case "unknown registration":
				s.Registration.Value = "unknown"
				s.Mode = InventoryClassification{State: Unavailable}
			}
			r := selectInventoryReport(t, &m, s)
			out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
			if err != nil {
				t.Fatal(err)
			}
			e := out.Entries()[0]
			if out.Relevance() != "known" || e.CurrentMode != "unknown" || e.KnownRegistration != m.KnownRegistration || e.Registration.Source != s.Registration.Source || e.Mode.Source != s.Mode.Source {
				t.Fatal("history or provenance lost", e)
			}
		})
	}
}

func TestBunkerWebInventoryRejectsMemberAndScopeSubstitution(t *testing.T) {
	c, m, r := inventoryFixture(t)
	cases := map[string]func(*BunkerWebInventoryContext, *[]BunkerWebInventoryMember, *[]BunkerWebInventoryReport){
		"scope": func(c *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			c.Scope = RateReference{}
		},
		"membership": func(c *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			c.Membership = RateReference{}
		},
		"policy": func(c *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			c.Policy = RateReference{}
		},
		"clock": func(c *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			c.Now = time.Time{}
		},
		"zero budget": func(c *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			c.MaxReportAge = 0
		},
		"negative budget": func(c *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			c.MaxRegistrationAge = -time.Second
		},
		"unbounded budget": func(c *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			c.MaxModeAge = MaxSnapshotLifetime + 1
		},
		"partial history": func(_ *BunkerWebInventoryContext, m *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			(*m)[0].KnownRegistration.SHA256 = ""
		},
		"partial selection": func(_ *BunkerWebInventoryContext, m *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			(*m)[0].Selection.CollectorID = ""
		},
		"invalid member": func(_ *BunkerWebInventoryContext, m *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			(*m)[0].Identity.NodeID = ""
		},
		"unselected report": func(_ *BunkerWebInventoryContext, m *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			(*m)[0].Selection = BunkerWebPresenceSelection{}
		},
		"foreign report": func(_ *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, r *[]BunkerWebInventoryReport) {
			(*r)[0].Identity.NodeID = "outside.scope"
		},
		"obsolete transport epoch": func(_ *BunkerWebInventoryContext, _ *[]BunkerWebInventoryMember, r *[]BunkerWebInventoryReport) {
			(*r)[0].Identity.Epoch = "old.epoch"
		},
		"member epoch conflict": func(_ *BunkerWebInventoryContext, m *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			other := (*m)[0]
			other.Identity.Epoch = "other"
			*m = append(*m, other)
		},
		"history conflict": func(_ *BunkerWebInventoryContext, m *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			other := (*m)[0]
			other.KnownRegistration.Ref = "other"
			*m = append(*m, other)
		},
		"selection conflict": func(_ *BunkerWebInventoryContext, m *[]BunkerWebInventoryMember, _ *[]BunkerWebInventoryReport) {
			other := (*m)[0]
			other.Selection.SHA256 = strings.Repeat("f", 64)
			*m = append(*m, other)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := c
			members := []BunkerWebInventoryMember{m}
			reports := []BunkerWebInventoryReport{r}
			change(&ctx, &members, &reports)
			assertInvalidInventory(t, ctx, members, reports)
		})
	}
}

func TestBunkerWebInventoryRejectedReportsPreserveOnlyTrustedFields(t *testing.T) {
	changes := map[string]func(*BunkerWebPresenceSnapshot){
		"scope":         func(s *BunkerWebPresenceSnapshot) { s.Scope.Ref = "other" },
		"policy":        func(s *BunkerWebPresenceSnapshot) { s.Policy.Ref = "other" },
		"payload node":  func(s *BunkerWebPresenceSnapshot) { s.Identity.NodeID = "other" },
		"epoch":         func(s *BunkerWebPresenceSnapshot) { s.Identity.Epoch = "other" },
		"collector":     func(s *BunkerWebPresenceSnapshot) { s.CollectorID = "other" },
		"snapshot":      func(s *BunkerWebPresenceSnapshot) { s.SnapshotID = "other" },
		"source digest": func(s *BunkerWebPresenceSnapshot) { s.Mode.Source.SHA256 = strings.Repeat("f", 64) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, m, _ := inventoryFixture(t)
			s := presenceFixture(t)
			change(&s)
			data, err := EncodeBunkerWebPresenceSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			reports := []BunkerWebInventoryReport{{Identity: m.Identity, Document: data}}
			out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, reports)
			if err != nil {
				t.Fatal(err)
			}
			e := out.Entries()[0]
			if e.ReportState != Rejected || e.Relevance != "known" || e.CurrentMode != "unknown" || e.Identity != m.Identity || e.KnownRegistration != m.KnownRegistration || e.Registration.Value != "" || e.Mode.Value != "" {
				t.Fatal("unbound fields disclosed", e)
			}
		})
	}
	for _, raw := range []string{"null", `{"schema":"secret.input.example"}`, `{"schema":null}`, ""} {
		c, m, r := inventoryFixture(t)
		r.Document = []byte(raw)
		out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
		if err != nil || out.Relevance() != "known" || out.Entries()[0].ReportState != Rejected || bytes.Contains(out.Manifest(), []byte("secret.input.example")) {
			t.Fatal("malformed report erased history or leaked input", err)
		}
	}
}

func TestBunkerWebInventoryOrderConflictAndCopies(t *testing.T) {
	c, m, r := inventoryFixture(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, r.Document, "", " "); err != nil {
		t.Fatal(err)
	}
	formatted := BunkerWebInventoryReport{Identity: r.Identity, Document: pretty.Bytes()}
	first, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m, m, m}, []BunkerWebInventoryReport{formatted, r, formatted})
	if err != nil || !bytes.Equal(first.Manifest(), repeated.Manifest()) {
		t.Fatal("identical reports or membership inflated inventory", err)
	}
	invalid := BunkerWebInventoryReport{Identity: r.Identity, Document: []byte("null")}
	var previous []byte
	for _, reports := range [][]BunkerWebInventoryReport{{r, invalid, r}, {invalid, r, invalid}, {r, r, invalid}} {
		out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, reports)
		if err != nil {
			t.Fatal(err)
		}
		e := out.Entries()[0]
		if e.ReportState != Rejected || e.Reason != "conflicting_reports" || e.Relevance != "known" || e.Mode.Value != "" || e.Registration.Value != "" {
			t.Fatal("conflicting report chosen", e)
		}
		if previous != nil && !bytes.Equal(previous, out.Manifest()) {
			t.Fatal("arrival order chose result")
		}
		previous = out.Manifest()
	}
}

func TestBunkerWebInventoryBounds(t *testing.T) {
	c, m, r := inventoryFixture(t)
	members := make([]BunkerWebInventoryMember, MaxBunkerWebInventoryInputs)
	for i := range members {
		members[i] = m
	}
	if out, err := ResolveBunkerWebInventory(c, members, nil); err != nil || len(out.Entries()) != 1 {
		t.Fatal("exact input bound rejected", err)
	}
	assertInvalidInventory(t, c, append(members, m), nil)
	unique := make([]BunkerWebInventoryMember, MaxBunkerWebInventoryMembers+1)
	for i := range unique {
		unique[i] = m
		unique[i].Identity.NodeID = fmt.Sprintf("node.%04d", i)
	}
	if out, err := ResolveBunkerWebInventory(c, unique[:MaxBunkerWebInventoryMembers], nil); err != nil || len(out.Entries()) != MaxBunkerWebInventoryMembers {
		t.Fatal("exact member bound rejected", err)
	}
	assertInvalidInventory(t, c, unique, nil)
	reports := make([]BunkerWebInventoryReport, MaxBunkerWebInventoryInputs)
	for i := range reports {
		reports[i] = BunkerWebInventoryReport{Identity: m.Identity, Document: []byte("null")}
	}
	if _, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, reports); err != nil {
		t.Fatal("exact report count rejected", err)
	}
	assertInvalidInventory(t, c, []BunkerWebInventoryMember{m}, append(reports, r))
	r.Document = bytes.Repeat([]byte(" "), MaxDocumentBytes+1)
	assertInvalidInventory(t, c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
	r.Document = r.Document[:MaxDocumentBytes]
	reports = make([]BunkerWebInventoryReport, MaxBunkerWebInventoryBytes/MaxDocumentBytes)
	for i := range reports {
		reports[i] = r
	}
	if _, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, reports); err != nil {
		t.Fatal("exact total bytes rejected", err)
	}
	assertInvalidInventory(t, c, []BunkerWebInventoryMember{m}, append(reports, BunkerWebInventoryReport{Identity: m.Identity, Document: []byte(" ")}))
}

func TestBunkerWebInventorySyntheticFleet(t *testing.T) {
	c, m, _ := inventoryFixture(t)
	members := make([]BunkerWebInventoryMember, 0, 1000)
	reports := make([]BunkerWebInventoryReport, 0, 800)
	for i := 0; i < 500; i++ {
		n := m
		n.Identity.NodeID = fmt.Sprintf("node.simulated.%03d", i)
		s := presenceFixture(t)
		s.Identity = n.Identity
		r := selectInventoryReport(t, &n, s)
		members = append(members, n, n)
		if i < 400 {
			reports = append(reports, r, r)
		}
	}
	out, err := ResolveBunkerWebInventory(c, members, reports)
	if err != nil || len(out.Entries()) != 500 || out.Relevance() != "known" {
		t.Fatal("simulated fleet lost membership", err)
	}
	missing := 0
	for _, e := range out.Entries() {
		if e.ReportState == Missing {
			missing++
		}
		if e.Relevance != "known" {
			t.Fatal("known member hidden")
		}
	}
	if missing != 100 {
		t.Fatal("nonresponding members excluded", missing)
	}
	slices.Reverse(members)
	slices.Reverse(reports)
	again, err := ResolveBunkerWebInventory(c, members, reports)
	if err != nil || !bytes.Equal(out.Manifest(), again.Manifest()) {
		t.Fatal("fleet order changed result", err)
	}
	// A denied member is not silently filtered after it influenced aggregation.
	assertInvalidInventory(t, c, members[:len(members)-2], reports)
}

func FuzzBunkerWebInventoryPermutation(f *testing.F) {
	f.Add([]byte{0, 1, 2, 0, 1})
	f.Add([]byte{2, 2, 1})
	c, m, r := inventoryFixture(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32 {
			return
		}
		inputs := []BunkerWebInventoryReport{r, {Identity: m.Identity, Document: []byte("null")}}
		reports := make([]BunkerWebInventoryReport, 0, len(data))
		for _, b := range data {
			reports = append(reports, inputs[int(b)%len(inputs)])
		}
		out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m, m}, reports)
		if err != nil {
			t.Fatal(err)
		}
		slices.Reverse(reports)
		again, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, reports)
		if err != nil || !bytes.Equal(out.Manifest(), again.Manifest()) {
			t.Fatal("permutation changed result", err)
		}
	})
}

func TestBunkerWebInventoryCurrentContextAndManifestBinding(t *testing.T) {
	c, m, r := inventoryFixture(t)
	base, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	original, err := base.Reference("inventory")
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*BunkerWebInventoryContext){
		"scope":               func(c *BunkerWebInventoryContext) { c.Scope.Ref = "new.scope" },
		"policy":              func(c *BunkerWebInventoryContext) { c.Policy.SHA256 = strings.Repeat("e", 64) },
		"membership":          func(c *BunkerWebInventoryContext) { c.Membership.Ref = "new.membership" },
		"instant":             func(c *BunkerWebInventoryContext) { c.Now = c.Now.Add(time.Second) },
		"report budget":       func(c *BunkerWebInventoryContext) { c.MaxReportAge += time.Second },
		"registration budget": func(c *BunkerWebInventoryContext) { c.MaxRegistrationAge += time.Second },
		"mode budget":         func(c *BunkerWebInventoryContext) { c.MaxModeAge += time.Second },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			next := c
			change(&next)
			out, err := ResolveBunkerWebInventory(next, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
			if err != nil {
				t.Fatal(err)
			}
			ref, err := out.Reference("inventory")
			if err != nil || ref == original {
				t.Fatal("context not bound to manifest", err)
			}
			if (name == "scope" || name == "policy") && out.Entries()[0].ReportState != Rejected {
				t.Fatal("report crossed current scope or policy")
			}
		})
	}
	c.Now = c.Now.Add(-time.Minute)
	future, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
	if err != nil || future.Relevance() != "known" || future.Entries()[0].ReportState != Rejected {
		t.Fatal("future report authorized", err)
	}
}

func TestBunkerWebInventoryRejectsLongRoutingIdentityBeforeIndexing(t *testing.T) {
	c, m, r := inventoryFixture(t)
	r.Identity.NodeID = strings.Repeat("x", MaxIdentifierBytes+1)
	assertInvalidInventory(t, c, []BunkerWebInventoryMember{m}, []BunkerWebInventoryReport{r})
}

func TestBunkerWebInventoryAbsenceRequiresCompleteCurrentEvidence(t *testing.T) {
	c, m, _ := inventoryFixture(t)
	m.KnownRegistration = RateReference{}
	s := presenceFixture(t)
	s.Registration.Value = "absent"
	s.Mode = InventoryClassification{State: Unavailable}
	r := selectInventoryReport(t, &m, s)
	other := m
	other.Identity.NodeID = "node.other"
	out, err := ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m, other}, []BunkerWebInventoryReport{r})
	if err != nil || out.Relevance() != "unknown" || len(out.Entries()) != 2 {
		t.Fatal("responding nodes became complete inventory", err)
	}
	s.Identity = other.Identity
	second := selectInventoryReport(t, &other, s)
	out, err = ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m, other}, []BunkerWebInventoryReport{r, second})
	if err != nil || out.Relevance() != "absent" {
		t.Fatal("current complete absence rejected", err)
	}
	c.Now = c.Now.Add(time.Hour)
	out, err = ResolveBunkerWebInventory(c, []BunkerWebInventoryMember{m, other}, []BunkerWebInventoryReport{r, second})
	if err != nil || out.Relevance() != "unknown" {
		t.Fatal("expired absence remained current", err)
	}
}

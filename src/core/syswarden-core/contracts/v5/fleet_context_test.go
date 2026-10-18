package v5

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func fleetContextFixture(t testing.TB) (FleetContextBinding, NodeExposureInventory, BunkerWebInventory) {
	t.Helper()
	e, em, er := exposureInventoryFixture(t)
	b, bm, br := inventoryFixture(t)
	exposure, err := ResolveNodeExposureInventory(e, []NodeExposureInventoryMember{em}, []NodeExposureInventoryReport{er})
	if err != nil {
		t.Fatal(err)
	}
	bunkerWeb, err := ResolveBunkerWebInventory(b, []BunkerWebInventoryMember{bm}, []BunkerWebInventoryReport{br})
	if err != nil {
		t.Fatal(err)
	}
	return FleetContextBinding{Exposure: e, BunkerWeb: b}, exposure, bunkerWeb
}

func requireInvalidFleetContext(t testing.TB, binding FleetContextBinding, e NodeExposureInventory, b BunkerWebInventory) {
	t.Helper()
	f, err := ComposeFleetContext(binding, e, b)
	if !errors.Is(err, ErrInvalidFleetContext) || f.Manifest() != nil {
		t.Fatal("invalid composition returned data", err)
	}
	if ref, err := f.Reference("invalid"); err == nil || ref != (RateReference{}) {
		t.Fatal("invalid composition referenced")
	}
	if v, err := f.Select("all"); err == nil || v.Entries() != nil || v.Manifest() != nil || v.Group() != "" || v.BunkerWebRelevance() != "" {
		t.Fatal("invalid composition selected")
	}
}

func TestFleetContextGoldenAndDefensiveCopies(t *testing.T) {
	c, e, b := fleetContextFixture(t)
	f, err := ComposeFleetContext(c, e, b)
	if err != nil || !bytes.Equal(f.Manifest(), fixture(t, "fleet-context.json")) {
		t.Fatal("golden fleet context differs", err)
	}
	ref, err := f.Reference("fleet.fixture.1")
	if err != nil || ref.SHA256 != strings.TrimSpace(string(fixture(t, "fleet-context-digest.txt"))) {
		t.Fatal("independent context digest differs", err)
	}
	v, err := f.Select("external")
	if err != nil || !bytes.Equal(v.Manifest(), fixture(t, "fleet-context-external.json")) {
		t.Fatal("golden external view differs", err)
	}
	ref, err = v.Reference("view.fixture.1")
	if err != nil || ref.SHA256 != strings.TrimSpace(string(fixture(t, "fleet-context-external-digest.txt"))) {
		t.Fatal("independent view digest differs", err)
	}
	entries := v.Entries()
	if len(entries) != 1 || entries[0].Exposure != e.Entries()[0] || entries[0].BunkerWeb != b.Entries()[0] {
		t.Fatal("composition changed an assessment")
	}
	entries[0].Exposure.Group = "internal"
	entries[0].BunkerWeb.Relevance = "absent"
	v.Manifest()[0] = 'X'
	f.Manifest()[0] = 'X'
	e.Entries()[0].Group = "internal"
	b.Entries()[0].Relevance = "absent"
	if v.Entries()[0].Exposure.Group != "external" || v.BunkerWebRelevance() != "known" || v.Manifest()[0] != '{' || f.Manifest()[0] != '{' {
		t.Fatal("caller mutated a context or view")
	}
	for _, group := range []string{"", "External", "unknown", "../all"} {
		bad, err := f.Select(group)
		if !errors.Is(err, ErrInvalidFleetContext) || bad.Entries() != nil || bad.Manifest() != nil || bad.Group() != "" || bad.BunkerWebRelevance() != "" {
			t.Fatal("invalid selection fell back or disclosed fields", group, err)
		}
	}
	if ref, err := f.Reference(""); err == nil || ref != (RateReference{}) {
		t.Fatal("invalid context reference accepted")
	}
	if ref, err := v.Reference(""); err == nil || ref != (RateReference{}) {
		t.Fatal("invalid view reference accepted")
	}
	if ref, err := (FleetContextView{}).Reference("zero"); err == nil || ref != (RateReference{}) {
		t.Fatal("uninitialized view reference accepted")
	}
}

func TestFleetContextBindsEveryExpectedContextField(t *testing.T) {
	changes := map[string]func(*FleetContextBinding){
		"exposure scope ref":              func(c *FleetContextBinding) { c.Exposure.Scope.Ref = "other" },
		"exposure scope digest":           func(c *FleetContextBinding) { c.Exposure.Scope.SHA256 = strings.Repeat("f", 64) },
		"exposure membership ref":         func(c *FleetContextBinding) { c.Exposure.Membership.Ref = "other" },
		"exposure membership digest":      func(c *FleetContextBinding) { c.Exposure.Membership.SHA256 = strings.Repeat("a", 64) },
		"exposure policy ref":             func(c *FleetContextBinding) { c.Exposure.Policy.Ref = "other" },
		"exposure policy digest":          func(c *FleetContextBinding) { c.Exposure.Policy.SHA256 = strings.Repeat("f", 64) },
		"exposure time":                   func(c *FleetContextBinding) { c.Exposure.Now = c.Exposure.Now.Add(time.Nanosecond) },
		"exposure report budget":          func(c *FleetContextBinding) { c.Exposure.MaxReportAge += time.Second },
		"exposure classification budget":  func(c *FleetContextBinding) { c.Exposure.MaxClassificationAge += time.Second },
		"integration scope ref":           func(c *FleetContextBinding) { c.BunkerWeb.Scope.Ref = "other" },
		"integration scope digest":        func(c *FleetContextBinding) { c.BunkerWeb.Scope.SHA256 = strings.Repeat("f", 64) },
		"integration membership ref":      func(c *FleetContextBinding) { c.BunkerWeb.Membership.Ref = "other" },
		"integration membership digest":   func(c *FleetContextBinding) { c.BunkerWeb.Membership.SHA256 = strings.Repeat("a", 64) },
		"integration policy ref":          func(c *FleetContextBinding) { c.BunkerWeb.Policy.Ref = "other" },
		"integration policy digest":       func(c *FleetContextBinding) { c.BunkerWeb.Policy.SHA256 = strings.Repeat("f", 64) },
		"integration time":                func(c *FleetContextBinding) { c.BunkerWeb.Now = c.BunkerWeb.Now.Add(time.Nanosecond) },
		"integration report budget":       func(c *FleetContextBinding) { c.BunkerWeb.MaxReportAge += time.Second },
		"integration registration budget": func(c *FleetContextBinding) { c.BunkerWeb.MaxRegistrationAge += time.Second },
		"integration mode budget":         func(c *FleetContextBinding) { c.BunkerWeb.MaxModeAge += time.Second },
		"invalid zero clock":              func(c *FleetContextBinding) { c.Exposure.Now = time.Time{} },
		"invalid report budget":           func(c *FleetContextBinding) { c.BunkerWeb.MaxReportAge = 0 },
		"excess classification budget":    func(c *FleetContextBinding) { c.Exposure.MaxClassificationAge = MaxSnapshotLifetime + 1 },
		"both scopes changed":             func(c *FleetContextBinding) { c.Exposure.Scope.Ref = "revoked"; c.BunkerWeb.Scope = c.Exposure.Scope },
		"both clocks advanced": func(c *FleetContextBinding) {
			c.Exposure.Now = c.Exposure.Now.Add(time.Second)
			c.BunkerWeb.Now = c.Exposure.Now
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, e, b := fleetContextFixture(t)
			change(&c)
			requireInvalidFleetContext(t, c, e, b)
		})
	}
	c, e, b := fleetContextFixture(t)
	requireInvalidFleetContext(t, c, NodeExposureInventory{}, b)
	requireInvalidFleetContext(t, c, e, BunkerWebInventory{})
	c.Exposure.Now = c.Exposure.Now.In(time.FixedZone("fixture", 3600))
	c.BunkerWeb.Now = c.BunkerWeb.Now.In(time.FixedZone("other", -3600))
	f, err := ComposeFleetContext(c, e, b)
	if err != nil || !bytes.Equal(f.Manifest(), fixture(t, "fleet-context.json")) {
		t.Fatal("equivalent instants rejected", err)
	}
}

func TestFleetContextRejectsActualMembershipMismatch(t *testing.T) {
	for _, field := range []string{"cluster", "node", "epoch", "extra", "missing"} {
		t.Run(field, func(t *testing.T) {
			c, e, _ := fleetContextFixture(t)
			_, bm, _ := inventoryFixture(t)
			members := []BunkerWebInventoryMember{bm}
			switch field {
			case "cluster":
				members[0].Identity.ClusterID = "different"
			case "node":
				members[0].Identity.NodeID = "different"
			case "epoch":
				members[0].Identity.Epoch = "different"
			case "extra":
				bm.Identity.NodeID = "extra"
				members = append(members, bm)
			case "missing":
				members = nil
			}
			b, err := ResolveBunkerWebInventory(c.BunkerWeb, members, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Deliberately reuse the same membership reference: actual contents differ.
			requireInvalidFleetContext(t, c, e, b)
		})
	}
}

func TestFleetContextMissingStaleRejectedAndDisabledStayIndependent(t *testing.T) {
	for _, state := range []string{"missing exposure", "stale exposure", "rejected exposure", "missing integration", "stale integration", "rejected integration", "disabled integration"} {
		t.Run(state, func(t *testing.T) {
			ec, em, er := exposureInventoryFixture(t)
			bc, bm, br := inventoryFixture(t)
			ers, brs := []NodeExposureInventoryReport{er}, []BunkerWebInventoryReport{br}
			wantGroup, wantMode := "external", "combined"
			switch state {
			case "missing exposure":
				ers = nil
				wantGroup = "needs_classification"
			case "stale exposure":
				ec.MaxClassificationAge = time.Second
				wantGroup = "needs_classification"
			case "rejected exposure":
				ers[0].Document = []byte("null")
				wantGroup = "needs_classification"
			case "missing integration":
				brs = nil
				wantMode = "unknown"
			case "stale integration":
				bc.MaxModeAge = time.Second
				wantMode = "unknown"
			case "rejected integration":
				brs[0].Document = []byte("null")
				wantMode = "unknown"
			case "disabled integration":
				s := presenceFixture(t)
				s.Mode.Value = "disabled"
				brs[0] = selectInventoryReport(t, &bm, s)
				wantMode = "disabled"
			}
			e, err := ResolveNodeExposureInventory(ec, []NodeExposureInventoryMember{em}, ers)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ResolveBunkerWebInventory(bc, []BunkerWebInventoryMember{bm}, brs)
			if err != nil {
				t.Fatal(err)
			}
			f, err := ComposeFleetContext(FleetContextBinding{Exposure: ec, BunkerWeb: bc}, e, b)
			if err != nil {
				t.Fatal(err)
			}
			v, err := f.Select(wantGroup)
			if err != nil || len(v.Entries()) != 1 || v.BunkerWebRelevance() != "known" || v.Entries()[0].BunkerWeb.CurrentMode != wantMode {
				t.Fatal("one component changed the other's state", err)
			}
			if v.Entries()[0].Exposure != e.Entries()[0] || v.Entries()[0].BunkerWeb != b.Entries()[0] {
				t.Fatal("composition renewed or discarded component evidence")
			}
		})
	}
}

func TestFleetContextEmptyAndDistinctSelections(t *testing.T) {
	c, _, _ := fleetContextFixture(t)
	e, err := ResolveNodeExposureInventory(c.Exposure, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveBunkerWebInventory(c.BunkerWeb, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ComposeFleetContext(c, e, b)
	if err != nil {
		t.Fatal(err)
	}
	previous := map[string]bool{}
	for _, group := range []string{"all", "external", "internal", "needs_classification"} {
		v, err := f.Select(group)
		if err != nil || v.Group() != group || v.Entries() == nil || len(v.Entries()) != 0 || v.BunkerWebRelevance() != "absent" {
			t.Fatal("empty authorized selection lost", err)
		}
		ref, err := v.Reference("view")
		if err != nil || previous[ref.SHA256] {
			t.Fatal("selection omitted from digest", err)
		}
		previous[ref.SHA256] = true
	}
}

func TestFleetContextSyntheticFleetSelectionAndPermutation(t *testing.T) {
	ec, em, _ := exposureInventoryFixture(t)
	bc, bm, _ := inventoryFixture(t)
	var ems []NodeExposureInventoryMember
	var bms []BunkerWebInventoryMember
	var ers []NodeExposureInventoryReport
	var brs []BunkerWebInventoryReport
	for i := 0; i < 500; i++ {
		e, b := em, bm
		e.Identity.NodeID = fmt.Sprintf("node.simulated.%03d", i)
		b.Identity = e.Identity
		es, bs := exposureFixture(t), presenceFixture(t)
		es.Identity, bs.Identity = e.Identity, e.Identity
		b.KnownRegistration = RateReference{}
		if i >= 200 {
			es.Exposure.Value = "internal_only"
		}
		// External has current absence; Internal has retained established history;
		// nonresponders have neither. Global relevance must not leak into a group.
		if i < 200 {
			bs.Registration.Value = "absent"
			bs.Mode = InventoryClassification{State: Unavailable}
		} else if i < 400 {
			b.KnownRegistration = bm.KnownRegistration
		}
		er := selectExposureInventoryReport(t, &e, es)
		br := selectInventoryReport(t, &b, bs)
		ems, bms = append(ems, e, e), append(bms, b, b)
		if i < 400 {
			ers, brs = append(ers, er, er), append(brs, br, br)
		}
	}
	resolve := func() FleetContext {
		e, err := ResolveNodeExposureInventory(ec, ems, ers)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ResolveBunkerWebInventory(bc, bms, brs)
		if err != nil {
			t.Fatal(err)
		}
		f, err := ComposeFleetContext(FleetContextBinding{Exposure: ec, BunkerWeb: bc}, e, b)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f := resolve()
	seen := map[NodeIdentity]bool{}
	for _, tc := range []struct {
		group, relevance string
		size             int
	}{{"external", "absent", 200}, {"internal", "known", 200}, {"needs_classification", "unknown", 100}, {"all", "known", 500}} {
		v, err := f.Select(tc.group)
		if err != nil || len(v.Entries()) != tc.size || v.BunkerWebRelevance() != tc.relevance {
			t.Fatal("wrong selected relevance/population", tc.group, err)
		}
		for _, row := range v.Entries() {
			if row.Exposure.Identity != row.BunkerWeb.Identity {
				t.Fatal("identity join mismatch")
			}
			if tc.group != "all" {
				if seen[row.Exposure.Identity] {
					t.Fatal("node counted in multiple groups")
				}
				seen[row.Exposure.Identity] = true
			}
		}
	}
	if len(seen) != 500 {
		t.Fatal("partition lost nodes")
	}
	slices.Reverse(ems)
	slices.Reverse(brs)
	permuted := resolve()
	if !bytes.Equal(f.Manifest(), permuted.Manifest()) {
		t.Fatal("input permutation changed join")
	}
	for _, group := range []string{"all", "external", "internal", "needs_classification"} {
		a, err := f.Select(group)
		if err != nil {
			t.Fatal(err)
		}
		b, err := permuted.Select(group)
		if err != nil || !bytes.Equal(a.Manifest(), b.Manifest()) {
			t.Fatal("permutation changed view", err)
		}
	}
	// A fresh authorized cycle with a complete outage still retains all members.
	ers, brs = nil, nil
	outage := resolve()
	v, err := outage.Select("needs_classification")
	if err != nil || len(v.Entries()) != 500 || v.BunkerWebRelevance() != "known" {
		t.Fatal("outage erased history or nodes", err)
	}
	for _, group := range []string{"external", "internal"} {
		v, err := outage.Select(group)
		if err != nil || len(v.Entries()) != 0 || v.BunkerWebRelevance() != "absent" {
			t.Fatal("outage reused former group", err)
		}
	}
}

func TestFleetContextReclassificationPreservesIntegrationAndBindsSources(t *testing.T) {
	c, e, b := fleetContextFixture(t)
	first, err := ComposeFleetContext(c, e, b)
	if err != nil {
		t.Fatal(err)
	}
	_, em, _ := exposureInventoryFixture(t)
	s := exposureFixture(t)
	s.Exposure.Value = "internal_only"
	s.SnapshotID = "reclassified"
	r := selectExposureInventoryReport(t, &em, s)
	e, err = ResolveNodeExposureInventory(c.Exposure, []NodeExposureInventoryMember{em}, []NodeExposureInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	next, err := ComposeFleetContext(c, e, b)
	if err != nil || bytes.Equal(first.Manifest(), next.Manifest()) {
		t.Fatal("new selection omitted from binding", err)
	}
	internal, err := next.Select("internal")
	if err != nil || len(internal.Entries()) != 1 || internal.Entries()[0].BunkerWeb != b.Entries()[0] {
		t.Fatal("reclassification lost independent integration", err)
	}
	external, err := next.Select("external")
	if err != nil || len(external.Entries()) != 0 || external.BunkerWebRelevance() != "absent" {
		t.Fatal("reclassification retained old group", err)
	}
	// A newly authorized freshness budget binds a different context even when
	// the rows and instant happen to remain identical.
	c.Exposure.MaxClassificationAge += time.Second
	e, err = ResolveNodeExposureInventory(c.Exposure, []NodeExposureInventoryMember{em}, []NodeExposureInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	changedBudget, err := ComposeFleetContext(c, e, b)
	if err != nil || bytes.Equal(next.Manifest(), changedBudget.Manifest()) {
		t.Fatal("component freshness budget omitted from source binding", err)
	}
}

func TestFleetContextAtResolverPopulationCeiling(t *testing.T) {
	c, _, _ := fleetContextFixture(t)
	_, em, _ := exposureInventoryFixture(t)
	_, bm, _ := inventoryFixture(t)
	ems := make([]NodeExposureInventoryMember, MaxNodeExposureInventoryMembers)
	bms := make([]BunkerWebInventoryMember, len(ems))
	for i := range ems {
		ems[i], bms[i] = em, bm
		ems[i].Identity.NodeID = fmt.Sprintf("node.limit.%04d", i)
		bms[i].Identity = ems[i].Identity
	}
	e, err := ResolveNodeExposureInventory(c.Exposure, ems, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveBunkerWebInventory(c.BunkerWeb, bms, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ComposeFleetContext(c, e, b)
	if err != nil || len(f.Manifest()) > MaxFleetContextBytes {
		t.Fatal("valid bounded population rejected", err)
	}
	v, err := f.Select("all")
	if err != nil || len(v.Entries()) != len(ems) || len(v.Manifest()) > MaxFleetContextBytes {
		t.Fatal("bounded selection lost members", err)
	}
}

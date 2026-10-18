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

func fleetStateFixture(t testing.TB) (FleetStateBinding, FleetContext, NodeStateInventory) {
	t.Helper()
	c, e, b := fleetContextFixture(t)
	f, err := ComposeFleetContext(c, e, b)
	if err != nil {
		t.Fatal(err)
	}
	nc, nm, nr := stateInventoryFixture(t)
	n, err := ResolveNodeStateInventory(nc, []NodeStateInventoryMember{nm}, []NodeStateInventoryReport{nr})
	if err != nil {
		t.Fatal(err)
	}
	return FleetStateBinding{Context: c, NodeState: nc}, f, n
}

func requireInvalidFleetState(t testing.TB, c FleetStateBinding, f FleetContext, n NodeStateInventory) {
	t.Helper()
	s, err := ComposeFleetState(c, f, n)
	if !errors.Is(err, ErrInvalidFleetState) || s.Manifest() != nil {
		t.Fatal("invalid composition disclosed data", err)
	}
	if ref, err := s.Reference("invalid"); err == nil || ref != (RateReference{}) {
		t.Fatal("rejected state referenced")
	}
	v, err := s.Select("all")
	if !errors.Is(err, ErrInvalidFleetState) || v.Entries() != nil || v.Manifest() != nil || v.Group() != "" || v.BunkerWebRelevance() != "" {
		t.Fatal("invalid composition selected", err)
	}
}

func TestFleetStateGoldenAndCopies(t *testing.T) {
	c, f, n := fleetStateFixture(t)
	s, err := ComposeFleetState(c, f, n)
	if err != nil || !bytes.Equal(s.Manifest(), fixture(t, "fleet-state.json")) {
		t.Fatal("independent state vector differs", err)
	}
	ref, err := s.Reference("fleet.state.1")
	if err != nil || ref.SHA256 != strings.TrimSpace(string(fixture(t, "fleet-state-digest.txt"))) {
		t.Fatal("independent state digest differs", err)
	}
	v, err := s.Select("external")
	if err != nil || !bytes.Equal(v.Manifest(), fixture(t, "fleet-state-external.json")) {
		t.Fatal("independent selected vector differs", err)
	}
	ref, err = v.Reference("fleet.view.1")
	if err != nil || ref.SHA256 != strings.TrimSpace(string(fixture(t, "fleet-state-external-digest.txt"))) {
		t.Fatal("independent view digest differs", err)
	}
	if v.Entries()[0] != (FleetStateEntry{Context: f.entries[0], NodeState: n.Entries()[0]}) {
		t.Fatal("join changed component observations")
	}
	v.Entries()[0].NodeState.ControlRef.Reported.Value = "changed"
	v.Entries()[0].Context.BunkerWeb.Relevance = "absent"
	v.Manifest()[0], s.Manifest()[0] = 'X', 'X'
	n.Entries()[0].CurrentReachability = "unknown"
	f.Manifest()[0] = 'X'
	again, err := s.Select("external")
	if err != nil || !bytes.Equal(again.Manifest(), fixture(t, "fleet-state-external.json")) || !bytes.Equal(s.Manifest(), fixture(t, "fleet-state.json")) {
		t.Fatal("caller mutated retained state", err)
	}
	for _, group := range []string{"", "External", "unknown", "../all", "all\x00"} {
		out, err := s.Select(group)
		if !errors.Is(err, ErrInvalidFleetState) || out.Entries() != nil || out.Manifest() != nil || out.Group() != "" || out.BunkerWebRelevance() != "" {
			t.Fatal("invalid selection disclosed fields or fell back", group, err)
		}
	}
	for _, bad := range []string{"", "../ref", strings.Repeat("x", 257)} {
		if ref, err := s.Reference(bad); err == nil || ref != (RateReference{}) {
			t.Fatal("invalid state reference accepted")
		}
		if ref, err := v.Reference(bad); err == nil || ref != (RateReference{}) {
			t.Fatal("invalid view reference accepted")
		}
	}
	if ref, err := (FleetStateView{}).Reference("zero"); err == nil || ref != (RateReference{}) {
		t.Fatal("uninitialized view referenced")
	}
}

func TestFleetStateBindsAllExpectedContextFields(t *testing.T) {
	// Enumerate references separately from their digests. Changing all sources
	// together still cannot reinterpret an already evaluated immutable snapshot.
	for _, component := range []string{"exposure", "bunkerweb", "node", "all"} {
		for _, field := range []string{"scope ref", "scope digest", "membership ref", "membership digest", "policy ref", "policy digest", "time", "report budget"} {
			t.Run(component+"/"+field, func(t *testing.T) {
				c, f, n := fleetStateFixture(t)
				change := func(scope, membership, policy *RateReference, now *time.Time, budget *time.Duration) {
					switch field {
					case "scope ref":
						scope.Ref = "changed"
					case "scope digest":
						scope.SHA256 = strings.Repeat("f", 64)
					case "membership ref":
						membership.Ref = "changed"
					case "membership digest":
						membership.SHA256 = strings.Repeat("a", 64)
					case "policy ref":
						policy.Ref = "changed"
					case "policy digest":
						policy.SHA256 = strings.Repeat("a", 64)
					case "time":
						*now = now.Add(time.Nanosecond)
					case "report budget":
						*budget += time.Second
					}
				}
				if component == "exposure" || component == "all" {
					e := &c.Context.Exposure
					change(&e.Scope, &e.Membership, &e.Policy, &e.Now, &e.MaxReportAge)
				}
				if component == "bunkerweb" || component == "all" {
					b := &c.Context.BunkerWeb
					change(&b.Scope, &b.Membership, &b.Policy, &b.Now, &b.MaxReportAge)
				}
				if component == "node" || component == "all" {
					v := &c.NodeState
					change(&v.Scope, &v.Membership, &v.Policy, &v.Now, &v.MaxReportAge)
				}
				requireInvalidFleetState(t, c, f, n)
			})
		}
	}
	for _, change := range []func(*FleetStateBinding){
		func(c *FleetStateBinding) { c.Context.Exposure.MaxClassificationAge += time.Second },
		func(c *FleetStateBinding) { c.Context.BunkerWeb.MaxModeAge += time.Second },
		func(c *FleetStateBinding) { c.Context.BunkerWeb.MaxRegistrationAge += time.Second },
		func(c *FleetStateBinding) { c.NodeState.Now = time.Time{} },
		func(c *FleetStateBinding) { c.NodeState.MaxReportAge = 0 },
		func(c *FleetStateBinding) { c.NodeState.MaxReportAge = MaxSnapshotLifetime + 1 },
	} {
		c, f, n := fleetStateFixture(t)
		change(&c)
		requireInvalidFleetState(t, c, f, n)
	}
	c, f, n := fleetStateFixture(t)
	requireInvalidFleetState(t, c, FleetContext{}, n)
	requireInvalidFleetState(t, c, f, NodeStateInventory{})
	c.Context.Exposure.Now = c.Context.Exposure.Now.In(time.FixedZone("east", 3600))
	c.Context.BunkerWeb.Now = c.Context.BunkerWeb.Now.In(time.FixedZone("west", -3600))
	c.NodeState.Now = c.NodeState.Now.In(time.FixedZone("other", 7200))
	s, err := ComposeFleetState(c, f, n)
	if err != nil || !bytes.Equal(s.Manifest(), fixture(t, "fleet-state.json")) {
		t.Fatal("equivalent instants changed the composition", err)
	}
}

func TestFleetStateRejectsDifferentAuthorizedContextsAndPopulations(t *testing.T) {
	for _, field := range []string{"scope", "policy", "membership", "time", "cluster", "node", "epoch", "extra", "missing"} {
		t.Run(field, func(t *testing.T) {
			c, f, _ := fleetStateFixture(t)
			_, m, _ := stateInventoryFixture(t)
			members := []NodeStateInventoryMember{m}
			switch field {
			case "scope":
				c.NodeState.Scope.Ref = "other"
			case "policy":
				c.NodeState.Policy.Ref = "other"
			case "membership":
				c.NodeState.Membership.Ref = "other"
			case "time":
				c.NodeState.Now = c.NodeState.Now.Add(time.Second)
			case "cluster":
				members[0].Identity.ClusterID = "other"
			case "node":
				members[0].Identity.NodeID = "other"
			case "epoch":
				members[0].Identity.Epoch = "replacement"
			case "extra":
				m.Identity.NodeID = "extra"
				members = append(members, m)
			case "missing":
				members = nil
			}
			// Expected context matches this newly constructed source. Reject its
			// different authority or actual identities, not just a stale pin.
			n, err := ResolveNodeStateInventory(c.NodeState, members, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireInvalidFleetState(t, c, f, n)
		})
	}
}

func TestFleetStateKeepsIndependentNodeEvidence(t *testing.T) {
	for _, state := range []string{"missing", "rejected", "stale", "unreachable", "unknown", "partial", "changed selection"} {
		t.Run(state, func(t *testing.T) {
			c, f, _ := fleetStateFixture(t)
			_, m, r := stateInventoryFixture(t)
			rs := []NodeStateInventoryReport{r}
			s := nodeFixture(t, "node-reachable.json")
			switch state {
			case "missing":
				rs = nil
			case "rejected":
				rs[0].Document = []byte("null")
			case "stale":
				c.NodeState.MaxReportAge = time.Second
			case "unreachable", "unknown":
				s = nodeFixture(t, "node-"+state+".json")
				rs[0] = selectStateInventoryReport(t, &m, s)
			case "partial":
				s.ControlRef.State = Partial
				rs[0] = selectStateInventoryReport(t, &m, s)
			case "changed selection":
				m.Selection.SnapshotID = "new.selection"
			}
			n, err := ResolveNodeStateInventory(c.NodeState, []NodeStateInventoryMember{m}, rs)
			if err != nil {
				t.Fatal(err)
			}
			joined, err := ComposeFleetState(c, f, n)
			if err != nil {
				t.Fatal(err)
			}
			v, err := joined.Select("external")
			if err != nil || len(v.Entries()) != 1 || v.BunkerWebRelevance() != "known" || v.Entries()[0] != (FleetStateEntry{Context: f.entries[0], NodeState: n.Entries()[0]}) {
				t.Fatal("node evidence lost, renewed or reclassified another component", err)
			}
		})
	}
}

func TestFleetStateEmptyAndNewSourceBinding(t *testing.T) {
	c, f, n := fleetStateFixture(t)
	first, err := ComposeFleetState(c, f, n)
	if err != nil {
		t.Fatal(err)
	}
	_, m, r := stateInventoryFixture(t)
	c.NodeState.MaxReportAge += time.Second
	n, err = ResolveNodeStateInventory(c.NodeState, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	next, err := ComposeFleetState(c, f, n)
	if err != nil || bytes.Equal(first.Manifest(), next.Manifest()) || first.entries[0] != next.entries[0] {
		t.Fatal("source freshness budget was omitted or changed observation", err)
	}
	e, err := ResolveNodeExposureInventory(c.Context.Exposure, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveBunkerWebInventory(c.Context.BunkerWeb, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err = ComposeFleetContext(c.Context, e, b)
	if err != nil {
		t.Fatal(err)
	}
	n, err = ResolveNodeStateInventory(c.NodeState, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := ComposeFleetState(c, f, n)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, group := range []string{"all", "external", "internal", "needs_classification"} {
		v, err := empty.Select(group)
		if err != nil || v.Group() != group || v.Entries() == nil || len(v.Entries()) != 0 || v.BunkerWebRelevance() != "absent" {
			t.Fatal("explicit empty population lost", err)
		}
		ref, err := v.Reference("empty")
		if err != nil || seen[ref.SHA256] {
			t.Fatal("empty selection identity lost", err)
		}
		seen[ref.SHA256] = true
	}
}

func TestFleetStateContextChangesPreserveNodeEvidence(t *testing.T) {
	for _, state := range []string{"missing exposure", "rejected exposure", "stale exposure", "internal", "missing integration", "stale integration", "disabled integration"} {
		t.Run(state, func(t *testing.T) {
			c, _, n := fleetStateFixture(t)
			_, em, er := exposureInventoryFixture(t)
			_, bm, br := inventoryFixture(t)
			ers, brs := []NodeExposureInventoryReport{er}, []BunkerWebInventoryReport{br}
			wantGroup, wantMode := "external", "combined"
			switch state {
			case "missing exposure":
				ers = nil
				wantGroup = "needs_classification"
			case "rejected exposure":
				ers[0].Document = []byte("null")
				wantGroup = "needs_classification"
			case "stale exposure":
				c.Context.Exposure.MaxClassificationAge = time.Second
				wantGroup = "needs_classification"
			case "internal":
				s := exposureFixture(t)
				s.Exposure.Value = "internal_only"
				ers[0] = selectExposureInventoryReport(t, &em, s)
				wantGroup = "internal"
			case "missing integration":
				brs = nil
				wantMode = "unknown"
			case "stale integration":
				c.Context.BunkerWeb.MaxModeAge = time.Second
				wantMode = "unknown"
			case "disabled integration":
				s := presenceFixture(t)
				s.Mode.Value = "disabled"
				brs[0] = selectInventoryReport(t, &bm, s)
				wantMode = "disabled"
			}
			e, err := ResolveNodeExposureInventory(c.Context.Exposure, []NodeExposureInventoryMember{em}, ers)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ResolveBunkerWebInventory(c.Context.BunkerWeb, []BunkerWebInventoryMember{bm}, brs)
			if err != nil {
				t.Fatal(err)
			}
			f, err := ComposeFleetContext(c.Context, e, b)
			if err != nil {
				t.Fatal(err)
			}
			s, err := ComposeFleetState(c, f, n)
			if err != nil {
				t.Fatal(err)
			}
			v, err := s.Select(wantGroup)
			if err != nil || len(v.Entries()) != 1 || v.BunkerWebRelevance() != "known" || v.Entries()[0].Context.BunkerWeb.CurrentMode != wantMode || v.Entries()[0].NodeState != n.Entries()[0] {
				t.Fatal("context changed independent node evidence", err)
			}
			if wantGroup != "external" {
				old, err := s.Select("external")
				if err != nil || len(old.Entries()) != 0 || old.BunkerWebRelevance() != "absent" {
					t.Fatal("former classification retained node state", err)
				}
			}
		})
	}
}

func TestFleetStateAtResolverPopulationCeiling(t *testing.T) {
	c, _, _ := fleetStateFixture(t)
	_, em, _ := exposureInventoryFixture(t)
	_, bm, _ := inventoryFixture(t)
	_, nm, _ := stateInventoryFixture(t)
	ems := make([]NodeExposureInventoryMember, MaxNodeExposureInventoryMembers)
	bms := make([]BunkerWebInventoryMember, len(ems))
	nms := make([]NodeStateInventoryMember, len(ems))
	for i := range ems {
		ems[i], bms[i], nms[i] = em, bm, nm
		ems[i].Identity.NodeID = fmt.Sprintf("node.limit.%04d", i)
		bms[i].Identity, nms[i].Identity = ems[i].Identity, ems[i].Identity
	}
	e, err := ResolveNodeExposureInventory(c.Context.Exposure, ems, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveBunkerWebInventory(c.Context.BunkerWeb, bms, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ResolveNodeStateInventory(c.NodeState, nms, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ComposeFleetContext(c.Context, e, b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ComposeFleetState(c, f, n)
	if err != nil || len(s.Manifest()) > MaxFleetStateBytes {
		t.Fatal("bounded population rejected", err)
	}
	v, err := s.Select("all")
	if err != nil || len(v.Entries()) != len(ems) || len(v.Manifest()) > MaxFleetStateBytes {
		t.Fatal("bounded selection lost membership", err)
	}
}

func TestFleetStateSyntheticFleetAndOutages(t *testing.T) {
	ec, em, _ := exposureInventoryFixture(t)
	bc, bm, _ := inventoryFixture(t)
	nc, nm, _ := stateInventoryFixture(t)
	var ems []NodeExposureInventoryMember
	var bms []BunkerWebInventoryMember
	var nms []NodeStateInventoryMember
	var ers []NodeExposureInventoryReport
	var brs []BunkerWebInventoryReport
	var nrs []NodeStateInventoryReport
	for i := 0; i < 500; i++ {
		e, b, n := em, bm, nm
		e.Identity.NodeID = fmt.Sprintf("node.simulated.%03d", i)
		b.Identity, n.Identity = e.Identity, e.Identity
		es, bs, ns := exposureFixture(t), presenceFixture(t), nodeFixture(t, "node-reachable.json")
		es.Identity, bs.Identity, ns.Identity = e.Identity, e.Identity, e.Identity
		if i >= 200 {
			es.Exposure.Value = "internal_only"
		} else {
			b.KnownRegistration = RateReference{}
			bs.Registration.Value = "absent"
			bs.Mode = InventoryClassification{State: Unavailable}
		}
		if i%2 == 1 {
			ns = nodeFixture(t, "node-unreachable.json")
			ns.Identity = e.Identity
		}
		er := selectExposureInventoryReport(t, &e, es)
		br := selectInventoryReport(t, &b, bs)
		nr := selectStateInventoryReport(t, &n, ns)
		ems, bms, nms = append(ems, e, e), append(bms, b, b), append(nms, n, n)
		if i < 400 {
			ers, brs = append(ers, er), append(brs, br)
		}
		if i < 300 {
			nrs = append(nrs, nr, nr)
		}
	}
	resolve := func() FleetState {
		t.Helper()
		e, err := ResolveNodeExposureInventory(ec, ems, ers)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ResolveBunkerWebInventory(bc, bms, brs)
		if err != nil {
			t.Fatal(err)
		}
		n, err := ResolveNodeStateInventory(nc, nms, nrs)
		if err != nil {
			t.Fatal(err)
		}
		binding := FleetStateBinding{Context: FleetContextBinding{Exposure: ec, BunkerWeb: bc}, NodeState: nc}
		f, err := ComposeFleetContext(binding.Context, e, b)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ComposeFleetState(binding, f, n)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := resolve()
	seen := map[NodeIdentity]bool{}
	for _, tc := range []struct {
		group, relevance string
		size, unknown    int
	}{{"external", "absent", 200, 0}, {"internal", "known", 200, 100}, {"needs_classification", "known", 100, 100}} {
		v, err := first.Select(tc.group)
		if err != nil || len(v.Entries()) != tc.size || v.BunkerWebRelevance() != tc.relevance {
			t.Fatal("wrong selected population or relevance", tc, err)
		}
		unknown := 0
		for _, row := range v.Entries() {
			if seen[row.NodeState.Identity] || row.NodeState.Identity != row.Context.Exposure.Identity || row.NodeState.Identity != row.Context.BunkerWeb.Identity {
				t.Fatal("crossed identities or overlapping groups")
			}
			seen[row.NodeState.Identity] = true
			if row.NodeState.CurrentReachability == "unknown" {
				unknown++
			}
		}
		if unknown != tc.unknown {
			t.Fatal("missing node state hidden or made current")
		}
	}
	if len(seen) != 500 {
		t.Fatal("nonresponders lost")
	}
	slices.Reverse(ems)
	slices.Reverse(brs)
	slices.Reverse(nms)
	slices.Reverse(nrs)
	permuted := resolve()
	if !bytes.Equal(first.Manifest(), permuted.Manifest()) {
		t.Fatal("delivery order changed the join")
	}
	for _, group := range []string{"all", "external", "internal", "needs_classification"} {
		a, err := first.Select(group)
		if err != nil {
			t.Fatal(err)
		}
		b, err := permuted.Select(group)
		if err != nil || !bytes.Equal(a.Manifest(), b.Manifest()) {
			t.Fatal("delivery order changed a selection", err)
		}
	}
	// Node-only loss does not erase independently current exposure or history.
	nrs = nil
	nodeOutage := resolve()
	v, err := nodeOutage.Select("external")
	if err != nil || len(v.Entries()) != 200 || v.BunkerWebRelevance() != "absent" {
		t.Fatal("node outage changed other assessments", err)
	}
	for _, row := range v.Entries() {
		if row.NodeState.ReportState != Missing || row.NodeState.CurrentReachability != "unknown" {
			t.Fatal("outage invented current node state")
		}
	}
	ers, brs = nil, nil
	outage := resolve()
	v, err = outage.Select("needs_classification")
	if err != nil || len(v.Entries()) != 500 || v.BunkerWebRelevance() != "known" {
		t.Fatal("total outage erased nodes or integration history", err)
	}
}

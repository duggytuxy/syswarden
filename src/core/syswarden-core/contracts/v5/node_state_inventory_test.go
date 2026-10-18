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

func stateInventoryFixture(t testing.TB) (NodeStateInventoryContext, NodeStateInventoryMember, NodeStateInventoryReport) {
	t.Helper()
	s := nodeFixture(t, "node-reachable.json")
	ctx := nodeViewContext(t, s)
	c := NodeStateInventoryContext{Scope: RateReference{Ref: "scope.fixture.1", SHA256: strings.Repeat("a", 64)}, Membership: RateReference{Ref: "membership.fixture.1", SHA256: strings.Repeat("f", 64)}, Policy: RateReference{Ref: "policy.fixture.1", SHA256: strings.Repeat("b", 64)}, Now: ctx.ReadContext.Now, MaxReportAge: ctx.ReadContext.MaxAge}
	m := NodeStateInventoryMember{Identity: s.Identity, Selection: NodeStateSelection{SnapshotID: s.SnapshotID, SHA256: ctx.SnapshotSHA256, CollectorID: s.CollectorID}}
	return c, m, NodeStateInventoryReport{Identity: s.Identity, Document: fixture(t, "node-reachable.json")}
}

func selectStateInventoryReport(t testing.TB, m *NodeStateInventoryMember, s NodeSnapshot) NodeStateInventoryReport {
	t.Helper()
	data, err := EncodeNodeSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := NodeSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	m.Selection = NodeStateSelection{SnapshotID: s.SnapshotID, SHA256: hash, CollectorID: s.CollectorID}
	return NodeStateInventoryReport{Identity: m.Identity, Document: data}
}

func invalidStateInventory(t testing.TB, c NodeStateInventoryContext, m []NodeStateInventoryMember, r []NodeStateInventoryReport) {
	t.Helper()
	out, err := ResolveNodeStateInventory(c, m, r)
	if !errors.Is(err, ErrInvalidNodeStateInventory) || out.Entries() != nil || out.Manifest() != nil {
		t.Fatal("invalid inventory disclosed partial data", err)
	}
	if ref, err := out.Reference("rejected"); err == nil || ref != (RateReference{}) {
		t.Fatal("rejected inventory referenced")
	}
}

func TestNodeStateInventoryGoldenAndCopies(t *testing.T) {
	c, m, r := stateInventoryFixture(t)
	out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Manifest(), fixture(t, "node-state-inventory.json")) {
		t.Fatal("independent canonical inventory changed")
	}
	ref, err := out.Reference("inventory.fixture.1")
	if err != nil || ref.SHA256 != strings.TrimSpace(string(fixture(t, "node-state-inventory-digest.txt"))) {
		t.Fatal("independent digest changed", err)
	}
	entries, data := out.Entries(), out.Manifest()
	entries[0].CurrentReachability = "unknown"
	entries[0].ControlRef.Reported.Value = "changed"
	data[0] = 'X'
	r.Document[0] = 'X'
	if out.Entries()[0].CurrentReachability != "reachable" || out.Entries()[0].ControlRef.Reported.Value != "control.fixture.1" || out.Manifest()[0] != '{' {
		t.Fatal("caller changed retained inventory")
	}
	if ref, err := out.Reference(""); err == nil || ref != (RateReference{}) {
		t.Fatal("invalid reference accepted")
	}
}

func TestNodeStateInventoryRetainsNonrespondersAndEmptyPopulation(t *testing.T) {
	c, m, r := stateInventoryFixture(t)
	other := m
	other.Identity.NodeID = "node.missing"
	other.Selection = NodeStateSelection{}
	out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{other, m, m}, []NodeStateInventoryReport{r})
	if err != nil || len(out.Entries()) != 2 {
		t.Fatal("membership lost or counted twice", err)
	}
	e := out.Entries()[1]
	if e.Identity != other.Identity || e.ReportState != Missing || e.Reason != "missing_report" || e.CurrentReachability != "unknown" || e.ControlRef.Reported.Value != "" {
		t.Fatal("missing report invented protection", e)
	}
	empty, err := ResolveNodeStateInventory(c, nil, nil)
	if err != nil || empty.Entries() == nil || len(empty.Entries()) != 0 || !bytes.Contains(empty.Manifest(), []byte(`"entries":[]`)) {
		t.Fatal("explicit empty population failed", err)
	}
	selected, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, nil)
	if err != nil || selected.Entries()[0].Selection != m.Selection || selected.Entries()[0].ReportState != Missing {
		t.Fatal("selected report mistaken for observed report", err)
	}
}

func TestNodeStateInventoryPreservesTransportAndSourceQuality(t *testing.T) {
	for _, name := range []string{"node-reachable.json", "node-unreachable.json", "node-unknown.json"} {
		for _, quality := range []string{Present, Partial, Stale, Missing, Unavailable, Rejected, NotApplicable} {
			for _, expired := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", name, quality, expired), func(t *testing.T) {
					c, m, _ := stateInventoryFixture(t)
					s := nodeFixture(t, name)
					s.ControlRef = Field{State: quality}
					if quality == Present || quality == Partial || quality == Stale {
						s.ControlRef.Value = "control.fixture.1"
					}
					if s.Reachability != "reachable" && (quality == Present || quality == Partial) {
						// An outage cannot promote cached agent facts to current evidence.
						data, err := json.Marshal(s)
						if err != nil {
							t.Fatal(err)
						}
						out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{{Identity: m.Identity, Document: data}})
						if err != nil || out.Entries()[0].ReportState != Rejected || out.Entries()[0].ControlRef.Reported.Value != "" {
							t.Fatal("outage promoted cached source data", err)
						}
						return
					}
					r := selectStateInventoryReport(t, &m, s)
					if expired {
						c.Now = c.Now.Add(time.Minute)
					}
					out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
					if err != nil {
						t.Fatal(err)
					}
					e := out.Entries()[0]
					state, current, wantQuality := Present, s.Reachability, quality
					if expired {
						state, current = Stale, "unknown"
						if s.ControlRef.Value != "" {
							wantQuality = Stale
						}
					}
					if e.ReportState != state || e.CurrentReachability != current || e.Reachability != (Field{State: state, Value: s.Reachability}) || e.ControlRef.Reported != s.ControlRef || e.ControlRef.State != wantQuality {
						t.Fatal("outage or source uncertainty changed", e)
					}
					if e.CollectedAt != s.CollectedAt || e.ValidUntil != s.ValidUntil || e.AgentVersion.Reported != s.AgentVersion || e.ClockQuality.Reported != s.ClockQuality || e.LastSuccessfulContact.Reported != s.LastSuccessfulContact || e.ObservedAt.Reported != s.ObservedAt || e.PolicyRef.Reported != s.PolicyRef || e.IntegrationRef.Reported != s.IntegrationRef {
						t.Fatal("historical fields lost or fabricated")
					}
				})
			}
		}
	}
}

func TestNodeStateInventoryRejectsPayloadWithoutDisclosure(t *testing.T) {
	for _, kind := range []string{"future", "collector", "snapshot", "digest", "node", "epoch", "version", "integration", "unknown field", "duplicate field", "null", "empty", "other schema"} {
		t.Run(kind, func(t *testing.T) {
			c, m, r := stateInventoryFixture(t)
			s := nodeFixture(t, "node-reachable.json")
			switch kind {
			case "future":
				c.Now = c.Now.Add(-time.Minute)
			case "collector":
				m.Selection.CollectorID = "other"
			case "snapshot":
				m.Selection.SnapshotID = "other"
			case "digest":
				m.Selection.SHA256 = strings.Repeat("0", 64)
			case "node":
				s.Identity.NodeID = "other"
			case "epoch":
				s.Identity.Epoch = "other"
			case "version":
				s.AgentVersion.Value = "private-substitution"
			case "integration":
				s.IntegrationRef.Value = "private-substitution"
			}
			data, err := EncodeNodeSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown field":
				data = append([]byte(`{"private":"private-substitution",`), data[1:]...)
			case "duplicate field":
				data = append([]byte(`{"snapshot_id":"private-substitution",`), data[1:]...)
			case "null":
				data = []byte("null")
			case "empty":
				data = nil
			case "other schema":
				data = fixture(t, "bunkerweb-presence.json")
			}
			r.Document = data
			out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
			if err != nil {
				t.Fatal(err)
			}
			e := out.Entries()[0]
			if e.Identity != m.Identity || e.Selection != m.Selection || e.ReportState != Rejected || e.Reason != "report_rejected" || e.CurrentReachability != "unknown" || e.CollectedAt != "" || e.ValidUntil != "" || e.Reachability != (Field{State: Rejected}) {
				t.Fatal("rejected metadata disclosed", e)
			}
			for _, field := range []NodeSnapshotFieldView{e.ControlRef, e.PolicyRef, e.IntegrationRef, e.AgentVersion, e.ClockQuality, e.ObservedAt, e.LastSuccessfulContact} {
				if field != (NodeSnapshotFieldView{State: Rejected, Reported: Field{State: Rejected}}) {
					t.Fatal("rejected payload field disclosed", field)
				}
			}
			if bytes.Contains(out.Manifest(), []byte("private-substitution")) {
				t.Fatal("private payload retained")
			}
		})
	}
}

func TestNodeStateInventoryConflictAndCanonicalDeduplication(t *testing.T) {
	c, m, r := stateInventoryFixture(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, r.Document, "", "  "); err != nil {
		t.Fatal(err)
	}
	formatted := NodeStateInventoryReport{Identity: m.Identity, Document: pretty.Bytes()}
	first, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m, m}, []NodeStateInventoryReport{formatted, r, r})
	if err != nil || !bytes.Equal(first.Manifest(), repeated.Manifest()) {
		t.Fatal("canonical duplicate changed result", err)
	}
	bad := NodeStateInventoryReport{Identity: m.Identity, Document: []byte("null")}
	var previous []byte
	for _, reports := range [][]NodeStateInventoryReport{{r, bad, r}, {bad, r, bad}, {r, r, bad}} {
		out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, reports)
		if err != nil {
			t.Fatal(err)
		}
		e := out.Entries()[0]
		if e.ReportState != Rejected || e.Reason != "conflicting_reports" || e.CurrentReachability != "unknown" || e.ControlRef.Reported.Value != "" {
			t.Fatal("conflict selected by arrival order", e)
		}
		if previous != nil && !bytes.Equal(previous, out.Manifest()) {
			t.Fatal("order changed conflict")
		}
		previous = out.Manifest()
	}
}

func TestNodeStateInventoryNewSelectionAndRevocation(t *testing.T) {
	c, m, old := stateInventoryFixture(t)
	s := nodeFixture(t, "node-unreachable.json")
	s.SnapshotID = "snapshot.new"
	next := selectStateInventoryReport(t, &m, s)
	out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{next})
	if err != nil || out.Entries()[0].CurrentReachability != "unreachable" || out.Entries()[0].Identity != m.Identity {
		t.Fatal("new selection lost", err)
	}
	replay, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{old})
	if err != nil || replay.Entries()[0].ReportState != Rejected {
		t.Fatal("old selection replay accepted", err)
	}
	invalidStateInventory(t, c, nil, []NodeStateInventoryReport{next})
	m.Identity.Epoch = "new.epoch"
	invalidStateInventory(t, c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{next})
}

func TestNodeStateInventorySimulatedFleetOutage(t *testing.T) {
	c, m, _ := stateInventoryFixture(t)
	members := make([]NodeStateInventoryMember, 0, 1000)
	reports := make([]NodeStateInventoryReport, 0, 800)
	for i := 0; i < 500; i++ {
		n := m
		n.Identity.NodeID = fmt.Sprintf("node.simulated.%03d", i)
		s := nodeFixture(t, "node-reachable.json")
		if i%2 == 1 {
			s = nodeFixture(t, "node-unreachable.json")
		}
		s.Identity = n.Identity
		r := selectStateInventoryReport(t, &n, s)
		members = append(members, n, n)
		if i < 400 {
			reports = append(reports, r, r)
		}
	}
	out, err := ResolveNodeStateInventory(c, members, reports)
	if err != nil || len(out.Entries()) != 500 {
		t.Fatal("nonresponders excluded", err)
	}
	observed := map[string]int{}
	for _, e := range out.Entries() {
		observed[e.CurrentReachability]++
	}
	if observed["reachable"] != 200 || observed["unreachable"] != 200 || observed["unknown"] != 100 {
		t.Fatal("transport population changed", observed)
	}
	slices.Reverse(members)
	slices.Reverse(reports)
	again, err := ResolveNodeStateInventory(c, members, reports)
	if err != nil || !bytes.Equal(out.Manifest(), again.Manifest()) {
		t.Fatal("order changed fleet", err)
	}
	absent, err := ResolveNodeStateInventory(c, members, nil)
	if err != nil || len(absent.Entries()) != 500 {
		t.Fatal("total outage hid nodes", err)
	}
	for _, e := range absent.Entries() {
		if e.ReportState != Missing || e.CurrentReachability != "unknown" {
			t.Fatal("outage invented connectivity")
		}
	}
	c.Now = c.Now.Add(time.Minute)
	stale, err := ResolveNodeStateInventory(c, members, reports)
	if err != nil || len(stale.Entries()) != 500 {
		t.Fatal("expired fleet hidden", err)
	}
	for _, e := range stale.Entries() {
		if e.CurrentReachability != "unknown" {
			t.Fatal("expired connection claimed current")
		}
	}
}

func TestNodeStateInventoryRejectsAmbiguousMembershipAndForeignReports(t *testing.T) {
	cases := map[string]func(*NodeStateInventoryContext, *[]NodeStateInventoryMember, *[]NodeStateInventoryReport){
		"scope": func(c *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			c.Scope = RateReference{}
		},
		"policy": func(c *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			c.Policy = RateReference{}
		},
		"membership": func(c *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			c.Membership.SHA256 = ""
		},
		"clock": func(c *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			c.Now = time.Time{}
		},
		"zero report age": func(c *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			c.MaxReportAge = 0
		},
		"excess report age": func(c *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			c.MaxReportAge = MaxSnapshotLifetime + 1
		},
		"partial selection": func(_ *NodeStateInventoryContext, m *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			(*m)[0].Selection.SHA256 = ""
		},
		"invalid member": func(_ *NodeStateInventoryContext, m *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			(*m)[0].Identity.NodeID = ""
		},
		"member epoch conflict": func(_ *NodeStateInventoryContext, m *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			other := (*m)[0]
			other.Identity.Epoch = "other"
			*m = append(*m, other)
		},
		"member selection conflict": func(_ *NodeStateInventoryContext, m *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			other := (*m)[0]
			other.Selection.SnapshotID = "other"
			*m = append(*m, other)
		},
		"unselected report": func(_ *NodeStateInventoryContext, m *[]NodeStateInventoryMember, _ *[]NodeStateInventoryReport) {
			(*m)[0].Selection = NodeStateSelection{}
		},
		"foreign node": func(_ *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, r *[]NodeStateInventoryReport) {
			(*r)[0].Identity.NodeID = "unauthorized"
		},
		"foreign cluster": func(_ *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, r *[]NodeStateInventoryReport) {
			(*r)[0].Identity.ClusterID = "other"
		},
		"old epoch": func(_ *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, r *[]NodeStateInventoryReport) {
			(*r)[0].Identity.Epoch = "old"
		},
		"oversized routing identity": func(_ *NodeStateInventoryContext, _ *[]NodeStateInventoryMember, r *[]NodeStateInventoryReport) {
			(*r)[0].Identity.NodeID = strings.Repeat("x", MaxIdentifierBytes+1)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, m, r := stateInventoryFixture(t)
			members := []NodeStateInventoryMember{m}
			reports := []NodeStateInventoryReport{r}
			change(&c, &members, &reports)
			invalidStateInventory(t, c, members, reports)
		})
	}
}

func TestNodeStateInventoryBounds(t *testing.T) {
	c, m, r := stateInventoryFixture(t)
	members := make([]NodeStateInventoryMember, MaxNodeStateInventoryInputs)
	for i := range members {
		members[i] = m
	}
	if out, err := ResolveNodeStateInventory(c, members, nil); err != nil || len(out.Entries()) != 1 {
		t.Fatal("exact input count rejected", err)
	}
	invalidStateInventory(t, c, append(members, m), nil)
	unique := make([]NodeStateInventoryMember, MaxNodeStateInventoryMembers+1)
	for i := range unique {
		unique[i] = m
		unique[i].Identity.NodeID = fmt.Sprintf("node.%04d", i)
	}
	if out, err := ResolveNodeStateInventory(c, unique[:MaxNodeStateInventoryMembers], nil); err != nil || len(out.Entries()) != MaxNodeStateInventoryMembers {
		t.Fatal("exact unique member limit rejected", err)
	}
	invalidStateInventory(t, c, unique, nil)
	reports := make([]NodeStateInventoryReport, MaxNodeStateInventoryInputs)
	for i := range reports {
		reports[i] = NodeStateInventoryReport{Identity: m.Identity, Document: []byte("null")}
	}
	if _, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, reports); err != nil {
		t.Fatal("exact report count rejected", err)
	}
	invalidStateInventory(t, c, []NodeStateInventoryMember{m}, append(reports, r))
	r.Document = bytes.Repeat([]byte(" "), MaxDocumentBytes+1)
	invalidStateInventory(t, c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
	r.Document = r.Document[:MaxDocumentBytes]
	reports = make([]NodeStateInventoryReport, MaxNodeStateInventoryBytes/MaxDocumentBytes)
	for i := range reports {
		reports[i] = r
	}
	if _, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, reports); err != nil {
		t.Fatal("exact total byte limit rejected", err)
	}
	invalidStateInventory(t, c, []NodeStateInventoryMember{m}, append(reports, NodeStateInventoryReport{Identity: m.Identity, Document: []byte(" ")}))
}

func TestNodeStateInventoryManifestBindsContext(t *testing.T) {
	c, m, r := stateInventoryFixture(t)
	first, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*NodeStateInventoryContext){
		"scope digest":      func(c *NodeStateInventoryContext) { c.Scope.SHA256 = strings.Repeat("c", 64) },
		"policy digest":     func(c *NodeStateInventoryContext) { c.Policy.SHA256 = strings.Repeat("c", 64) },
		"membership digest": func(c *NodeStateInventoryContext) { c.Membership.SHA256 = strings.Repeat("c", 64) },
		"scope":             func(c *NodeStateInventoryContext) { c.Scope.Ref = "new.scope" },
		"policy":            func(c *NodeStateInventoryContext) { c.Policy.Ref = "new.policy" },
		"membership":        func(c *NodeStateInventoryContext) { c.Membership.Ref = "new.membership" },
		"time":              func(c *NodeStateInventoryContext) { c.Now = c.Now.Add(time.Second) },
		"report age":        func(c *NodeStateInventoryContext) { c.MaxReportAge += time.Second },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			ctx := c
			change(&ctx)
			next, err := ResolveNodeStateInventory(ctx, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
			if err != nil || bytes.Equal(first.Manifest(), next.Manifest()) {
				t.Fatal("context omitted from manifest", err)
			}
		})
	}
	// Equivalent UTC instants must not change the manifest.
	c.Now = c.Now.In(time.FixedZone("fixture", 3600))
	same, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
	if err != nil || !bytes.Equal(first.Manifest(), same.Manifest()) {
		t.Fatal("equivalent instant changed manifest", err)
	}
}

func TestNodeStateInventoryBoundsExpandedManifest(t *testing.T) {
	c, _, _ := stateInventoryFixture(t)
	s := nodeFixture(t, "node-reachable.json")
	long := strings.Repeat("x", MaxIdentifierBytes)
	s.Identity.ClusterID, s.Identity.Epoch = long, long
	s.SnapshotID, s.CollectorID = long, long
	for _, field := range []*Field{&s.AgentVersion, &s.PolicyRef, &s.ControlRef, &s.IntegrationRef} {
		field.Value = long
	}
	members := make([]NodeStateInventoryMember, 0, MaxNodeStateInventoryMembers)
	reports := make([]NodeStateInventoryReport, 0, MaxNodeStateInventoryMembers)
	total := 0
	for i := 0; i < MaxNodeStateInventoryMembers; i++ {
		s.Identity.NodeID = fmt.Sprintf("%0128d", i)
		m := NodeStateInventoryMember{Identity: s.Identity}
		r := selectStateInventoryReport(t, &m, s)
		members, reports = append(members, m), append(reports, r)
		total += len(r.Document)
	}
	if total > MaxNodeStateInventoryBytes {
		t.Fatal("fixture exceeded the input budget instead of testing output expansion")
	}
	out, err := ResolveNodeStateInventory(c, members, reports)
	if !errors.Is(err, ErrInvalidNodeStateInventory) || !strings.Contains(err.Error(), "manifest bounds") || out.Entries() != nil || out.Manifest() != nil {
		t.Fatal("expanded output exceeded its budget or disclosed partial inventory", err)
	}
}

func FuzzNodeStateInventoryPermutation(f *testing.F) {
	f.Add([]byte{0, 1, 2, 0, 3})
	f.Add([]byte{2, 2, 1})
	f.Add([]byte{})
	c, m, r := stateInventoryFixture(f)
	other := m
	other.Identity.NodeID = "node.second"
	s := nodeFixture(f, "node-unreachable.json")
	s.Identity = other.Identity
	second := selectStateInventoryReport(f, &other, s)
	inputs := []NodeStateInventoryReport{r, second, {Identity: m.Identity, Document: []byte("null")}, {Identity: other.Identity, Document: []byte("null")}}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32 {
			return
		}
		reports := make([]NodeStateInventoryReport, 0, len(data))
		for _, b := range data {
			reports = append(reports, inputs[int(b)%len(inputs)])
		}
		out, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{m, other, m}, reports)
		if err != nil {
			t.Fatal(err)
		}
		slices.Reverse(reports)
		again, err := ResolveNodeStateInventory(c, []NodeStateInventoryMember{other, m}, reports)
		if err != nil || !bytes.Equal(out.Manifest(), again.Manifest()) {
			t.Fatal("permutation or duplicate changed result", err)
		}
	})
}

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

func exposureInventoryFixture(t testing.TB) (NodeExposureInventoryContext, NodeExposureInventoryMember, NodeExposureInventoryReport) {
	t.Helper()
	s := exposureFixture(t)
	ctx := exposureContext(t, s)
	c := NodeExposureInventoryContext{Scope: s.Scope, Membership: RateReference{Ref: "membership.fixture.1", SHA256: strings.Repeat("f", 64)}, Policy: s.Policy, Now: ctx.Now, MaxReportAge: ctx.MaxReportAge, MaxClassificationAge: ctx.MaxClassificationAge}
	m := NodeExposureInventoryMember{Identity: s.Identity, Selection: NodeExposureSelection{SnapshotID: s.SnapshotID, SHA256: ctx.SnapshotSHA256, CollectorID: s.CollectorID}}
	return c, m, NodeExposureInventoryReport{Identity: s.Identity, Document: fixture(t, "node-exposure.json")}
}

func selectExposureInventoryReport(t testing.TB, m *NodeExposureInventoryMember, s NodeExposureSnapshot) NodeExposureInventoryReport {
	t.Helper()
	data, err := EncodeNodeExposureSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := NodeExposureSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	m.Selection = NodeExposureSelection{SnapshotID: s.SnapshotID, SHA256: hash, CollectorID: s.CollectorID}
	return NodeExposureInventoryReport{Identity: m.Identity, Document: data}
}

func invalidExposureInventory(t testing.TB, c NodeExposureInventoryContext, m []NodeExposureInventoryMember, r []NodeExposureInventoryReport) {
	t.Helper()
	out, err := ResolveNodeExposureInventory(c, m, r)
	if !errors.Is(err, ErrInvalidNodeExposureInventory) || out.Entries() != nil || out.Manifest() != nil {
		t.Fatal("invalid inventory disclosed partial data", err)
	}
	if ref, err := out.Reference("rejected"); err == nil || ref != (RateReference{}) {
		t.Fatal("rejected inventory referenced")
	}
	if entries, err := out.SelectGroup("external"); err == nil || entries != nil {
		t.Fatal("rejected inventory selected")
	}
}

func TestNodeExposureInventoryGoldenAndIndependentCopies(t *testing.T) {
	c, m, r := exposureInventoryFixture(t)
	out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Manifest(), fixture(t, "node-exposure-inventory.json")) {
		t.Fatal("canonical inventory changed")
	}
	ref, err := out.Reference("inventory.fixture.1")
	if err != nil || ref.SHA256 != strings.TrimSpace(string(fixture(t, "node-exposure-inventory-digest.txt"))) {
		t.Fatal("independent golden digest changed", err)
	}
	entries, data := out.Entries(), out.Manifest()
	entries[0].Group = "internal"
	data[0] = 'X'
	r.Document[0] = 'X'
	selected, err := out.SelectGroup("external")
	if err != nil || len(selected) != 1 {
		t.Fatal("valid selection lost", err)
	}
	selected[0].Exposure.Value = "internal_only"
	if out.Entries()[0].Group != "external" || out.Entries()[0].Exposure.Value != "internet_exposed" || out.Manifest()[0] != '{' {
		t.Fatal("caller mutated inventory")
	}
	for _, group := range []string{"internal", "needs_classification"} {
		selected, err := out.SelectGroup(group)
		if err != nil || selected == nil || len(selected) != 0 {
			t.Fatal("valid empty group indistinguishable from invalid selection", err)
		}
	}
	for _, group := range []string{"", "all", "External", "unknown", "../external"} {
		selected, err := out.SelectGroup(group)
		if !errors.Is(err, ErrInvalidNodeExposureInventory) || selected != nil {
			t.Fatal("invalid group accepted", group)
		}
	}
	if ref, err := out.Reference(""); err == nil || ref != (RateReference{}) {
		t.Fatal("invalid reference accepted")
	}
}

func TestNodeExposureInventoryRetainsNonrespondersAndEmptyPopulation(t *testing.T) {
	c, m, r := exposureInventoryFixture(t)
	other := m
	other.Identity.NodeID = "node.missing"
	other.Selection = NodeExposureSelection{}
	out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{other, m, m}, []NodeExposureInventoryReport{r})
	if err != nil || len(out.Entries()) != 2 {
		t.Fatal("nonresponder hidden or duplicate counted", err)
	}
	missing, err := out.SelectGroup("needs_classification")
	if err != nil || len(missing) != 1 || missing[0].Identity != other.Identity || missing[0].ReportState != Missing || missing[0].Reason != "missing_report" {
		t.Fatal("missing node defaulted to Internal or was lost", err)
	}
	empty, err := ResolveNodeExposureInventory(c, nil, nil)
	if err != nil || empty.Entries() == nil || len(empty.Entries()) != 0 || !bytes.Contains(empty.Manifest(), []byte(`"entries":[]`)) {
		t.Fatal("explicit empty membership failed", err)
	}
	if group, err := empty.SelectGroup("external"); err != nil || group == nil || len(group) != 0 {
		t.Fatal("empty authorized population failed", err)
	}
	// A selected but unavailable report also remains visible.
	missingSelected, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, nil)
	if err != nil || missingSelected.Entries()[0].Selection != m.Selection || missingSelected.Entries()[0].Group != "needs_classification" {
		t.Fatal("selection erased or used as exposure", err)
	}
}

func TestNodeExposureInventoryHostingDoesNotSelectTabs(t *testing.T) {
	for _, hosting := range []string{"on_premises", "cloud", "colocation", "unknown"} {
		for exposure, group := range map[string]string{"internet_exposed": "external", "internal_only": "internal", "unknown": "needs_classification"} {
			t.Run(hosting+"/"+exposure, func(t *testing.T) {
				c, m, _ := exposureInventoryFixture(t)
				s := exposureFixture(t)
				s.HostingModel.Value = hosting
				s.Exposure.Value = exposure
				r := selectExposureInventoryReport(t, &m, s)
				out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
				if err != nil || out.Entries()[0].Group != group || out.Entries()[0].HostingModel != s.HostingModel {
					t.Fatal("hosting inferred exposure", err)
				}
				selected, err := out.SelectGroup(group)
				if err != nil || len(selected) != 1 || selected[0] != out.Entries()[0] {
					t.Fatal("group disagrees with global inventory", err)
				}
			})
		}
	}
}

func TestNodeExposureInventoryFreshnessAndMissingEvidence(t *testing.T) {
	for _, kind := range []string{"expired report", "unknown clock", "stale exposure", "missing exposure", "unavailable exposure", "rejected exposure", "old assessment", "stale hosting", "unknown exposure"} {
		t.Run(kind, func(t *testing.T) {
			c, m, _ := exposureInventoryFixture(t)
			s := exposureFixture(t)
			switch kind {
			case "expired report":
				c.Now = c.Now.Add(time.Minute)
			case "unknown clock":
				s.ClockQuality = "unknown"
			case "stale exposure":
				s.Exposure.State = Stale
			case "missing exposure":
				s.Exposure = InventoryClassification{State: Missing}
			case "unavailable exposure":
				s.Exposure = InventoryClassification{State: Unavailable}
			case "rejected exposure":
				s.Exposure = InventoryClassification{State: Rejected}
			case "old assessment":
				c.MaxClassificationAge = time.Minute
			case "stale hosting":
				s.HostingModel.State = Stale
			case "unknown exposure":
				s.Exposure.Value = "unknown"
			}
			r := selectExposureInventoryReport(t, &m, s)
			out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
			if err != nil {
				t.Fatal(err)
			}
			e := out.Entries()[0]
			want := "needs_classification"
			if kind == "stale hosting" {
				want = "external"
			}
			if e.Group != want || e.Exposure.Value != s.Exposure.Value || e.Exposure.Source != s.Exposure.Source || e.Exposure.AssessedAt != s.Exposure.AssessedAt {
				t.Fatal("classification renewed, discarded or inferred", e)
			}
			if kind == "expired report" && e.ReportState != Stale {
				t.Fatal("report expiry lost")
			}
			if kind == "unknown clock" && e.ReportState != Unavailable {
				t.Fatal("unknown clock became trusted")
			}
		})
	}
}

func TestNodeExposureInventoryRejectsAmbiguousMembershipAndForeignReports(t *testing.T) {
	cases := map[string]func(*NodeExposureInventoryContext, *[]NodeExposureInventoryMember, *[]NodeExposureInventoryReport){
		"scope": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.Scope = RateReference{}
		},
		"policy": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.Policy = RateReference{}
		},
		"membership": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.Membership.SHA256 = ""
		},
		"clock": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.Now = time.Time{}
		},
		"zero report age": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.MaxReportAge = 0
		},
		"negative classification age": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.MaxClassificationAge = -1
		},
		"excess report age": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.MaxReportAge = MaxSnapshotLifetime + 1
		},
		"excess classification age": func(c *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			c.MaxClassificationAge = MaxSnapshotLifetime + 1
		},
		"partial selection": func(_ *NodeExposureInventoryContext, m *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			(*m)[0].Selection.SHA256 = ""
		},
		"invalid member": func(_ *NodeExposureInventoryContext, m *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			(*m)[0].Identity.NodeID = ""
		},
		"member epoch conflict": func(_ *NodeExposureInventoryContext, m *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			other := (*m)[0]
			other.Identity.Epoch = "other"
			*m = append(*m, other)
		},
		"member selection conflict": func(_ *NodeExposureInventoryContext, m *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			other := (*m)[0]
			other.Selection.SnapshotID = "other"
			*m = append(*m, other)
		},
		"unselected report": func(_ *NodeExposureInventoryContext, m *[]NodeExposureInventoryMember, _ *[]NodeExposureInventoryReport) {
			(*m)[0].Selection = NodeExposureSelection{}
		},
		"foreign node": func(_ *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, r *[]NodeExposureInventoryReport) {
			(*r)[0].Identity.NodeID = "unauthorized"
		},
		"foreign cluster": func(_ *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, r *[]NodeExposureInventoryReport) {
			(*r)[0].Identity.ClusterID = "other"
		},
		"old epoch": func(_ *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, r *[]NodeExposureInventoryReport) {
			(*r)[0].Identity.Epoch = "old"
		},
		"oversized routing identity": func(_ *NodeExposureInventoryContext, _ *[]NodeExposureInventoryMember, r *[]NodeExposureInventoryReport) {
			(*r)[0].Identity.NodeID = strings.Repeat("x", MaxIdentifierBytes+1)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, m, r := exposureInventoryFixture(t)
			members := []NodeExposureInventoryMember{m}
			reports := []NodeExposureInventoryReport{r}
			change(&c, &members, &reports)
			invalidExposureInventory(t, c, members, reports)
		})
	}
}

func TestNodeExposureInventoryRejectsSelectedPayloadWithoutDisclosingIt(t *testing.T) {
	changes := map[string]func(*NodeExposureInventoryContext, *NodeExposureInventoryMember, *NodeExposureSnapshot){
		"context scope": func(c *NodeExposureInventoryContext, _ *NodeExposureInventoryMember, _ *NodeExposureSnapshot) {
			c.Scope.Ref = "other"
		},
		"context policy": func(c *NodeExposureInventoryContext, _ *NodeExposureInventoryMember, _ *NodeExposureSnapshot) {
			c.Policy.Ref = "other"
		},
		"future report": func(c *NodeExposureInventoryContext, _ *NodeExposureInventoryMember, _ *NodeExposureSnapshot) {
			c.Now = c.Now.Add(-time.Minute)
		},
		"collector": func(_ *NodeExposureInventoryContext, m *NodeExposureInventoryMember, _ *NodeExposureSnapshot) {
			m.Selection.CollectorID = "other"
		},
		"snapshot": func(_ *NodeExposureInventoryContext, m *NodeExposureInventoryMember, _ *NodeExposureSnapshot) {
			m.Selection.SnapshotID = "other"
		},
		"selected digest": func(_ *NodeExposureInventoryContext, m *NodeExposureInventoryMember, _ *NodeExposureSnapshot) {
			m.Selection.SHA256 = strings.Repeat("f", 64)
		},
		"payload node": func(_ *NodeExposureInventoryContext, _ *NodeExposureInventoryMember, s *NodeExposureSnapshot) {
			s.Identity.NodeID = "other"
		},
		"payload exposure": func(_ *NodeExposureInventoryContext, _ *NodeExposureInventoryMember, s *NodeExposureSnapshot) {
			s.Exposure.Value = "internal_only"
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, m, _ := exposureInventoryFixture(t)
			s := exposureFixture(t)
			change(&c, &m, &s)
			data, err := EncodeNodeExposureSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{{Identity: m.Identity, Document: data}})
			if err != nil {
				t.Fatal(err)
			}
			e := out.Entries()[0]
			if e.Identity != m.Identity || e.Selection != m.Selection || e.ReportState != Rejected || e.Group != "needs_classification" || e.Exposure != (InventoryClassification{State: Rejected}) || e.HostingModel != (InventoryClassification{State: Rejected}) {
				t.Fatal("rejected report changed trusted context or disclosed fields", e)
			}
		})
	}
	for _, raw := range []string{"null", "", `{"schema":"sensitive.example"}`, string(fixture(t, "bunkerweb-presence.json"))} {
		c, m, r := exposureInventoryFixture(t)
		r.Document = []byte(raw)
		out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
		if err != nil || out.Entries()[0].ReportState != Rejected || bytes.Contains(out.Manifest(), []byte("sensitive.example")) {
			t.Fatal("malformed or other-schema report disclosed", err)
		}
	}
}

func TestNodeExposureInventoryConflictsAndDeduplicationAreOrderIndependent(t *testing.T) {
	c, m, r := exposureInventoryFixture(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, r.Document, "", "  "); err != nil {
		t.Fatal(err)
	}
	formatted := NodeExposureInventoryReport{Identity: m.Identity, Document: pretty.Bytes()}
	first, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m, m}, []NodeExposureInventoryReport{formatted, r, r})
	if err != nil || !bytes.Equal(first.Manifest(), repeated.Manifest()) {
		t.Fatal("identical input duplicated membership", err)
	}
	bad := NodeExposureInventoryReport{Identity: m.Identity, Document: []byte("null")}
	var previous []byte
	for _, reports := range [][]NodeExposureInventoryReport{{r, bad, r}, {bad, r, bad}, {r, r, bad}} {
		out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, reports)
		if err != nil {
			t.Fatal(err)
		}
		e := out.Entries()[0]
		if e.Group != "needs_classification" || e.ReportState != Rejected || e.Reason != "conflicting_reports" || e.Exposure.Value != "" || e.HostingModel.Value != "" {
			t.Fatal("conflict chosen by arrival order", e)
		}
		if previous != nil && !bytes.Equal(previous, out.Manifest()) {
			t.Fatal("conflict output changed with order")
		}
		previous = out.Manifest()
	}
}

func TestNodeExposureInventoryReclassificationAndRevocation(t *testing.T) {
	c, m, r := exposureInventoryFixture(t)
	initial, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	s := exposureFixture(t)
	s.SnapshotID = "new.assessment"
	s.Exposure.Value = "internal_only"
	next := selectExposureInventoryReport(t, &m, s)
	current, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{next})
	if err != nil || current.Entries()[0].Identity != initial.Entries()[0].Identity {
		t.Fatal("reclassification lost stable identity", err)
	}
	external, err := current.SelectGroup("external")
	if err != nil || len(external) != 0 {
		t.Fatal("old group persisted", err)
	}
	internal, err := current.SelectGroup("internal")
	if err != nil || len(internal) != 1 {
		t.Fatal("new group missing", err)
	}
	replayed, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
	if err != nil || replayed.Entries()[0].ReportState != Rejected {
		t.Fatal("old selection restored after reassessment", err)
	}
	// Current membership excludes the node, even if an old report still arrives.
	invalidExposureInventory(t, c, nil, []NodeExposureInventoryReport{next})
	// A new epoch also cannot consume the previous epoch's report.
	m.Identity.Epoch = "new.epoch"
	invalidExposureInventory(t, c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{next})
}

func TestNodeExposureInventoryBounds(t *testing.T) {
	c, m, r := exposureInventoryFixture(t)
	members := make([]NodeExposureInventoryMember, MaxNodeExposureInventoryInputs)
	for i := range members {
		members[i] = m
	}
	if out, err := ResolveNodeExposureInventory(c, members, nil); err != nil || len(out.Entries()) != 1 {
		t.Fatal("exact input count rejected", err)
	}
	invalidExposureInventory(t, c, append(members, m), nil)
	unique := make([]NodeExposureInventoryMember, MaxNodeExposureInventoryMembers+1)
	for i := range unique {
		unique[i] = m
		unique[i].Identity.NodeID = fmt.Sprintf("node.%04d", i)
	}
	if out, err := ResolveNodeExposureInventory(c, unique[:MaxNodeExposureInventoryMembers], nil); err != nil || len(out.Entries()) != MaxNodeExposureInventoryMembers {
		t.Fatal("exact unique member limit rejected", err)
	}
	invalidExposureInventory(t, c, unique, nil)
	reports := make([]NodeExposureInventoryReport, MaxNodeExposureInventoryInputs)
	for i := range reports {
		reports[i] = NodeExposureInventoryReport{Identity: m.Identity, Document: []byte("null")}
	}
	if _, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, reports); err != nil {
		t.Fatal("exact report count rejected", err)
	}
	invalidExposureInventory(t, c, []NodeExposureInventoryMember{m}, append(reports, r))
	r.Document = bytes.Repeat([]byte(" "), MaxDocumentBytes+1)
	invalidExposureInventory(t, c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
	r.Document = r.Document[:MaxDocumentBytes]
	reports = make([]NodeExposureInventoryReport, MaxNodeExposureInventoryBytes/MaxDocumentBytes)
	for i := range reports {
		reports[i] = r
	}
	if _, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, reports); err != nil {
		t.Fatal("exact total byte limit rejected", err)
	}
	invalidExposureInventory(t, c, []NodeExposureInventoryMember{m}, append(reports, NodeExposureInventoryReport{Identity: m.Identity, Document: []byte(" ")}))
}

func TestNodeExposureInventoryManifestBindsContext(t *testing.T) {
	c, m, r := exposureInventoryFixture(t)
	first, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*NodeExposureInventoryContext){
		"scope":              func(c *NodeExposureInventoryContext) { c.Scope.Ref = "new.scope" },
		"policy":             func(c *NodeExposureInventoryContext) { c.Policy.Ref = "new.policy" },
		"membership":         func(c *NodeExposureInventoryContext) { c.Membership.Ref = "new.membership" },
		"time":               func(c *NodeExposureInventoryContext) { c.Now = c.Now.Add(time.Second) },
		"report age":         func(c *NodeExposureInventoryContext) { c.MaxReportAge += time.Second },
		"classification age": func(c *NodeExposureInventoryContext) { c.MaxClassificationAge += time.Second },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			ctx := c
			change(&ctx)
			next, err := ResolveNodeExposureInventory(ctx, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
			if err != nil || bytes.Equal(first.Manifest(), next.Manifest()) {
				t.Fatal("context omitted from manifest", err)
			}
		})
	}
	// Equivalent UTC instants must not change the manifest.
	c.Now = c.Now.In(time.FixedZone("fixture", 3600))
	same, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m}, []NodeExposureInventoryReport{r})
	if err != nil || !bytes.Equal(first.Manifest(), same.Manifest()) {
		t.Fatal("equivalent instant changed manifest", err)
	}
}

func TestNodeExposureInventorySyntheticFleetPartitions(t *testing.T) {
	c, m, _ := exposureInventoryFixture(t)
	members := make([]NodeExposureInventoryMember, 0, 1000)
	reports := make([]NodeExposureInventoryReport, 0, 800)
	for i := 0; i < 500; i++ {
		n := m
		n.Identity.NodeID = fmt.Sprintf("node.simulated.%03d", i)
		s := exposureFixture(t)
		s.Identity = n.Identity
		if i%2 == 1 {
			s.Exposure.Value = "internal_only"
		}
		if i%3 == 0 {
			s.HostingModel.Value = "cloud"
		}
		r := selectExposureInventoryReport(t, &n, s)
		members = append(members, n, n)
		if i < 400 {
			reports = append(reports, r, r)
		}
	}
	out, err := ResolveNodeExposureInventory(c, members, reports)
	if err != nil || len(out.Entries()) != 500 {
		t.Fatal("complete membership lost", err)
	}
	seen := map[NodeIdentity]bool{}
	for group, want := range map[string]int{"external": 200, "internal": 200, "needs_classification": 100} {
		entries, err := out.SelectGroup(group)
		if err != nil || len(entries) != want {
			t.Fatal("partition mismatch", group, err)
		}
		for _, e := range entries {
			if seen[e.Identity] {
				t.Fatal("node appears in multiple groups")
			}
			seen[e.Identity] = true
		}
	}
	if len(seen) != 500 {
		t.Fatal("global inventory and groups disagree")
	}
	slices.Reverse(members)
	slices.Reverse(reports)
	again, err := ResolveNodeExposureInventory(c, members, reports)
	if err != nil || !bytes.Equal(out.Manifest(), again.Manifest()) {
		t.Fatal("order changed fleet", err)
	}
	invalidExposureInventory(t, c, members[:len(members)-2], reports)
	// Entirely unavailable reports retain the complete population and select no map nodes.
	absent, err := ResolveNodeExposureInventory(c, members, nil)
	if err != nil {
		t.Fatal(err)
	}
	group, err := absent.SelectGroup("needs_classification")
	if err != nil || len(group) != 500 {
		t.Fatal("outage removed inventory", err)
	}
	external, err := absent.SelectGroup("external")
	if err != nil || len(external) != 0 {
		t.Fatal("outage retained map eligibility", err)
	}
}

func FuzzNodeExposureInventoryPermutation(f *testing.F) {
	f.Add([]byte{0, 1, 2, 0, 3})
	f.Add([]byte{2, 2, 1})
	f.Add([]byte{})
	c, m, r := exposureInventoryFixture(f)
	other := m
	other.Identity.NodeID = "node.second"
	s := exposureFixture(f)
	s.Identity = other.Identity
	s.Exposure.Value = "internal_only"
	second := selectExposureInventoryReport(f, &other, s)
	inputs := []NodeExposureInventoryReport{r, second, {Identity: m.Identity, Document: []byte("null")}, {Identity: other.Identity, Document: []byte("null")}}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32 {
			return
		}
		reports := make([]NodeExposureInventoryReport, 0, len(data))
		for _, b := range data {
			reports = append(reports, inputs[int(b)%len(inputs)])
		}
		out, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{m, other, m}, reports)
		if err != nil {
			t.Fatal(err)
		}
		slices.Reverse(reports)
		again, err := ResolveNodeExposureInventory(c, []NodeExposureInventoryMember{other, m}, reports)
		if err != nil || !bytes.Equal(out.Manifest(), again.Manifest()) {
			t.Fatal("permutation or duplicate changed result", err)
		}
	})
}

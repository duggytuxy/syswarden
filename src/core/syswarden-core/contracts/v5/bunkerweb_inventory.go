package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	BunkerWebInventorySchema     = "syswarden.bunkerweb-inventory.v1"
	MaxBunkerWebInventoryMembers = 4096
	MaxBunkerWebInventoryInputs  = 8192
	MaxBunkerWebInventoryBytes   = 8 * 1024 * 1024
)

var ErrInvalidBunkerWebInventory = errors.New("invalid BunkerWeb inventory")

// BunkerWebInventoryContext pins a complete independently authorized membership,
// report-selection policy and measurement instant. The caller must authenticate
// that membership and its contents before calling ResolveBunkerWebInventory.
// The supplied reference is byte identity, not proof of completeness or authority.
type BunkerWebInventoryContext struct {
	Scope              RateReference
	Membership         RateReference
	Policy             RateReference
	Now                time.Time
	MaxReportAge       time.Duration
	MaxRegistrationAge time.Duration
	MaxModeAge         time.Duration
}

func (c BunkerWebInventoryContext) validate() bool {
	return c.Scope.validate() && c.Membership.validate() && c.Policy.validate() &&
		timestamp(c.Now.UTC().Format(time.RFC3339Nano)) &&
		c.MaxReportAge > 0 && c.MaxReportAge <= MaxSnapshotLifetime &&
		c.MaxRegistrationAge > 0 && c.MaxRegistrationAge <= MaxSnapshotLifetime &&
		c.MaxModeAge > 0 && c.MaxModeAge <= MaxSnapshotLifetime
}

// BunkerWebPresenceSelection comes from trusted report admission, not from a
// submitted report. Empty means no report has been selected; partial is invalid.
type BunkerWebPresenceSelection struct {
	SnapshotID  string `json:"snapshot_id"`
	SHA256      string `json:"sha256"`
	CollectorID string `json:"collector_id"`
}

func (s BunkerWebPresenceSelection) validate() bool {
	return s == (BunkerWebPresenceSelection{}) ||
		(identifier(s.SnapshotID) && digest(s.SHA256) && identifier(s.CollectorID))
}

// BunkerWebInventoryMember includes nonresponding authorized nodes. A nonempty
// KnownRegistration pins independently retained registration history, never a
// path/event-name inference. Removing it requires a newly authorized membership
// and retirement decision outside this component, not a missing or absent report.
type BunkerWebInventoryMember struct {
	Identity          NodeIdentity
	KnownRegistration RateReference
	Selection         BunkerWebPresenceSelection
}

// BunkerWebInventoryReport is a bounded document routed by independently
// authenticated node identity. Neither this struct nor a document enrolls a node.
// Callers must not modify input slices concurrently with resolution.
type BunkerWebInventoryReport struct {
	Identity NodeIdentity
	Document []byte
}

// BunkerWebInventoryEntry contains only authorized inventory and successfully
// projected report fields. Rejected reports expose no payload values. Retained
// history can keep relevance known without asserting a current configuration.
type BunkerWebInventoryEntry struct {
	Identity          NodeIdentity               `json:"identity"`
	KnownRegistration RateReference              `json:"known_registration"`
	Selection         BunkerWebPresenceSelection `json:"selection"`
	ReportState       string                     `json:"report_state"`
	Relevance         string                     `json:"relevance"`
	CurrentMode       string                     `json:"current_mode"`
	Reason            string                     `json:"reason"`
	Registration      InventoryClassification    `json:"registration"`
	Mode              InventoryClassification    `json:"mode"`
}

type bunkerWebInventoryManifest struct {
	Schema               string                    `json:"schema"`
	Scope                RateReference             `json:"scope"`
	Membership           RateReference             `json:"membership"`
	Policy               RateReference             `json:"policy"`
	AssessedAt           string                    `json:"assessed_at"`
	MaxReportAgeNS       int64                     `json:"max_report_age_ns"`
	MaxRegistrationAgeNS int64                     `json:"max_registration_age_ns"`
	MaxModeAgeNS         int64                     `json:"max_mode_age_ns"`
	Relevance            string                    `json:"relevance"`
	Entries              []BunkerWebInventoryEntry `json:"entries"`
}

// BunkerWebInventory is immutable through this API. Its private manifest is not
// a public endpoint, authenticated export, persistent registry or KPI population.
type BunkerWebInventory struct {
	context   BunkerWebInventoryContext
	entries   []BunkerWebInventoryEntry
	relevance string
	manifest  []byte
}

func (i BunkerWebInventory) Entries() []BunkerWebInventoryEntry { return slices.Clone(i.entries) }
func (i BunkerWebInventory) Relevance() string                  { return i.relevance }
func (i BunkerWebInventory) Manifest() []byte                   { return slices.Clone(i.manifest) }

func (i BunkerWebInventory) Reference(ref string) (RateReference, error) {
	if len(i.manifest) == 0 || !identifier(ref) {
		return RateReference{}, invalidBunkerWebInventory("reference")
	}
	sum := sha256.Sum256(i.manifest)
	return RateReference{Ref: ref, SHA256: hex.EncodeToString(sum[:])}, nil
}

func invalidBunkerWebInventory(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidBunkerWebInventory, field)
}

type bunkerWebInventoryDocumentKey struct {
	identity NodeIdentity
	digest   [sha256.Size]byte
}

type bunkerWebInventoryObservation struct {
	entry    BunkerWebInventoryEntry
	seen     bool
	conflict bool
}

// ResolveBunkerWebInventory retains complete authorized membership, including
// missing, rejected and stale nodes. It never chooses a report by arrival order.
// Foreign identities, changed epochs, conflicting membership and input bounds
// reject the entire result. Malformed/substituted reports for an authorized
// member reject only that member's report and preserve trusted history.
func ResolveBunkerWebInventory(c BunkerWebInventoryContext, members []BunkerWebInventoryMember, reports []BunkerWebInventoryReport) (BunkerWebInventory, error) {
	if !c.validate() || len(members) > MaxBunkerWebInventoryInputs || len(reports) > MaxBunkerWebInventoryInputs {
		return BunkerWebInventory{}, invalidBunkerWebInventory("context or input count")
	}
	indexed := make(map[NodeIdentity]BunkerWebInventoryMember)
	epochs := make(map[[2]string]string)
	for _, m := range members {
		if m.Identity.Validate() != nil || !m.Selection.validate() ||
			(m.KnownRegistration != (RateReference{}) && !m.KnownRegistration.validate()) {
			return BunkerWebInventory{}, invalidBunkerWebInventory("member")
		}
		key := [2]string{m.Identity.ClusterID, m.Identity.NodeID}
		if epoch, exists := epochs[key]; exists && epoch != m.Identity.Epoch {
			return BunkerWebInventory{}, invalidBunkerWebInventory("membership epoch conflict")
		}
		if old, exists := indexed[m.Identity]; exists && old != m {
			return BunkerWebInventory{}, invalidBunkerWebInventory("membership conflict")
		}
		indexed[m.Identity], epochs[key] = m, m.Identity.Epoch
		if len(indexed) > MaxBunkerWebInventoryMembers {
			return BunkerWebInventory{}, invalidBunkerWebInventory("member count")
		}
	}
	total := 0
	for _, r := range reports {
		if r.Identity.Validate() != nil {
			return BunkerWebInventory{}, invalidBunkerWebInventory("report identity")
		}
		m, exists := indexed[r.Identity]
		if !exists || m.Selection == (BunkerWebPresenceSelection{}) {
			return BunkerWebInventory{}, invalidBunkerWebInventory("foreign or unselected report")
		}
		if len(r.Document) > MaxDocumentBytes || len(r.Document) > MaxBunkerWebInventoryBytes-total {
			return BunkerWebInventory{}, invalidBunkerWebInventory("document bounds")
		}
		total += len(r.Document)
	}
	observations := make(map[NodeIdentity]bunkerWebInventoryObservation)
	processed := make(map[bunkerWebInventoryDocumentKey]struct{})
	for _, r := range reports {
		old := observations[r.Identity]
		if old.conflict {
			continue
		}
		// Hash only after validating every routing identity and the total byte budget.
		// Repeated transport bytes need not be parsed again; this grants no authority.
		key := bunkerWebInventoryDocumentKey{identity: r.Identity, digest: sha256.Sum256(r.Document)}
		if _, seen := processed[key]; seen {
			continue
		}
		processed[key] = struct{}{}
		candidate := projectBunkerWebInventoryReport(c, indexed[r.Identity], r.Document)
		if old.seen && old.entry != candidate {
			observations[r.Identity] = bunkerWebInventoryObservation{seen: true, conflict: true,
				entry: unavailableBunkerWebInventoryEntry(indexed[r.Identity], Rejected, "conflicting_reports")}
		} else {
			observations[r.Identity] = bunkerWebInventoryObservation{seen: true, entry: candidate}
		}
	}
	entries := make([]BunkerWebInventoryEntry, 0, len(indexed))
	relevance := "absent"
	for identity, m := range indexed {
		entry := unavailableBunkerWebInventoryEntry(m, Missing, "missing_report")
		if observation := observations[identity]; observation.seen {
			entry = observation.entry
		}
		entries = append(entries, entry)
		relevance = mergeBunkerWebRelevance(relevance, entry.Relevance)
	}
	slices.SortFunc(entries, func(a, b BunkerWebInventoryEntry) int {
		return compareNodeRateFields([3]string{a.Identity.ClusterID, a.Identity.NodeID, a.Identity.Epoch},
			[3]string{b.Identity.ClusterID, b.Identity.NodeID, b.Identity.Epoch})
	})
	manifest := bunkerWebInventoryManifest{Schema: BunkerWebInventorySchema, Scope: c.Scope, Membership: c.Membership,
		Policy: c.Policy, AssessedAt: c.Now.UTC().Format(time.RFC3339Nano),
		MaxReportAgeNS: int64(c.MaxReportAge), MaxRegistrationAgeNS: int64(c.MaxRegistrationAge), MaxModeAgeNS: int64(c.MaxModeAge),
		Relevance: relevance, Entries: entries}
	data, err := json.Marshal(manifest)
	if err != nil || len(data) > MaxBunkerWebInventoryBytes {
		return BunkerWebInventory{}, invalidBunkerWebInventory("manifest bounds")
	}
	c.Now = c.Now.UTC()
	return BunkerWebInventory{context: c, entries: entries, relevance: relevance, manifest: data}, nil
}

func mergeBunkerWebRelevance(current, next string) string {
	if next == "known" || (next == "unknown" && current == "absent") {
		return next
	}
	return current
}

func unavailableBunkerWebInventoryEntry(m BunkerWebInventoryMember, state, reason string) BunkerWebInventoryEntry {
	relevance := "unknown"
	if m.KnownRegistration != (RateReference{}) {
		relevance = "known"
	}
	return BunkerWebInventoryEntry{Identity: m.Identity, KnownRegistration: m.KnownRegistration, Selection: m.Selection,
		ReportState: state, Relevance: relevance, CurrentMode: "unknown", Reason: reason,
		Registration: InventoryClassification{State: state}, Mode: InventoryClassification{State: state}}
}

func projectBunkerWebInventoryReport(c BunkerWebInventoryContext, m BunkerWebInventoryMember, data []byte) BunkerWebInventoryEntry {
	rejected := unavailableBunkerWebInventoryEntry(m, Rejected, "report_rejected")
	s, err := DecodeBunkerWebPresenceSnapshot(data)
	if err != nil {
		return rejected
	}
	view, err := ProjectBunkerWebPresenceSnapshot(s, BunkerWebPresenceReadContext{
		SnapshotID: m.Selection.SnapshotID, SnapshotSHA256: m.Selection.SHA256, CollectorID: m.Selection.CollectorID,
		ExpectedIdentity: m.Identity, Scope: c.Scope, Policy: c.Policy, Now: c.Now, MaxReportAge: c.MaxReportAge,
		MaxRegistrationAge: c.MaxRegistrationAge, MaxModeAge: c.MaxModeAge})
	if err != nil {
		return rejected
	}
	if m.KnownRegistration != (RateReference{}) && view.Relevance == "absent" {
		rejected.Reason = "registration_conflict"
		return rejected
	}
	entry := BunkerWebInventoryEntry{Identity: m.Identity, KnownRegistration: m.KnownRegistration, Selection: m.Selection,
		ReportState: view.ReportState, Relevance: view.Relevance, CurrentMode: view.CurrentMode, Reason: view.Reason,
		Registration: view.Registration, Mode: view.Mode}
	if m.KnownRegistration != (RateReference{}) {
		entry.Relevance = "known"
	}
	return entry
}

package v5

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	FleetContextSchema     = "syswarden.fleet-context.v1"
	FleetContextViewSchema = "syswarden.fleet-context-view.v1"
	MaxFleetContextBytes   = 16 * 1024 * 1024
)

var ErrInvalidFleetContext = errors.New("invalid fleet context")

// FleetContextBinding is independently supplied by the authorized producer.
// It pins both inventories' full contexts, including separate freshness budgets.
// A shared reference alone does not prove membership or grant field permissions.
type FleetContextBinding struct {
	Exposure  NodeExposureInventoryContext
	BunkerWeb BunkerWebInventoryContext
}

// FleetContextEntry retains each component's exact assessment and identity.
// Composition checks both identities, not only the shared membership reference.
type FleetContextEntry struct {
	Exposure  NodeExposureInventoryEntry `json:"exposure"`
	BunkerWeb BunkerWebInventoryEntry    `json:"bunkerweb"`
}

type fleetContextManifest struct {
	Schema          string              `json:"schema"`
	Scope           RateReference       `json:"scope"`
	Membership      RateReference       `json:"membership"`
	Policy          RateReference       `json:"policy"`
	AssessedAt      string              `json:"assessed_at"`
	ExposureSHA256  string              `json:"exposure_sha256"`
	BunkerWebSHA256 string              `json:"bunkerweb_sha256"`
	Entries         []FleetContextEntry `json:"entries"`
}

// FleetContext is an immutable join of two already authorized read models.
// It is not an enrollment registry, health verdict, permission or live cache.
type FleetContext struct {
	entries  []FleetContextEntry
	manifest []byte
}

func (f FleetContext) Manifest() []byte { return slices.Clone(f.manifest) }

func (f FleetContext) Reference(ref string) (RateReference, error) {
	return fleetContextReference(f.manifest, ref)
}

type fleetContextViewManifest struct {
	Schema             string              `json:"schema"`
	ContextSHA256      string              `json:"context_sha256"`
	Group              string              `json:"group"`
	BunkerWebRelevance string              `json:"bunkerweb_relevance"`
	Entries            []FleetContextEntry `json:"entries"`
}

// FleetContextView contains one explicit selection from a single context.
// Relevance is computed only from that selection, never the unselected fleet.
// An empty valid view is not a denial or proof of fleet-wide integration absence.
type FleetContextView struct {
	group     string
	relevance string
	entries   []FleetContextEntry
	manifest  []byte
}

func (v FleetContextView) Group() string                { return v.group }
func (v FleetContextView) BunkerWebRelevance() string   { return v.relevance }
func (v FleetContextView) Entries() []FleetContextEntry { return slices.Clone(v.entries) }
func (v FleetContextView) Manifest() []byte             { return slices.Clone(v.manifest) }
func (v FleetContextView) Reference(ref string) (RateReference, error) {
	return fleetContextReference(v.manifest, ref)
}

func invalidFleetContext(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidFleetContext, field)
}

func fleetContextReference(manifest []byte, ref string) (RateReference, error) {
	if len(manifest) == 0 || !identifier(ref) {
		return RateReference{}, invalidFleetContext("reference")
	}
	return RateReference{Ref: ref, SHA256: nodeRateDigest(manifest)}, nil
}

// ComposeFleetContext rejects different scopes, policies, measurement times,
// budgets or actual identity populations before returning any joined entries.
// The producer must independently authorize and verify all inputs. Inventories
// can only be constructed through their existing bounded resolvers, not decoded
// from submitted manifests. No union, intersection or response-only fallback is
// allowed. A stale observation stays stale; joining does not renew it.
func ComposeFleetContext(binding FleetContextBinding, exposure NodeExposureInventory, bunkerWeb BunkerWebInventory) (FleetContext, error) {
	e, b := binding.Exposure, binding.BunkerWeb
	e.Now, b.Now = e.Now.UTC(), b.Now.UTC()
	if !e.validate() || !b.validate() || e.Scope != b.Scope || e.Membership != b.Membership ||
		e.Policy != b.Policy || !e.Now.Equal(b.Now) {
		return FleetContext{}, invalidFleetContext("incompatible expected contexts")
	}
	if len(exposure.manifest) == 0 || len(bunkerWeb.manifest) == 0 ||
		e != exposure.context || b != bunkerWeb.context {
		return FleetContext{}, invalidFleetContext("inventory context binding")
	}
	if len(exposure.entries) != len(bunkerWeb.entries) {
		return FleetContext{}, invalidFleetContext("membership population")
	}
	// Both resolvers already sort and deduplicate by exact cluster/node/epoch.
	// Check the entire actual population before copying any component fields.
	for i, entry := range exposure.entries {
		if entry.Identity != bunkerWeb.entries[i].Identity {
			return FleetContext{}, invalidFleetContext("membership identity")
		}
	}
	entries := make([]FleetContextEntry, 0, len(exposure.entries))
	for i, entry := range exposure.entries {
		entries = append(entries, FleetContextEntry{Exposure: entry, BunkerWeb: bunkerWeb.entries[i]})
	}
	data, err := json.Marshal(fleetContextManifest{Schema: FleetContextSchema, Scope: e.Scope,
		Membership: e.Membership, Policy: e.Policy, AssessedAt: e.Now.Format(time.RFC3339Nano),
		ExposureSHA256: nodeRateDigest(exposure.manifest), BunkerWebSHA256: nodeRateDigest(bunkerWeb.manifest), Entries: entries})
	if err != nil || len(data) > MaxFleetContextBytes {
		return FleetContext{}, invalidFleetContext("manifest bounds")
	}
	return FleetContext{entries: entries, manifest: data}, nil
}

// Select requires an explicit all, external, internal or needs_classification
// selection. An invalid group never falls back to all. Reauthorize and rebuild
// after scope, policy or time changes before disclosing current results.
func (f FleetContext) Select(group string) (FleetContextView, error) {
	if len(f.manifest) == 0 || !member("all", "external", "internal", "needs_classification")(group) {
		return FleetContextView{}, invalidFleetContext("selection")
	}
	entries := make([]FleetContextEntry, 0)
	relevance := "absent"
	for _, entry := range f.entries {
		if group != "all" && entry.Exposure.Group != group {
			continue
		}
		entries = append(entries, entry)
		relevance = mergeBunkerWebRelevance(relevance, entry.BunkerWeb.Relevance)
	}
	data, err := json.Marshal(fleetContextViewManifest{Schema: FleetContextViewSchema,
		ContextSHA256: nodeRateDigest(f.manifest), Group: group, BunkerWebRelevance: relevance, Entries: entries})
	if err != nil || len(data) > MaxFleetContextBytes {
		return FleetContextView{}, invalidFleetContext("view bounds")
	}
	return FleetContextView{group: group, relevance: relevance, entries: entries, manifest: data}, nil
}

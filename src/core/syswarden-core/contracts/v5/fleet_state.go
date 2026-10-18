package v5

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	FleetStateSchema     = "syswarden.fleet-state.v1"
	FleetStateViewSchema = "syswarden.fleet-state-view.v1"
	MaxFleetStateBytes   = 24 * 1024 * 1024
)

var ErrInvalidFleetState = errors.New("invalid fleet state")

// FleetStateBinding pins independently authorized source contexts. Equal
// references do not authenticate membership, authorize fields or grant access.
type FleetStateBinding struct {
	Context   FleetContextBinding
	NodeState NodeStateInventoryContext
}

// FleetStateEntry preserves independent assessments without deriving a health,
// protection or partner-applied verdict from reachability or integration mode.
type FleetStateEntry struct {
	Context   FleetContextEntry       `json:"context"`
	NodeState NodeStateInventoryEntry `json:"node_state"`
}

type fleetStateManifest struct {
	Schema          string            `json:"schema"`
	Scope           RateReference     `json:"scope"`
	Membership      RateReference     `json:"membership"`
	Policy          RateReference     `json:"policy"`
	AssessedAt      string            `json:"assessed_at"`
	ContextSHA256   string            `json:"context_sha256"`
	NodeStateSHA256 string            `json:"node_state_sha256"`
	Entries         []FleetStateEntry `json:"entries"`
}

// FleetState is an immutable, bounded join. It is not an enrollment registry,
// authorized browser response, live cache or cross-component security verdict.
type FleetState struct {
	entries  []FleetStateEntry
	manifest []byte
}

func (f FleetState) Manifest() []byte { return slices.Clone(f.manifest) }
func (f FleetState) Reference(ref string) (RateReference, error) {
	return fleetStateReference(f.manifest, ref)
}

type fleetStateViewManifest struct {
	Schema             string            `json:"schema"`
	StateSHA256        string            `json:"state_sha256"`
	Group              string            `json:"group"`
	BunkerWebRelevance string            `json:"bunkerweb_relevance"`
	Entries            []FleetStateEntry `json:"entries"`
}

// FleetStateView selects all components together. Missing node reports cannot
// remove members or change their independently assessed exposure or relevance.
type FleetStateView struct {
	group     string
	relevance string
	entries   []FleetStateEntry
	manifest  []byte
}

func (v FleetStateView) Group() string              { return v.group }
func (v FleetStateView) BunkerWebRelevance() string { return v.relevance }
func (v FleetStateView) Entries() []FleetStateEntry { return slices.Clone(v.entries) }
func (v FleetStateView) Manifest() []byte           { return slices.Clone(v.manifest) }
func (v FleetStateView) Reference(ref string) (RateReference, error) {
	return fleetStateReference(v.manifest, ref)
}

func invalidFleetState(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidFleetState, field)
}

func fleetStateReference(manifest []byte, ref string) (RateReference, error) {
	if len(manifest) == 0 || !identifier(ref) {
		return RateReference{}, invalidFleetState("reference")
	}
	return RateReference{Ref: ref, SHA256: nodeRateDigest(manifest)}, nil
}

// ComposeFleetState consumes only constructed typed sources. It checks every
// expected context field, shared authority context and actual identity before
// copying any data. It never intersects populations or renews old observations.
// The producer must reauthorize and rebuild after scope, policy or time changes.
func ComposeFleetState(binding FleetStateBinding, context FleetContext, nodes NodeStateInventory) (FleetState, error) {
	e, b, n := binding.Context.Exposure, binding.Context.BunkerWeb, binding.NodeState
	e.Now, b.Now, n.Now = e.Now.UTC(), b.Now.UTC(), n.Now.UTC()
	if !e.validate() || !b.validate() || !n.validate() ||
		e.Scope != b.Scope || e.Scope != n.Scope || e.Membership != b.Membership || e.Membership != n.Membership ||
		e.Policy != b.Policy || e.Policy != n.Policy || !e.Now.Equal(b.Now) || !e.Now.Equal(n.Now) {
		return FleetState{}, invalidFleetState("incompatible expected contexts")
	}
	if len(context.manifest) == 0 || len(nodes.manifest) == 0 ||
		context.binding != (FleetContextBinding{Exposure: e, BunkerWeb: b}) || nodes.context != n {
		return FleetState{}, invalidFleetState("source context binding")
	}
	if len(context.entries) != len(nodes.entries) {
		return FleetState{}, invalidFleetState("membership population")
	}
	// Upstream resolvers sort by cluster/node/epoch. Check every identity even
	// when independent membership references claim the same population.
	for i, entry := range context.entries {
		if entry.Exposure.Identity != nodes.entries[i].Identity || entry.BunkerWeb.Identity != nodes.entries[i].Identity {
			return FleetState{}, invalidFleetState("membership identity")
		}
	}
	entries := make([]FleetStateEntry, 0, len(context.entries))
	for i, entry := range context.entries {
		entries = append(entries, FleetStateEntry{Context: entry, NodeState: nodes.entries[i]})
	}
	data, err := json.Marshal(fleetStateManifest{Schema: FleetStateSchema, Scope: e.Scope,
		Membership: e.Membership, Policy: e.Policy, AssessedAt: e.Now.Format(time.RFC3339Nano),
		ContextSHA256: nodeRateDigest(context.manifest), NodeStateSHA256: nodeRateDigest(nodes.manifest), Entries: entries})
	if err != nil || len(data) > MaxFleetStateBytes {
		return FleetState{}, invalidFleetState("manifest bounds")
	}
	return FleetState{entries: entries, manifest: data}, nil
}

// Select filters one already authorized complete population. Selection never
// authorizes nodes or fields, falls back to all or infers exposure from an IP.
func (f FleetState) Select(group string) (FleetStateView, error) {
	if len(f.manifest) == 0 || !member("all", "external", "internal", "needs_classification")(group) {
		return FleetStateView{}, invalidFleetState("selection")
	}
	entries := make([]FleetStateEntry, 0)
	relevance := "absent"
	for _, entry := range f.entries {
		if group != "all" && entry.Context.Exposure.Group != group {
			continue
		}
		entries = append(entries, entry)
		relevance = mergeBunkerWebRelevance(relevance, entry.Context.BunkerWeb.Relevance)
	}
	data, err := json.Marshal(fleetStateViewManifest{Schema: FleetStateViewSchema,
		StateSHA256: nodeRateDigest(f.manifest), Group: group, BunkerWebRelevance: relevance, Entries: entries})
	if err != nil || len(data) > MaxFleetStateBytes {
		return FleetStateView{}, invalidFleetState("view bounds")
	}
	return FleetStateView{group: group, relevance: relevance, entries: entries, manifest: data}, nil
}

package v5

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	NodeAdmissionRegistrySchema   = "syswarden.node-admission-registry.v1"
	MaxNodeAdmissionMembers       = 4096
	MaxNodeAdmissionSources       = 16
	MaxNodeAdmissionSlots         = 2
	MaxNodeAdmissionRegistryBytes = 16 * 1024 * 1024
	MaxNodeAdmissionOverlap       = time.Hour
)

var (
	ErrInvalidNodeRegistry         = errors.New("invalid node admission registry")
	ErrInvalidNodeRegistryContext  = errors.New("invalid node registry read context")
	ErrNodeRegistryBindingMismatch = errors.New("node registry does not match the approved snapshot")
	ErrNodeRegistryNotAdmitted     = errors.New("node credential or producer is not admitted")
)

// NodeAdmissionRegistryBinding identifies independently approved membership and
// policy generations. Registry is NOT a hash of the enclosing snapshot, which
// would create a circular reference through the grants.
type NodeAdmissionRegistryBinding struct {
	Registry RateReference `json:"registry"`
	Policy   RateReference `json:"policy"`
}

func (b NodeAdmissionRegistryBinding) validate() bool {
	return b.Registry.validate() && b.Policy.validate()
}

// Admission windows are independent of certificate validity. A predecessor can
// stop being admitted while its signed public certificate is still valid.
type NodeTransportSlot struct {
	Grant      NodeTransportGrant `json:"grant"`
	AdmitFrom  string             `json:"admit_from"`
	AdmitUntil string             `json:"admit_until"`
}

type NodeProducerSlot struct {
	Grant      NodeProducerGrant `json:"grant"`
	AdmitFrom  string            `json:"admit_from"`
	AdmitUntil string            `json:"admit_until"`
}

// NodeAdmissionMember is current bounded working state, not an audit archive.
// Empty slot lists do not infer credentials or reduce membership. Retained
// revoked records consume the same limits and cannot be silently discarded.
type NodeAdmissionMember struct {
	Identity  NodeIdentity        `json:"identity"`
	Status    string              `json:"status"`
	Transport []NodeTransportSlot `json:"transport"`
	Producers []NodeProducerSlot  `json:"producers"`
}

type nodeRegistryManifest struct {
	Schema     string                       `json:"schema"`
	SnapshotID string                       `json:"snapshot_id"`
	Binding    NodeAdmissionRegistryBinding `json:"binding"`
	Members    []NodeAdmissionMember        `json:"members"`
}

type nodeRegistryLocation struct{ member, slot int }

// NodeAdmissionRegistry is an immutable, structurally checked snapshot. It does
// not authenticate its input or establish durable/live membership. Decoding a
// manifest requires an independent pin and never establishes admission authority.
type NodeAdmissionRegistry struct {
	binding   NodeAdmissionRegistryBinding
	reference RateReference
	members   []NodeAdmissionMember
	transport map[string]nodeRegistryLocation
	producers map[string]nodeRegistryLocation
	manifest  []byte
}

func (r NodeAdmissionRegistry) Reference() RateReference { return r.reference }
func (r NodeAdmissionRegistry) Manifest() []byte         { return slices.Clone(r.manifest) }
func (r NodeAdmissionRegistry) Members() []NodeAdmissionMember {
	return cloneNodeAdmissionMembers(r.members)
}

func cloneNodeAdmissionMembers(members []NodeAdmissionMember) []NodeAdmissionMember {
	out := make([]NodeAdmissionMember, len(members))
	for i, m := range members {
		out[i] = m
		out[i].Transport = append([]NodeTransportSlot{}, m.Transport...)
		out[i].Producers = append([]NodeProducerSlot{}, m.Producers...)
	}
	return out
}

func invalidNodeRegistry(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeRegistry, field)
}

// BuildNodeAdmissionRegistry validates the complete candidate before returning
// any usable result. The future protected writer must independently approve its
// exact digest and serialize changes with admissions. Partial lists, plausible
// hashes or a successfully built snapshot are not evidence of authorization.
func BuildNodeAdmissionRegistry(id string, binding NodeAdmissionRegistryBinding, members []NodeAdmissionMember) (NodeAdmissionRegistry, error) {
	if !identifier(id) || !binding.validate() || len(members) > MaxNodeAdmissionMembers {
		return NodeAdmissionRegistry{}, invalidNodeRegistry("binding or member count")
	}
	// Validate bounded individual records and the exact aggregate byte budget
	// before allocating identity/key indexes or copying the full collection.
	if err := preflightNodeRegistry(id, binding, members); err != nil {
		return NodeAdmissionRegistry{}, err
	}
	out := NodeAdmissionRegistry{binding: binding, members: cloneNodeAdmissionMembers(members),
		transport: make(map[string]nodeRegistryLocation), producers: make(map[string]nodeRegistryLocation)}
	slices.SortFunc(out.members, func(a, b NodeAdmissionMember) int {
		if c := strings.Compare(a.Identity.ClusterID, b.Identity.ClusterID); c != 0 {
			return c
		}
		if c := strings.Compare(a.Identity.NodeID, b.Identity.NodeID); c != 0 {
			return c
		}
		return strings.Compare(a.Identity.Epoch, b.Identity.Epoch)
	})
	nodes := make(map[[2]string]struct{})
	keys := make(map[string]struct{})
	certs := make(map[string]struct{})
	producerIDs := make(map[string]struct{})
	for i := range out.members {
		m := &out.members[i]
		node := [2]string{m.Identity.ClusterID, m.Identity.NodeID}
		if !nodeRegistryUnique(nodes, node) {
			return NodeAdmissionRegistry{}, invalidNodeRegistry("duplicate node or mixed epoch")
		}
		slices.SortFunc(m.Transport, func(a, b NodeTransportSlot) int { return strings.Compare(a.Grant.CredentialID, b.Grant.CredentialID) })
		slices.SortFunc(m.Producers, func(a, b NodeProducerSlot) int { return strings.Compare(a.Grant.GrantID, b.Grant.GrantID) })
		for j, s := range m.Transport {
			if _, exists := out.transport[s.Grant.CredentialID]; exists {
				return NodeAdmissionRegistry{}, invalidNodeRegistry("duplicate credential")
			}
			if !nodeRegistryUnique(keys, s.Grant.PublicKeySHA256) || !nodeRegistryUnique(certs, s.Grant.CertificateSHA256) {
				return NodeAdmissionRegistry{}, invalidNodeRegistry("reused key or certificate")
			}
			out.transport[s.Grant.CredentialID] = nodeRegistryLocation{i, j}
		}
		for j, s := range m.Producers {
			if _, exists := out.producers[s.Grant.GrantID]; exists {
				return NodeAdmissionRegistry{}, invalidNodeRegistry("duplicate producer grant")
			}
			if !nodeRegistryUnique(keys, s.Grant.PublicKeySHA256) || !nodeRegistryUnique(producerIDs, s.Grant.KeyID) {
				return NodeAdmissionRegistry{}, invalidNodeRegistry("reused producer key")
			}
			out.producers[s.Grant.GrantID] = nodeRegistryLocation{i, j}
		}
	}
	data, err := json.Marshal(nodeRegistryManifest{NodeAdmissionRegistrySchema, id, binding, out.members})
	if err != nil || len(data) > MaxNodeAdmissionRegistryBytes {
		return NodeAdmissionRegistry{}, invalidNodeRegistry("manifest size")
	}
	out.manifest = data
	out.reference = RateReference{Ref: id, SHA256: nodeBytesSHA256(data)}
	return out, nil
}

func nodeRegistryUnique[T comparable](index map[T]struct{}, key T) bool {
	if _, exists := index[key]; exists {
		return false
	}
	index[key] = struct{}{}
	return true
}

func preflightNodeRegistry(id string, b NodeAdmissionRegistryBinding, members []NodeAdmissionMember) error {
	header, err := json.Marshal(nodeRegistryManifest{NodeAdmissionRegistrySchema, id, b, []NodeAdmissionMember{}})
	if err != nil {
		return invalidNodeRegistry("header")
	}
	total := len(header)
	for i, m := range members {
		if err := validateNodeAdmissionMember(b, m); err != nil {
			return err
		}
		// Normalize empty lists exactly as the final immutable copy does.
		normalized := m
		if normalized.Transport == nil {
			normalized.Transport = []NodeTransportSlot{}
		}
		if normalized.Producers == nil {
			normalized.Producers = []NodeProducerSlot{}
		}
		data, err := json.Marshal(normalized)
		if i > 0 {
			total++
		}
		if err != nil || len(data) > MaxNodeAdmissionRegistryBytes-total {
			return invalidNodeRegistry("aggregate byte budget")
		}
		total += len(data)
	}
	return nil
}

func validateNodeAdmissionMember(b NodeAdmissionRegistryBinding, m NodeAdmissionMember) error {
	if m.Identity.Validate() != nil || !member("active", "revoked")(m.Status) || len(m.Transport) > MaxNodeAdmissionSlots || len(m.Producers) > MaxNodeAdmissionSources*MaxNodeAdmissionSlots {
		return invalidNodeRegistry("member or slot count")
	}
	for _, s := range m.Transport {
		g := s.Grant
		if g.Validate() != nil || g.Identity != m.Identity || g.Registry != b.Registry || g.Policy != b.Policy || !nodeAdmissionWindow(s.AdmitFrom, s.AdmitUntil, g.NotBefore, g.NotAfter) {
			return invalidNodeRegistry("transport slot")
		}
	}
	if m.Status == "active" && len(m.Transport) == 2 {
		a, z := m.Transport[0], m.Transport[1]
		if a.Grant.Status == "active" && z.Grant.Status == "active" && !nodeAdmissionRotation(a.AdmitFrom, a.AdmitUntil, a.Grant.NotBefore, z.AdmitFrom, z.AdmitUntil, z.Grant.NotBefore, 12*time.Hour) {
			return invalidNodeRegistry("transport rotation")
		}
	}
	sources := make(map[string][]NodeProducerSlot)
	for _, s := range m.Producers {
		g := s.Grant
		if g.Validate() != nil || g.Identity != m.Identity || g.Registry != b.Registry || g.Policy != b.Policy || !nodeAdmissionWindow(s.AdmitFrom, s.AdmitUntil, g.NotBefore, g.NotAfter) {
			return invalidNodeRegistry("producer slot")
		}
		prior := sources[g.SourceID]
		if len(prior) >= MaxNodeAdmissionSlots {
			return invalidNodeRegistry("source key count")
		}
		if len(prior) == 1 {
			a := prior[0]
			if a.Grant.PayloadSchema != g.PayloadSchema {
				return invalidNodeRegistry("source schema conflict")
			}
			if m.Status == "active" && a.Grant.Status == "active" && g.Status == "active" && !nodeAdmissionRotation(a.AdmitFrom, a.AdmitUntil, a.Grant.NotBefore, s.AdmitFrom, s.AdmitUntil, g.NotBefore, 15*24*time.Hour) {
				return invalidNodeRegistry("producer rotation")
			}
		}
		sources[g.SourceID] = append(prior, s)
		if len(sources) > MaxNodeAdmissionSources {
			return invalidNodeRegistry("source count")
		}
	}
	return nil
}

func nodeAdmissionWindow(start, end, grantStart, grantEnd string) bool {
	if !timestamp(start) || !timestamp(end) {
		return false
	}
	from, _ := time.Parse(time.RFC3339Nano, start)
	until, _ := time.Parse(time.RFC3339Nano, end)
	low, _ := time.Parse(time.RFC3339Nano, grantStart)
	high, _ := time.Parse(time.RFC3339Nano, grantEnd)
	return until.After(from) && !from.Before(low) && !until.After(high)
}

// A successor must advance time, preserve source/schema scope and honor the
// minimum renewal age. Disjoint windows are allowed; an outage is not healed by
// silently adding a grace period. Approval and proofs of both keys remain external.
func nodeAdmissionRotation(aStart, aEnd, aIssued, bStart, bEnd, bIssued string, minimumAge time.Duration) bool {
	a, _ := time.Parse(time.RFC3339Nano, aStart)
	ae, _ := time.Parse(time.RFC3339Nano, aEnd)
	ai, _ := time.Parse(time.RFC3339Nano, aIssued)
	b, _ := time.Parse(time.RFC3339Nano, bStart)
	be, _ := time.Parse(time.RFC3339Nano, bEnd)
	bi, _ := time.Parse(time.RFC3339Nano, bIssued)
	if b.Before(a) {
		a, b = b, a
		ae, be = be, ae
		ai, bi = bi, ai
	}
	return b.After(a) && be.After(ae) && bi.Sub(ai) >= minimumAge && ae.Sub(b) <= MaxNodeAdmissionOverlap
}

package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

const (
	NodeRatePopulationSchema = "syswarden.node-rate-population.v1"
	MaxNodeRateMembers       = 4096
	MaxNodeRateInputs        = 8192
	MaxNodeRateManifestBytes = 8 * 1024 * 1024
)

var ErrInvalidNodeRatePopulation = errors.New("invalid node rate population")

// NodeRateBasis comes from an independently authenticated producer. Membership
// pins its complete authorized population, not the set of responding agents.
// This component cannot establish the completeness or authority of that input.
type NodeRateBasis struct {
	DefinitionID string        `json:"definition_id"`
	Scope        RateReference `json:"scope"`
	Membership   RateReference `json:"membership"`
	Policy       RateReference `json:"policy"`
	Window       RateWindow    `json:"window"`
	State        string        `json:"state"`
}

func (b NodeRateBasis) validate() bool {
	d, err := LookupRateDefinition(b.DefinitionID)
	return err == nil && d.Population == "nodes" && b.Window.Kind == "snapshot" &&
		b.Window.validate() && b.Scope.validate() && b.Membership.validate() &&
		b.Policy.validate() && member(Present, Partial, Stale)(b.State)
}

// NodeRateBasisSHA256 binds assessments to one exact formula, authorized scope,
// membership generation, policy and measurement instant. It is not a signature.
func NodeRateBasisSHA256(b NodeRateBasis) (string, error) {
	if !b.validate() {
		return "", invalidNodeRatePopulation("basis")
	}
	data, err := json.Marshal(b)
	if err != nil {
		return "", invalidNodeRatePopulation("basis encoding")
	}
	return nodeRateDigest(data), nil
}

// NodeRateMember is supplied by the authorized population resolver. A nonempty
// Exclusion pins a separately reviewed eligibility decision under Basis.Policy.
// Missing reports and transport failures are not exclusion decisions. Duplicate
// group membership is allowed only when the complete member is identical.
type NodeRateMember struct {
	Identity  NodeIdentity  `json:"identity"`
	Exclusion RateReference `json:"exclusion"`
}

// NodeRateAssessment is an already evaluated, independently verified producer
// decision. Part is matched, other, unknown or stale. Evidence pins the exact
// assessment record, not a free-text explanation. The producer must check source
// authentication, policy, freshness and verdict before assigning a part. Neither
// a digest nor a caller-supplied matched value proves protection or conformity.
type NodeRateAssessment struct {
	Identity    NodeIdentity
	BasisSHA256 string
	Part        string
	Evidence    RateReference
}

type nodeRateEvidence struct {
	Part     string        `json:"part"`
	Evidence RateReference `json:"evidence"`
}

type nodeRateEntry struct {
	Identity    NodeIdentity       `json:"identity"`
	Exclusion   RateReference      `json:"exclusion"`
	Part        string             `json:"part"`
	Reason      string             `json:"reason"`
	Assessments []nodeRateEvidence `json:"assessments"`
}

type nodeRateManifest struct {
	Schema           string          `json:"schema"`
	Basis            NodeRateBasis   `json:"basis"`
	BasisSHA256      string          `json:"basis_sha256"`
	DefinitionSHA256 string          `json:"definition_sha256"`
	Counts           RateCounts      `json:"counts"`
	Members          []nodeRateEntry `json:"members"`
}

// NodeRatePopulation is a bounded deterministic result, not an authenticated
// export. Its private manifest contains authorized identities and evidence
// references; access must be reauthorized before disclosure or export.
type NodeRatePopulation struct {
	basis      NodeRateBasis
	identities []NodeIdentity
	manifest   []byte
	counts     RateCounts
}

// Manifest returns an independent copy of canonical compact struct-order JSON.
// No network decoder or trust admission is provided by this component.
func (p NodeRatePopulation) Manifest() []byte { return slices.Clone(p.manifest) }

// Counts returns calculation provenance for the existing rate snapshot codec.
func (p NodeRatePopulation) Counts() RateCounts { return p.counts }

// Reference names the exact generated manifest for RateInputs.Population. The
// identifier comes from the producer; it does not authorize storage or fetching.
func (p NodeRatePopulation) Reference(ref string) (RateReference, error) {
	if len(p.manifest) == 0 || !identifier(ref) {
		return RateReference{}, invalidNodeRatePopulation("manifest reference")
	}
	return RateReference{Ref: ref, SHA256: nodeRateDigest(p.manifest)}, nil
}

func invalidNodeRatePopulation(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeRatePopulation, field)
}

func nodeRateDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ResolveNodeRatePopulation deduplicates already authorized member decisions,
// retains every eligible identity and assembles a canonical partition. It never
// averages percentages, selects a newest assessment or grants response authority.
// Incompatible membership, foreign assessments and excessive inputs return no
// partial population. Differing assessments for one eligible identity produce
// unknown, with all distinct evidence retained, regardless of their arrival order.
func ResolveNodeRatePopulation(basis NodeRateBasis, members []NodeRateMember, assessments []NodeRateAssessment) (NodeRatePopulation, error) {
	if len(members) > MaxNodeRateInputs || len(assessments) > MaxNodeRateInputs {
		return NodeRatePopulation{}, invalidNodeRatePopulation("input budget")
	}
	basisHash, err := NodeRateBasisSHA256(basis)
	if err != nil {
		return NodeRatePopulation{}, err
	}
	population, err := indexNodeRateMembers(members)
	if err != nil {
		return NodeRatePopulation{}, err
	}
	observations := make(map[NodeIdentity]map[nodeRateEvidence]struct{}, len(population))
	for _, assessment := range assessments {
		m, found := population[assessment.Identity]
		if !found || m.Exclusion != (RateReference{}) || assessment.BasisSHA256 != basisHash ||
			!member("matched", "other", "unknown", "stale")(assessment.Part) || !assessment.Evidence.validate() {
			return NodeRatePopulation{}, invalidNodeRatePopulation("assessment binding")
		}
		if observations[m.Identity] == nil {
			observations[m.Identity] = make(map[nodeRateEvidence]struct{})
		}
		observations[m.Identity][nodeRateEvidence{assessment.Part, assessment.Evidence}] = struct{}{}
	}
	entries := make([]nodeRateEntry, 0, len(population))
	for _, m := range population {
		entries = append(entries, resolveNodeRateEntry(m, observations[m.Identity]))
	}
	slices.SortFunc(entries, func(a, b nodeRateEntry) int {
		return compareNodeRateFields([3]string{a.Identity.ClusterID, a.Identity.NodeID, a.Identity.Epoch},
			[3]string{b.Identity.ClusterID, b.Identity.NodeID, b.Identity.Epoch})
	})
	counts := countNodeRateEntries(basis.State, entries)
	definitionHash, err := RateDefinitionSHA256(basis.DefinitionID)
	if err != nil {
		return NodeRatePopulation{}, err
	}
	data, err := json.Marshal(nodeRateManifest{NodeRatePopulationSchema, basis, basisHash, definitionHash, counts, entries})
	if err != nil || len(data) > MaxNodeRateManifestBytes {
		return NodeRatePopulation{}, invalidNodeRatePopulation("manifest encoding budget")
	}
	identities := make([]NodeIdentity, len(entries))
	for i, entry := range entries {
		identities[i] = entry.Identity
	}
	return NodeRatePopulation{basis: basis, identities: identities, manifest: data, counts: counts}, nil
}

func indexNodeRateMembers(members []NodeRateMember) (map[NodeIdentity]NodeRateMember, error) {
	population := make(map[NodeIdentity]NodeRateMember)
	// A snapshot cannot silently count two generations of the same node.
	epochs := make(map[[2]string]string)
	for _, m := range members {
		if m.Identity.Validate() != nil || (m.Exclusion != (RateReference{}) && !m.Exclusion.validate()) {
			return nil, invalidNodeRatePopulation("member")
		}
		key := [2]string{m.Identity.ClusterID, m.Identity.NodeID}
		if epoch, found := epochs[key]; found && epoch != m.Identity.Epoch {
			return nil, invalidNodeRatePopulation("membership epoch conflict")
		}
		if previous, found := population[m.Identity]; found && previous != m {
			return nil, invalidNodeRatePopulation("eligibility conflict")
		}
		population[m.Identity], epochs[key] = m, m.Identity.Epoch
		if len(population) > MaxNodeRateMembers {
			return nil, invalidNodeRatePopulation("member budget")
		}
	}
	return population, nil
}

func compareNodeRateFields(a, b [3]string) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func resolveNodeRateEntry(m NodeRateMember, observations map[nodeRateEvidence]struct{}) nodeRateEntry {
	e := nodeRateEntry{Identity: m.Identity, Exclusion: m.Exclusion, Part: "unknown", Reason: "missing_assessment",
		Assessments: make([]nodeRateEvidence, 0, len(observations))}
	if m.Exclusion != (RateReference{}) {
		e.Part, e.Reason = "excluded", "policy_exclusion"
		return e
	}
	for observation := range observations {
		e.Assessments = append(e.Assessments, observation)
	}
	slices.SortFunc(e.Assessments, func(a, b nodeRateEvidence) int {
		return compareNodeRateFields([3]string{a.Part, a.Evidence.Ref, a.Evidence.SHA256},
			[3]string{b.Part, b.Evidence.Ref, b.Evidence.SHA256})
	})
	switch len(e.Assessments) {
	case 0:
	case 1:
		e.Part, e.Reason = e.Assessments[0].Part, "assessed"
	default:
		e.Reason = "conflicting_assessments"
	}
	return e
}

func countNodeRateEntries(state string, entries []nodeRateEntry) RateCounts {
	counts := make(map[string]int, 5)
	for _, e := range entries {
		counts[e.Part]++
	}
	if state == Present && (counts["unknown"] > 0 || counts["stale"] > 0) {
		state = Partial
	}
	return RateCounts{State: state, Eligible: strconv.Itoa(len(entries) - counts["excluded"]),
		Matched: strconv.Itoa(counts["matched"]), Other: strconv.Itoa(counts["other"]),
		Unknown: strconv.Itoa(counts["unknown"]), Stale: strconv.Itoa(counts["stale"]), Excluded: strconv.Itoa(counts["excluded"])}
}

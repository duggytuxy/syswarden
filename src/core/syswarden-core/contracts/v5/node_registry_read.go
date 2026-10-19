package v5

import "time"

// NodeAdmissionRegistryReadContext is supplied by independently authenticated
// current registry custody, never copied from an uploaded snapshot. Snapshot is
// the complete compiled-content reference, separate from the generation binding.
type NodeAdmissionRegistryReadContext struct {
	Snapshot RateReference
	Binding  NodeAdmissionRegistryBinding
	Now      time.Time
}

func (r NodeAdmissionRegistry) checkContext(c NodeAdmissionRegistryReadContext) error {
	if !c.Snapshot.validate() || !c.Binding.validate() || !timestamp(c.Now.UTC().Format(time.RFC3339Nano)) {
		return ErrInvalidNodeRegistryContext
	}
	if len(r.manifest) == 0 || c.Snapshot != r.reference || c.Binding != r.binding {
		return ErrNodeRegistryBindingMismatch
	}
	return nil
}

func nodeSlotCurrent(status, start, end string, now time.Time) bool {
	from, _ := time.Parse(time.RFC3339Nano, start)
	until, _ := time.Parse(time.RFC3339Nano, end)
	return status == "active" && !now.Before(from) && now.Before(until)
}

// Transport returns an exact record and its pinned per-record context only after
// independently bound snapshot, member, identity and admission-window checks.
// This is not a lease: recheck against current durable authority before use/commit.
func (r NodeAdmissionRegistry) Transport(c NodeAdmissionRegistryReadContext, identity NodeIdentity, credentialID string) (NodeTransportGrant, NodeGrantReadContext, error) {
	if err := r.checkContext(c); err != nil {
		return NodeTransportGrant{}, NodeGrantReadContext{}, err
	}
	if identity.Validate() != nil || !identifier(credentialID) {
		return NodeTransportGrant{}, NodeGrantReadContext{}, ErrInvalidNodeRegistryContext
	}
	loc, exists := r.transport[credentialID]
	if !exists {
		return NodeTransportGrant{}, NodeGrantReadContext{}, ErrNodeRegistryNotAdmitted
	}
	m := r.members[loc.member]
	s := m.Transport[loc.slot]
	if m.Identity != identity || !nodeSlotCurrent(m.Status, s.AdmitFrom, s.AdmitUntil, c.Now) {
		return NodeTransportGrant{}, NodeGrantReadContext{}, ErrNodeRegistryNotAdmitted
	}
	hash, err := NodeTransportGrantSHA256(s.Grant)
	if err != nil {
		return NodeTransportGrant{}, NodeGrantReadContext{}, err
	}
	ctx := NodeGrantReadContext{Record: RateReference{Ref: credentialID, SHA256: hash}, Identity: identity, Registry: r.binding.Registry, Policy: r.binding.Policy, Now: c.Now}
	if err := CheckCurrentNodeTransportGrant(s.Grant, ctx); err != nil {
		return NodeTransportGrant{}, NodeGrantReadContext{}, err
	}
	return s.Grant, ctx, nil
}

// Producer does not infer source permission from the connection identity. It
// requires the separate exact grant/source/schema and current slot. The caller
// must still bind the public key and verify the signed sample and replay state.
func (r NodeAdmissionRegistry) Producer(c NodeAdmissionRegistryReadContext, identity NodeIdentity, grantID, sourceID, payloadSchema string) (NodeProducerGrant, NodeGrantReadContext, error) {
	if err := r.checkContext(c); err != nil {
		return NodeProducerGrant{}, NodeGrantReadContext{}, err
	}
	if identity.Validate() != nil || !identifier(grantID) || !identifier(sourceID) || !identifier(payloadSchema) {
		return NodeProducerGrant{}, NodeGrantReadContext{}, ErrInvalidNodeRegistryContext
	}
	loc, exists := r.producers[grantID]
	if !exists {
		return NodeProducerGrant{}, NodeGrantReadContext{}, ErrNodeRegistryNotAdmitted
	}
	m := r.members[loc.member]
	s := m.Producers[loc.slot]
	if m.Identity != identity || s.Grant.SourceID != sourceID || s.Grant.PayloadSchema != payloadSchema || !nodeSlotCurrent(m.Status, s.AdmitFrom, s.AdmitUntil, c.Now) {
		return NodeProducerGrant{}, NodeGrantReadContext{}, ErrNodeRegistryNotAdmitted
	}
	hash, err := NodeProducerGrantSHA256(s.Grant)
	if err != nil {
		return NodeProducerGrant{}, NodeGrantReadContext{}, err
	}
	ctx := NodeGrantReadContext{Record: RateReference{Ref: grantID, SHA256: hash}, Identity: identity, Registry: r.binding.Registry, Policy: r.binding.Policy, Now: c.Now}
	if err := CheckCurrentNodeProducerGrant(s.Grant, ctx); err != nil {
		return NodeProducerGrant{}, NodeGrantReadContext{}, err
	}
	return s.Grant, ctx, nil
}

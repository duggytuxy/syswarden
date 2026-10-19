package v5

// Ordinary changes keep every member and slot, including expired/revoked state.
// This bounded initial profile refuses further rotation at capacity. Reclaiming
// slots needs a separate protected denial/history compaction protocol; an expiry
// or a successful new approval alone is never permission to forget old keys.
func retainNodeRegistryHistory(current, next NodeAdmissionRegistry) error {
	members := make(map[NodeIdentity]NodeAdmissionMember, len(next.members))
	for _, m := range next.members {
		members[m.Identity] = m
	}
	for _, old := range current.members {
		m, exists := members[old.Identity]
		if !exists || (old.Status == "revoked" && (m.Status != "revoked" || len(m.Transport) != len(old.Transport) || len(m.Producers) != len(old.Producers))) {
			return ErrNodeContinuityChange
		}
		for _, s := range old.Transport {
			loc, ok := next.transport[s.Grant.CredentialID]
			if !ok || next.members[loc.member].Identity != old.Identity {
				return ErrNodeContinuityChange
			}
			n := next.members[loc.member].Transport[loc.slot]
			grant := n.Grant
			grant.Status = s.Grant.Status
			if grant != s.Grant || !nodeGrantStatusForward(s.Grant.Status, n.Grant.Status) ||
				!nodeAdmissionWindow(n.AdmitFrom, n.AdmitUntil, s.AdmitFrom, s.AdmitUntil) {
				return ErrNodeContinuityChange
			}
		}
		for _, s := range old.Producers {
			loc, ok := next.producers[s.Grant.GrantID]
			if !ok || next.members[loc.member].Identity != old.Identity {
				return ErrNodeContinuityChange
			}
			n := next.members[loc.member].Producers[loc.slot]
			grant := n.Grant
			grant.Status = s.Grant.Status
			if grant != s.Grant || !nodeGrantStatusForward(s.Grant.Status, n.Grant.Status) ||
				!nodeAdmissionWindow(n.AdmitFrom, n.AdmitUntil, s.AdmitFrom, s.AdmitUntil) {
				return ErrNodeContinuityChange
			}
		}
	}
	return nil
}

func nodeGrantStatusForward(before, after string) bool {
	return before == after || (before == "active" && after == "revoked")
}

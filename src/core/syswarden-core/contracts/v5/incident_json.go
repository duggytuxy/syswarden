package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// DecodeIncidentRelation accepts exact bounded fields and returns a zero
// record on error. It neither looks up endpoints nor validates a causal claim.
func DecodeIncidentRelation(data []byte) (IncidentRelation, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[IncidentRelation]()) {
		return IncidentRelation{}, invalidIncident("encoding, bounds or object shape")
	}
	var relation IncidentRelation
	if err := json.Unmarshal(data, &relation); err != nil {
		return IncidentRelation{}, invalidIncident("encoding")
	}
	if err := relation.Validate(); err != nil {
		return IncidentRelation{}, err
	}
	return relation, nil
}

// EncodeIncidentRelation emits compact, explicit struct-order JSON without a
// final newline. This is not JCS, a signed assertion or an executable request.
func EncodeIncidentRelation(relation IncidentRelation) ([]byte, error) {
	if err := relation.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(relation)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidIncident("encoding or size")
	}
	return data, nil
}

// IncidentRecordReferenceFromJSON validates one endpoint against its separate
// ingestion identity and hashes its deterministic schema encoding. It never
// upgrades the endpoint's age, evidence quality or authority. Event envelopes
// lack cluster/epoch: only the independently authenticated journal supplies
// those missing scope components. Frozen v4 events cannot supply them.
func IncidentRecordReferenceFromJSON(input ResolvedIncidentRecord) (IncidentRecordReference, error) {
	if input.Identity.Validate() != nil {
		return IncidentRecordReference{}, ErrInvalidIncidentInput
	}
	var encoded []byte
	var id string
	var identity NodeIdentity
	var err error
	switch input.Schema {
	case EventSchema:
		var record Event
		record, err = DecodeEvent(input.Data)
		if err != nil || record.EventID.State != Present || record.NodeID.State != Present || record.NodeID.Value != input.Identity.NodeID {
			return IncidentRecordReference{}, ErrInvalidIncidentInput
		}
		id, identity = record.EventID.Value, input.Identity
		encoded, err = EncodeEvent(record)
	case NodeSnapshotSchema:
		var record NodeSnapshot
		record, err = DecodeNodeSnapshot(input.Data)
		if err != nil {
			return IncidentRecordReference{}, ErrInvalidIncidentInput
		}
		id, identity = record.SnapshotID, record.Identity
		encoded, err = EncodeNodeSnapshot(record)
	case PolicyDecisionSchema:
		var record PolicyDecision
		record, err = DecodePolicyDecision(input.Data)
		if err != nil {
			return IncidentRecordReference{}, ErrInvalidIncidentInput
		}
		id, identity = record.DecisionID, record.Identity
		encoded, err = EncodePolicyDecision(record)
	case ActionOutcomeSchema:
		var record ActionOutcome
		record, err = DecodeActionOutcome(input.Data)
		if err != nil {
			return IncidentRecordReference{}, ErrInvalidIncidentInput
		}
		id, identity = record.OutcomeID, record.Identity
		encoded, err = EncodeActionOutcome(record)
	case ControlSnapshotSchema:
		var record ControlSnapshot
		record, err = DecodeControlSnapshot(input.Data)
		if err != nil {
			return IncidentRecordReference{}, ErrInvalidIncidentInput
		}
		id, identity = record.SnapshotID, record.Identity
		encoded, err = EncodeControlSnapshot(record)
	case EvidenceDescriptorSchema:
		var record EvidenceDescriptor
		record, err = DecodeEvidenceDescriptor(input.Data)
		if err != nil {
			return IncidentRecordReference{}, ErrInvalidIncidentInput
		}
		id, identity = record.EvidenceID, record.Identity
		encoded, err = EncodeEvidenceDescriptor(record)
	default:
		return IncidentRecordReference{}, ErrInvalidIncidentInput
	}
	if err != nil || identity != input.Identity {
		return IncidentRecordReference{}, ErrInvalidIncidentInput
	}
	sum := sha256.Sum256(encoded)
	return IncidentRecordReference{Schema: input.Schema, RecordID: id, SHA256: hex.EncodeToString(sum[:])}, nil
}

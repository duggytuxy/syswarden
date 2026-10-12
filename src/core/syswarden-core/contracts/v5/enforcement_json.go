package v5

import (
	"encoding/json"
	"reflect"
)

// DecodeActionOutcome accepts exact members within the shared JSON bounds.
// Errors return a zero record and never expose input values.
func DecodeActionOutcome(data []byte) (ActionOutcome, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[ActionOutcome]()) {
		return ActionOutcome{}, invalidAction("encoding, bounds or object shape")
	}
	var outcome ActionOutcome
	if err := json.Unmarshal(data, &outcome); err != nil {
		return ActionOutcome{}, invalidAction("encoding")
	}
	if err := outcome.Validate(); err != nil {
		return ActionOutcome{}, err
	}
	return outcome, nil
}

// EncodeActionOutcome emits compact struct-order JSON with explicit fields and
// no final newline. This is not a signed or executable transaction format.
func EncodeActionOutcome(outcome ActionOutcome) ([]byte, error) {
	if err := outcome.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(outcome)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidAction("encoding or size")
	}
	return data, nil
}

// DecodeControlSnapshot checks shape and declared coherence, not freshness or
// evidence authenticity. Malformed records never produce a partially usable
// snapshot. Use the contextual check before considering currency metadata.
func DecodeControlSnapshot(data []byte) (ControlSnapshot, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[ControlSnapshot]()) {
		return ControlSnapshot{}, invalidControl("encoding, bounds or object shape")
	}
	var snapshot ControlSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return ControlSnapshot{}, invalidControl("encoding")
	}
	if err := snapshot.Validate(); err != nil {
		return ControlSnapshot{}, err
	}
	return snapshot, nil
}

// EncodeControlSnapshot emits deterministic explicit fields without a final
// newline. This format is not JCS or a cryptographic proof of protection.
func EncodeControlSnapshot(snapshot ControlSnapshot) ([]byte, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidControl("encoding or size")
	}
	return data, nil
}

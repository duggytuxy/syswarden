package v5

import (
	"encoding/json"
	"reflect"
)

// DecodePolicyDecision requires exact fields, explicit availability and the
// shared JSON bounds. Failures return a zero record without untrusted values
// in errors. Decoding alone does not establish input binding or authority.
func DecodePolicyDecision(data []byte) (PolicyDecision, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[PolicyDecision]()) {
		return PolicyDecision{}, invalidDecision("encoding, bounds or object shape")
	}
	var decision PolicyDecision
	if err := json.Unmarshal(data, &decision); err != nil {
		return PolicyDecision{}, invalidDecision("encoding")
	}
	if err := decision.Validate(); err != nil {
		return PolicyDecision{}, err
	}
	return decision, nil
}

// EncodePolicyDecision emits compact explicit fields in struct order without
// a trailing newline. It is not JCS, a signed proof or an executable request.
func EncodePolicyDecision(decision PolicyDecision) ([]byte, error) {
	if err := decision.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(decision)
	if err != nil {
		return nil, invalidDecision("encoding")
	}
	if len(data) > MaxDocumentBytes {
		return nil, invalidDecision("size")
	}
	return data, nil
}

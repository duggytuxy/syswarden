package v5

import (
	"encoding/json"
	"reflect"
)

// DecodeEvidenceDescriptor rejects ambiguous or oversized metadata without
// returning partially usable evidence or exposing untrusted values in errors.
func DecodeEvidenceDescriptor(data []byte) (EvidenceDescriptor, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[EvidenceDescriptor]()) {
		return EvidenceDescriptor{}, invalidEvidence("encoding, bounds or object shape")
	}
	var descriptor EvidenceDescriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		return EvidenceDescriptor{}, invalidEvidence("encoding")
	}
	if err := descriptor.Validate(); err != nil {
		return EvidenceDescriptor{}, err
	}
	return descriptor, nil
}

// EncodeEvidenceDescriptor emits explicit compact struct-order JSON without
// a final newline. This is not JCS or a signed evidence capsule format.
func EncodeEvidenceDescriptor(descriptor EvidenceDescriptor) ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(descriptor)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidEvidence("encoding or size")
	}
	return data, nil
}

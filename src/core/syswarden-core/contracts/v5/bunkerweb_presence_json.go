package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// DecodeBunkerWebPresenceSnapshot requires the exact bounded schema. Rejected input
// returns no partial presence and diagnostics never echo document values.
func DecodeBunkerWebPresenceSnapshot(data []byte) (BunkerWebPresenceSnapshot, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[BunkerWebPresenceSnapshot]()) {
		return BunkerWebPresenceSnapshot{}, invalidBunkerWebPresence("encoding, bounds or object shape")
	}
	var s BunkerWebPresenceSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return BunkerWebPresenceSnapshot{}, invalidBunkerWebPresence("encoding")
	}
	if err := s.Validate(); err != nil {
		return BunkerWebPresenceSnapshot{}, err
	}
	return s, nil
}

// EncodeBunkerWebPresenceSnapshot emits compact struct-order JSON, not JCS or a
// signature. Existing node, event and KPI schema bytes remain unchanged.
func EncodeBunkerWebPresenceSnapshot(s BunkerWebPresenceSnapshot) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(s)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidBunkerWebPresence("encoding or size")
	}
	return data, nil
}

// BunkerWebPresenceSnapshotSHA256 binds the entire canonical presence report.
// This digest supplies byte identity only, not authentication or authorization.
func BunkerWebPresenceSnapshotSHA256(s BunkerWebPresenceSnapshot) (string, error) {
	data, err := EncodeBunkerWebPresenceSnapshot(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

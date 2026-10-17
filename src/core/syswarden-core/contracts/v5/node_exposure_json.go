package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// DecodeNodeExposureSnapshot requires the exact bounded schema. Rejected input
// returns no partial classification and diagnostics never echo document values.
func DecodeNodeExposureSnapshot(data []byte) (NodeExposureSnapshot, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[NodeExposureSnapshot]()) {
		return NodeExposureSnapshot{}, invalidNodeExposure("encoding, bounds or object shape")
	}
	var s NodeExposureSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return NodeExposureSnapshot{}, invalidNodeExposure("encoding")
	}
	if err := s.Validate(); err != nil {
		return NodeExposureSnapshot{}, err
	}
	return s, nil
}

// EncodeNodeExposureSnapshot emits compact struct-order JSON, not JCS or a
// signature. Existing node, event and KPI schema bytes remain unchanged.
func EncodeNodeExposureSnapshot(s NodeExposureSnapshot) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(s)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidNodeExposure("encoding or size")
	}
	return data, nil
}

// NodeExposureSnapshotSHA256 binds the entire canonical classification report.
// This digest supplies byte identity only, not authentication or authorization.
func NodeExposureSnapshotSHA256(s NodeExposureSnapshot) (string, error) {
	data, err := EncodeNodeExposureSnapshot(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

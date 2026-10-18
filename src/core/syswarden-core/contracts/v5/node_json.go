package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// DecodeNodeSnapshot uses the same bounded, ambiguity-rejecting JSON parser as
// events. All members are mandatory. Errors return a zero snapshot and do not
// include untrusted data. This does not perform the contextual current check.
func DecodeNodeSnapshot(data []byte) (NodeSnapshot, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[NodeSnapshot]()) {
		return NodeSnapshot{}, invalidNode("encoding, bounds or object shape")
	}
	var snapshot NodeSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return NodeSnapshot{}, invalidNode("encoding")
	}
	if err := snapshot.Validate(); err != nil {
		return NodeSnapshot{}, err
	}
	return snapshot, nil
}

// EncodeNodeSnapshot emits explicit fields in struct order, compact JSON and
// no trailing newline. This schema-specific form is not JCS or a signed proof.
func EncodeNodeSnapshot(snapshot NodeSnapshot) ([]byte, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, invalidNode("encoding")
	}
	if len(data) > MaxDocumentBytes {
		return nil, invalidNode("size")
	}
	return data, nil
}

// NodeSnapshotSHA256 binds every field of the existing canonical node schema.
// It supplies byte identity only, not collector authentication or read authority.
func NodeSnapshotSHA256(s NodeSnapshot) (string, error) {
	data, err := EncodeNodeSnapshot(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

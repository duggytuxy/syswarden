package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// DecodeRateSnapshot accepts one bounded, exact document and returns zero on
// error. It does not trust input-supplied formulas or calculate a security score.
func DecodeRateSnapshot(data []byte) (RateSnapshot, error) {
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[RateSnapshot]()) {
		return RateSnapshot{}, invalidRate("encoding, bounds or object shape")
	}
	var s RateSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return RateSnapshot{}, invalidRate("encoding")
	}
	if err := s.Validate(); err != nil {
		return RateSnapshot{}, err
	}
	return s, nil
}

// EncodeRateSnapshot emits compact struct-order JSON without a final newline.
// This schema encoding is not JCS, a signature or authenticated KPI evidence.
func EncodeRateSnapshot(s RateSnapshot) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(s)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidRate("encoding or size")
	}
	return data, nil
}

// RateSnapshotSHA256 binds all report metadata and calculation provenance.
// It is distinct from the formula, population, scope and policy byte digests.
func RateSnapshotSHA256(s RateSnapshot) (string, error) {
	data, err := EncodeRateSnapshot(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

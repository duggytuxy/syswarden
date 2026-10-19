package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// The two independent, bounded schemas deliberately use no generic extension
// map or roles array. Their canonical bytes are not a registry signature.
func decodeNodeGrant[T interface{ Validate() error }](data []byte) (T, error) {
	var zero T
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[T]()) {
		return zero, invalidNodeGrant("encoding, bounds or object shape")
	}
	var grant T
	if err := json.Unmarshal(data, &grant); err != nil {
		return zero, invalidNodeGrant("encoding")
	}
	if err := grant.Validate(); err != nil {
		return zero, err
	}
	return grant, nil
}

func encodeNodeGrant[T interface{ Validate() error }](grant T) ([]byte, error) {
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(grant)
	if err != nil || len(data) > MaxDocumentBytes {
		return nil, invalidNodeGrant("encoding or size")
	}
	return data, nil
}

func nodeGrantSHA256[T interface{ Validate() error }](grant T) (string, error) {
	data, err := encodeNodeGrant(grant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func DecodeNodeTransportGrant(data []byte) (NodeTransportGrant, error) {
	return decodeNodeGrant[NodeTransportGrant](data)
}
func EncodeNodeTransportGrant(g NodeTransportGrant) ([]byte, error) { return encodeNodeGrant(g) }
func NodeTransportGrantSHA256(g NodeTransportGrant) (string, error) { return nodeGrantSHA256(g) }
func DecodeNodeProducerGrant(data []byte) (NodeProducerGrant, error) {
	return decodeNodeGrant[NodeProducerGrant](data)
}
func EncodeNodeProducerGrant(g NodeProducerGrant) ([]byte, error) { return encodeNodeGrant(g) }
func NodeProducerGrantSHA256(g NodeProducerGrant) (string, error) { return nodeGrantSHA256(g) }

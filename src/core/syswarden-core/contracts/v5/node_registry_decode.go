package v5

import (
	"bytes"
	"encoding/json"
	"io"
)

// DecodeNodeAdmissionRegistry reads only an independently pinned complete
// snapshot. Expected must come from current protected continuity, never the
// submitted bytes themselves. A digest checks identity, not approval or custody.
// Arrays are bounded during decoding, before allocating the complete candidate.
func DecodeNodeAdmissionRegistry(data []byte, expected RateReference) (NodeAdmissionRegistry, error) {
	if len(data) == 0 || len(data) > MaxNodeAdmissionRegistryBytes || !expected.validate() || nodeBytesSHA256(data) != expected.SHA256 {
		return NodeAdmissionRegistry{}, invalidNodeRegistry("encoding size or expected snapshot")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var schema, id string
	var binding NodeAdmissionRegistryBinding
	if !registryToken(d, json.Delim('{')) || !registryField(d, "schema", &schema) || schema != NodeAdmissionRegistrySchema ||
		!registryField(d, "snapshot_id", &id) || id != expected.Ref || !identifier(id) ||
		!registryField(d, "binding", &binding) || !binding.validate() || !registryToken(d, "members") || !registryToken(d, json.Delim('[')) {
		return NodeAdmissionRegistry{}, invalidNodeRegistry("header")
	}
	members := make([]NodeAdmissionMember, 0)
	for d.More() {
		if len(members) >= MaxNodeAdmissionMembers {
			return NodeAdmissionRegistry{}, invalidNodeRegistry("member count")
		}
		m, err := decodeRegistryMember(d, binding)
		if err != nil {
			return NodeAdmissionRegistry{}, err
		}
		members = append(members, m)
	}
	if !registryToken(d, json.Delim(']')) || !registryToken(d, json.Delim('}')) {
		return NodeAdmissionRegistry{}, invalidNodeRegistry("trailer")
	}
	if _, err := d.Token(); err != io.EOF {
		return NodeAdmissionRegistry{}, invalidNodeRegistry("trailing data")
	}
	r, err := BuildNodeAdmissionRegistry(id, binding, members)
	if err != nil {
		return NodeAdmissionRegistry{}, err
	}
	// Reject reordered records/fields, duplicate aliases, null arrays and lossy
	// strings, even if their decoded values would produce the expected shape.
	if r.reference != expected || !bytes.Equal(r.manifest, data) {
		return NodeAdmissionRegistry{}, invalidNodeRegistry("noncanonical snapshot")
	}
	return r, nil
}

func registryToken(d *json.Decoder, want any) bool {
	token, err := d.Token()
	return err == nil && token == want
}

func registryField(d *json.Decoder, name string, value any) bool {
	return registryToken(d, name) && d.Decode(value) == nil
}

func decodeRegistryMember(d *json.Decoder, binding NodeAdmissionRegistryBinding) (NodeAdmissionMember, error) {
	var m NodeAdmissionMember
	if !registryToken(d, json.Delim('{')) || !registryField(d, "identity", &m.Identity) || m.Identity.Validate() != nil ||
		!registryField(d, "status", &m.Status) || !member("active", "revoked")(m.Status) || !registryToken(d, "transport") {
		return NodeAdmissionMember{}, invalidNodeRegistry("member header")
	}
	var err error
	m.Transport, err = decodeRegistrySlots[NodeTransportSlot](d, MaxNodeAdmissionSlots, func(s NodeTransportSlot) bool { return s.Grant.Validate() == nil })
	if err != nil || !registryToken(d, "producers") {
		return NodeAdmissionMember{}, invalidNodeRegistry("transport slots")
	}
	m.Producers, err = decodeRegistrySlots[NodeProducerSlot](d, MaxNodeAdmissionSources*MaxNodeAdmissionSlots, func(s NodeProducerSlot) bool { return s.Grant.Validate() == nil })
	if err != nil || !registryToken(d, json.Delim('}')) || validateNodeAdmissionMember(binding, m) != nil {
		return NodeAdmissionMember{}, invalidNodeRegistry("producer slots or member")
	}
	return m, nil
}

func decodeRegistrySlots[T any](d *json.Decoder, maximum int, valid func(T) bool) ([]T, error) {
	if !registryToken(d, json.Delim('[')) {
		return nil, invalidNodeRegistry("slot array")
	}
	result := make([]T, 0)
	for d.More() {
		if len(result) >= maximum {
			return nil, invalidNodeRegistry("slot count")
		}
		var s T
		if d.Decode(&s) != nil || !valid(s) {
			return nil, invalidNodeRegistry("slot")
		}
		result = append(result, s)
	}
	if !registryToken(d, json.Delim(']')) {
		return nil, invalidNodeRegistry("slot trailer")
	}
	return result, nil
}

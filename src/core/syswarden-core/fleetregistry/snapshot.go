// Package fleetregistry implements inactive fleet registry persistence inputs.
// It does not provision trust, approve enrollment or establish durable continuity.
package fleetregistry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	contracts "syswarden-core/contracts/v5"
)

const snapshotMagic = "SYSWARDEN-NODE-REGISTRY-V1\n"

// MaxSnapshotBytes bounds a complete storage object, not process heap usage or
// the combined registry/receipt/audit budget. No compression is accepted.
const MaxSnapshotBytes = len(snapshotMagic) + 12 + 2*contracts.MaxNodeContinuityBytes + contracts.MaxNodeAdmissionRegistryBytes

var ErrSnapshot = errors.New("invalid bounded fleet registry snapshot")

// Snapshot contains administrative state, including disabled/revoked records.
// All values are owned copies or immutable registry views. Reading this object
// does not authenticate a requester or grant operational admission.
type Snapshot struct {
	Generation contracts.NodeRegistryGeneration
	Checkpoint contracts.NodeRegistryCheckpoint
	Registry   contracts.NodeAdmissionRegistry
}

// EncodeSnapshot constructs bytes for independent provisioning, without writing
// a file or acknowledging a commit. Expected must be independently approved.
func EncodeSnapshot(s Snapshot, expected contracts.NodeRegistryContinuityContext) ([]byte, error) {
	if err := contracts.CheckNodeRegistryContinuity(s.Generation, s.Checkpoint, s.Registry, expected); err != nil {
		return nil, err
	}
	g, err := contracts.EncodeNodeRegistryGeneration(s.Generation)
	if err != nil {
		return nil, err
	}
	c, err := contracts.EncodeNodeRegistryCheckpoint(s.Checkpoint)
	if err != nil {
		return nil, err
	}
	r := s.Registry.Manifest()
	data := make([]byte, 0, len(snapshotMagic)+12+len(g)+len(c)+len(r))
	data = append(data, snapshotMagic...)
	for _, section := range [][]byte{g, c, r} {
		// Each section was bounded by its encoder or immutable registry builder.
		n := len(section)
		if n <= 0 || n > math.MaxUint32 || n > contracts.MaxNodeAdmissionRegistryBytes {
			return nil, ErrSnapshot
		}
		data = binary.BigEndian.AppendUint32(data, uint32(n))
		data = append(data, section...)
	}
	return data, nil
}

// DecodeSnapshot rejects the complete object on a partial/mixed/trailing state.
// The expected generation and checkpoint are never adopted from this file.
func DecodeSnapshot(data []byte, expected contracts.NodeRegistryContinuityContext) (Snapshot, error) {
	if len(data) <= len(snapshotMagic) || len(data) > MaxSnapshotBytes || !bytes.HasPrefix(data, []byte(snapshotMagic)) {
		return Snapshot{}, ErrSnapshot
	}
	remaining := data[len(snapshotMagic):]
	g, rest, err := snapshotSection(remaining, contracts.MaxNodeContinuityBytes)
	if err != nil {
		return Snapshot{}, err
	}
	c, rest, err := snapshotSection(rest, contracts.MaxNodeContinuityBytes)
	if err != nil {
		return Snapshot{}, err
	}
	r, rest, err := snapshotSection(rest, contracts.MaxNodeAdmissionRegistryBytes)
	if err != nil || len(rest) != 0 {
		return Snapshot{}, ErrSnapshot
	}
	generation, err := contracts.DecodeNodeRegistryGeneration(g)
	if err != nil {
		return Snapshot{}, err
	}
	checkpoint, err := contracts.DecodeNodeRegistryCheckpoint(c)
	if err != nil {
		return Snapshot{}, err
	}
	// Pin small metadata before parsing the larger collection.
	gr, ge := generation.Reference()
	cr, ce := checkpoint.Reference()
	if ge != nil || ce != nil || gr != expected.Generation || cr != expected.Checkpoint || generation.AuthorityID != expected.AuthorityID || generation.LineageID != expected.LineageID {
		return Snapshot{}, contracts.ErrNodeContinuityBinding
	}
	registry, err := contracts.DecodeNodeAdmissionRegistry(r, checkpoint.Snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	if err := contracts.CheckNodeRegistryContinuity(generation, checkpoint, registry, expected); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{generation, checkpoint, registry}, nil
}

func snapshotSection(data []byte, maximum int) ([]byte, []byte, error) {
	if len(data) < 4 {
		return nil, nil, ErrSnapshot
	}
	n := binary.BigEndian.Uint32(data[:4])
	if n == 0 || int64(n) > int64(maximum) || int64(n) > int64(len(data)-4) {
		return nil, nil, ErrSnapshot
	}
	end := 4 + int(n)
	return data[4:end], data[end:], nil
}

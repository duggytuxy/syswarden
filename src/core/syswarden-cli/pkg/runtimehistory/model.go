// Package runtimehistory decodes the exact quiescent native lifecycle store.
// Schema validation alone does not authorize kernel cleanup. Callers must
// separately attest private file ownership, quiescent writers and live claims.
package runtimehistory

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

const MaximumStateBytes = 16 << 20

const (
	schemaVersion     = 1
	MaximumRecords    = 16384
	confirmationDelay = 30 * time.Second
)

// Claim records a verified native transition, independently
// of the attack journal. An administrative ban never becomes a physical hit.
type Claim struct {
	Entry        string `json:"entry"`
	Generation   uint64 `json:"generation"`
	State        string `json:"state"`
	Cause        string `json:"cause"`
	CreatedAt    string `json:"created_at"`
	TransitionAt string `json:"transition_at"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	ConfirmedAt  string `json:"confirmed_at,omitempty"`
}

type Model struct {
	SchemaVersion int     `json:"schema_version"`
	IntentFormat  int     `json:"intent_format,omitempty"`
	RetiredIntent string  `json:"retired_intent_sha256,omitempty"`
	Identity      string  `json:"identity"`
	Sequence      uint64  `json:"sequence"`
	UpdatedAt     string  `json:"updated_at"`
	Records       []Claim `json:"records"`
}

func canonicalEntry(entry string) bool {
	if address, err := netip.ParseAddr(entry); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == entry
	}
	prefix, err := netip.ParsePrefix(entry)
	return err == nil && !prefix.Addr().Is4In6() && prefix.Masked().String() == entry
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("runtime lifecycle timestamp is not canonical")
	}
	return parsed, nil
}

func (model Model) validate() error {
	identity, identityErr := hex.DecodeString(model.Identity)
	retired, retiredErr := hex.DecodeString(model.RetiredIntent)
	if model.SchemaVersion != schemaVersion || model.IntentFormat < 0 || model.IntentFormat > 1 || identityErr != nil || len(identity) != 32 ||
		hex.EncodeToString(identity) != model.Identity || model.Sequence == 0 || model.Records == nil ||
		len(model.Records) > MaximumRecords {
		return fmt.Errorf("runtime lifecycle model identity or bounds are invalid")
	}
	if model.RetiredIntent != "" && (model.IntentFormat != 1 || retiredErr != nil || len(retired) != 32 || hex.EncodeToString(retired) != model.RetiredIntent) {
		return fmt.Errorf("runtime lifecycle retired intent binding is invalid")
	}
	updated, err := canonicalTime(model.UpdatedAt)
	if err != nil {
		return err
	}
	previous := ""
	for _, record := range model.Records {
		if !canonicalEntry(record.Entry) || record.Entry <= previous || record.Generation == 0 || record.Generation > model.Sequence {
			return fmt.Errorf("runtime lifecycle inventory is not canonical")
		}
		previous = record.Entry
		created, firstErr := canonicalTime(record.CreatedAt)
		transition, lastErr := canonicalTime(record.TransitionAt)
		if firstErr != nil || lastErr != nil || transition.Before(created) || transition.After(updated) {
			return fmt.Errorf("runtime lifecycle chronology is invalid")
		}
		var expiry time.Time
		if record.ExpiresAt != "" {
			expiry, err = canonicalTime(record.ExpiresAt)
			if err != nil || !expiry.After(created) {
				return fmt.Errorf("runtime lifecycle expiry is invalid")
			}
		}
		switch record.State {
		case "active":
			if record.Cause != "verified-ban" || record.ConfirmedAt != "" {
				return fmt.Errorf("active runtime lifecycle claim is invalid")
			}
		case "deleted", "expired", "tombstoned":
			if record.Cause != "verified-deletion" && record.Cause != "native-expiry" {
				return fmt.Errorf("runtime lifecycle cause is invalid")
			}
			if record.State == "deleted" && record.Cause != "verified-deletion" || record.State == "expired" && record.Cause != "native-expiry" {
				return fmt.Errorf("runtime lifecycle state and cause differ")
			}
			if record.Cause == "native-expiry" && (expiry.IsZero() || transition.Before(expiry)) {
				return fmt.Errorf("runtime lifecycle expiry is premature")
			}
			if record.State == "tombstoned" {
				confirmed, confirmErr := canonicalTime(record.ConfirmedAt)
				if confirmErr != nil || confirmed.Before(transition.Add(confirmationDelay)) || confirmed.After(updated) {
					return fmt.Errorf("runtime absence confirmation is premature or invalid")
				}
			} else if record.ConfirmedAt != "" {
				return fmt.Errorf("unconfirmed runtime transition claims confirmation")
			}
		default:
			return fmt.Errorf("runtime lifecycle state is unknown")
		}
	}
	return nil
}

type Anchor struct {
	Version  int    `json:"version"`
	Identity string `json:"identity"`
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

type Intent struct {
	Entry            string `json:"entry"`
	Present          bool   `json:"present"`
	Permanent        bool   `json:"permanent"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	PreparedAt       string `json:"prepared_at"`
	PreserveStronger bool   `json:"preserve_stronger,omitempty"`
}

type intentFrame struct {
	Version int     `json:"version"`
	Anchor  Anchor  `json:"anchor"`
	Intent  *Intent `json:"intent,omitempty"`
}

type Snapshot struct {
	Model       Model
	StateSHA256 string
}

func canonicalJSON(wire []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("runtime history encoding is invalid")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(wire, append(canonical, '\n')) {
		return fmt.Errorf("runtime history encoding is not canonical")
	}
	return nil
}

// DecodeQuiescent recognizes either exact genesis or a fixed intent frame
// durably consumed by the current model. The actual core deliberately retains
// consumed frames; their presence is not an outstanding mutation. A missing
// or different retired-frame digest never authorizes recovery here.
func DecodeQuiescent(state, anchor, intent []byte) (Snapshot, error) {
	var result Snapshot
	if len(state) == 0 || len(state) > MaximumStateBytes || len(anchor) == 0 || len(anchor) > 4096 || len(intent) != 4096 {
		return result, fmt.Errorf("runtime history exceeds its closed format bounds")
	}
	if err := canonicalJSON(state, &result.Model); err != nil {
		return Snapshot{}, err
	}
	if err := result.Model.validate(); err != nil {
		return Snapshot{}, err
	}
	if result.Model.IntentFormat != 1 {
		return Snapshot{}, fmt.Errorf("runtime history requires the current fixed-slot intent format")
	}
	result.StateSHA256 = fmt.Sprintf("%x", sha256.Sum256(state))
	expected := Anchor{1, result.Model.Identity, result.Model.Sequence, result.StateSHA256}
	var actual Anchor
	if err := canonicalJSON(anchor, &actual); err != nil {
		return Snapshot{}, err
	}
	if actual != expected {
		return Snapshot{}, fmt.Errorf("runtime history anchor does not bind its complete state")
	}
	frame, err := decodeFrame(intent)
	if err != nil {
		return Snapshot{}, err
	}
	if frame.Anchor.Identity != result.Model.Identity || frame.Anchor.Sequence == 0 || frame.Anchor.Sequence > result.Model.Sequence {
		return Snapshot{}, fmt.Errorf("runtime intent frame belongs to a different or later history")
	}
	if result.Model.RetiredIntent != "" {
		if result.Model.RetiredIntent != fmt.Sprintf("%x", sha256.Sum256(intent)) {
			return Snapshot{}, fmt.Errorf("runtime history has an unconsumed or changed intent frame; preserve it for verified recovery")
		}
		return result, nil
	}
	if result.Model.Sequence != 1 || len(result.Model.Records) != 0 || frame.Intent != nil || frame.Anchor != expected {
		return Snapshot{}, fmt.Errorf("runtime history lacks exact genesis or a durably consumed frame")
	}
	return result, nil
}

func decodeFrame(wire []byte) (intentFrame, error) {
	var frame intentFrame
	if len(wire) != 4096 || string(wire[:8]) != "SWINT001" {
		return frame, fmt.Errorf("runtime intent frame has invalid framing")
	}
	size := int(binary.BigEndian.Uint32(wire[8:12]))
	if size < 1 || size > 4096-44 {
		return frame, fmt.Errorf("runtime intent frame payload is outside its bound")
	}
	var checked [4096]byte
	copy(checked[:], wire)
	clear(checked[12:44])
	sum := sha256.Sum256(checked[:])
	if !bytes.Equal(sum[:], wire[12:44]) {
		return frame, fmt.Errorf("runtime intent frame checksum differs")
	}
	for _, value := range wire[44+size:] {
		if value != 0 {
			return frame, fmt.Errorf("runtime intent frame padding is not canonical")
		}
	}
	if err := canonicalJSON(append(bytes.Clone(wire[44:44+size]), '\n'), &frame); err != nil {
		return intentFrame{}, err
	}
	digest, err := hex.DecodeString(frame.Anchor.Digest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != frame.Anchor.Digest || frame.Version != 1 || frame.Anchor.Version != 1 {
		return intentFrame{}, fmt.Errorf("runtime intent frame version or anchor digest is invalid")
	}
	if frame.Intent != nil {
		request := frame.Intent
		prepared, err := canonicalTime(request.PreparedAt)
		if err != nil || !canonicalEntry(request.Entry) {
			return intentFrame{}, fmt.Errorf("runtime intent entry or timestamp is invalid")
		}
		if !request.Present && (request.Permanent || request.ExpiresAt != "" || request.PreserveStronger) || request.Permanent && request.ExpiresAt != "" {
			return intentFrame{}, fmt.Errorf("runtime intent lifetime metadata is contradictory")
		}
		if request.Present && !request.Permanent {
			expiry, err := canonicalTime(request.ExpiresAt)
			if err != nil || !expiry.After(prepared) || expiry.Sub(prepared) > 30*24*time.Hour+2*time.Second {
				return intentFrame{}, fmt.Errorf("runtime intent expiry is invalid")
			}
		}
	}
	return frame, nil
}

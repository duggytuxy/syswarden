package runtimehistory

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func historyTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(wire, '\n')
}

// Construct deterministic protocol inputs, independently of host evidence.
// Native integration tests additionally exercise the installed core producer.
func historyTestFrame(t *testing.T, frame intentFrame) []byte {
	t.Helper()
	payload := bytes.TrimSuffix(historyTestJSON(t, frame), []byte{'\n'})
	size := len(payload)
	if size < 1 || size > 4096-44 {
		t.Fatal("synthetic frame exceeds its fixed payload bound")
		return nil
	}
	wire := make([]byte, 4096)
	copy(wire, "SWINT001")
	binary.BigEndian.PutUint32(wire[8:12], uint32(size))
	copy(wire[44:], payload)
	historyTestChecksum(wire)
	return wire
}

func historyTestChecksum(wire []byte) {
	clear(wire[12:44])
	sum := sha256.Sum256(wire)
	copy(wire[12:44], sum[:])
}

func historyTestInput(t *testing.T, kind string) (Model, intentFrame) {
	t.Helper()
	model := Model{SchemaVersion: 1, IntentFormat: 1, Identity: strings.Repeat("1", 64), Sequence: 2,
		UpdatedAt: "2026-01-01T12:00:00Z", Records: []Claim{{Entry: "192.0.2.4", Generation: 1,
			State: "active", Cause: "verified-ban", CreatedAt: "2026-01-01T12:00:00Z",
			TransitionAt: "2026-01-01T12:00:00Z", ExpiresAt: "2026-01-02T12:00:00Z"}}}
	frame := intentFrame{Version: 1, Anchor: Anchor{1, model.Identity, 1, strings.Repeat("2", 64)},
		Intent: &Intent{Entry: "192.0.2.4", Present: true, ExpiresAt: "2026-01-02T12:00:00Z", PreparedAt: "2026-01-01T12:00:00Z", PreserveStronger: true}}
	switch kind {
	case "genesis":
		model.Sequence, model.Records, frame.Intent = 1, []Claim{}, nil
	case "permanent":
		model.Records[0].ExpiresAt, frame.Intent.ExpiresAt, frame.Intent.Permanent = "", "", true
	case "deleted", "expired", "tombstoned":
		model.Sequence, frame.Anchor.Sequence = 3, 2
		model.UpdatedAt, model.Records[0].TransitionAt = "2026-01-02T12:00:00Z", "2026-01-02T12:00:00Z"
		model.Records[0].State, model.Records[0].Cause = kind, "verified-deletion"
		frame.Intent = &Intent{Entry: "192.0.2.4", PreparedAt: "2026-01-02T12:00:00Z"}
		if kind == "expired" {
			model.Records[0].Cause = "native-expiry"
		}
		if kind == "tombstoned" {
			model.UpdatedAt, model.Records[0].ConfirmedAt = "2026-01-02T12:00:30Z", "2026-01-02T12:00:30Z"
		}
	case "consumed-noop":
		frame.Anchor.Sequence, frame.Intent.PreparedAt = 2, "2026-01-01T12:00:01Z"
	case "active":
	default:
		t.Fatal("unknown fixture", kind)
	}
	return model, frame
}

func historyTestEncode(t *testing.T, model Model, frame intentFrame) ([]byte, []byte, []byte) {
	t.Helper()
	if frame.Intent == nil && model.Sequence == 1 && len(model.Records) == 0 {
		frame.Anchor.Digest = fmt.Sprintf("%x", sha256.Sum256(historyTestJSON(t, model)))
	}
	intent := historyTestFrame(t, frame)
	if frame.Intent != nil {
		model.RetiredIntent = fmt.Sprintf("%x", sha256.Sum256(intent))
	}
	state := historyTestJSON(t, model)
	anchor := historyTestJSON(t, Anchor{1, model.Identity, model.Sequence, fmt.Sprintf("%x", sha256.Sum256(state))})
	return state, anchor, intent
}

func TestDecodeQuiescentNativeTransitionForms(t *testing.T) {
	for _, kind := range []string{"genesis", "active", "permanent", "deleted", "expired", "tombstoned", "consumed-noop"} {
		t.Run(kind, func(t *testing.T) {
			model, frame := historyTestInput(t, kind)
			state, anchor, intent := historyTestEncode(t, model, frame)
			before := bytes.Clone(intent)
			actual, err := DecodeQuiescent(state, anchor, intent)
			if err != nil || actual.Model.Sequence != model.Sequence || !bytes.Equal(before, intent) {
				t.Fatalf("valid native history changed or refused: %+v, %v", actual, err)
			}
		})
	}
}

func TestDecodeQuiescentRejectsInvalidBoundSemantics(t *testing.T) {
	for _, kind := range []string{"generation", "duplicate", "unordered", "noncanonical-address", "chronology", "active-cause", "premature-expiry", "premature-confirmation", "foreign-frame", "future-frame", "intent-ttl", "intent-contradiction", "unknown-state", "old-format"} {
		t.Run(kind, func(t *testing.T) {
			model, frame := historyTestInput(t, "active")
			switch kind {
			case "generation":
				model.Records[0].Generation = 3
			case "duplicate":
				model.Records = append(model.Records, model.Records[0])
			case "unordered":
				model.Records = append(model.Records, model.Records[0])
				model.Records[1].Entry = "192.0.2.1"
			case "noncanonical-address":
				model.Records[0].Entry = "::ffff:192.0.2.4"
			case "chronology":
				model.Records[0].TransitionAt = "2026-01-01T12:00:01Z"
			case "active-cause":
				model.Records[0].Cause = "verified-deletion"
			case "premature-expiry":
				model.Records[0].State, model.Records[0].Cause = "expired", "native-expiry"
			case "premature-confirmation":
				model.Records[0].State, model.Records[0].Cause, model.Records[0].ConfirmedAt = "tombstoned", "verified-deletion", model.UpdatedAt
			case "foreign-frame":
				frame.Anchor.Identity = strings.Repeat("3", 64)
			case "future-frame":
				frame.Anchor.Sequence = model.Sequence + 1
			case "intent-ttl":
				frame.Intent.ExpiresAt = "2027-01-01T12:00:00Z"
			case "intent-contradiction":
				frame.Intent.Permanent = true
			case "unknown-state":
				model.Records[0].State = "custom"
			case "old-format":
				model.IntentFormat = 0
			}
			state, anchor, intent := historyTestEncode(t, model, frame)
			if _, err := DecodeQuiescent(state, anchor, intent); err == nil {
				t.Fatal("invalid but hash-bound semantics accepted")
			}
		})
	}
}

func TestDecodeQuiescentRejectsPendingAndCorruptEvidence(t *testing.T) {
	for _, kind := range []string{"pending-frame", "unbound-model", "anchor", "missing-slot", "checksum", "padding", "duplicate-field", "unknown-field", "oversize-state", "oversize-anchor"} {
		t.Run(kind, func(t *testing.T) {
			model, frame := historyTestInput(t, "active")
			state, anchor, intent := historyTestEncode(t, model, frame)
			switch kind {
			case "pending-frame":
				frame.Intent.PreparedAt = "2026-01-01T12:00:01Z"
				intent = historyTestFrame(t, frame)
			case "unbound-model":
				state = historyTestJSON(t, model)
				anchor = historyTestJSON(t, Anchor{1, model.Identity, model.Sequence, fmt.Sprintf("%x", sha256.Sum256(state))})
			case "anchor":
				anchor = bytes.Replace(anchor, []byte(`"sequence":2`), []byte(`"sequence":3`), 1)
			case "missing-slot":
				intent = nil
			case "checksum":
				intent[100] ^= 1
			case "padding":
				intent[4095] = 1
				historyTestChecksum(intent)
			case "duplicate-field":
				state = append([]byte(`{"sequence":2,`), state[1:]...)
			case "unknown-field":
				state = append([]byte(`{"custom":true,`), state[1:]...)
			case "oversize-state":
				state = make([]byte, MaximumStateBytes+1)
			case "oversize-anchor":
				anchor = make([]byte, 4097)
			}
			if _, err := DecodeQuiescent(state, anchor, intent); err == nil {
				t.Fatal("unproven history accepted")
			}
		})
	}
}

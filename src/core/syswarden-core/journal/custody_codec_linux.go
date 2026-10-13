package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	contracts "syswarden-core/contracts/v5"
)

const (
	// MaxCustodyRecords includes bootstrap, prepare, finish and approval records.
	// Exhaustion never evicts history or silently resets the enrolled scope.
	MaxCustodyRecords  = 1024
	maxCustodyDocument = 8192
	maxCustodyFile     = MaxCustodyRecords * (4 + maxCustodyDocument + sha256.Size)
	custodyFileName    = "restart-custody-v1.swc"
	custodySchema      = "syswarden.journal-custody.v1"
	custodyDomain      = "syswarden/journal-custody-record/v1\x00"
)

var ErrCustodyFormat = errors.New("invalid bounded local custody ledger")

type custodyKeyWire struct {
	JournalID     string                 `json:"journal_id"`
	Identity      contracts.NodeIdentity `json:"identity"`
	KeyID         string                 `json:"key_id"`
	PublicKey     string                 `json:"public_key"`
	FirstSequence string                 `json:"first_sequence"`
	LastSequence  string                 `json:"last_sequence"`
}
type custodyIntentWire struct {
	Before           json.RawMessage `json:"before"`
	After            json.RawMessage `json:"after"`
	SegmentName      string          `json:"segment_name"`
	SegmentSHA256    string          `json:"segment_sha256"`
	CheckpointSHA256 string          `json:"checkpoint_bundle_sha256"`
	MaxBytes         string          `json:"max_bytes"`
	MaxFrames        string          `json:"max_frames"`
	KeyID            string          `json:"key_id"`
	PublicKeySHA256  string          `json:"public_key_sha256"`
	FirstSequence    string          `json:"first_sequence"`
	LastSequence     string          `json:"last_sequence"`
}
type custodyStateWire struct {
	Initial   json.RawMessage    `json:"initial"`
	Head      json.RawMessage    `json:"head"`
	Authority custodyKeyWire     `json:"authority"`
	Pending   *custodyIntentWire `json:"pending"`
}
type custodyRecord struct {
	Schema         string           `json:"schema"`
	Sequence       string           `json:"sequence"`
	Operation      string           `json:"operation"`
	State          custodyStateWire `json:"state"`
	PlanSHA256     string           `json:"plan_sha256"`
	DecisionSHA256 string           `json:"decision_sha256"`
}

type custodyTip struct {
	state          RestartState
	plan, decision string
	hash           [sha256.Size]byte
	count, bytes   int
}

func custodyWire(s RestartState) (custodyStateWire, error) {
	if err := validateRestartState(s); err != nil {
		return custodyStateWire{}, err
	}
	initial, err := encodeAnchor(s.Initial)
	if err != nil {
		return custodyStateWire{}, err
	}
	head, err := encodeAnchor(s.Head)
	if err != nil {
		return custodyStateWire{}, err
	}
	k := s.Authority
	w := custodyStateWire{Initial: initial, Head: head, Authority: custodyKeyWire{JournalID: k.JournalID, Identity: k.Identity, KeyID: k.KeyID, PublicKey: hex.EncodeToString(k.PublicKey), FirstSequence: strconv.FormatUint(k.FirstSequence, 10), LastSequence: strconv.FormatUint(k.LastSequence, 10)}}
	if p := s.Pending; p != (CustodyIntent{}) {
		before, e := encodeAnchor(p.Before)
		if e != nil {
			return custodyStateWire{}, e
		}
		after, e := encodeAnchor(p.After)
		if e != nil {
			return custodyStateWire{}, e
		}
		w.Pending = &custodyIntentWire{Before: before, After: after, SegmentName: p.SegmentName, SegmentSHA256: p.SegmentSHA256, CheckpointSHA256: p.CheckpointSHA256, MaxBytes: strconv.Itoa(p.Limits.MaxBytes), MaxFrames: strconv.Itoa(p.Limits.MaxFrames), KeyID: p.KeyID, PublicKeySHA256: p.PublicKeySHA256, FirstSequence: strconv.FormatUint(p.FirstSequence, 10), LastSequence: strconv.FormatUint(p.LastSequence, 10)}
	}
	return w, nil
}

func custodyUint(s string, max uint64) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || n > max || strconv.FormatUint(n, 10) != s {
		return 0, ErrCustodyFormat
	}
	return n, nil
}

func custodyStateFromWire(w custodyStateWire) (RestartState, error) {
	var s RestartState
	var err error
	s.Initial, err = decodeAnchor(w.Initial)
	if err != nil {
		return RestartState{}, err
	}
	s.Head, err = decodeAnchor(w.Head)
	if err != nil {
		return RestartState{}, err
	}
	k := w.Authority
	if !validRecoveryApproval(k.PublicKey) {
		return RestartState{}, ErrCustodyFormat
	}
	pub, err := hex.DecodeString(k.PublicKey)
	if err != nil {
		return RestartState{}, err
	}
	first, e1 := custodyUint(k.FirstSequence, ^uint64(0)-1)
	last, e2 := custodyUint(k.LastSequence, ^uint64(0)-1)
	if e1 != nil || e2 != nil {
		return RestartState{}, ErrCustodyFormat
	}
	s.Authority = contracts.JournalCheckpointAuthority{JournalID: k.JournalID, Identity: k.Identity, KeyID: k.KeyID, PublicKey: pub, FirstSequence: first, LastSequence: last}
	if p := w.Pending; p != nil {
		before, e1 := decodeAnchor(p.Before)
		after, e2 := decodeAnchor(p.After)
		maxBytes, e3 := custodyUint(p.MaxBytes, contracts.MaxJournalScanBytes)
		maxFrames, e4 := custodyUint(p.MaxFrames, contracts.MaxJournalScanFrames)
		first, e5 := custodyUint(p.FirstSequence, ^uint64(0)-1)
		last, e6 := custodyUint(p.LastSequence, ^uint64(0)-1)
		if errors.Join(e1, e2, e3, e4, e5, e6) != nil || maxBytes > contracts.MaxJournalScanBytes || maxFrames > contracts.MaxJournalScanFrames {
			return RestartState{}, ErrCustodyFormat
		}
		s.Pending = CustodyIntent{Before: before, After: after, SegmentName: p.SegmentName, SegmentSHA256: p.SegmentSHA256, CheckpointSHA256: p.CheckpointSHA256, Limits: Limits{MaxBytes: int(maxBytes), MaxFrames: int(maxFrames)}, KeyID: p.KeyID, PublicKeySHA256: p.PublicKeySHA256, FirstSequence: first, LastSequence: last}
	}
	if err = validateRestartState(s); err != nil {
		return RestartState{}, err
	}
	return s, nil
}

func encodeCustodyRecord(state RestartState, sequence int, operation, plan, decision string) ([]byte, error) {
	if sequence < 1 || sequence > MaxCustodyRecords {
		return nil, ErrCustodyFormat
	}
	if operation != "bootstrap" && operation != "prepare" && operation != "finish" && operation != "approve" {
		return nil, ErrCustodyFormat
	}
	if operation == "approve" {
		if !validRecoveryApproval(plan) || !validRecoveryApproval(decision) {
			return nil, ErrCustodyFormat
		}
	} else if plan != "" || decision != "" {
		return nil, ErrCustodyFormat
	}
	w, err := custodyWire(state)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(custodyRecord{Schema: custodySchema, Sequence: strconv.Itoa(sequence), Operation: operation, State: w, PlanSHA256: plan, DecisionSHA256: decision})
	if err != nil || len(b) > maxCustodyDocument {
		return nil, ErrCustodyFormat
	}
	return b, nil
}

func decodeCustodyRecord(b []byte) (RestartState, custodyRecord, error) {
	var d custodyRecord
	if len(b) == 0 || len(b) > maxCustodyDocument || json.Unmarshal(b, &d) != nil || d.Schema != custodySchema {
		return RestartState{}, custodyRecord{}, ErrCustodyFormat
	}
	n, err := custodyUint(d.Sequence, MaxCustodyRecords)
	if err != nil || n > MaxCustodyRecords {
		return RestartState{}, custodyRecord{}, ErrCustodyFormat
	}
	s, err := custodyStateFromWire(d.State)
	if err != nil {
		return RestartState{}, custodyRecord{}, ErrCustodyFormat
	}
	canonical, err := encodeCustodyRecord(s, int(n), d.Operation, d.PlanSHA256, d.DecisionSHA256)
	if err != nil || !bytes.Equal(canonical, b) {
		return RestartState{}, custodyRecord{}, ErrCustodyFormat
	}
	return s, d, nil
}

func custodyHash(previous [sha256.Size]byte, document []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(custodyDomain))
	_, _ = h.Write(previous[:])
	_, _ = h.Write(document)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func custodyFrame(state RestartState, sequence int, operation, plan, decision string, previous [sha256.Size]byte) ([]byte, error) {
	doc, err := encodeCustodyRecord(state, sequence, operation, plan, decision)
	if err != nil {
		return nil, err
	}
	size := len(doc)
	if size > maxCustodyDocument {
		return nil, ErrCustodyFormat
	}
	out := make([]byte, 4+size+sha256.Size)
	binary.BigEndian.PutUint32(out[:4], uint32(size))
	copy(out[4:], doc)
	sum := custodyHash(previous, doc)
	copy(out[4+size:], sum[:])
	return out, nil
}

func custodyTransition(before, after RestartState, operation string) bool {
	expected := before
	switch operation {
	case "prepare":
		if before.Pending != (CustodyIntent{}) || after.Pending == (CustodyIntent{}) {
			return false
		}
		expected.Pending = after.Pending
	case "finish":
		if before.Pending == (CustodyIntent{}) {
			return false
		}
		expected.Head, expected.Pending = before.Pending.After, CustodyIntent{}
	case "approve":
		if before.Pending == (CustodyIntent{}) {
			return false
		}
	default:
		return false
	}
	return sameRestartState(expected, after)
}

func scanCustody(data []byte, enrollment RestartState) (custodyTip, error) {
	if len(data) == 0 || len(data) > maxCustodyFile {
		return custodyTip{}, ErrCustodyFormat
	}
	var tip custodyTip
	for offset := 0; offset < len(data); {
		if tip.count >= MaxCustodyRecords || len(data)-offset < 4 {
			return custodyTip{}, ErrCustodyFormat
		}
		size := binary.BigEndian.Uint32(data[offset : offset+4])
		if size == 0 || size > maxCustodyDocument || len(data)-offset-4 < int(size)+sha256.Size {
			return custodyTip{}, ErrCustodyFormat
		}
		end := offset + 4 + int(size)
		doc := data[offset+4 : end]
		s, d, err := decodeCustodyRecord(doc)
		if err != nil || d.Sequence != strconv.Itoa(tip.count+1) {
			return custodyTip{}, ErrCustodyFormat
		}
		if tip.count == 0 {
			if d.Operation != "bootstrap" || !sameRestartState(s, enrollment) {
				return custodyTip{}, ErrCustodyFormat
			}
		} else if !custodyTransition(tip.state, s, d.Operation) {
			return custodyTip{}, ErrCustodyFormat
		}
		sum := custodyHash(tip.hash, doc)
		if !bytes.Equal(data[end:end+sha256.Size], sum[:]) {
			return custodyTip{}, ErrCustodyFormat
		}
		tip.state, tip.hash, tip.plan, tip.decision = s, sum, d.PlanSHA256, d.DecisionSHA256
		tip.count++
		offset = end + sha256.Size
	}
	tip.bytes = len(data)
	return tip, nil
}

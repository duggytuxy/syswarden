package v5

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
)

const (
	JournalCheckpointSchema = "syswarden.journal-checkpoint.v1"
	MaxCheckpointBytes      = 4096
	checkpointDomain        = "syswarden/journal-checkpoint/v1\x00"
)

var (
	ErrInvalidJournalCheckpoint = errors.New("invalid journal checkpoint")
	ErrInvalidCheckpointTrust   = errors.New("invalid journal checkpoint trust context")
	ErrCheckpointNotAuthorized  = errors.New("journal checkpoint does not match the authorized continuity context")
	ErrCheckpointSignature      = errors.New("journal checkpoint signature is invalid")
	ErrCheckpointSegment        = errors.New("journal segment does not match the authenticated checkpoint")
)

// JournalPosition encodes a cursor position using an exact decimal sequence.
// Journal and membership identity are carried once by the checkpoint.
type JournalPosition struct {
	NextSequence   string `json:"next_sequence"`
	PreviousSHA256 string `json:"previous_sha256"`
}

func checkpointInteger(s string, minimum, maximum uint64) (uint64, bool) {
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && n >= minimum && n <= maximum && strconv.FormatUint(n, 10) == s
}

// JournalCheckpoint is a signer statement about a bounded segment, not proof
// that the signer actually wrote or synchronized it. It contains no key bytes.
// RecordedAt is declared metadata, never a replay counter or trusted timestamp.
type JournalCheckpoint struct {
	Schema                   string          `json:"schema"`
	CheckpointID             string          `json:"checkpoint_id"`
	Sequence                 string          `json:"sequence"`
	KeyID                    string          `json:"key_id"`
	JournalID                string          `json:"journal_id"`
	Identity                 NodeIdentity    `json:"identity"`
	PreviousCheckpointSHA256 string          `json:"previous_checkpoint_sha256"`
	Start                    JournalPosition `json:"start"`
	End                      JournalPosition `json:"end"`
	SegmentBytes             string          `json:"segment_bytes"`
	RecordedAt               string          `json:"recorded_at"`
	ClockQuality             string          `json:"clock_quality"`
}

func (c JournalCheckpoint) Validate() error {
	_, sequenceOK := checkpointInteger(c.Sequence, 1, math.MaxUint64-1)
	start, startOK := checkpointInteger(c.Start.NextSequence, 1, math.MaxUint64)
	end, endOK := checkpointInteger(c.End.NextSequence, 1, math.MaxUint64)
	size, sizeOK := checkpointInteger(c.SegmentBytes, 0, MaxJournalScanBytes)
	if c.Schema != JournalCheckpointSchema || !identifier(c.CheckpointID) || !identifier(c.KeyID) ||
		!identifier(c.JournalID) || c.Identity.Validate() != nil || !digest(c.PreviousCheckpointSHA256) ||
		!sequenceOK || !startOK || !endOK || !sizeOK || !digest(c.Start.PreviousSHA256) || !digest(c.End.PreviousSHA256) ||
		!timestamp(c.RecordedAt) || !member("unknown", "synchronized", "unsynchronized")(c.ClockQuality) {
		return ErrInvalidJournalCheckpoint
	}
	if end < start || end-start > MaxJournalScanFrames {
		return ErrInvalidJournalCheckpoint
	}
	if end == start {
		if size != 0 || c.End != c.Start {
			return ErrInvalidJournalCheckpoint
		}
	} else if size < (end-start)*(journalPrefixBytes+journalHashBytes+2) {
		// Even the smallest syntactic frame has positive header/payload lengths.
		return ErrInvalidJournalCheckpoint
	}
	return nil
}

// EncodeJournalCheckpoint pins compact struct-order JSON without a newline.
// Signatures bind these exact bytes, not a decoder-normalized equivalent.
func EncodeJournalCheckpoint(c JournalCheckpoint) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(c)
	if err != nil || len(data) > MaxCheckpointBytes {
		return nil, ErrInvalidJournalCheckpoint
	}
	return data, nil
}

// DecodeJournalCheckpoint checks canonical shape only, never authenticity.
func DecodeJournalCheckpoint(data []byte) (JournalCheckpoint, error) {
	if len(data) > MaxCheckpointBytes {
		return JournalCheckpoint{}, ErrInvalidJournalCheckpoint
	}
	v, err := parseDocument(data)
	if err != nil || !exactShape(v, reflect.TypeFor[JournalCheckpoint]()) {
		return JournalCheckpoint{}, ErrInvalidJournalCheckpoint
	}
	var c JournalCheckpoint
	if json.Unmarshal(data, &c) != nil {
		return JournalCheckpoint{}, ErrInvalidJournalCheckpoint
	}
	canonical, err := EncodeJournalCheckpoint(c)
	if err != nil || !bytes.Equal(canonical, data) {
		return JournalCheckpoint{}, ErrInvalidJournalCheckpoint
	}
	return c, nil
}

func checkpointMessage(data []byte) []byte {
	message := make([]byte, len(checkpointDomain)+len(data))
	copy(message, checkpointDomain)
	copy(message[len(checkpointDomain):], data)
	return message
}

// JournalCheckpointSigningMessage supplies the domain-separated message for a
// future authorized Ed25519 signer. It does not hold a key, sign, perform I/O,
// authorize a signer or assert a durable commit. It returns owned bytes.
func JournalCheckpointSigningMessage(c JournalCheckpoint) ([]byte, error) {
	data, err := EncodeJournalCheckpoint(c)
	if err != nil {
		return nil, err
	}
	return checkpointMessage(data), nil
}

// JournalCheckpointAnchor must come from independently protected continuity
// state. Both counters are local to one journal and membership epoch. No
// all-zero digest or initial counter automatically establishes a trusted root.
type JournalCheckpointAnchor struct {
	Cursor         JournalCursor
	NextSequence   uint64
	PreviousSHA256 string
}

// JournalCheckpointAuthority is resolved outside this package from a trusted
// registry for the anchor's exact journal and membership. Sequence limits are
// inclusive and explicit; a checkpoint never enrolls or rotates its own key.
// The resolver must apply current revocation and authorization policy.
type JournalCheckpointAuthority struct {
	JournalID     string
	Identity      NodeIdentity
	KeyID         string
	PublicKey     ed25519.PublicKey
	FirstSequence uint64
	LastSequence  uint64
}

type JournalCheckpointContext struct {
	Anchor    JournalCheckpointAnchor
	Authority JournalCheckpointAuthority
}

func (c JournalCheckpointContext) validate() bool {
	a, k := c.Anchor, c.Authority
	return a.Cursor.validate() && a.NextSequence > 0 && a.NextSequence < math.MaxUint64 && digest(a.PreviousSHA256) &&
		k.JournalID == a.Cursor.JournalID && k.Identity == a.Cursor.Identity &&
		identifier(k.KeyID) && len(k.PublicKey) == ed25519.PublicKeySize && k.FirstSequence > 0 &&
		k.LastSequence >= k.FirstSequence && k.LastSequence < math.MaxUint64
}

func (c JournalCheckpoint) cursor(p JournalPosition) JournalCursor {
	n, _ := strconv.ParseUint(p.NextSequence, 10, 64)
	return JournalCursor{JournalID: c.JournalID, Identity: c.Identity, NextSequence: n, PreviousSHA256: p.PreviousSHA256}
}

// VerifyJournalCheckpoint authenticates a historical statement against an
// independently authorized key and exact next continuity anchor. It performs
// no time-freshness check and reads no segment. The proposed next anchor must
// not be committed merely because metadata authentication succeeded.
// Failure returns neither metadata nor an advanced anchor.
func VerifyJournalCheckpoint(data, signature []byte, context JournalCheckpointContext) (JournalCheckpoint, JournalCheckpointAnchor, error) {
	if !context.validate() {
		return JournalCheckpoint{}, JournalCheckpointAnchor{}, ErrInvalidCheckpointTrust
	}
	c, err := DecodeJournalCheckpoint(data)
	if err != nil {
		return JournalCheckpoint{}, JournalCheckpointAnchor{}, err
	}
	a, k := context.Anchor, context.Authority
	if c.cursor(c.Start) != a.Cursor || c.Sequence != strconv.FormatUint(a.NextSequence, 10) ||
		c.PreviousCheckpointSHA256 != a.PreviousSHA256 || c.KeyID != k.KeyID ||
		a.NextSequence < k.FirstSequence || a.NextSequence > k.LastSequence {
		return JournalCheckpoint{}, JournalCheckpointAnchor{}, ErrCheckpointNotAuthorized
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(k.PublicKey, checkpointMessage(data), signature) {
		return JournalCheckpoint{}, JournalCheckpointAnchor{}, ErrCheckpointSignature
	}
	next := JournalCheckpointAnchor{Cursor: c.cursor(c.End), NextSequence: a.NextSequence + 1, PreviousSHA256: journalDigest(data)}
	return c, next, nil
}

// ReadAuthenticatedJournalSegment authenticates exact checkpoint bytes again
// and checks the complete segment against them. It never trusts a mutable
// "verified" struct supplied by a caller. Failure exposes no partial records
// or advanced anchor. The caller still owns durable anchor storage, source
// authenticity, read authorization and concurrency/anti-rollback authority.
func ReadAuthenticatedJournalSegment(data, checkpoint, signature []byte, context JournalCheckpointContext, maxBytes, maxFrames int) (JournalScan, JournalCheckpointAnchor, error) {
	c, next, err := VerifyJournalCheckpoint(checkpoint, signature, context)
	if err != nil {
		return JournalScan{}, JournalCheckpointAnchor{}, err
	}
	if c.SegmentBytes != strconv.Itoa(len(data)) {
		return JournalScan{}, JournalCheckpointAnchor{}, ErrCheckpointSegment
	}
	scan, err := ReadEventJournalSegment(data, JournalReadContext{Start: context.Anchor.Cursor, MaxBytes: maxBytes, MaxFrames: maxFrames}, next.Cursor)
	if err != nil {
		return JournalScan{}, JournalCheckpointAnchor{}, err
	}
	return scan, next, nil
}

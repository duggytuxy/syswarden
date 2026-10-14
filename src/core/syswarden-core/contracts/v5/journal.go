package v5

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
)

const (
	EventJournalFrameSchema = "syswarden.event-journal-frame.v1"
	MaxJournalHeaderBytes   = 2048
	MaxJournalScanBytes     = 8 * 1024 * 1024
	MaxJournalScanFrames    = 1024
	journalMagic            = "SWJEV1\x00\x00"
	journalPrefixBytes      = 16
	journalHashBytes        = sha256.Size

	JournalCleanBoundary  = "clean_boundary"
	JournalIncompleteTail = "incomplete_tail"
	JournalCorruptTail    = "corrupt_tail"
	JournalFrameLimit     = "frame_limit"
)

var (
	ErrInvalidJournalContext = errors.New("invalid event journal context")
	ErrJournalInputTooLarge  = errors.New("event journal input exceeds the caller byte budget")
	ErrJournalSequenceLimit  = errors.New("event journal sequence is exhausted")
	ErrInvalidJournalEvent   = errors.New("invalid event journal observation")
	ErrJournalEndMismatch    = errors.New("event journal does not match the expected end cursor")
)

// JournalCursor is an independently established anchor, not an authenticated
// checkpoint. A reader must obtain journal identity, membership epoch and the
// previous frame digest from its trusted context, never from the first frame.
type JournalCursor struct {
	JournalID      string
	Identity       NodeIdentity
	NextSequence   uint64
	PreviousSHA256 string
}

func (c JournalCursor) validate() bool {
	return identifier(c.JournalID) && c.Identity.Validate() == nil && c.NextSequence > 0 && digest(c.PreviousSHA256)
}

// EventJournalHeader is canonical metadata for one exact event payload. The
// sequence is local journal order, not cross-node causal or source-time order.
type EventJournalHeader struct {
	Schema         string       `json:"schema"`
	JournalID      string       `json:"journal_id"`
	Identity       NodeIdentity `json:"identity"`
	Sequence       string       `json:"sequence"`
	PreviousSHA256 string       `json:"previous_sha256"`
	EventID        string       `json:"event_id"`
	PayloadSHA256  string       `json:"payload_sha256"`
}

func (h EventJournalHeader) validate() bool {
	n, err := strconv.ParseUint(h.Sequence, 10, 64)
	return h.Schema == EventJournalFrameSchema && identifier(h.JournalID) && h.Identity.Validate() == nil &&
		err == nil && n > 0 && n < math.MaxUint64 && strconv.FormatUint(n, 10) == h.Sequence &&
		digest(h.PreviousSHA256) && identifier(h.EventID) && digest(h.PayloadSHA256)
}

func decodeJournalHeader(data []byte) (EventJournalHeader, bool) {
	if len(data) > MaxJournalHeaderBytes {
		return EventJournalHeader{}, false
	}
	value, err := parseDocument(data)
	if err != nil || !exactShape(value, reflect.TypeFor[EventJournalHeader]()) {
		return EventJournalHeader{}, false
	}
	var h EventJournalHeader
	if json.Unmarshal(data, &h) != nil || !h.validate() {
		return EventJournalHeader{}, false
	}
	canonical, err := json.Marshal(h)
	if err != nil || !bytes.Equal(canonical, data) {
		return EventJournalHeader{}, false
	}
	return h, true
}

func journalDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func journalEvent(data []byte, identity NodeIdentity) (Event, bool) {
	e, err := DecodeEvent(data)
	return e, err == nil && e.EventID.State == Present && e.NodeID.State == Present && e.NodeID.Value == identity.NodeID
}

// EncodeEventJournalFrame copies and binds one validated event's exact JSON
// bytes. It performs no I/O, durability claim, signing or membership decision.
// The returned next cursor is usable only after the future writer commits the
// complete frame durably. On failure, neither bytes nor a cursor are returned.
func EncodeEventJournalFrame(payload []byte, cursor JournalCursor) ([]byte, JournalCursor, error) {
	if !cursor.validate() {
		return nil, JournalCursor{}, ErrInvalidJournalContext
	}
	if cursor.NextSequence == math.MaxUint64 {
		return nil, JournalCursor{}, ErrJournalSequenceLimit
	}
	payloadSize := len(payload)
	if payloadSize <= 0 || payloadSize > MaxDocumentBytes {
		return nil, JournalCursor{}, ErrInvalidJournalEvent
	}
	e, ok := journalEvent(payload, cursor.Identity)
	if !ok {
		return nil, JournalCursor{}, ErrInvalidJournalEvent
	}
	h := EventJournalHeader{Schema: EventJournalFrameSchema, JournalID: cursor.JournalID, Identity: cursor.Identity,
		Sequence: strconv.FormatUint(cursor.NextSequence, 10), PreviousSHA256: cursor.PreviousSHA256,
		EventID: e.EventID.Value, PayloadSHA256: journalDigest(payload)}
	header, err := json.Marshal(h)
	headerSize := len(header)
	if err != nil || headerSize <= 0 || headerSize > MaxJournalHeaderBytes {
		return nil, JournalCursor{}, ErrInvalidJournalEvent
	}
	// Both conversions are bounded by the header and strict event codec limits.
	frame := make([]byte, journalPrefixBytes+len(header)+len(payload)+journalHashBytes)
	copy(frame, journalMagic)
	binary.BigEndian.PutUint32(frame[8:12], uint32(headerSize))
	binary.BigEndian.PutUint32(frame[12:16], uint32(payloadSize))
	copy(frame[journalPrefixBytes:], header)
	copy(frame[journalPrefixBytes+len(header):], payload)
	sum := sha256.Sum256(frame[:len(frame)-journalHashBytes])
	copy(frame[len(frame)-journalHashBytes:], sum[:])
	next := cursor
	next.NextSequence++
	next.PreviousSHA256 = hex.EncodeToString(sum[:])
	return frame, next, nil
}

// JournalReadContext requires explicit per-call budgets. These hard caps are
// framing limits, not measured runtime or retention budgets. Apply MaxBytes
// before allocating/reading the input too. Start is independently resolved.
type JournalReadContext struct {
	Start     JournalCursor
	MaxBytes  int
	MaxFrames int
}

// JournalRecord owns its payload copy, including whitespace and final newline.
// It is a verified frame in a prefix, not proof of event authenticity or a
// deduplicated observation. Separate journal entries can reference one event.
type JournalRecord struct {
	Header      EventJournalHeader
	Payload     []byte
	FrameSHA256 string
	Offset      int
	NextOffset  int
}

// JournalScan exposes the accepted prefix and every unverified trailing byte.
// CleanBoundary means the supplied bytes end on a valid frame boundary only.
// It does not prove that a whole frame/segment was not deleted or rolled back.
type JournalScan struct {
	Records         []JournalRecord
	Cursor          JournalCursor
	VerifiedBytes   int
	UnverifiedBytes int
	Tail            string
	ReasonCode      string
}

// ScanEventJournal stops at the first incomplete/corrupt frame or frame limit.
// It never searches for a later magic marker, edits bytes, discards a tail or
// authorizes an append. Only invalid context or an exceeded input-byte budget
// returns an error with a zero result; tail conditions are explicit results.
func ScanEventJournal(data []byte, context JournalReadContext) (JournalScan, error) {
	if !context.Start.validate() || context.MaxBytes <= 0 || context.MaxBytes > MaxJournalScanBytes ||
		context.MaxFrames <= 0 || context.MaxFrames > MaxJournalScanFrames {
		return JournalScan{}, ErrInvalidJournalContext
	}
	if len(data) > context.MaxBytes {
		return JournalScan{}, ErrJournalInputTooLarge
	}
	result := JournalScan{Cursor: context.Start, Tail: JournalCleanBoundary, ReasonCode: "none"}
	stop := func(tail, reason string) (JournalScan, error) {
		result.Tail, result.ReasonCode = tail, reason
		result.UnverifiedBytes = len(data) - result.VerifiedBytes
		return result, nil
	}
	for result.VerifiedBytes < len(data) {
		if len(result.Records) >= context.MaxFrames {
			return stop(JournalFrameLimit, "frame_budget_exhausted")
		}
		rest := data[result.VerifiedBytes:]
		if len(rest) < journalPrefixBytes {
			return stop(JournalIncompleteTail, "incomplete_prefix")
		}
		if string(rest[:8]) != journalMagic {
			return stop(JournalCorruptTail, "invalid_magic")
		}
		headerBytes := binary.BigEndian.Uint32(rest[8:12])
		payloadBytes := binary.BigEndian.Uint32(rest[12:16])
		if headerBytes == 0 || headerBytes > MaxJournalHeaderBytes || payloadBytes == 0 || payloadBytes > MaxDocumentBytes {
			return stop(JournalCorruptTail, "invalid_lengths")
		}
		// Convert only after checking small wire limits, including on 32-bit hosts.
		headerEnd := journalPrefixBytes + int(headerBytes)
		payloadEnd := headerEnd + int(payloadBytes)
		frameEnd := payloadEnd + journalHashBytes
		if len(rest) < frameEnd {
			return stop(JournalIncompleteTail, "incomplete_frame")
		}
		sum := sha256.Sum256(rest[:payloadEnd])
		if !bytes.Equal(sum[:], rest[payloadEnd:frameEnd]) {
			return stop(JournalCorruptTail, "frame_digest_mismatch")
		}
		h, ok := decodeJournalHeader(rest[journalPrefixBytes:headerEnd])
		if !ok {
			return stop(JournalCorruptTail, "invalid_header")
		}
		if h.JournalID != result.Cursor.JournalID || h.Identity != result.Cursor.Identity ||
			h.Sequence != strconv.FormatUint(result.Cursor.NextSequence, 10) || h.PreviousSHA256 != result.Cursor.PreviousSHA256 {
			return stop(JournalCorruptTail, "chain_mismatch")
		}
		payload := rest[headerEnd:payloadEnd]
		if journalDigest(payload) != h.PayloadSHA256 {
			return stop(JournalCorruptTail, "payload_digest_mismatch")
		}
		e, ok := journalEvent(payload, result.Cursor.Identity)
		if !ok || e.EventID.Value != h.EventID {
			return stop(JournalCorruptTail, "invalid_event")
		}
		frameHash := hex.EncodeToString(sum[:])
		nextOffset := result.VerifiedBytes + frameEnd
		result.Records = append(result.Records, JournalRecord{Header: h, Payload: bytes.Clone(payload), FrameSHA256: frameHash,
			Offset: result.VerifiedBytes, NextOffset: nextOffset})
		result.VerifiedBytes = nextOffset
		result.Cursor.NextSequence++
		result.Cursor.PreviousSHA256 = frameHash
	}
	return result, nil
}

// ReadEventJournalSegment scans exact bytes and requires an independently
// trusted end cursor. It detects whole-frame truncation, extension or rollback
// relative to that anchor. A failed bound read returns no usable prefix; use
// ScanEventJournal separately for explicit recovery inspection. This neither
// authenticates anchors nor protects against replacement of local checkpoints.
func ReadEventJournalSegment(data []byte, context JournalReadContext, expected JournalCursor) (JournalScan, error) {
	if !expected.validate() || expected.JournalID != context.Start.JournalID || expected.Identity != context.Start.Identity ||
		expected.NextSequence < context.Start.NextSequence {
		return JournalScan{}, ErrInvalidJournalContext
	}
	scan, err := ScanEventJournal(data, context)
	if err != nil {
		return JournalScan{}, err
	}
	if scan.Tail != JournalCleanBoundary || scan.UnverifiedBytes != 0 || scan.Cursor != expected {
		return JournalScan{}, ErrJournalEndMismatch
	}
	return scan, nil
}

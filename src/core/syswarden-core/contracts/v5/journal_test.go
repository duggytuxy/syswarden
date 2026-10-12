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
	"strings"
	"testing"
)

func journalContext() JournalReadContext {
	return JournalReadContext{Start: JournalCursor{JournalID: "journal.fixture.1", Identity: readContext().ExpectedIdentity,
		NextSequence: 1, PreviousSHA256: strings.Repeat("0", 64)}, MaxBytes: MaxJournalScanBytes, MaxFrames: MaxJournalScanFrames}
}

func journalFrames(t testing.TB) ([]byte, int, JournalCursor, JournalCursor) {
	t.Helper()
	c := journalContext()
	first, middle, err := EncodeEventJournalFrame(fixture(t, "native-ip.json"), c.Start)
	if err != nil {
		t.Fatal(err)
	}
	second, end, err := EncodeEventJournalFrame(fixture(t, "native-l2.json"), middle)
	if err != nil {
		t.Fatal(err)
	}
	return append(first, second...), len(first), middle, end
}

// Reframing with a fresh digest exercises semantic validation independently
// of accidental byte corruption. It models a producer that can recompute hashes.
func testJournalReframe(t testing.TB, header, payload []byte) []byte {
	t.Helper()
	headerSize, payloadSize := len(header), len(payload)
	if headerSize <= 0 || headerSize > MaxJournalHeaderBytes || payloadSize <= 0 || payloadSize > MaxDocumentBytes {
		t.Fatal("invalid reframing fixture size")
		return nil
	}
	data := make([]byte, journalPrefixBytes+len(header)+len(payload)+journalHashBytes)
	copy(data, journalMagic)
	binary.BigEndian.PutUint32(data[8:12], uint32(headerSize))
	binary.BigEndian.PutUint32(data[12:16], uint32(payloadSize))
	copy(data[16:], header)
	copy(data[16+len(header):], payload)
	sum := sha256.Sum256(data[:len(data)-journalHashBytes])
	copy(data[len(data)-journalHashBytes:], sum[:])
	return data
}

func TestJournalGoldenAndExactPayload(t *testing.T) {
	data, boundary, middle, end := journalFrames(t)
	golden, err := hex.DecodeString(string(fixture(t, "journal-two-events.hex")))
	if err != nil || !bytes.Equal(data, golden) {
		t.Fatal("journal wire bytes changed", err)
	}
	s, err := ReadEventJournalSegment(golden, journalContext(), end)
	if err != nil || len(s.Records) != 2 || s.Cursor != end || s.VerifiedBytes != len(data) || s.UnverifiedBytes != 0 || s.Tail != JournalCleanBoundary {
		t.Fatal("valid anchored segment rejected", err)
	}
	for i, name := range []string{"native-ip.json", "native-l2.json"} {
		if !bytes.Equal(s.Records[i].Payload, fixture(t, name)) || s.Records[i].Header.Sequence != strconv.Itoa(i+1) {
			t.Fatal("event bytes or order changed")
		}
	}
	if s.Records[0].Offset != 0 || s.Records[0].NextOffset != boundary || s.Records[1].Offset != boundary || s.Records[1].NextOffset != len(data) {
		t.Fatal("incorrect byte offsets")
	}
	if s.Records[0].FrameSHA256 != middle.PreviousSHA256 || s.Records[1].FrameSHA256 != end.PreviousSHA256 {
		t.Fatal("cursor digest mismatch")
	}
	payloadOffset := journalPrefixBytes + int(binary.BigEndian.Uint32(golden[8:12]))
	golden[payloadOffset] ^= 1
	if !bytes.Equal(s.Records[0].Payload, fixture(t, "native-ip.json")) {
		t.Fatal("scan output aliases input")
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, fixture(t, "native-ip.json"), "", "  "); err != nil {
		t.Fatal(err)
	}
	payload := append(pretty.Bytes(), '\n')
	frame, next, err := EncodeEventJournalFrame(payload, journalContext().Start)
	if err != nil {
		t.Fatal(err)
	}
	copyOfPayload := bytes.Clone(payload)
	payload[0] = 'x'
	read, err := ReadEventJournalSegment(frame, journalContext(), next)
	if err != nil || !bytes.Equal(read.Records[0].Payload, copyOfPayload) {
		t.Fatal("exact whitespace/newline changed or encoder aliased payload", err)
	}
}

func TestJournalEveryInterruptedWritePosition(t *testing.T) {
	data, boundary, middle, end := journalFrames(t)
	for cut := 0; cut < len(data); cut++ {
		s, err := ScanEventJournal(data[:cut], journalContext())
		if err != nil {
			t.Fatal("bounded prefix returned context error", cut, err)
		}
		wantBytes, wantRecords, wantCursor := 0, 0, journalContext().Start
		if cut >= boundary {
			wantBytes, wantRecords, wantCursor = boundary, 1, middle
		}
		wantTail := JournalIncompleteTail
		if cut == 0 || cut == boundary {
			wantTail = JournalCleanBoundary
		}
		if s.VerifiedBytes != wantBytes || s.UnverifiedBytes != cut-wantBytes || len(s.Records) != wantRecords || s.Cursor != wantCursor || s.Tail != wantTail {
			t.Fatal("interruption hid bytes or fabricated a record", cut, s.Tail, s.VerifiedBytes)
		}
		bound, err := ReadEventJournalSegment(data[:cut], journalContext(), end)
		if !errors.Is(err, ErrJournalEndMismatch) || !reflect.DeepEqual(bound, JournalScan{}) {
			t.Fatal("truncated segment became complete", cut, err)
		}
	}
}

func TestJournalCorruptionDoesNotSkipOrResynchronize(t *testing.T) {
	data, boundary, middle, end := journalFrames(t)
	for _, at := range []int{0, 7, 16, boundary - 1, boundary, boundary + 16, len(data) - 1} {
		bad := bytes.Clone(data)
		bad[at] ^= 0x40
		s, err := ScanEventJournal(bad, journalContext())
		wantOffset, wantCursor := 0, journalContext().Start
		if at >= boundary {
			wantOffset, wantCursor = boundary, middle
		}
		if err != nil || s.Tail != JournalCorruptTail || s.VerifiedBytes != wantOffset || s.Cursor != wantCursor || s.UnverifiedBytes != len(bad)-wantOffset {
			t.Fatal("corrupt data hidden or skipped", at, err, s.ReasonCode)
		}
		if bound, err := ReadEventJournalSegment(bad, journalContext(), end); !errors.Is(err, ErrJournalEndMismatch) || !reflect.DeepEqual(bound, JournalScan{}) {
			t.Fatal("corrupt segment released records", err)
		}
	}
	// A later valid-looking magic/frame cannot resurrect a damaged prefix.
	bad := append(bytes.Repeat([]byte{'x'}, journalPrefixBytes), data...)
	s, err := ScanEventJournal(bad, journalContext())
	if err != nil || len(s.Records) != 0 || s.VerifiedBytes != 0 || s.UnverifiedBytes != len(bad) || s.ReasonCode != "invalid_magic" {
		t.Fatal("reader searched beyond corruption", err)
	}
}

func TestJournalRejectsReplayedReorderedAndCrossScopeFrames(t *testing.T) {
	data, boundary, middle, _ := journalFrames(t)
	first, second := data[:boundary], data[boundary:]
	for name, input := range map[string][]byte{
		"replayed frame":   append(bytes.Clone(first), first...),
		"reordered frames": append(bytes.Clone(second), first...),
		"missing first":    bytes.Clone(second),
	} {
		t.Run(name, func(t *testing.T) {
			s, err := ScanEventJournal(input, journalContext())
			if err != nil || s.Tail != JournalCorruptTail || s.ReasonCode != "chain_mismatch" {
				t.Fatal("replay or reorder accepted", err)
			}
		})
	}
	for name, change := range map[string]func(*JournalCursor){
		"journal":  func(c *JournalCursor) { c.JournalID = "journal.other" },
		"cluster":  func(c *JournalCursor) { c.Identity.ClusterID = "cluster.other" },
		"node":     func(c *JournalCursor) { c.Identity.NodeID = "node.other" },
		"epoch":    func(c *JournalCursor) { c.Identity.Epoch = "epoch.other" },
		"sequence": func(c *JournalCursor) { c.NextSequence = 2 },
		"anchor":   func(c *JournalCursor) { c.PreviousSHA256 = strings.Repeat("1", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			c := journalContext()
			change(&c.Start)
			s, err := ScanEventJournal(data, c)
			if err != nil || s.Tail != JournalCorruptTail || len(s.Records) != 0 || s.ReasonCode != "chain_mismatch" {
				t.Fatal("scope/anchor mismatch accepted", err)
			}
		})
	}
	// Resuming at an independently pinned middle cursor is an explicit segment.
	c := journalContext()
	c.Start = middle
	if s, err := ScanEventJournal(second, c); err != nil || s.Tail != JournalCleanBoundary || len(s.Records) != 1 {
		t.Fatal("valid anchored continuation rejected", err)
	}
}

func TestJournalHeaderAndPayloadValidationBeyondHashes(t *testing.T) {
	data, boundary, _, _ := journalFrames(t)
	headerLen := int(binary.BigEndian.Uint32(data[8:12]))
	head := data[16 : 16+headerLen]
	payload := data[16+headerLen : boundary-journalHashBytes]
	for name, header := range map[string][]byte{
		"unknown schema":   bytes.Replace(head, []byte(EventJournalFrameSchema), []byte("future"), 1),
		"whitespace":       append([]byte(" "), head...),
		"duplicate":        bytes.Replace(head, []byte("{"), []byte(`{"schema":"ignored",`), 1),
		"alias":            bytes.Replace(head, []byte(`"event_id":`), []byte(`"Event_ID":`), 1),
		"missing":          bytes.Replace(head, []byte(`"event_id":"event.fixture.1",`), nil, 1),
		"leading zero":     bytes.Replace(head, []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1),
		"numeric sequence": bytes.Replace(head, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1),
		"invalid Unicode":  bytes.Replace(head, []byte("journal.fixture.1"), []byte{0xff}, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(head, header) {
				t.Fatal("mutation did not touch header")
			}
			s, err := ScanEventJournal(testJournalReframe(t, header, payload), journalContext())
			if err != nil || s.ReasonCode != "invalid_header" || len(s.Records) != 0 {
				t.Fatal("self-consistent malformed header accepted", err, s.ReasonCode)
			}
		})
	}
	var header EventJournalHeader
	if err := json.Unmarshal(head, &header); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*EventJournalHeader){
		func(h *EventJournalHeader) { h.EventID = "event.other" },
		func(h *EventJournalHeader) { h.PayloadSHA256 = strings.Repeat("1", 64) },
	} {
		h := header
		change(&h)
		raw, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ScanEventJournal(testJournalReframe(t, raw, payload), journalContext())
		if err != nil || s.Tail != JournalCorruptTail || len(s.Records) != 0 {
			t.Fatal("recomputed frame hash hid substituted metadata", err)
		}
	}
	for _, badPayload := range [][]byte{[]byte(`{"schema":null}`), fixture(t, "rate-mixed.json")} {
		h := header
		h.PayloadSHA256 = journalDigest(badPayload)
		raw, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ScanEventJournal(testJournalReframe(t, raw, badPayload), journalContext())
		if err != nil || s.ReasonCode != "invalid_event" || len(s.Records) != 0 {
			t.Fatal("non-event with valid hashes accepted", err)
		}
	}
}

func TestJournalCallerBoundsAndLengthAttacks(t *testing.T) {
	data, boundary, middle, end := journalFrames(t)
	for name, change := range map[string]func(*JournalReadContext){
		"zero bytes":      func(c *JournalReadContext) { c.MaxBytes = 0 },
		"overlong bytes":  func(c *JournalReadContext) { c.MaxBytes = MaxJournalScanBytes + 1 },
		"zero frames":     func(c *JournalReadContext) { c.MaxFrames = 0 },
		"overlong frames": func(c *JournalReadContext) { c.MaxFrames = MaxJournalScanFrames + 1 },
		"empty journal":   func(c *JournalReadContext) { c.Start.JournalID = "" },
		"empty epoch":     func(c *JournalReadContext) { c.Start.Identity.Epoch = "" },
		"zero sequence":   func(c *JournalReadContext) { c.Start.NextSequence = 0 },
		"empty digest":    func(c *JournalReadContext) { c.Start.PreviousSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := journalContext()
			change(&c)
			if s, err := ScanEventJournal(data, c); !errors.Is(err, ErrInvalidJournalContext) || !reflect.DeepEqual(s, JournalScan{}) {
				t.Fatal("invalid context gave usable output", err)
			}
		})
	}
	c := journalContext()
	c.MaxBytes = len(data) - 1
	if s, err := ScanEventJournal(data, c); !errors.Is(err, ErrJournalInputTooLarge) || !reflect.DeepEqual(s, JournalScan{}) {
		t.Fatal("byte budget silently truncated input", err)
	}
	c.MaxBytes = len(data)
	c.MaxFrames = 1
	s, err := ScanEventJournal(data, c)
	if err != nil || s.Tail != JournalFrameLimit || s.Cursor != middle || s.VerifiedBytes != boundary || s.UnverifiedBytes != len(data)-boundary {
		t.Fatal("frame budget hid remaining bytes", err)
	}
	if bound, err := ReadEventJournalSegment(data, c, end); !errors.Is(err, ErrJournalEndMismatch) || !reflect.DeepEqual(bound, JournalScan{}) {
		t.Fatal("limited prefix became complete", err)
	}
	if s, err := ScanEventJournal(data[:boundary], c); err != nil || s.Tail != JournalCleanBoundary {
		t.Fatal("exact frame boundary rejected", err)
	}
	for _, lengths := range [][2]uint32{{0, 1}, {1, 0}, {MaxJournalHeaderBytes + 1, 1}, {1, MaxDocumentBytes + 1}, {math.MaxUint32, math.MaxUint32}} {
		bad := make([]byte, journalPrefixBytes)
		copy(bad, journalMagic)
		binary.BigEndian.PutUint32(bad[8:12], lengths[0])
		binary.BigEndian.PutUint32(bad[12:16], lengths[1])
		if s, err := ScanEventJournal(bad, journalContext()); err != nil || s.ReasonCode != "invalid_lengths" || s.VerifiedBytes != 0 {
			t.Fatal("hostile length accepted", err)
		}
	}
}

func TestJournalEncoderAndSequenceLimit(t *testing.T) {
	c := journalContext().Start
	for _, payload := range [][]byte{nil, fixture(t, "rate-mixed.json"), bytes.Repeat([]byte(" "), MaxDocumentBytes+1), fixture(t, "legacy-projections.ndjson")} {
		data, next, err := EncodeEventJournalFrame(payload, c)
		if !errors.Is(err, ErrInvalidJournalEvent) || data != nil || next != (JournalCursor{}) {
			t.Fatal("invalid observation encoded", err)
		}
	}
	for _, change := range []func(*Event){
		func(e *Event) { e.EventID = Field{State: Missing} },
		func(e *Event) { e.NodeID = Field{State: Missing} },
		func(e *Event) { e.NodeID = Field{State: Present, Value: "node.other"} },
	} {
		e, err := DecodeEvent(fixture(t, "native-ip.json"))
		if err != nil {
			t.Fatal(err)
		}
		change(&e)
		payload, err := EncodeEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		if data, next, err := EncodeEventJournalFrame(payload, c); !errors.Is(err, ErrInvalidJournalEvent) || data != nil || next != (JournalCursor{}) {
			t.Fatal("unidentified/cross-node event encoded", err)
		}
	}
	bad := c
	bad.NextSequence = 0
	if data, next, err := EncodeEventJournalFrame(fixture(t, "native-ip.json"), bad); !errors.Is(err, ErrInvalidJournalContext) || data != nil || next != (JournalCursor{}) {
		t.Fatal("invalid cursor encoded", err)
	}
	c.NextSequence = math.MaxUint64 - 1
	data, next, err := EncodeEventJournalFrame(fixture(t, "native-ip.json"), c)
	if err != nil || next.NextSequence != math.MaxUint64 {
		t.Fatal("last valid sequence rejected", err)
	}
	readContext := journalContext()
	readContext.Start = c
	if _, err := ReadEventJournalSegment(data, readContext, next); err != nil {
		t.Fatal("last sequence cannot be read", err)
	}
	if data, after, err := EncodeEventJournalFrame(fixture(t, "native-ip.json"), next); !errors.Is(err, ErrJournalSequenceLimit) || data != nil || after != (JournalCursor{}) {
		t.Fatal("sequence wrapped", err)
	}
}

func TestJournalMaximumPayloadAndFrameBudget(t *testing.T) {
	c := journalContext()
	payload := fixture(t, "native-ip.json")
	payload = append(payload, bytes.Repeat([]byte(" "), MaxDocumentBytes-len(payload))...)
	frame, end, err := EncodeEventJournalFrame(payload, c.Start)
	if err != nil {
		t.Fatal("maximum event payload rejected", err)
	}
	s, err := ReadEventJournalSegment(frame, c, end)
	if err != nil || len(s.Records) != 1 || !bytes.Equal(s.Records[0].Payload, payload) {
		t.Fatal("maximum payload changed", err)
	}
	if data, cursor, err := EncodeEventJournalFrame(append(payload, ' '), c.Start); !errors.Is(err, ErrInvalidJournalEvent) || data != nil || cursor != (JournalCursor{}) {
		t.Fatal("oversized event accepted", err)
	}
	var data []byte
	end = c.Start
	for i := 0; i < MaxJournalScanFrames; i++ {
		frame, end, err = EncodeEventJournalFrame(fixture(t, "native-ip.json"), end)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, frame...)
	}
	s, err = ReadEventJournalSegment(data, c, end)
	if err != nil || len(s.Records) != MaxJournalScanFrames || s.VerifiedBytes != len(data) {
		t.Fatal("maximum frame budget rejected", err)
	}
	next, _, err := EncodeEventJournalFrame(fixture(t, "native-ip.json"), end)
	if err != nil {
		t.Fatal(err)
	}
	boundedBytes := len(data)
	s, err = ScanEventJournal(append(data, next...), c)
	if err != nil || s.Tail != JournalFrameLimit || s.VerifiedBytes != boundedBytes || s.UnverifiedBytes != len(next) || s.Cursor != end {
		t.Fatal("maximum frame budget hid an extra entry", err)
	}
}

func TestJournalEndAnchorsAndDuplicateObservationSemantics(t *testing.T) {
	data, boundary, middle, end := journalFrames(t)
	for name, expected := range map[string]JournalCursor{"wrong end": middle, "wrong digest": {JournalID: end.JournalID, Identity: end.Identity, NextSequence: end.NextSequence, PreviousSHA256: strings.Repeat("1", 64)}} {
		t.Run(name, func(t *testing.T) {
			if s, err := ReadEventJournalSegment(data, journalContext(), expected); !errors.Is(err, ErrJournalEndMismatch) || !reflect.DeepEqual(s, JournalScan{}) {
				t.Fatal("false end accepted", err)
			}
		})
	}
	bad := end
	bad.Identity.Epoch = "epoch.other"
	if s, err := ReadEventJournalSegment(data, journalContext(), bad); !errors.Is(err, ErrInvalidJournalContext) || !reflect.DeepEqual(s, JournalScan{}) {
		t.Fatal("cross-epoch end accepted", err)
	}
	if s, err := ReadEventJournalSegment(nil, journalContext(), journalContext().Start); err != nil || s.Tail != JournalCleanBoundary || len(s.Records) != 0 {
		t.Fatal("explicitly empty segment rejected", err)
	}
	// Two separate ingestion entries may carry the same event. Framing is not
	// event deduplication, and a rate producer must not count them as two events.
	second, after, err := EncodeEventJournalFrame(fixture(t, "native-ip.json"), middle)
	if err != nil {
		t.Fatal(err)
	}
	dup := append(bytes.Clone(data[:boundary]), second...)
	s, err := ReadEventJournalSegment(dup, journalContext(), after)
	if err != nil || len(s.Records) != 2 || s.Records[0].Header.EventID != s.Records[1].Header.EventID {
		t.Fatal("journal invented event uniqueness", err)
	}
}

func FuzzEventJournalScan(f *testing.F) {
	data, boundary, _, end := journalFrames(f)
	for _, seed := range [][]byte{nil, data, data[:boundary], data[:len(data)-1], []byte(journalMagic)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ScanEventJournal(data, journalContext())
		if err != nil {
			if !reflect.DeepEqual(s, JournalScan{}) {
				t.Fatal("partial output on context/budget error")
			}
			return
		}
		if s.VerifiedBytes < 0 || s.UnverifiedBytes < 0 || s.VerifiedBytes+s.UnverifiedBytes != len(data) || len(s.Records) > MaxJournalScanFrames {
			t.Fatal("unbounded or hidden scan bytes")
		}
		if s.Tail == JournalCleanBoundary && s.UnverifiedBytes != 0 {
			t.Fatal("unverified clean tail")
		}
		if _, err := ReadEventJournalSegment(data[:s.VerifiedBytes], journalContext(), s.Cursor); err != nil {
			t.Fatal("accepted prefix cannot be rebound", err)
		}
		bound, err := ReadEventJournalSegment(data, journalContext(), end)
		if err != nil && !reflect.DeepEqual(bound, JournalScan{}) {
			t.Fatal("failed bound read released records")
		}
	})
}

func FuzzEventJournalEncoding(f *testing.F) {
	f.Add(fixture(f, "native-ip.json"), uint64(1))
	f.Add(fixture(f, "native-l2.json"), uint64(math.MaxUint64-1))
	f.Add([]byte("null"), uint64(0))
	f.Fuzz(func(t *testing.T, payload []byte, sequence uint64) {
		c := journalContext()
		c.Start.NextSequence = sequence
		data, end, err := EncodeEventJournalFrame(payload, c.Start)
		if err != nil {
			if data != nil || end != (JournalCursor{}) {
				t.Fatal("encoder leaked partial frame")
			}
			return
		}
		s, err := ReadEventJournalSegment(data, c, end)
		if err != nil || len(s.Records) != 1 || !bytes.Equal(s.Records[0].Payload, payload) {
			t.Fatal("encoded event did not round trip exactly", err)
		}
		if len(data) > journalPrefixBytes+MaxJournalHeaderBytes+MaxDocumentBytes+journalHashBytes {
			t.Fatal("frame byte cap exceeded")
		}
	})
}

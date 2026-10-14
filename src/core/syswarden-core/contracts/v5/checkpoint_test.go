package v5

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// This deterministic key is public synthetic test material, never an authority.
func checkpointTestKey(value byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
}

func checkpointContext() JournalCheckpointContext {
	a := JournalCheckpointAnchor{Cursor: journalContext().Start, NextSequence: 1, PreviousSHA256: strings.Repeat("0", 64)}
	return JournalCheckpointContext{Anchor: a, Authority: JournalCheckpointAuthority{
		JournalID: a.Cursor.JournalID, Identity: a.Cursor.Identity, KeyID: "key.fixture.1",
		PublicKey: checkpointTestKey(0x42).Public().(ed25519.PublicKey), FirstSequence: 1, LastSequence: 10,
	}}
}

func checkpointFor(t testing.TB, context JournalCheckpointContext, data []byte, end JournalCursor) JournalCheckpoint {
	t.Helper()
	start := context.Anchor.Cursor
	return JournalCheckpoint{Schema: JournalCheckpointSchema, CheckpointID: "checkpoint.fixture.1",
		Sequence: strconv.FormatUint(context.Anchor.NextSequence, 10), KeyID: context.Authority.KeyID,
		JournalID: start.JournalID, Identity: start.Identity, PreviousCheckpointSHA256: context.Anchor.PreviousSHA256,
		Start:        JournalPosition{NextSequence: strconv.FormatUint(start.NextSequence, 10), PreviousSHA256: start.PreviousSHA256},
		End:          JournalPosition{NextSequence: strconv.FormatUint(end.NextSequence, 10), PreviousSHA256: end.PreviousSHA256},
		SegmentBytes: strconv.Itoa(len(data)), RecordedAt: "2026-01-01T00:00:02Z", ClockQuality: "unknown"}
}

func signedCheckpoint(t testing.TB, c JournalCheckpoint, key ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	data, err := EncodeJournalCheckpoint(c)
	if err != nil {
		t.Fatal(err)
	}
	message, err := JournalCheckpointSigningMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	return data, ed25519.Sign(key, message)
}

func TestCheckpointGoldenAndAuthenticatedSegment(t *testing.T) {
	data, _, _, end := journalFrames(t)
	context := checkpointContext()
	c := checkpointFor(t, context, data, end)
	raw, signature := signedCheckpoint(t, c, checkpointTestKey(0x42))
	if !bytes.Equal(raw, fixture(t, "checkpoint-two-events.json")) {
		t.Fatal("canonical checkpoint changed")
	}
	goldenSignature, err := hex.DecodeString(string(fixture(t, "checkpoint-signature.hex")))
	if err != nil || !bytes.Equal(signature, goldenSignature) {
		t.Fatal("domain-separated signature changed", err)
	}
	public, err := hex.DecodeString(string(fixture(t, "checkpoint-public-key.hex")))
	if err != nil || !bytes.Equal(public, context.Authority.PublicKey) {
		t.Fatal("synthetic public key changed", err)
	}
	message, err := JournalCheckpointSigningMessage(c)
	if err != nil || !bytes.Equal(message, append([]byte("syswarden/journal-checkpoint/v1\x00"), raw...)) {
		t.Fatal("incorrect signing message", err)
	}
	got, next, err := VerifyJournalCheckpoint(raw, signature, context)
	if err != nil || got != c || next.Cursor != end || next.NextSequence != 2 || next.PreviousSHA256 != journalDigest(raw) {
		t.Fatal("valid metadata rejected", err)
	}
	scan, actualNext, err := ReadAuthenticatedJournalSegment(data, raw, signature, context, MaxJournalScanBytes, MaxJournalScanFrames)
	if err != nil || len(scan.Records) != 2 || actualNext != next {
		t.Fatal("authenticated segment rejected", err)
	}
	// Mutating caller-owned source bytes after return cannot alter retained records.
	before := bytes.Clone(scan.Records[0].Payload)
	for i := range data {
		data[i] = 0
	}
	if !bytes.Equal(before, scan.Records[0].Payload) {
		t.Fatal("authenticated read aliases source")
	}
}

func TestCheckpointRejectsMalformedAndNoncanonicalEncoding(t *testing.T) {
	good := fixture(t, "checkpoint-two-events.json")
	for name, data := range map[string][]byte{
		"null": []byte("null"), "oversize": bytes.Repeat([]byte(" "), MaxCheckpointBytes+1),
		"newline": append(bytes.Clone(good), '\n'), "space": append([]byte(" "), good...),
		"duplicate":         bytes.Replace(good, []byte("{"), []byte(`{"sequence":"1",`), 1),
		"alias":             bytes.Replace(good, []byte(`"sequence":`), []byte(`"Sequence":`), 1),
		"missing":           bytes.Replace(good, []byte(`,"clock_quality":"unknown"`), nil, 1),
		"unknown":           bytes.Replace(good, []byte("{"), []byte(`{"future":true,`), 1),
		"numeric":           bytes.Replace(good, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1),
		"leading zero":      bytes.Replace(good, []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1),
		"future schema":     bytes.Replace(good, []byte(JournalCheckpointSchema), []byte("future"), 1),
		"invalid Unicode":   bytes.Replace(good, []byte("checkpoint.fixture.1"), []byte{0xff}, 1),
		"trailing document": append(bytes.Clone(good), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(data, good) {
				t.Fatal("invalid test mutation")
			}
			c, err := DecodeJournalCheckpoint(data)
			if !errors.Is(err, ErrInvalidJournalCheckpoint) || c != (JournalCheckpoint{}) {
				t.Fatal("malformed metadata yielded a record", err)
			}
		})
	}
}

func TestCheckpointRejectsInvalidStatements(t *testing.T) {
	data, _, _, end := journalFrames(t)
	base := checkpointFor(t, checkpointContext(), data, end)
	for name, change := range map[string]func(*JournalCheckpoint){
		"schema":                  func(c *JournalCheckpoint) { c.Schema = "future" },
		"identifier":              func(c *JournalCheckpoint) { c.CheckpointID = "" },
		"key":                     func(c *JournalCheckpoint) { c.KeyID = "../key" },
		"journal":                 func(c *JournalCheckpoint) { c.JournalID = "" },
		"epoch":                   func(c *JournalCheckpoint) { c.Identity.Epoch = "" },
		"previous checkpoint":     func(c *JournalCheckpoint) { c.PreviousCheckpointSHA256 = "" },
		"zero sequence":           func(c *JournalCheckpoint) { c.Sequence = "0" },
		"overflow sequence":       func(c *JournalCheckpoint) { c.Sequence = "18446744073709551616" },
		"exhausted sequence":      func(c *JournalCheckpoint) { c.Sequence = "18446744073709551615" },
		"negative position":       func(c *JournalCheckpoint) { c.Start.NextSequence = "-1" },
		"zero position":           func(c *JournalCheckpoint) { c.Start.NextSequence = "0" },
		"backward end":            func(c *JournalCheckpoint) { c.Start.NextSequence = "4" },
		"excessive frames":        func(c *JournalCheckpoint) { c.End.NextSequence = strconv.Itoa(MaxJournalScanFrames + 2) },
		"empty with bytes":        func(c *JournalCheckpoint) { c.End = c.Start },
		"empty with changed hash": func(c *JournalCheckpoint) { c.End.NextSequence = c.Start.NextSequence; c.SegmentBytes = "0" },
		"impossible size":         func(c *JournalCheckpoint) { c.SegmentBytes = "1" },
		"excessive bytes":         func(c *JournalCheckpoint) { c.SegmentBytes = strconv.Itoa(MaxJournalScanBytes + 1) },
		"size exponent":           func(c *JournalCheckpoint) { c.SegmentBytes = "1e3" },
		"start hash":              func(c *JournalCheckpoint) { c.Start.PreviousSHA256 = "" },
		"end hash":                func(c *JournalCheckpoint) { c.End.PreviousSHA256 = "" },
		"timestamp":               func(c *JournalCheckpoint) { c.RecordedAt = "2026-01-01" },
		"clock":                   func(c *JournalCheckpoint) { c.ClockQuality = "trusted" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			change(&c)
			if b, err := EncodeJournalCheckpoint(c); !errors.Is(err, ErrInvalidJournalCheckpoint) || b != nil {
				t.Fatal("invalid checkpoint encoded", err)
			}
			if b, err := JournalCheckpointSigningMessage(c); !errors.Is(err, ErrInvalidJournalCheckpoint) || b != nil {
				t.Fatal("invalid signing message", err)
			}
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if c, err := DecodeJournalCheckpoint(raw); !errors.Is(err, ErrInvalidJournalCheckpoint) || c != (JournalCheckpoint{}) {
				t.Fatal("invalid checkpoint decoded", err)
			}
		})
	}
}

func TestCheckpointRequiresIndependentScopedTrust(t *testing.T) {
	data, _, _, end := journalFrames(t)
	context := checkpointContext()
	base := checkpointFor(t, context, data, end)
	raw, sig := signedCheckpoint(t, base, checkpointTestKey(0x42))
	for name, change := range map[string]func(*JournalCheckpointContext){
		"empty key":          func(c *JournalCheckpointContext) { c.Authority.PublicKey = nil },
		"short key":          func(c *JournalCheckpointContext) { c.Authority.PublicKey = make([]byte, 31) },
		"long key":           func(c *JournalCheckpointContext) { c.Authority.PublicKey = make([]byte, 33) },
		"unset key ID":       func(c *JournalCheckpointContext) { c.Authority.KeyID = "" },
		"unset epoch":        func(c *JournalCheckpointContext) { c.Anchor.Cursor.Identity.Epoch = "" },
		"authority journal":  func(c *JournalCheckpointContext) { c.Authority.JournalID = "journal.other" },
		"authority identity": func(c *JournalCheckpointContext) { c.Authority.Identity.NodeID = "node.other" },
		"unset anchor":       func(c *JournalCheckpointContext) { c.Anchor.PreviousSHA256 = "" },
		"zero ordinal":       func(c *JournalCheckpointContext) { c.Anchor.NextSequence = 0 },
		"exhausted ordinal":  func(c *JournalCheckpointContext) { c.Anchor.NextSequence = math.MaxUint64 },
		"zero first":         func(c *JournalCheckpointContext) { c.Authority.FirstSequence = 0 },
		"backward range":     func(c *JournalCheckpointContext) { c.Authority.FirstSequence = 11 },
		"excessive range":    func(c *JournalCheckpointContext) { c.Authority.LastSequence = math.MaxUint64 },
	} {
		t.Run(name, func(t *testing.T) {
			c := context
			change(&c)
			got, next, err := VerifyJournalCheckpoint(raw, sig, c)
			if !errors.Is(err, ErrInvalidCheckpointTrust) || got != (JournalCheckpoint{}) || next != (JournalCheckpointAnchor{}) {
				t.Fatal("invalid trust yielded output", err)
			}
		})
	}
	for name, change := range map[string]func(*JournalCheckpointContext){
		"wrong key ID":       func(c *JournalCheckpointContext) { c.Authority.KeyID = "key.other" },
		"future key":         func(c *JournalCheckpointContext) { c.Authority.FirstSequence = 2 },
		"previous digest":    func(c *JournalCheckpointContext) { c.Anchor.PreviousSHA256 = strings.Repeat("1", 64) },
		"missing checkpoint": func(c *JournalCheckpointContext) { c.Anchor.NextSequence = 2 },
		"start position":     func(c *JournalCheckpointContext) { c.Anchor.Cursor.NextSequence = 2 },
		"start digest":       func(c *JournalCheckpointContext) { c.Anchor.Cursor.PreviousSHA256 = strings.Repeat("1", 64) },
		"journal": func(c *JournalCheckpointContext) {
			c.Anchor.Cursor.JournalID = "journal.other"
			c.Authority.JournalID = "journal.other"
		},
		"cluster": func(c *JournalCheckpointContext) {
			c.Anchor.Cursor.Identity.ClusterID = "cluster.other"
			c.Authority.Identity = c.Anchor.Cursor.Identity
		},
		"node": func(c *JournalCheckpointContext) {
			c.Anchor.Cursor.Identity.NodeID = "node.other"
			c.Authority.Identity = c.Anchor.Cursor.Identity
		},
		"epoch": func(c *JournalCheckpointContext) {
			c.Anchor.Cursor.Identity.Epoch = "epoch.other"
			c.Authority.Identity = c.Anchor.Cursor.Identity
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := context
			change(&c)
			got, next, err := VerifyJournalCheckpoint(raw, sig, c)
			if !errors.Is(err, ErrCheckpointNotAuthorized) || got != (JournalCheckpoint{}) || next != (JournalCheckpointAnchor{}) {
				t.Fatal("foreign continuity accepted", err)
			}
		})
	}
}

func TestCheckpointCryptographicBindingAndDomain(t *testing.T) {
	data, _, _, end := journalFrames(t)
	context := checkpointContext()
	c := checkpointFor(t, context, data, end)
	raw, sig := signedCheckpoint(t, c, checkpointTestKey(0x42))
	bad := bytes.Clone(sig)
	bad[0] ^= 1
	for name, signature := range map[string][]byte{
		"absent": nil, "short": sig[:63], "long": append(bytes.Clone(sig), 0), "corrupt": bad,
		"unsigned domain":  ed25519.Sign(checkpointTestKey(0x42), raw),
		"different domain": ed25519.Sign(checkpointTestKey(0x42), append([]byte("syswarden/event/v1\x00"), raw...)),
		"foreign key":      ed25519.Sign(checkpointTestKey(0x43), checkpointMessage(raw)),
	} {
		t.Run(name, func(t *testing.T) {
			got, next, err := VerifyJournalCheckpoint(raw, signature, context)
			if !errors.Is(err, ErrCheckpointSignature) || got != (JournalCheckpoint{}) || next != (JournalCheckpointAnchor{}) {
				t.Fatal("invalid signature yielded output", err)
			}
		})
	}
	// Validly shaped metadata substitutions still require a fresh signature.
	for _, change := range []func(*JournalCheckpoint){
		func(c *JournalCheckpoint) { c.CheckpointID = "checkpoint.other" },
		func(c *JournalCheckpoint) { c.End.PreviousSHA256 = strings.Repeat("1", 64) },
		func(c *JournalCheckpoint) { c.SegmentBytes = "4096" },
		func(c *JournalCheckpoint) { c.RecordedAt = "2027-01-01T00:00:02Z" },
		func(c *JournalCheckpoint) { c.ClockQuality = "synchronized" },
	} {
		changed := c
		change(&changed)
		b, err := EncodeJournalCheckpoint(changed)
		if err != nil {
			t.Fatal(err)
		}
		if got, next, err := VerifyJournalCheckpoint(b, sig, context); !errors.Is(err, ErrCheckpointSignature) || got != (JournalCheckpoint{}) || next != (JournalCheckpointAnchor{}) {
			t.Fatal("substitution kept old signature", err)
		}
	}
}

func TestCheckpointRejectsRollbackGapsAndUnauthorizedRotation(t *testing.T) {
	data, _, _, end := journalFrames(t)
	context := checkpointContext()
	c := checkpointFor(t, context, data, end)
	raw, sig := signedCheckpoint(t, c, checkpointTestKey(0x42))
	_, anchor, err := ReadAuthenticatedJournalSegment(data, raw, sig, context, MaxJournalScanBytes, MaxJournalScanFrames)
	if err != nil {
		t.Fatal(err)
	}
	context.Anchor = anchor
	if _, next, err := VerifyJournalCheckpoint(raw, sig, context); !errors.Is(err, ErrCheckpointNotAuthorized) || next != (JournalCheckpointAnchor{}) {
		t.Fatal("replayed old checkpoint", err)
	}
	// A new checkpoint may cover an explicitly empty segment, but still advances
	// the checkpoint counter and previous-checkpoint digest.
	c = checkpointFor(t, context, nil, anchor.Cursor)
	c.CheckpointID = "checkpoint.fixture.2"
	second, signature := signedCheckpoint(t, c, checkpointTestKey(0x42))
	_, next, err := ReadAuthenticatedJournalSegment(nil, second, signature, context, 1, 1)
	if err != nil || next.NextSequence != 3 || next.Cursor != anchor.Cursor {
		t.Fatal("empty checkpoint lost continuity", err)
	}
	newContext := context
	newContext.Anchor = next
	if _, _, err := VerifyJournalCheckpoint(second, signature, newContext); !errors.Is(err, ErrCheckpointNotAuthorized) {
		t.Fatal("empty checkpoint replayed", err)
	}
	gap := c
	gap.Sequence = "3"
	gap.RecordedAt = "2027-01-01T00:00:02Z"
	b, s := signedCheckpoint(t, gap, checkpointTestKey(0x42))
	if _, _, err := VerifyJournalCheckpoint(b, s, context); !errors.Is(err, ErrCheckpointNotAuthorized) {
		t.Fatal("newer timestamp hid missing checkpoint", err)
	}
	// A separately authorized key replaces the signer at the explicit sequence.
	rotated := c
	rotated.KeyID = "key.fixture.2"
	b, s = signedCheckpoint(t, rotated, checkpointTestKey(0x43))
	if _, _, err := VerifyJournalCheckpoint(b, s, context); !errors.Is(err, ErrCheckpointNotAuthorized) {
		t.Fatal("document self-rotated key", err)
	}
	old := context
	old.Authority.LastSequence = 1
	if _, _, err := VerifyJournalCheckpoint(second, signature, old); !errors.Is(err, ErrCheckpointNotAuthorized) {
		t.Fatal("retired sequence range accepted", err)
	}
	context.Authority.KeyID = rotated.KeyID
	context.Authority.PublicKey = checkpointTestKey(0x43).Public().(ed25519.PublicKey)
	context.Authority.FirstSequence = 2
	context.Authority.LastSequence = 2
	if _, _, err := ReadAuthenticatedJournalSegment(nil, b, s, context, 1, 1); err != nil {
		t.Fatal("independently authorized rotation rejected", err)
	}
}

func TestCheckpointRequiresMatchingBytesAndCallerBudgets(t *testing.T) {
	data, boundary, _, end := journalFrames(t)
	context := checkpointContext()
	c := checkpointFor(t, context, data, end)
	raw, sig := signedCheckpoint(t, c, checkpointTestKey(0x42))
	corrupt := bytes.Clone(data)
	corrupt[len(corrupt)-1] ^= 1
	for name, input := range map[string][]byte{"whole frame deletion": data[:boundary], "empty": nil, "extension": append(bytes.Clone(data), 0), "same-size corruption": corrupt} {
		t.Run(name, func(t *testing.T) {
			s, next, err := ReadAuthenticatedJournalSegment(input, raw, sig, context, MaxJournalScanBytes, MaxJournalScanFrames)
			if err == nil || !reflect.DeepEqual(s, JournalScan{}) || next != (JournalCheckpointAnchor{}) {
				t.Fatal("signature replaced byte validation")
			}
		})
	}
	for _, budget := range [][2]int{{0, 1}, {1, 0}, {len(data) - 1, 2}, {len(data), 1}, {MaxJournalScanBytes + 1, 2}, {len(data), MaxJournalScanFrames + 1}} {
		s, next, err := ReadAuthenticatedJournalSegment(data, raw, sig, context, budget[0], budget[1])
		if err == nil || !reflect.DeepEqual(s, JournalScan{}) || next != (JournalCheckpointAnchor{}) {
			t.Fatal("caller budget bypassed")
		}
	}
	// Authentication can accept an authorized signer's false size declaration;
	// full segment validation must still reject it without advancing the anchor.
	c.SegmentBytes = strconv.Itoa(len(data) + 1)
	raw, sig = signedCheckpoint(t, c, checkpointTestKey(0x42))
	if _, _, err := VerifyJournalCheckpoint(raw, sig, context); err != nil {
		t.Fatal("metadata test setup", err)
	}
	if s, next, err := ReadAuthenticatedJournalSegment(data, raw, sig, context, MaxJournalScanBytes, MaxJournalScanFrames); !errors.Is(err, ErrCheckpointSegment) || !reflect.DeepEqual(s, JournalScan{}) || next != (JournalCheckpointAnchor{}) {
		t.Fatal("signed false size accepted", err)
	}
}

func TestCheckpointCounterExhaustionAndHistoricalTime(t *testing.T) {
	context := checkpointContext()
	context.Anchor.NextSequence = math.MaxUint64 - 1
	context.Authority.FirstSequence = math.MaxUint64 - 1
	context.Authority.LastSequence = math.MaxUint64 - 1
	c := checkpointFor(t, context, nil, context.Anchor.Cursor)
	// Historical verification is independent of wall time. Current UI freshness
	// must be established separately; an old signed journal remains recoverable.
	c.RecordedAt = "2000-01-01T00:00:00Z"
	c.ClockQuality = "unsynchronized"
	raw, sig := signedCheckpoint(t, c, checkpointTestKey(0x42))
	_, next, err := ReadAuthenticatedJournalSegment(nil, raw, sig, context, 1, 1)
	if err != nil || next.NextSequence != math.MaxUint64 {
		t.Fatal("last checkpoint rejected", err)
	}
	context.Anchor = next
	if got, after, err := VerifyJournalCheckpoint(raw, sig, context); !errors.Is(err, ErrInvalidCheckpointTrust) || got != (JournalCheckpoint{}) || after != (JournalCheckpointAnchor{}) {
		t.Fatal("checkpoint counter wrapped", err)
	}
}

func TestCheckpointContinuityRequiresRetainedAnchor(t *testing.T) {
	data, _, _, end := journalFrames(t)
	context := checkpointContext()
	c := checkpointFor(t, context, data, end)
	first, sig := signedCheckpoint(t, c, checkpointTestKey(0x42))
	_, accepted, err := VerifyJournalCheckpoint(first, sig, context)
	if err != nil {
		t.Fatal(err)
	}
	c.CheckpointID = "checkpoint.alternative"
	alternative, signature := signedCheckpoint(t, c, checkpointTestKey(0x42))
	_, alternateAnchor, err := VerifyJournalCheckpoint(alternative, signature, context)
	if err != nil || alternateAnchor == accepted {
		t.Fatal("test must model two signed branches from the same old anchor", err)
	}
	// A local verifier cannot detect equivocation if callers reset the anchor.
	// Once a branch is retained, the other branch cannot silently replace it.
	context.Anchor = accepted
	if _, _, err := VerifyJournalCheckpoint(alternative, signature, context); !errors.Is(err, ErrCheckpointNotAuthorized) {
		t.Fatal("alternative branch replaced retained checkpoint", err)
	}
	other := context
	other.Anchor = alternateAnchor
	following := checkpointFor(t, other, nil, end)
	next, signature := signedCheckpoint(t, following, checkpointTestKey(0x42))
	if _, _, err := VerifyJournalCheckpoint(next, signature, context); !errors.Is(err, ErrCheckpointNotAuthorized) {
		t.Fatal("same-position fork extension accepted", err)
	}
	context = checkpointContext()
	context.Authority.PublicKey = checkpointTestKey(0x43).Public().(ed25519.PublicKey)
	if got, next, err := VerifyJournalCheckpoint(first, sig, context); !errors.Is(err, ErrCheckpointSignature) || got != (JournalCheckpoint{}) || next != (JournalCheckpointAnchor{}) {
		t.Fatal("key ID substituted for actual trusted key", err)
	}
}

func FuzzJournalCheckpointVerification(f *testing.F) {
	data, _, _, end := journalFrames(f)
	context := checkpointContext()
	c := checkpointFor(f, context, data, end)
	raw, sig := signedCheckpoint(f, c, checkpointTestKey(0x42))
	f.Add(raw, sig)
	f.Add([]byte("null"), []byte{})
	f.Add(append(bytes.Clone(raw), '\n'), sig)
	f.Fuzz(func(t *testing.T, raw, signature []byte) {
		c, next, err := VerifyJournalCheckpoint(raw, signature, context)
		if err != nil {
			if c != (JournalCheckpoint{}) || next != (JournalCheckpointAnchor{}) {
				t.Fatal("failed verification leaked output")
			}
			return
		}
		canonical, err := EncodeJournalCheckpoint(c)
		if err != nil || !bytes.Equal(raw, canonical) || len(raw) > MaxCheckpointBytes {
			t.Fatal("accepted noncanonical checkpoint")
		}
		if !ed25519.Verify(context.Authority.PublicKey, append([]byte("syswarden/journal-checkpoint/v1\x00"), raw...), signature) {
			t.Fatal("accepted signature without independent verification")
		}
		s, anchor, err := ReadAuthenticatedJournalSegment(data, raw, signature, context, MaxJournalScanBytes, MaxJournalScanFrames)
		if err != nil && (!reflect.DeepEqual(s, JournalScan{}) || anchor != (JournalCheckpointAnchor{})) {
			t.Fatal("failed segment leaked output")
		}
	})
}

func FuzzJournalCheckpointSignedStatements(f *testing.F) {
	f.Add(fixture(f, "checkpoint-two-events.json"))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := DecodeJournalCheckpoint(raw)
		if err != nil {
			if c != (JournalCheckpoint{}) {
				t.Fatal("partial decoded checkpoint")
			}
			return
		}
		message, err := JournalCheckpointSigningMessage(c)
		if err != nil {
			t.Fatal(err)
		}
		context := checkpointContext()
		sig := ed25519.Sign(checkpointTestKey(0x42), message)
		got, next, err := VerifyJournalCheckpoint(raw, sig, context)
		if err != nil {
			if got != (JournalCheckpoint{}) || next != (JournalCheckpointAnchor{}) {
				t.Fatal("signed foreign context leaked output")
			}
			return
		}
		if got != c || next.NextSequence != 2 || next.PreviousSHA256 != journalDigest(raw) || got.Start.NextSequence != "1" || got.KeyID != "key.fixture.1" {
			t.Fatal("signed input changed trusted continuity")
		}
	})
}

package v5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func evidenceFixture(t testing.TB, name string) EvidenceDescriptor {
	t.Helper()
	e, err := DecodeEvidenceDescriptor(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Raw evidence must retain its final newline, unlike the JSON fixture helper.
func evidencePayload(t testing.TB, name string) []byte {
	t.Helper()
	data, err := goldenFixtures.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func evidenceContext(t testing.TB, e EvidenceDescriptor) EvidenceReadContext {
	t.Helper()
	hash, err := EvidenceDescriptorSHA256(e)
	if err != nil {
		t.Fatal(err)
	}
	// Test-only trusted context. Production must resolve it independently.
	return EvidenceReadContext{ExpectedIdentity: e.Identity, EvidenceID: e.EvidenceID,
		DescriptorSHA256: hash, MaxBytes: 1024}
}

func TestEvidenceGoldenAndExactBytes(t *testing.T) {
	for _, name := range []string{"original", "redacted", "derived", "unavailable", "unknown"} {
		t.Run(name, func(t *testing.T) {
			e := evidenceFixture(t, "evidence-"+name+".json")
			data, err := EncodeEvidenceDescriptor(e)
			if err != nil || !bytes.Equal(data, fixture(t, "evidence-"+name+".json")) {
				t.Fatal("evidence golden encoding changed", err)
			}
			context := evidenceContext(t, e)
			if name == "unavailable" || name == "unknown" {
				if err := CheckEvidencePayloadBinding(e, context, nil); !errors.Is(err, ErrEvidencePayloadMismatch) {
					t.Fatal("missing evidence became a verified empty payload", err)
				}
				return
			}
			payload := evidencePayload(t, "evidence-"+name+".txt")
			context.MaxBytes = int64(len(payload))
			if err := CheckEvidencePayloadBinding(e, context, payload); err != nil {
				t.Fatal("exact payload rejected at exact budget", err)
			}
			context.MaxBytes--
			if err := CheckEvidencePayloadBinding(e, context, payload); !errors.Is(err, ErrEvidencePayloadMismatch) {
				t.Fatal("caller budget ignored", err)
			}
			context.MaxBytes++
			changed := bytes.Clone(payload)
			changed[0] ^= 1
			for _, other := range [][]byte{changed, bytes.TrimSuffix(payload, []byte("\n")), append(bytes.Clone(payload), '\n'), nil} {
				if err := CheckEvidencePayloadBinding(e, context, other); !errors.Is(err, ErrEvidencePayloadMismatch) {
					t.Fatal("different bytes accepted", err)
				}
			}
		})
	}
}

func TestEvidenceLineageDoesNotPromoteTransformedBytes(t *testing.T) {
	original := evidenceFixture(t, "evidence-original.json")
	redacted := evidenceFixture(t, "evidence-redacted.json")
	derived := evidenceFixture(t, "evidence-derived.json")
	for _, pair := range [][2]EvidenceDescriptor{{redacted, original}, {derived, redacted}} {
		if err := CheckEvidenceParentBinding(pair[0], pair[1]); err != nil {
			t.Fatal("pinned lineage rejected", err)
		}
	}
	if err := CheckEvidenceParentBinding(derived, original); !errors.Is(err, ErrEvidenceParentMismatch) {
		t.Fatal("grandparent substituted for exact parent", err)
	}
	if err := CheckEvidencePayloadBinding(original, evidenceContext(t, original), evidencePayload(t, "evidence-redacted.txt")); !errors.Is(err, ErrEvidencePayloadMismatch) {
		t.Fatal("redacted bytes substituted for original", err)
	}
	for _, pair := range []struct {
		descriptor EvidenceDescriptor
		file       string
	}{
		{redacted, "evidence-transformation.txt"}, {derived, "evidence-derivation.txt"},
	} {
		sum := sha256.Sum256(evidencePayload(t, pair.file))
		if pair.descriptor.Transformation.SHA256.Value != hex.EncodeToString(sum[:]) {
			t.Fatal("fixture transformation definition not pinned")
		}
	}
	// Even identical content does not identify an equivalent parent record.
	for name, mutate := range map[string]func(*EvidenceDescriptor){
		"cluster":     func(e *EvidenceDescriptor) { e.Identity.ClusterID = "cluster.other" },
		"node":        func(e *EvidenceDescriptor) { e.Identity.NodeID = "node.other" },
		"epoch":       func(e *EvidenceDescriptor) { e.Identity.Epoch = "generation.other" },
		"evidence ID": func(e *EvidenceDescriptor) { e.EvidenceID = "evidence.other" },
		"collector":   func(e *EvidenceDescriptor) { e.CollectorID = "collector.other" },
		"source":      func(e *EvidenceDescriptor) { e.SourceID = "source.other" },
		"time":        func(e *EvidenceDescriptor) { e.CollectedAt = "2027-01-01T00:00:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			parent := original
			mutate(&parent)
			if err := CheckEvidenceParentBinding(redacted, parent); !errors.Is(err, ErrEvidenceParentMismatch) {
				t.Fatal("parent substitution accepted", err)
			}
		})
	}
	if err := CheckEvidenceParentBinding(original, redacted); !errors.Is(err, ErrEvidenceParentMismatch) {
		t.Fatal("original gained transformation lineage", err)
	}
}

func TestEvidenceBindingPinsEntireDescriptorAndScope(t *testing.T) {
	e := evidenceFixture(t, "evidence-redacted.json")
	context := evidenceContext(t, e)
	payload := evidencePayload(t, "evidence-redacted.txt")
	for name, mutate := range map[string]func(*EvidenceDescriptor){
		"collector":            func(e *EvidenceDescriptor) { e.CollectorID = "collector.other" },
		"source":               func(e *EvidenceDescriptor) { e.SourceID = "source.other" },
		"representation":       func(e *EvidenceDescriptor) { e.Representation = "derived" },
		"content ref":          func(e *EvidenceDescriptor) { e.Content.Ref.Value = "object.other" },
		"parent digest":        func(e *EvidenceDescriptor) { e.Parent.SHA256.Value = strings.Repeat("0", 64) },
		"transformation ref":   func(e *EvidenceDescriptor) { e.Transformation.Ref.Value = "transform.other" },
		"transformation bytes": func(e *EvidenceDescriptor) { e.Transformation.SHA256.Value = strings.Repeat("0", 64) },
		"clock":                func(e *EvidenceDescriptor) { e.ClockQuality = "unsynchronized" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := e
			mutate(&changed)
			if err := CheckEvidencePayloadBinding(changed, context, payload); !errors.Is(err, ErrEvidenceBindingMismatch) {
				t.Fatal("metadata substitution accepted", err)
			}
		})
	}
	for name, mutate := range map[string]func(*EvidenceReadContext){
		"cluster":           func(c *EvidenceReadContext) { c.ExpectedIdentity.ClusterID = "cluster.other" },
		"node":              func(c *EvidenceReadContext) { c.ExpectedIdentity.NodeID = "node.other" },
		"epoch":             func(c *EvidenceReadContext) { c.ExpectedIdentity.Epoch = "generation.other" },
		"evidence ID":       func(c *EvidenceReadContext) { c.EvidenceID = "evidence.other" },
		"descriptor digest": func(c *EvidenceReadContext) { c.DescriptorSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := context
			mutate(&changed)
			if err := CheckEvidencePayloadBinding(e, changed, payload); !errors.Is(err, ErrEvidenceBindingMismatch) {
				t.Fatal("cross-context binding accepted", err)
			}
		})
	}
}

func TestEvidenceAvailabilityAndEmptyObjectAreDistinct(t *testing.T) {
	for _, state := range []string{Present, Stale, Partial, Missing, Unavailable, Rejected, NotApplicable} {
		t.Run(state, func(t *testing.T) {
			e := evidenceFixture(t, "evidence-original.json")
			for _, field := range []*Field{&e.Content.Ref, &e.Content.SHA256, &e.Content.SizeBytes} {
				field.State = state
				if !field.hasValue() {
					field.Value = ""
				}
			}
			data, err := EncodeEvidenceDescriptor(e)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeEvidenceDescriptor(data)
			if err != nil || again != e {
				t.Fatal("availability lost", err)
			}
			err = CheckEvidencePayloadBinding(e, evidenceContext(t, e), evidencePayload(t, "evidence-original.txt"))
			if state == Present {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrEvidencePayloadMismatch) {
				t.Fatal("degraded evidence promoted", err)
			}
		})
	}
	e := evidenceFixture(t, "evidence-original.json")
	sum := sha256.Sum256(nil)
	e.Content.SHA256.Value = hex.EncodeToString(sum[:])
	e.Content.SizeBytes.Value = "0"
	if err := CheckEvidencePayloadBinding(e, evidenceContext(t, e), nil); err != nil {
		t.Fatal("explicitly identified empty object rejected", err)
	}
	// Historical skew does not invalidate bytes or manufacture event ordering.
	e.CollectedAt = "2099-01-01T00:00:00Z"
	e.ClockQuality = "unsynchronized"
	if err := CheckEvidencePayloadBinding(e, evidenceContext(t, e), nil); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceRejectsInvalidConstructedValues(t *testing.T) {
	for name, mutate := range map[string]func(*EvidenceDescriptor){
		"identity":            func(e *EvidenceDescriptor) { e.Identity.Epoch = "" },
		"identifier":          func(e *EvidenceDescriptor) { e.EvidenceID = "../private/not-for-errors" },
		"collector":           func(e *EvidenceDescriptor) { e.CollectorID = "" },
		"source":              func(e *EvidenceDescriptor) { e.SourceID = strings.Repeat("x", MaxIdentifierBytes+1) },
		"time":                func(e *EvidenceDescriptor) { e.CollectedAt = "2026-01-01T00:00:00.000Z" },
		"clock":               func(e *EvidenceDescriptor) { e.ClockQuality = "trusted" },
		"representation":      func(e *EvidenceDescriptor) { e.Representation = "authentic" },
		"digest":              func(e *EvidenceDescriptor) { e.Content.SHA256.Value = strings.Repeat("A", 64) },
		"empty ref":           func(e *EvidenceDescriptor) { e.Content.Ref.Value = "" },
		"size availability":   func(e *EvidenceDescriptor) { e.Content.SizeBytes.State = Stale },
		"digest availability": func(e *EvidenceDescriptor) { e.Content.SHA256 = Field{State: Missing} },
		"URL":                 func(e *EvidenceDescriptor) { e.Content.Ref.Value = "https://example.invalid/object" },
		"original parent": func(e *EvidenceDescriptor) {
			e.Parent.Ref = Field{Present, "evidence.parent"}
			e.Parent.SHA256 = Field{Present, strings.Repeat("0", 64)}
		},
		"original transform": func(e *EvidenceDescriptor) {
			e.Transformation.Ref.State = Missing
			e.Transformation.SHA256.State = Missing
		},
		"redacted without parent": func(e *EvidenceDescriptor) { e.Representation = "redacted" },
		"derived without parent":  func(e *EvidenceDescriptor) { e.Representation = "derived" },
		"unknown with bytes":      func(e *EvidenceDescriptor) { e.Representation = "unknown" },
		"lineage mismatch":        func(e *EvidenceDescriptor) { e.Parent.SHA256.State = Missing },
		"hidden lineage value":    func(e *EvidenceDescriptor) { e.Transformation.Ref.Value = "transform.hidden" },
	} {
		t.Run(name, func(t *testing.T) {
			e := evidenceFixture(t, "evidence-original.json")
			mutate(&e)
			if data, err := EncodeEvidenceDescriptor(e); !errors.Is(err, ErrInvalidEvidenceDocument) || data != nil {
				t.Fatal("invalid record encoded", err)
			}
			if hash, err := EvidenceDescriptorSHA256(e); err == nil || hash != "" {
				t.Fatal("invalid record hashed")
			}
			if err := CheckEvidencePayloadBinding(e, EvidenceReadContext{}, nil); err == nil {
				t.Fatal("invalid record bound")
			}
		})
	}
	for _, size := range []string{"", "-1", "-0", "+1", "01", "1.0", "1e2", " 1", "1 ", "9223372036854775808", strings.Repeat("9", 128)} {
		e := evidenceFixture(t, "evidence-original.json")
		e.Content.SizeBytes.Value = size
		if err := e.Validate(); !errors.Is(err, ErrInvalidEvidenceDocument) {
			t.Fatal("noncanonical or overflowing size accepted", err)
		}
	}
	e := evidenceFixture(t, "evidence-original.json")
	e.Content.SizeBytes.Value = "9223372036854775807"
	if err := e.Validate(); err != nil {
		t.Fatal("wire size boundary rejected", err)
	}
	if err := CheckEvidencePayloadBinding(e, evidenceContext(t, e), nil); !errors.Is(err, ErrEvidencePayloadMismatch) {
		t.Fatal("declared large size bypassed payload check", err)
	}
	e = evidenceFixture(t, "evidence-redacted.json")
	e.Parent.Ref.Value = e.EvidenceID
	if err := e.Validate(); !errors.Is(err, ErrInvalidEvidenceDocument) {
		t.Fatal("self parent accepted", err)
	}
	for _, fieldName := range []string{"parent", "transformation"} {
		for _, state := range []string{Stale, Partial, Missing, Unavailable, Rejected, NotApplicable} {
			e = evidenceFixture(t, "evidence-redacted.json")
			ref := &e.Parent
			if fieldName == "transformation" {
				ref = &e.Transformation
			}
			ref.Ref.State = state
			ref.SHA256.State = state
			if !ref.Ref.hasValue() {
				ref.Ref.Value = ""
				ref.SHA256.Value = ""
			}
			if err := e.Validate(); !errors.Is(err, ErrInvalidEvidenceDocument) {
				t.Fatal("transformed evidence without pinned lineage accepted", fieldName, state, err)
			}
		}
	}
}

func TestEvidenceRequiresExplicitValidReadContext(t *testing.T) {
	e := evidenceFixture(t, "evidence-original.json")
	for _, mutate := range []func(*EvidenceReadContext){
		func(c *EvidenceReadContext) { c.ExpectedIdentity.NodeID = "" },
		func(c *EvidenceReadContext) { c.EvidenceID = "" },
		func(c *EvidenceReadContext) { c.DescriptorSHA256 = "" },
		func(c *EvidenceReadContext) { c.MaxBytes = 0 },
		func(c *EvidenceReadContext) { c.MaxBytes = -1 },
	} {
		context := evidenceContext(t, e)
		mutate(&context)
		if err := CheckEvidencePayloadBinding(e, context, evidencePayload(t, "evidence-original.txt")); !errors.Is(err, ErrInvalidEvidenceContext) {
			t.Fatal("invalid caller context accepted", err)
		}
	}
}

func FuzzEvidencePayloadBinding(f *testing.F) {
	f.Add(evidencePayload(f, "evidence-original.txt"))
	f.Add([]byte{})
	f.Add([]byte{0, 0xff, '\n', '\r'})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > MaxDocumentBytes {
			return
		}
		e := evidenceFixture(t, "evidence-original.json")
		sum := sha256.Sum256(payload)
		e.Content.SHA256.Value = hex.EncodeToString(sum[:])
		e.Content.SizeBytes.Value = strconv.Itoa(len(payload))
		context := evidenceContext(t, e)
		context.MaxBytes = MaxDocumentBytes
		if err := CheckEvidencePayloadBinding(e, context, payload); err != nil {
			t.Fatal(err)
		}
		other := bytes.Clone(payload)
		if len(other) == 0 {
			other = append(other, 0)
		} else {
			other[len(other)/2] ^= 1
		}
		if err := CheckEvidencePayloadBinding(e, context, other); !errors.Is(err, ErrEvidencePayloadMismatch) {
			t.Fatal("modified payload bound", err)
		}
	})
}

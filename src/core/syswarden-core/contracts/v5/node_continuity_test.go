package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func continuityFixture(t testing.TB) (NodeRegistryGeneration, NodeRegistryCheckpoint, NodeAdmissionRegistry, NodeRegistryContinuityContext) {
	t.Helper()
	g, err := DecodeNodeRegistryGeneration(fixture(t, "node-registry-generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	gr, err := g.Reference()
	if err != nil {
		t.Fatal(err)
	}
	_, members := nodeRegistryFixture(t)
	for i := range members {
		for j := range members[i].Transport {
			members[i].Transport[j].Grant.Registry = gr
		}
		for j := range members[i].Producers {
			members[i].Producers[j].Grant.Registry = gr
		}
	}
	r, err := BuildNodeAdmissionRegistry("continuity-snapshot.1", NodeAdmissionRegistryBinding{gr, g.Policy}, members)
	if err != nil {
		t.Fatal(err)
	}
	c := NodeRegistryCheckpoint{NodeRegistryCheckpointSchema, "checkpoint.1", g.AuthorityID, g.LineageID, "1", nodeContinuityGenesis, gr, r.Reference(), "active"}
	return g, c, r, NodeRegistryContinuityContext{g.AuthorityID, g.LineageID, gr, checkpointRef(t, c)}
}

func checkpointRef(t testing.TB, c NodeRegistryCheckpoint) RateReference {
	t.Helper()
	r, err := c.Reference()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func continuityNext(t testing.TB, c NodeRegistryCheckpoint, r NodeAdmissionRegistry, members []NodeAdmissionMember) (NodeRegistryCheckpoint, NodeAdmissionRegistry) {
	t.Helper()
	n, _ := strconv.ParseUint(c.Sequence, 10, 64)
	next := c
	next.Sequence = strconv.FormatUint(n+1, 10)
	next.CheckpointID = "checkpoint." + next.Sequence
	next.PreviousSHA256 = checkpointRef(t, c).SHA256
	candidate, err := BuildNodeAdmissionRegistry("continuity-snapshot."+next.Sequence, r.binding, members)
	if err != nil {
		t.Fatal(err)
	}
	next.Snapshot = candidate.Reference()
	return next, candidate
}

func TestNodeContinuityGolden(t *testing.T) {
	g, c, r, ctx := continuityFixture(t)
	gb, err := EncodeNodeRegistryGeneration(g)
	if err != nil || !bytes.Equal(gb, fixture(t, "node-registry-generation.json")) || ctx.Generation.SHA256 != strings.TrimSpace(string(fixture(t, "node-registry-generation-digest.txt"))) {
		t.Fatal("generation golden changed", err)
	}
	cb, err := EncodeNodeRegistryCheckpoint(c)
	if err != nil || !bytes.Equal(cb, fixture(t, "node-registry-checkpoint.json")) || ctx.Checkpoint.SHA256 != strings.TrimSpace(string(fixture(t, "node-registry-checkpoint-digest.txt"))) {
		t.Fatal("checkpoint golden changed", err)
	}
	decoded, err := DecodeNodeRegistryCheckpoint(cb)
	if err != nil || decoded != c {
		t.Fatal("checkpoint roundtrip", err)
	}
	now := nodeRegistryContext(t, r).Now
	read, err := NodeRegistryReadContext(g, c, r, ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	m := r.Members()[0]
	if _, _, err := r.Transport(read, m.Identity, m.Transport[0].Grant.CredentialID); err != nil {
		t.Fatal("transport composition", err)
	}
	p := m.Producers[0].Grant
	if _, _, err := r.Producer(read, m.Identity, p.GrantID, p.SourceID, p.PayloadSchema); err != nil {
		t.Fatal("producer composition", err)
	}
	for _, b := range [][]byte{gb, cb} {
		if _, err := DecodeNodeTransportGrant(b); err == nil {
			t.Fatal("continuity accepted as a credential")
		}
		if _, err := DecodeNodeSnapshot(b); err == nil {
			t.Fatal("continuity accepted as observation")
		}
	}
}

func TestNodeContinuityStrictEncoding(t *testing.T) {
	for _, name := range []string{"node-registry-generation", "node-registry-checkpoint"} {
		t.Run(name, func(t *testing.T) {
			original := fixture(t, name+".json")
			cases := map[string][]byte{
				"empty": nil, "null": []byte("null"), "array": []byte("[]"), "trailing": append(bytes.Clone(original), '\n'),
				"oversize":      bytes.Repeat([]byte(" "), MaxNodeContinuityBytes+1),
				"unknown":       append([]byte(`{"unknown":"value",`), original[1:]...),
				"duplicate":     append([]byte(`{"schema":"foreign",`), original[1:]...),
				"case alias":    bytes.Replace(original, []byte(`"schema"`), []byte(`"Schema"`), 1),
				"escaped alias": bytes.Replace(original, []byte(`"schema"`), []byte(`"\u0073chema"`), 1),
				"invalid utf8":  append([]byte{0xff}, original...),
				"surrogate":     bytes.Replace(original, []byte("fixture"), []byte(`\ud800`), 1),
				"other schema":  fixture(t, "node-transport-grant.json"),
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(original, &object); err != nil {
				t.Fatal(err)
			}
			for field := range object {
				clone := make(map[string]json.RawMessage, len(object))
				for k, v := range object {
					clone[k] = v
				}
				delete(clone, field)
				cases["missing "+field], _ = json.Marshal(clone)
				clone[field] = json.RawMessage("null")
				cases["null "+field], _ = json.Marshal(clone)
			}
			for label, b := range cases {
				t.Run(label, func(t *testing.T) {
					if name == "node-registry-generation" {
						v, err := DecodeNodeRegistryGeneration(b)
						if !errors.Is(err, ErrInvalidNodeContinuity) || v != (NodeRegistryGeneration{}) {
							t.Fatal("invalid generation returned authority", err)
						}
					} else {
						v, err := DecodeNodeRegistryCheckpoint(b)
						if !errors.Is(err, ErrInvalidNodeContinuity) || v != (NodeRegistryCheckpoint{}) {
							t.Fatal("invalid checkpoint returned authority", err)
						}
					}
				})
			}
		})
	}
}

func TestNodeContinuityCheckpointShape(t *testing.T) {
	_, good, _, _ := continuityFixture(t)
	for _, sequence := range []string{"", "0", "01", "+1", "-1", "1.0", "1e0", "18446744073709551616", " 1"} {
		t.Run("sequence="+sequence, func(t *testing.T) {
			c := good
			c.Sequence = sequence
			if c.Validate() == nil {
				t.Fatal("noncanonical or overflowing sequence")
			}
		})
	}
	for name, mutate := range map[string]func(*NodeRegistryCheckpoint){
		"wrong schema":         func(c *NodeRegistryCheckpoint) { c.Schema = NodeRegistryGenerationSchema },
		"genesis predecessor":  func(c *NodeRegistryCheckpoint) { c.PreviousSHA256 = strings.Repeat("a", 64) },
		"non genesis sentinel": func(c *NodeRegistryCheckpoint) { c.Sequence = "2" },
		"missing id":           func(c *NodeRegistryCheckpoint) { c.CheckpointID = "" },
		"missing authority":    func(c *NodeRegistryCheckpoint) { c.AuthorityID = "" },
		"missing lineage":      func(c *NodeRegistryCheckpoint) { c.LineageID = "" },
		"bad digest":           func(c *NodeRegistryCheckpoint) { c.Snapshot.SHA256 = strings.Repeat("A", 64) },
		"bad generation":       func(c *NodeRegistryCheckpoint) { c.Generation.Ref = "" },
		"bad state":            func(c *NodeRegistryCheckpoint) { c.State = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			c := good
			mutate(&c)
			if data, err := EncodeNodeRegistryCheckpoint(c); err == nil || data != nil {
				t.Fatal("encoded invalid checkpoint")
			}
			if ref, err := c.Reference(); err == nil || ref != (RateReference{}) {
				t.Fatal("invalid checkpoint returned reference")
			}
		})
	}
}

func TestNodeContinuityIndependentBinding(t *testing.T) {
	cases := map[string]func(*NodeRegistryGeneration, *NodeRegistryCheckpoint, *NodeAdmissionRegistry, *NodeRegistryContinuityContext){
		"authority": func(_ *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, x *NodeRegistryContinuityContext) {
			x.AuthorityID = "other"
		},
		"lineage": func(_ *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, x *NodeRegistryContinuityContext) {
			x.LineageID = "other"
		},
		"generation": func(_ *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, x *NodeRegistryContinuityContext) {
			x.Generation.SHA256 = strings.Repeat("c", 64)
		},
		"checkpoint": func(_ *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, x *NodeRegistryContinuityContext) {
			x.Checkpoint.Ref = "other"
		},
		"unprovisioned": func(_ *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, x *NodeRegistryContinuityContext) {
			*x = NodeRegistryContinuityContext{}
		},
		"client trust": func(g *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, _ *NodeRegistryContinuityContext) {
			g.ClientTrust.Ref = "other"
		},
		"administration": func(g *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, _ *NodeRegistryContinuityContext) {
			g.Administration.Ref = "other"
		},
		"policy": func(g *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, _ *NodeRegistryContinuityContext) {
			g.Policy.Ref = "other"
		},
		"snapshot": func(_ *NodeRegistryGeneration, c *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, _ *NodeRegistryContinuityContext) {
			c.Snapshot.SHA256 = strings.Repeat("c", 64)
		},
		"disabled": func(_ *NodeRegistryGeneration, c *NodeRegistryCheckpoint, _ *NodeAdmissionRegistry, x *NodeRegistryContinuityContext) {
			c.State = "disabled"
			x.Checkpoint = checkpointRef(t, *c)
		},
		"empty registry": func(_ *NodeRegistryGeneration, _ *NodeRegistryCheckpoint, r *NodeAdmissionRegistry, _ *NodeRegistryContinuityContext) {
			*r = NodeAdmissionRegistry{}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			g, c, r, x := continuityFixture(t)
			mutate(&g, &c, &r, &x)
			read, err := NodeRegistryReadContext(g, c, r, x, time.Now())
			if err == nil || read != (NodeAdmissionRegistryReadContext{}) {
				t.Fatal("returned partial authority", err)
			}
		})
	}
	g, c, r, x := continuityFixture(t)
	if read, err := NodeRegistryReadContext(g, c, r, x, time.Time{}); err == nil || read != (NodeAdmissionRegistryReadContext{}) {
		t.Fatal("zero clock accepted")
	}
}

func TestNodeContinuityRevocationAndRollback(t *testing.T) {
	g, before, r, expected := continuityFixture(t)
	m := r.Members()
	m[0].Transport[0].Grant.Status = "revoked"
	next, candidate := continuityNext(t, before, r, m)
	approved := checkpointRef(t, next)
	if err := CheckNodeRegistryAdvance(g, before, r, next, candidate, expected, approved); err != nil {
		t.Fatal("exact approved revocation", err)
	}
	// An unchanged producer must not admit under an obsolete whole checkpoint.
	if _, err := NodeRegistryReadContext(g, next, candidate, expected, time.Now()); !errors.Is(err, ErrNodeContinuityBinding) {
		t.Fatal("old checkpoint admitted new state", err)
	}
	expected.Checkpoint = approved
	if _, err := NodeRegistryReadContext(g, before, r, expected, time.Now()); !errors.Is(err, ErrNodeContinuityBinding) {
		t.Fatal("rolled-back snapshot accepted", err)
	}
	ctx, err := NodeRegistryReadContext(g, next, candidate, expected, nodeRegistryContext(t, r).Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := candidate.Transport(ctx, m[0].Identity, m[0].Transport[0].Grant.CredentialID); !errors.Is(err, ErrNodeGrantNotCurrent) {
		t.Fatal("revoked transport admitted", err)
	}
	p := m[0].Producers[0].Grant
	if _, _, err := candidate.Producer(ctx, m[0].Identity, p.GrantID, p.SourceID, p.PayloadSchema); err != nil {
		t.Fatal("independent producer changed", err)
	}
	resurrect, oldRegistry := continuityNext(t, next, candidate, r.Members())
	if err := CheckNodeRegistryAdvance(g, next, candidate, resurrect, oldRegistry, expected, checkpointRef(t, resurrect)); !errors.Is(err, ErrNodeContinuityChange) {
		t.Fatal("ordinary approval resurrected a revoked key", err)
	}
	if err := CheckNodeRegistryAdvance(g, next, candidate, next, candidate, expected, approved); err == nil {
		t.Fatal("replayed acknowledgement became new transition")
	}
}

func TestNodeContinuityHistoryAndNarrowing(t *testing.T) {
	cases := map[string]struct {
		mutate func([]NodeAdmissionMember) []NodeAdmissionMember
		valid  bool
	}{
		"drop member":    {func(m []NodeAdmissionMember) []NodeAdmissionMember { return nil }, false},
		"drop transport": {func(m []NodeAdmissionMember) []NodeAdmissionMember { m[0].Transport = nil; return m }, false},
		"drop producer":  {func(m []NodeAdmissionMember) []NodeAdmissionMember { m[0].Producers = nil; return m }, false},
		"rewrite key": {func(m []NodeAdmissionMember) []NodeAdmissionMember {
			m[0].Transport[0].Grant.PublicKeySHA256 = nodeBytesSHA256([]byte("replacement-transport-key"))
			return m
		}, false},
		"rewrite certificate": {func(m []NodeAdmissionMember) []NodeAdmissionMember {
			m[0].Transport[0].Grant.CertificateSHA256 = strings.Repeat("d", 64)
			return m
		}, false},
		"rewrite producer": {func(m []NodeAdmissionMember) []NodeAdmissionMember {
			m[0].Producers[0].Grant.SourceID = "other"
			return m
		}, false},
		"replace id": {func(m []NodeAdmissionMember) []NodeAdmissionMember {
			m[0].Transport[0].Grant.CredentialID = "new"
			return m
		}, false},
		"epoch replacement": {func(m []NodeAdmissionMember) []NodeAdmissionMember {
			m[0].Identity.Epoch = "new"
			m[0].Transport[0].Grant.Identity = m[0].Identity
			m[0].Producers[0].Grant.Identity = m[0].Identity
			return m
		}, false},
		"member revocation": {func(m []NodeAdmissionMember) []NodeAdmissionMember { m[0].Status = "revoked"; return m }, true},
		"producer revocation": {func(m []NodeAdmissionMember) []NodeAdmissionMember {
			m[0].Producers[0].Grant.Status = "revoked"
			return m
		}, true},
		"narrow": {func(m []NodeAdmissionMember) []NodeAdmissionMember {
			for j := range m[0].Transport {
				s := &m[0].Transport[j]
				from, _ := time.Parse(time.RFC3339Nano, s.AdmitFrom)
				until, _ := time.Parse(time.RFC3339Nano, s.AdmitUntil)
				s.AdmitFrom = from.Add(time.Minute).Format(time.RFC3339Nano)
				s.AdmitUntil = until.Add(-time.Minute).Format(time.RFC3339Nano)
			}
			return m
		}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g, c, r, x := continuityFixture(t)
			next, nr := continuityNext(t, c, r, tc.mutate(r.Members()))
			err := CheckNodeRegistryAdvance(g, c, r, next, nr, x, checkpointRef(t, next))
			if (err == nil) != tc.valid {
				t.Fatal("history result", err)
			}
			if tc.valid {
				x.Checkpoint = checkpointRef(t, next)
				restore, restored := continuityNext(t, next, nr, r.Members())
				if err := CheckNodeRegistryAdvance(g, next, nr, restore, restored, x, checkpointRef(t, restore)); err == nil {
					t.Fatal("withdrawn authority restored")
				}
			}
		})
	}
}

func TestNodeContinuityApprovalAndSequence(t *testing.T) {
	for name, mutate := range map[string]func(*NodeRegistryCheckpoint){
		"gap":                    func(c *NodeRegistryCheckpoint) { c.Sequence = "3" },
		"wrong predecessor":      func(c *NodeRegistryCheckpoint) { c.PreviousSHA256 = strings.Repeat("e", 64) },
		"id reuse":               func(c *NodeRegistryCheckpoint) { c.CheckpointID = "checkpoint.1" },
		"authority replacement":  func(c *NodeRegistryCheckpoint) { c.AuthorityID = "other" },
		"lineage replacement":    func(c *NodeRegistryCheckpoint) { c.LineageID = "other" },
		"generation replacement": func(c *NodeRegistryCheckpoint) { c.Generation.Ref = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			g, c, r, x := continuityFixture(t)
			next, nr := continuityNext(t, c, r, r.Members())
			mutate(&next)
			if err := CheckNodeRegistryAdvance(g, c, r, next, nr, x, checkpointRef(t, next)); err == nil {
				t.Fatal("accepted invalid successor")
			}
		})
	}
	g, c, r, x := continuityFixture(t)
	next, nr := continuityNext(t, c, r, r.Members())
	for _, approval := range []RateReference{{}, x.Checkpoint, {Ref: next.CheckpointID, SHA256: strings.Repeat("e", 64)}} {
		if err := CheckNodeRegistryAdvance(g, c, r, next, nr, x, approval); err == nil {
			t.Fatal("unapproved successor")
		}
	}
	c.Sequence = "18446744073709551615"
	c.PreviousSHA256 = strings.Repeat("e", 64)
	x.Checkpoint = checkpointRef(t, c)
	next.Sequence = "1"
	next.PreviousSHA256 = nodeContinuityGenesis
	if err := CheckNodeRegistryAdvance(g, c, r, next, nr, x, checkpointRef(t, next)); err == nil {
		t.Fatal("sequence wrapped")
	}
}

func TestNodeContinuityDisableAndAddMember(t *testing.T) {
	g, c, r, x := continuityFixture(t)
	m := r.Members()
	extra := uniqueRegistryMember(t, 1)
	extra.Transport[0].Grant.Registry = x.Generation
	extra.Producers[0].Grant.Registry = x.Generation
	m = append(m, extra)
	next, nr := continuityNext(t, c, r, m)
	if err := CheckNodeRegistryAdvance(g, c, r, next, nr, x, checkpointRef(t, next)); err != nil {
		t.Fatal("approved new member", err)
	}
	next.State = "disabled"
	if err := CheckNodeRegistryAdvance(g, c, r, next, nr, x, checkpointRef(t, next)); err != nil {
		t.Fatal("disable", err)
	}
	x.Checkpoint = checkpointRef(t, next)
	if _, err := NodeRegistryReadContext(g, next, nr, x, time.Now()); !errors.Is(err, ErrNodeRegistryNotAdmitted) {
		t.Fatal("disabled registry admitted")
	}
	third, tr := continuityNext(t, next, nr, nr.Members())
	if err := CheckNodeRegistryAdvance(g, next, nr, third, tr, x, checkpointRef(t, third)); err != nil {
		t.Fatal("continued disabled history", err)
	}
	third.State = "active"
	if err := CheckNodeRegistryAdvance(g, next, nr, third, tr, x, checkpointRef(t, third)); err == nil {
		t.Fatal("ordinary reactivation")
	}
}

func TestNodeContinuityRevokedMembersAndProducerKeys(t *testing.T) {
	for _, target := range []string{"member", "producer"} {
		t.Run(target, func(t *testing.T) {
			g, c, r, x := continuityFixture(t)
			m := r.Members()
			if target == "member" {
				m[0].Status = "revoked"
			} else {
				m[0].Producers[0].Grant.Status = "revoked"
			}
			next, nr := continuityNext(t, c, r, m)
			x.Checkpoint = checkpointRef(t, next)
			restored, rr := continuityNext(t, next, nr, r.Members())
			if err := CheckNodeRegistryAdvance(g, next, nr, restored, rr, x, checkpointRef(t, restored)); err == nil {
				t.Fatal("revoked authority reactivated")
			}
			if target == "member" {
				m = nr.Members()
				add := m[0].Transport[0]
				add.Grant.CredentialID = "extra"
				add.Grant.PublicKeySHA256 = nodeBytesSHA256([]byte("extra-key"))
				add.Grant.CertificateSHA256 = nodeBytesSHA256([]byte("extra-cert"))
				m[0].Transport = append(m[0].Transport, add)
				third, tr := continuityNext(t, next, nr, m)
				if err := CheckNodeRegistryAdvance(g, next, nr, third, tr, x, checkpointRef(t, third)); err == nil {
					t.Fatal("new credential attached to retired member")
				}
			}
		})
	}
}

func TestNodeContinuityRotationAndRetentionBoundary(t *testing.T) {
	g, c, r, x := continuityFixture(t)
	m := r.Members()
	old := &m[0].Transport[0]
	start, _ := time.Parse(time.RFC3339Nano, old.Grant.NotBefore)
	old.AdmitUntil = start.Add(13 * time.Hour).Format(time.RFC3339Nano)
	successor := *old
	successor.Grant.CredentialID = "transport.successor"
	successor.Grant.PublicKeySHA256 = nodeBytesSHA256([]byte("successor-key"))
	successor.Grant.CertificateSHA256 = nodeBytesSHA256([]byte("successor-cert"))
	successor.Grant.NotBefore = start.Add(12 * time.Hour).Format(time.RFC3339Nano)
	successor.Grant.NotAfter = start.Add(36 * time.Hour).Format(time.RFC3339Nano)
	successor.AdmitFrom, successor.AdmitUntil = successor.Grant.NotBefore, successor.Grant.NotAfter
	m[0].Transport = append(m[0].Transport, successor)
	next, nr := continuityNext(t, c, r, m)
	if err := CheckNodeRegistryAdvance(g, c, r, next, nr, x, checkpointRef(t, next)); err != nil {
		t.Fatal("approved bounded rotation", err)
	}
	x.Checkpoint = checkpointRef(t, next)
	m = nr.Members()
	m[0].Transport = []NodeTransportSlot{successor}
	third, tr := continuityNext(t, next, nr, m)
	if err := CheckNodeRegistryAdvance(g, next, nr, third, tr, x, checkpointRef(t, third)); err == nil {
		t.Fatal("expired predecessor forgotten without retention protocol")
	}
	// The exact same snapshot can be disabled without manufacturing a new ID.
	third.Snapshot = nr.Reference()
	third.State = "disabled"
	if err := CheckNodeRegistryAdvance(g, next, nr, third, nr, x, checkpointRef(t, third)); err != nil {
		t.Fatal("disable unchanged snapshot", err)
	}
	m = nr.Members()
	m[0].Status = "revoked"
	reused, err := BuildNodeAdmissionRegistry(nr.Reference().Ref, nr.binding, m)
	if err != nil {
		t.Fatal(err)
	}
	third.Snapshot = reused.Reference()
	if err := CheckNodeRegistryAdvance(g, next, nr, third, reused, x, checkpointRef(t, third)); err == nil {
		t.Fatal("snapshot ID reused with different bytes")
	}
}

func TestNodeContinuityGenerationValidation(t *testing.T) {
	for name, mutate := range map[string]func(*NodeRegistryGeneration){
		"schema":         func(g *NodeRegistryGeneration) { g.Schema = "foreign" },
		"id":             func(g *NodeRegistryGeneration) { g.GenerationID = "" },
		"authority":      func(g *NodeRegistryGeneration) { g.AuthorityID = "" },
		"lineage":        func(g *NodeRegistryGeneration) { g.LineageID = "" },
		"policy":         func(g *NodeRegistryGeneration) { g.Policy.SHA256 = "bad" },
		"trust":          func(g *NodeRegistryGeneration) { g.ClientTrust.Ref = "" },
		"administration": func(g *NodeRegistryGeneration) { g.Administration.Ref = "" },
		"oversized id":   func(g *NodeRegistryGeneration) { g.GenerationID = strings.Repeat("x", MaxNodeContinuityBytes) },
	} {
		t.Run(name, func(t *testing.T) {
			g, _, _, _ := continuityFixture(t)
			mutate(&g)
			if b, err := EncodeNodeRegistryGeneration(g); err == nil || b != nil {
				t.Fatal("invalid generation encoded")
			}
			if r, err := g.Reference(); err == nil || r != (RateReference{}) {
				t.Fatal("invalid generation referenced")
			}
		})
	}
}

func FuzzNodeContinuityCanonical(f *testing.F) {
	f.Add(fixture(f, "node-registry-generation.json"))
	f.Add(fixture(f, "node-registry-checkpoint.json"))
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		g, ge := DecodeNodeRegistryGeneration(b)
		if ge == nil {
			encoded, err := EncodeNodeRegistryGeneration(g)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("noncanonical generation")
			}
		} else if g != (NodeRegistryGeneration{}) {
			t.Fatal("partial generation")
		}
		c, ce := DecodeNodeRegistryCheckpoint(b)
		if ce == nil {
			encoded, err := EncodeNodeRegistryCheckpoint(c)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("noncanonical checkpoint")
			}
		} else if c != (NodeRegistryCheckpoint{}) {
			t.Fatal("partial checkpoint")
		}
		if ge == nil && ce == nil {
			t.Fatalf("shared authority schema for %d bytes", len(b))
		}
	})
}

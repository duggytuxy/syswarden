package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func nodeRegistryFixture(t testing.TB) (NodeAdmissionRegistryBinding, []NodeAdmissionMember) {
	t.Helper()
	tg, pg := transportGrantFixture(t), producerGrantFixture(t)
	return NodeAdmissionRegistryBinding{Registry: tg.Registry, Policy: tg.Policy}, []NodeAdmissionMember{{Identity: tg.Identity, Status: "active",
		Transport: []NodeTransportSlot{{tg, tg.NotBefore, tg.NotAfter}}, Producers: []NodeProducerSlot{{pg, pg.NotBefore, pg.NotAfter}}}}
}

func nodeRegistryContext(t testing.TB, r NodeAdmissionRegistry) NodeAdmissionRegistryReadContext {
	t.Helper()
	return NodeAdmissionRegistryReadContext{Snapshot: r.Reference(), Binding: r.binding, Now: time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)}
}

func buildRegistry(t testing.TB, b NodeAdmissionRegistryBinding, m []NodeAdmissionMember) NodeAdmissionRegistry {
	t.Helper()
	r, err := BuildNodeAdmissionRegistry("registry-snapshot.fixture", b, m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assertNoRegistry(t testing.TB, b NodeAdmissionRegistryBinding, m []NodeAdmissionMember) {
	t.Helper()
	r, err := BuildNodeAdmissionRegistry("registry-snapshot.fixture", b, m)
	if !errors.Is(err, ErrInvalidNodeRegistry) || r.Reference() != (RateReference{}) || len(r.Manifest()) != 0 || len(r.Members()) != 0 || len(r.transport) != 0 || len(r.producers) != 0 {
		t.Fatal("invalid candidate returned partial registry", err)
	}
	if strings.Contains(err.Error(), "fixture") {
		t.Fatal("registry error reflected input")
	}
}

func uniqueRegistryMember(t testing.TB, i int) NodeAdmissionMember {
	t.Helper()
	_, m := nodeRegistryFixture(t)
	v := m[0]
	v.Identity.NodeID = fmt.Sprintf("node.%d", i)
	tg := &v.Transport[0].Grant
	tg.Identity = v.Identity
	tg.CredentialID = fmt.Sprintf("credential.%d", i)
	tg.PublicKeySHA256 = nodeBytesSHA256([]byte(fmt.Sprintf("transport-key-%d", i)))
	tg.CertificateSHA256 = nodeBytesSHA256([]byte(fmt.Sprintf("certificate-%d", i)))
	pg := &v.Producers[0].Grant
	pg.Identity = v.Identity
	pg.GrantID = fmt.Sprintf("grant.%d", i)
	pg.KeyID = fmt.Sprintf("producer-key.%d", i)
	pg.PublicKeySHA256 = nodeBytesSHA256([]byte(fmt.Sprintf("producer-key-%d", i)))
	return v
}

func TestNodeRegistryGoldenAndGrantComposition(t *testing.T) {
	b, m := nodeRegistryFixture(t)
	r := buildRegistry(t, b, m)
	if !bytes.Equal(r.Manifest(), fixture(t, "node-admission-registry.json")) || r.Reference() != (RateReference{Ref: "registry-snapshot.fixture", SHA256: strings.TrimSpace(string(fixture(t, "node-admission-registry-digest.txt")))}) {
		t.Fatal("registry golden bytes changed")
	}
	c := nodeRegistryContext(t, r)
	tg, tc, err := r.Transport(c, m[0].Identity, m[0].Transport[0].Grant.CredentialID)
	if err != nil || tg != m[0].Transport[0].Grant || CheckCurrentNodeTransportGrant(tg, tc) != nil {
		t.Fatal("transport context composition", err)
	}
	pg := m[0].Producers[0].Grant
	actual, pc, err := r.Producer(c, m[0].Identity, pg.GrantID, pg.SourceID, pg.PayloadSchema)
	if err != nil || actual != pg || CheckCurrentNodeProducerGrant(actual, pc) != nil {
		t.Fatal("producer context composition", err)
	}
	for _, input := range [][]byte{r.Manifest(), fixture(t, "node-transport-grant.json")} {
		if _, err := DecodeNodeSnapshot(input); err == nil {
			t.Fatal("authority accepted as observation")
		}
	}
	if _, err := DecodeNodeTransportGrant(r.Manifest()); err == nil {
		t.Fatal("registry accepted as a transport grant")
	}
	if _, err := DecodeNodeProducerGrant(r.Manifest()); err == nil {
		t.Fatal("registry accepted as a producer grant")
	}
}

func TestNodeRegistryImmutabilityAndConcurrentReads(t *testing.T) {
	b, m := nodeRegistryFixture(t)
	r := buildRegistry(t, b, m)
	c := nodeRegistryContext(t, r)
	before := r.Manifest()
	ref := r.Reference()
	id := m[0].Identity
	credential := m[0].Transport[0].Grant.CredentialID
	m[0].Identity.NodeID = "changed"
	m[0].Transport[0].Grant.Status = "revoked"
	m[0].Producers[0].AdmitUntil = "changed"
	returned := r.Members()
	returned[0].Status = "revoked"
	returned[0].Transport[0].Grant.Status = "revoked"
	returned[0].Producers[0].Grant.SourceID = "changed"
	encoded := r.Manifest()
	encoded[0] = '!'
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				if g, _, err := r.Transport(c, id, credential); err != nil || g.Status != "active" {
					t.Error("mutated authorization", err)
				}
				if !bytes.Equal(before, r.Manifest()) || r.Reference() != ref {
					t.Error("mutable manifest")
				}
			}
		}()
	}
	wg.Wait()
}

func TestNodeRegistryRejectsMembersScopesAndCollisions(t *testing.T) {
	cases := map[string]func(*NodeAdmissionRegistryBinding, *[]NodeAdmissionMember){
		"missing binding":  func(b *NodeAdmissionRegistryBinding, _ *[]NodeAdmissionMember) { b.Registry = RateReference{} },
		"missing policy":   func(b *NodeAdmissionRegistryBinding, _ *[]NodeAdmissionMember) { b.Policy = RateReference{} },
		"bad member":       func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) { (*m)[0].Identity.NodeID = "" },
		"pending member":   func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) { (*m)[0].Status = "pending" },
		"duplicate member": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) { *m = append(*m, (*m)[0]) },
		"mixed epoch": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			v := uniqueRegistryMember(t, 99)
			v.Identity = (*m)[0].Identity
			v.Identity.Epoch = "other"
			v.Transport[0].Grant.Identity = v.Identity
			v.Producers[0].Grant.Identity = v.Identity
			*m = append(*m, v)
		},
		"transport identity": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Transport[0].Grant.Identity.NodeID = "other"
		},
		"transport registry": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Transport[0].Grant.Registry.SHA256 = strings.Repeat("0", 64)
		},
		"transport policy": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Transport[0].Grant.Policy.Ref = "other"
		},
		"producer identity": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Producers[0].Grant.Identity.Epoch = "other"
		},
		"producer registry": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Producers[0].Grant.Registry.Ref = "other"
		},
		"producer policy": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Producers[0].Grant.Policy.SHA256 = strings.Repeat("0", 64)
		},
		"bad transport": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Transport[0].Grant.Algorithm = "wrong"
		},
		"bad producer": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Producers[0].Grant.Algorithm = "wrong"
		},
		"cross purpose key": func(_ *NodeAdmissionRegistryBinding, m *[]NodeAdmissionMember) {
			(*m)[0].Producers[0].Grant.PublicKeySHA256 = (*m)[0].Transport[0].Grant.PublicKeySHA256
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) { b, m := nodeRegistryFixture(t); change(&b, &m); assertNoRegistry(t, b, m) })
	}
	for _, mode := range []string{"transport id", "transport key", "certificate", "producer id", "producer key id", "producer key", "cross node purpose", "revoked key"} {
		t.Run(mode, func(t *testing.T) {
			b, m := nodeRegistryFixture(t)
			m = append(m, uniqueRegistryMember(t, 99))
			switch mode {
			case "transport id":
				m[1].Transport[0].Grant.CredentialID = m[0].Transport[0].Grant.CredentialID
			case "transport key":
				m[1].Transport[0].Grant.PublicKeySHA256 = m[0].Transport[0].Grant.PublicKeySHA256
			case "certificate":
				m[1].Transport[0].Grant.CertificateSHA256 = m[0].Transport[0].Grant.CertificateSHA256
			case "producer id":
				m[1].Producers[0].Grant.GrantID = m[0].Producers[0].Grant.GrantID
			case "producer key id":
				m[1].Producers[0].Grant.KeyID = m[0].Producers[0].Grant.KeyID
			case "producer key":
				m[1].Producers[0].Grant.PublicKeySHA256 = m[0].Producers[0].Grant.PublicKeySHA256
			case "cross node purpose":
				m[1].Transport[0].Grant.PublicKeySHA256 = m[0].Producers[0].Grant.PublicKeySHA256
			case "revoked key":
				m[0].Status = "revoked"
				m[1].Transport[0].Grant.PublicKeySHA256 = m[0].Transport[0].Grant.PublicKeySHA256
			}
			assertNoRegistry(t, b, m)
			slices.Reverse(m)
			assertNoRegistry(t, b, m)
		})
	}
	b, m := nodeRegistryFixture(t)
	if r, err := BuildNodeAdmissionRegistry("", b, m); err == nil || len(r.Manifest()) != 0 {
		t.Fatal("missing snapshot ID accepted")
	}
}

func TestNodeRegistryAdmissionWindows(t *testing.T) {
	for _, kind := range []string{"transport", "producer"} {
		for _, mode := range []string{"empty", "alias", "zero", "reversed", "before grant", "after grant"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				b, m := nodeRegistryFixture(t)
				from, until := &m[0].Transport[0].AdmitFrom, &m[0].Transport[0].AdmitUntil
				if kind == "producer" {
					from, until = &m[0].Producers[0].AdmitFrom, &m[0].Producers[0].AdmitUntil
				}
				switch mode {
				case "empty":
					*from = ""
				case "alias":
					*from = "2026-10-19T09:00:00+00:00"
				case "zero":
					*until = *from
				case "reversed":
					*until = "2026-10-18T09:00:00Z"
				case "before grant":
					*from = "2026-10-19T08:59:59Z"
				case "after grant":
					*until = "2026-10-20T09:00:00.000000001Z"
				}
				assertNoRegistry(t, b, m)
			})
		}
	}
	b, m := nodeRegistryFixture(t)
	for i := range m[0].Transport {
		m[0].Transport[i].AdmitFrom = "2026-10-19T10:00:00Z"
		m[0].Transport[i].AdmitUntil = "2026-10-19T11:00:00Z"
	}
	for i := range m[0].Producers {
		m[0].Producers[i].AdmitFrom = "2026-10-19T10:00:00Z"
		m[0].Producers[i].AdmitUntil = "2026-10-19T11:00:00Z"
	}
	r := buildRegistry(t, b, m)
	pg := m[0].Producers[0].Grant
	for _, instant := range []struct {
		at       string
		accepted bool
	}{{"2026-10-19T09:59:59.999999999Z", false}, {"2026-10-19T10:00:00Z", true}, {"2026-10-19T10:59:59.999999999Z", true}, {"2026-10-19T11:00:00Z", false}} {
		c := nodeRegistryContext(t, r)
		c.Now, _ = time.Parse(time.RFC3339Nano, instant.at)
		_, _, te := r.Transport(c, m[0].Identity, m[0].Transport[0].Grant.CredentialID)
		_, _, pe := r.Producer(c, m[0].Identity, pg.GrantID, pg.SourceID, pg.PayloadSchema)
		if (te == nil) != instant.accepted || (pe == nil) != instant.accepted {
			t.Fatal("admission-window boundary", instant, te, pe)
		}
	}
}

func rotatingRegistryMember(t testing.TB, kind string) NodeAdmissionMember {
	t.Helper()
	_, m := nodeRegistryFixture(t)
	v := m[0]
	if kind == "transport" {
		old := &v.Transport[0]
		next := *old
		old.AdmitUntil = "2026-10-19T22:00:00Z"
		next.Grant.CredentialID = "credential.next"
		next.Grant.PublicKeySHA256 = nodeBytesSHA256([]byte("next transport"))
		next.Grant.CertificateSHA256 = nodeBytesSHA256([]byte("next certificate"))
		next.Grant.NotBefore = "2026-10-19T21:00:00Z"
		next.Grant.NotAfter = "2026-10-20T21:00:00Z"
		next.AdmitFrom = next.Grant.NotBefore
		next.AdmitUntil = next.Grant.NotAfter
		v.Transport = append(v.Transport, next)
	} else {
		old := &v.Producers[0]
		old.Grant.NotAfter = "2026-11-18T09:00:00Z"
		old.AdmitUntil = "2026-11-03T10:00:00Z"
		next := *old
		next.Grant.GrantID = "grant.next"
		next.Grant.KeyID = "producer-key.next"
		next.Grant.PublicKeySHA256 = nodeBytesSHA256([]byte("next producer"))
		next.Grant.NotBefore = "2026-11-03T09:00:00Z"
		next.Grant.NotAfter = "2026-12-03T09:00:00Z"
		next.AdmitFrom = next.Grant.NotBefore
		next.AdmitUntil = next.Grant.NotAfter
		v.Producers = append(v.Producers, next)
	}
	return v
}

func TestNodeRegistryRotationBounds(t *testing.T) {
	for _, kind := range []string{"transport", "producer"} {
		for _, mode := range []string{"one hour", "no overlap", "gap", "excess overlap", "early renewal", "equal start", "nested end", "third slot", "same key", "schema change"} {
			if kind == "transport" && mode == "schema change" {
				continue
			}
			t.Run(kind+"/"+mode, func(t *testing.T) {
				b, _ := nodeRegistryFixture(t)
				m := rotatingRegistryMember(t, kind)
				var oldEnd, newFrom, newUntil, newIssued, key *string
				if kind == "transport" {
					oldEnd = &m.Transport[0].AdmitUntil
					newFrom = &m.Transport[1].AdmitFrom
					newUntil = &m.Transport[1].AdmitUntil
					newIssued = &m.Transport[1].Grant.NotBefore
					key = &m.Transport[1].Grant.PublicKeySHA256
				} else {
					oldEnd = &m.Producers[0].AdmitUntil
					newFrom = &m.Producers[1].AdmitFrom
					newUntil = &m.Producers[1].AdmitUntil
					newIssued = &m.Producers[1].Grant.NotBefore
					key = &m.Producers[1].Grant.PublicKeySHA256
				}
				start, _ := time.Parse(time.RFC3339Nano, *newFrom)
				switch mode {
				case "no overlap":
					*oldEnd = *newFrom
				case "gap":
					*oldEnd = start.Add(-time.Hour).Format(time.RFC3339Nano)
				case "excess overlap":
					*oldEnd = start.Add(time.Hour + time.Nanosecond).Format(time.RFC3339Nano)
				case "early renewal":
					*newIssued = start.Add(-time.Nanosecond).Format(time.RFC3339Nano)
					if kind == "transport" {
						m.Transport[1].Grant.NotAfter = start.Add(24*time.Hour - time.Nanosecond).Format(time.RFC3339Nano)
						*newUntil = m.Transport[1].Grant.NotAfter
					} else {
						m.Producers[1].Grant.NotAfter = start.Add(30*24*time.Hour - time.Nanosecond).Format(time.RFC3339Nano)
						*newUntil = m.Producers[1].Grant.NotAfter
					}
				case "equal start":
					if kind == "transport" {
						m.Transport[0].AdmitFrom = *newFrom
					} else {
						m.Producers[0].AdmitFrom = *newFrom
					}
				case "nested end":
					*newUntil = *oldEnd
				case "third slot":
					if kind == "transport" {
						m.Transport = append(m.Transport, m.Transport[1])
					} else {
						m.Producers = append(m.Producers, m.Producers[1])
					}
				case "same key":
					if kind == "transport" {
						*key = m.Transport[0].Grant.PublicKeySHA256
					} else {
						*key = m.Producers[0].Grant.PublicKeySHA256
					}
				case "schema change":
					m.Producers[1].Grant.PayloadSchema = "syswarden.other.v1"
				}
				good := mode == "one hour" || mode == "no overlap" || mode == "gap"
				for range 2 {
					if good {
						buildRegistry(t, b, []NodeAdmissionMember{m})
					} else {
						assertNoRegistry(t, b, []NodeAdmissionMember{m})
					}
					slices.Reverse(m.Transport)
					slices.Reverse(m.Producers)
				}
			})
		}
	}
}

func TestNodeRegistryReadContextAndNoPartialAuthority(t *testing.T) {
	b, m := nodeRegistryFixture(t)
	r := buildRegistry(t, b, m)
	base := nodeRegistryContext(t, r)
	id := m[0].Identity
	pg, tg := m[0].Producers[0].Grant, m[0].Transport[0].Grant
	for _, mode := range []string{"zero", "snapshot id", "snapshot digest", "registry id", "registry digest", "policy id", "policy digest", "clock", "node", "epoch", "cluster", "missing record", "wrong source", "wrong schema", "wrong purpose", "invalid identity"} {
		t.Run(mode, func(t *testing.T) {
			c, identity, credential, grant, source, schema := base, id, tg.CredentialID, pg.GrantID, pg.SourceID, pg.PayloadSchema
			switch mode {
			case "zero":
				c = NodeAdmissionRegistryReadContext{}
			case "snapshot id":
				c.Snapshot.Ref = "different"
			case "snapshot digest":
				c.Snapshot.SHA256 = strings.Repeat("0", 64)
			case "registry id":
				c.Binding.Registry.Ref = "different"
			case "registry digest":
				c.Binding.Registry.SHA256 = strings.Repeat("0", 64)
			case "policy id":
				c.Binding.Policy.Ref = "different"
			case "policy digest":
				c.Binding.Policy.SHA256 = strings.Repeat("0", 64)
			case "clock":
				c.Now = time.Time{}
			case "node":
				identity.NodeID = "foreign"
			case "epoch":
				identity.Epoch = "foreign"
			case "cluster":
				identity.ClusterID = "foreign"
			case "missing record":
				credential, grant = "missing", "missing"
			case "wrong source":
				source = "different"
			case "wrong schema":
				schema = "different"
			case "wrong purpose":
				credential, grant = pg.GrantID, tg.CredentialID
			case "invalid identity":
				identity.NodeID = ""
			}
			if mode != "wrong source" && mode != "wrong schema" {
				g, ctx, err := r.Transport(c, identity, credential)
				if err == nil || g != (NodeTransportGrant{}) || ctx != (NodeGrantReadContext{}) {
					t.Fatal("partial transport authority", err)
				}
			}
			g, ctx, err := r.Producer(c, identity, grant, source, schema)
			if err == nil || g != (NodeProducerGrant{}) || ctx != (NodeGrantReadContext{}) {
				t.Fatal("partial producer authority", err)
			}
		})
	}
	var zero NodeAdmissionRegistry
	if _, _, err := zero.Transport(base, id, tg.CredentialID); !errors.Is(err, ErrNodeRegistryBindingMismatch) {
		t.Fatal("zero registry accepted")
	}
	for _, mode := range []string{"member revoked", "transport revoked", "producer revoked", "future", "expired", "empty slots"} {
		t.Run(mode, func(t *testing.T) {
			changed := cloneNodeAdmissionMembers(m)
			c := base
			switch mode {
			case "member revoked":
				changed[0].Status = "revoked"
			case "transport revoked":
				changed[0].Transport[0].Grant.Status = "revoked"
			case "producer revoked":
				changed[0].Producers[0].Grant.Status = "revoked"
			case "future":
				c.Now = c.Now.Add(-time.Nanosecond)
			case "expired":
				c.Now = c.Now.Add(24 * time.Hour)
			case "empty slots":
				changed[0].Transport = nil
				changed[0].Producers = nil
			}
			next := buildRegistry(t, b, changed)
			if mode != "future" && mode != "expired" {
				if next.Reference() == base.Snapshot {
					t.Fatal("changed authority retained same digest")
				}
				if _, _, err := next.Transport(base, id, tg.CredentialID); !errors.Is(err, ErrNodeRegistryBindingMismatch) {
					t.Fatal("stale snapshot authorized new state")
				}
			}
			c.Snapshot = next.Reference()
			actual, tc, te := next.Transport(c, id, tg.CredentialID)
			producer, pc, pe := next.Producer(c, id, pg.GrantID, pg.SourceID, pg.PayloadSchema)
			if mode != "producer revoked" && (te == nil || actual != (NodeTransportGrant{}) || tc != (NodeGrantReadContext{})) {
				t.Fatal("withdrawn transport admitted", te)
			}
			if mode != "transport revoked" && (pe == nil || producer != (NodeProducerGrant{}) || pc != (NodeGrantReadContext{})) {
				t.Fatal("withdrawn producer admitted", pe)
			}
			if mode == "producer revoked" && te != nil {
				t.Fatal("producer revocation coupled to transport")
			}
			if mode == "transport revoked" && pe != nil {
				t.Fatal("transport revocation coupled to producer key")
			}
		})
	}
}

func TestNodeRegistryCertificateRetirement(t *testing.T) {
	f := newNodeCertificateFixture(t)
	g, certctx := f.grant(t)
	b, m := nodeRegistryFixture(t)
	m[0].Transport[0].Grant = g
	m[0].Transport[0].AdmitUntil = "2026-10-19T10:00:00Z"
	r := buildRegistry(t, b, m)
	c := nodeRegistryContext(t, r)
	admitted, ctx, err := r.Transport(c, m[0].Identity, g.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	certctx.Grant = ctx
	if err := CheckNodeTransportCertificateBinding(admitted, certctx, f.leafDER, f.issuerDER, f.rootDER); err != nil {
		t.Fatal(err)
	}
	c.Now = c.Now.Add(time.Hour)
	if _, _, err := r.Transport(c, m[0].Identity, g.CredentialID); !errors.Is(err, ErrNodeRegistryNotAdmitted) {
		t.Fatal("retired certificate admitted")
	}
	// Its public validity is intentionally unchanged. Only registry admission ends.
	certctx.Grant.Now = c.Now
	if err := CheckNodeTransportCertificateBinding(g, certctx, f.leafDER, f.issuerDER, f.rootDER); err != nil {
		t.Fatal("retirement changed certificate profile", err)
	}
}

func TestNodeRegistrySourcesAndCounts(t *testing.T) {
	b, base := nodeRegistryFixture(t)
	for _, n := range []int{0, 1, 500, MaxNodeAdmissionMembers, MaxNodeAdmissionMembers + 1} {
		t.Run(fmt.Sprintf("members-%d", n), func(t *testing.T) {
			m := make([]NodeAdmissionMember, n)
			for i := range m {
				m[i] = NodeAdmissionMember{Identity: NodeIdentity{ClusterID: "cluster.fixture", NodeID: fmt.Sprintf("node.%d", i), Epoch: "epoch.fixture"}, Status: "active"}
			}
			if n > MaxNodeAdmissionMembers {
				assertNoRegistry(t, b, m)
				return
			}
			r := buildRegistry(t, b, m)
			if len(r.Members()) != n {
				t.Fatal("member without credentials was dropped")
			}
			for _, member := range r.Members() {
				if _, _, err := r.Transport(nodeRegistryContext(t, r), member.Identity, "missing"); !errors.Is(err, ErrNodeRegistryNotAdmitted) {
					t.Fatal("credential inferred from membership")
				}
			}
		})
	}
	for _, n := range []int{16, 17, 33} {
		t.Run(fmt.Sprintf("sources-%d", n), func(t *testing.T) {
			m := cloneNodeAdmissionMembers(base)
			m[0].Producers = nil
			for i := 0; i < n; i++ {
				s := base[0].Producers[0]
				s.Grant.SourceID = fmt.Sprintf("source.%d", i)
				s.Grant.GrantID = fmt.Sprintf("grant.%d", i)
				s.Grant.KeyID = fmt.Sprintf("key.%d", i)
				s.Grant.PublicKeySHA256 = nodeBytesSHA256([]byte(s.Grant.KeyID))
				m[0].Producers = append(m[0].Producers, s)
			}
			if n <= MaxNodeAdmissionSources {
				buildRegistry(t, b, m)
			} else {
				assertNoRegistry(t, b, m)
			}
		})
	}
	// All 16 source rotations fit the two-key bound with distinct keys.
	m := rotatingRegistryMember(t, "producer")
	pair := slices.Clone(m.Producers)
	m.Producers = nil
	for i := 0; i < 16; i++ {
		for j, s := range pair {
			s.Grant.SourceID = fmt.Sprintf("source.%d", i)
			s.Grant.GrantID = fmt.Sprintf("grant.%d.%d", i, j)
			s.Grant.KeyID = fmt.Sprintf("key.%d.%d", i, j)
			s.Grant.PublicKeySHA256 = nodeBytesSHA256([]byte(s.Grant.KeyID))
			m.Producers = append(m.Producers, s)
		}
	}
	buildRegistry(t, b, []NodeAdmissionMember{m})
	// Count and byte ceilings are independent. Valid record shapes can exhaust
	// the byte budget before identity indexes are built, without partial output.
	large := make([]NodeAdmissionMember, MaxNodeAdmissionMembers)
	for i := range large {
		large[i] = m
	}
	result, err := BuildNodeAdmissionRegistry("large.fixture", b, large)
	if err == nil || !strings.Contains(err.Error(), "aggregate byte budget") || len(result.Manifest()) != 0 {
		t.Fatal("aggregate bound not enforced before indexes", err)
	}
}

func TestNodeRegistryPermutationAndCompleteBinding(t *testing.T) {
	b, _ := nodeRegistryFixture(t)
	m := []NodeAdmissionMember{uniqueRegistryMember(t, 1), uniqueRegistryMember(t, 2), uniqueRegistryMember(t, 3)}
	before := buildRegistry(t, b, m)
	slices.Reverse(m)
	after := buildRegistry(t, b, m)
	if !bytes.Equal(before.Manifest(), after.Manifest()) {
		t.Fatal("order changed canonical registry")
	}
	original := cloneNodeAdmissionMembers(m)
	original[2].Status = "revoked"
	changed := buildRegistry(t, b, original)
	// Even an unaffected record must not be read under an old aggregate digest.
	c := nodeRegistryContext(t, before)
	if _, _, err := changed.Transport(c, m[0].Identity, m[0].Transport[0].Grant.CredentialID); !errors.Is(err, ErrNodeRegistryBindingMismatch) {
		t.Fatal("partial snapshot accepted under old complete binding")
	}
	// Equal empty collections normalize to arrays in the canonical manifest.
	m[0].Transport = nil
	m[0].Producers = nil
	a := buildRegistry(t, b, m)
	m[0].Transport = []NodeTransportSlot{}
	m[0].Producers = []NodeProducerSlot{}
	z := buildRegistry(t, b, m)
	if !bytes.Equal(a.Manifest(), z.Manifest()) {
		t.Fatal("nil and empty lists differ")
	}
	var decoded map[string]any
	if err := json.Unmarshal(a.Manifest(), &decoded); err != nil {
		t.Fatal(err)
	}
}

func FuzzNodeRegistryPermutation(f *testing.F) {
	b, _ := nodeRegistryFixture(f)
	m := []NodeAdmissionMember{uniqueRegistryMember(f, 1), uniqueRegistryMember(f, 2), uniqueRegistryMember(f, 3)}
	baseline := buildRegistry(f, b, m)
	expected := baseline.Manifest()
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{2, 1, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, order []byte) {
		if len(order) > 64 {
			return
		}
		copied := cloneNodeAdmissionMembers(m)
		for i, v := range order {
			a := i % len(copied)
			z := int(v) % len(copied)
			copied[a], copied[z] = copied[z], copied[a]
		}
		r := buildRegistry(t, b, copied)
		if !bytes.Equal(expected, r.Manifest()) {
			t.Fatal("permutation changed canonical authority")
		}
		copied[0].Producers[0].Grant.PublicKeySHA256 = copied[1].Transport[0].Grant.PublicKeySHA256
		assertNoRegistry(t, b, copied)
	})
}

func TestNodeRegistryFiveHundredCredentialPopulation(t *testing.T) {
	b, _ := nodeRegistryFixture(t)
	members := make([]NodeAdmissionMember, 500)
	for i := range members {
		members[i] = uniqueRegistryMember(t, i)
	}
	r := buildRegistry(t, b, members)
	c := nodeRegistryContext(t, r)
	for _, m := range members {
		g, ctx, err := r.Transport(c, m.Identity, m.Transport[0].Grant.CredentialID)
		if err != nil || g.Identity != m.Identity || ctx.Identity != m.Identity {
			t.Fatal("transport cross-node binding", err)
		}
		pg := m.Producers[0].Grant
		actual, pc, err := r.Producer(c, m.Identity, pg.GrantID, pg.SourceID, pg.PayloadSchema)
		if err != nil || actual.Identity != m.Identity || pc.Identity != m.Identity {
			t.Fatal("producer cross-node binding", err)
		}
	}
	// A fault in the last member invalidates the complete candidate, not just it.
	members[len(members)-1].Producers[0].Grant.PublicKeySHA256 = members[0].Transport[0].Grant.PublicKeySHA256
	assertNoRegistry(t, b, members)
}

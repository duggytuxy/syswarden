package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func transportGrantFixture(t testing.TB) NodeTransportGrant {
	t.Helper()
	g, err := DecodeNodeTransportGrant(fixture(t, "node-transport-grant.json"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func producerGrantFixture(t testing.TB) NodeProducerGrant {
	t.Helper()
	g, err := DecodeNodeProducerGrant(fixture(t, "node-producer-grant.json"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func transportGrantContext(t testing.TB, g NodeTransportGrant) NodeGrantReadContext {
	t.Helper()
	hash, err := NodeTransportGrantSHA256(g)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, g.NotBefore)
	if err != nil {
		t.Fatal(err)
	}
	return NodeGrantReadContext{Record: RateReference{Ref: g.CredentialID, SHA256: hash},
		Identity: g.Identity, Registry: g.Registry, Policy: g.Policy, Now: now}
}

func producerGrantContext(t testing.TB, g NodeProducerGrant) NodeGrantReadContext {
	t.Helper()
	hash, err := NodeProducerGrantSHA256(g)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, g.NotBefore)
	if err != nil {
		t.Fatal(err)
	}
	return NodeGrantReadContext{Record: RateReference{Ref: g.GrantID, SHA256: hash},
		Identity: g.Identity, Registry: g.Registry, Policy: g.Policy, Now: now}
}

func TestNodeAdmissionGolden(t *testing.T) {
	transport, producer := transportGrantFixture(t), producerGrantFixture(t)
	for _, name := range []string{"transport", "producer"} {
		t.Run(name, func(t *testing.T) {
			var data []byte
			var hash string
			var err error
			if name == "transport" {
				data, err = EncodeNodeTransportGrant(transport)
				hash, _ = NodeTransportGrantSHA256(transport)
			} else {
				data, err = EncodeNodeProducerGrant(producer)
				hash, _ = NodeProducerGrantSHA256(producer)
			}
			if err != nil || !bytes.Equal(data, fixture(t, "node-"+name+"-grant.json")) || hash != strings.TrimSpace(string(fixture(t, "node-"+name+"-grant-digest.txt"))) {
				t.Fatal("grant canonical bytes changed", err)
			}
		})
	}
	if err := CheckCurrentNodeTransportGrant(transport, transportGrantContext(t, transport)); err != nil {
		t.Fatal(err)
	}
	if err := CheckCurrentNodeProducerGrant(producer, producerGrantContext(t, producer)); err != nil {
		t.Fatal(err)
	}
}

func TestNodeAdmissionContextIsolation(t *testing.T) {
	transport, producer := transportGrantFixture(t), producerGrantFixture(t)
	changes := map[string]func(*NodeGrantReadContext){
		"record id":       func(c *NodeGrantReadContext) { c.Record.Ref += ".other" },
		"record digest":   func(c *NodeGrantReadContext) { c.Record.SHA256 = strings.Repeat("0", 64) },
		"node":            func(c *NodeGrantReadContext) { c.Identity.NodeID += ".other" },
		"cluster":         func(c *NodeGrantReadContext) { c.Identity.ClusterID += ".other" },
		"epoch":           func(c *NodeGrantReadContext) { c.Identity.Epoch += ".other" },
		"registry id":     func(c *NodeGrantReadContext) { c.Registry.Ref += ".other" },
		"registry digest": func(c *NodeGrantReadContext) { c.Registry.SHA256 = strings.Repeat("0", 64) },
		"policy id":       func(c *NodeGrantReadContext) { c.Policy.Ref += ".other" },
		"policy digest":   func(c *NodeGrantReadContext) { c.Policy.SHA256 = strings.Repeat("0", 64) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			ct, cp := transportGrantContext(t, transport), producerGrantContext(t, producer)
			change(&ct)
			change(&cp)
			if !errors.Is(CheckCurrentNodeTransportGrant(transport, ct), ErrNodeGrantBindingMismatch) ||
				!errors.Is(CheckCurrentNodeProducerGrant(producer, cp), ErrNodeGrantBindingMismatch) {
				t.Fatal("foreign grant context accepted")
			}
		})
	}
	for _, name := range []string{"zero clock", "empty context", "bad hash", "bad identity", "missing registry", "missing policy"} {
		t.Run(name, func(t *testing.T) {
			ct, cp := transportGrantContext(t, transport), producerGrantContext(t, producer)
			for _, c := range []*NodeGrantReadContext{&ct, &cp} {
				switch name {
				case "zero clock":
					c.Now = time.Time{}
				case "empty context":
					*c = NodeGrantReadContext{}
				case "bad hash":
					c.Record.SHA256 = "bad"
				case "bad identity":
					c.Identity.NodeID = ""
				case "missing registry":
					c.Registry = RateReference{}
				case "missing policy":
					c.Policy = RateReference{}
				}
			}
			if !errors.Is(CheckCurrentNodeTransportGrant(transport, ct), ErrInvalidNodeGrantContext) ||
				!errors.Is(CheckCurrentNodeProducerGrant(producer, cp), ErrInvalidNodeGrantContext) {
				t.Fatal("missing independent context accepted")
			}
		})
	}
}

func TestNodeAdmissionValidityAndRevocation(t *testing.T) {
	for _, name := range []string{"start", "before", "last instant", "expiry", "after", "revoked"} {
		t.Run(name, func(t *testing.T) {
			tg, pg := transportGrantFixture(t), producerGrantFixture(t)
			if name == "revoked" {
				tg.Status = "revoked"
				pg.Status = "revoked"
			}
			ct, cp := transportGrantContext(t, tg), producerGrantContext(t, pg)
			until, _ := time.Parse(time.RFC3339Nano, tg.NotAfter)
			for _, c := range []*NodeGrantReadContext{&ct, &cp} {
				switch name {
				case "before":
					c.Now = c.Now.Add(-time.Nanosecond)
				case "last instant":
					c.Now = until.Add(-time.Nanosecond)
				case "expiry":
					c.Now = until
				case "after":
					c.Now = until.Add(time.Nanosecond)
				}
			}
			for _, err := range []error{CheckCurrentNodeTransportGrant(tg, ct), CheckCurrentNodeProducerGrant(pg, cp)} {
				if name == "start" || name == "last instant" {
					if err != nil {
						t.Fatal(err)
					}
				} else if !errors.Is(err, ErrNodeGrantNotCurrent) {
					t.Fatal("inactive grant accepted", err)
				}
			}
		})
	}
	tg := transportGrantFixture(t)
	old := transportGrantContext(t, tg)
	tg.NotAfter = old.Now.Add(MaxNodeCredentialLifetime + time.Nanosecond).Format(time.RFC3339Nano)
	if tg.Validate() == nil {
		t.Fatal("excess transport lifetime accepted")
	}
	tg = transportGrantFixture(t)
	tg.Status = "revoked"
	if !errors.Is(CheckCurrentNodeTransportGrant(tg, old), ErrNodeGrantBindingMismatch) {
		t.Fatal("changed status retained old digest")
	}
	pg := producerGrantFixture(t)
	cp := producerGrantContext(t, pg)
	pg.NotAfter = cp.Now.Add(MaxNodeProducerGrantLifetime).Format(time.RFC3339Nano)
	if err := pg.Validate(); err != nil {
		t.Fatal("maximum producer lifetime rejected", err)
	}
	pg.NotAfter = cp.Now.Add(MaxNodeProducerGrantLifetime + time.Nanosecond).Format(time.RFC3339Nano)
	if pg.Validate() == nil {
		t.Fatal("excess producer lifetime accepted")
	}
}

func TestNodeAdmissionInvalidFields(t *testing.T) {
	for _, kind := range []string{"transport", "producer"} {
		data := fixture(t, "node-"+kind+"-grant.json")
		var original map[string]any
		if err := json.Unmarshal(data, &original); err != nil {
			t.Fatal(err)
		}
		for field := range original {
			t.Run(kind+"/empty/"+field, func(t *testing.T) {
				var input map[string]any
				if err := json.Unmarshal(data, &input); err != nil {
					t.Fatal(err)
				}
				input[field] = ""
				b, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				assertNodeGrantRejected(t, kind, b)
			})
		}
		for name, pair := range map[string][2]string{
			"pending is not active": {"\"active\"", "\"pending\""},
			"unknown algorithm":     {"ecdsa-p256", "rsa-4096"},
			"invalid node":          {"node.fixture", "not/a/node"},
			"zero window":           {"2026-10-20T09:00:00Z", "2026-10-19T09:00:00Z"},
			"reverse window":        {"2026-10-20T09:00:00Z", "2026-10-18T09:00:00Z"},
			"unbounded lifetime":    {"2026-10-20T09:00:00Z", "2027-10-20T09:00:00Z"},
			"clock alias":           {"2026-10-19T09:00:00Z", "2026-10-19T09:00:00+00:00"},
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				assertNodeGrantRejected(t, kind, []byte(strings.Replace(string(data), pair[0], pair[1], 1)))
			})
		}
	}
	pg := producerGrantFixture(t)
	pg.SourceID = "*"
	if pg.Validate() == nil {
		t.Fatal("wildcard source accepted")
	}
	pg = producerGrantFixture(t)
	pg.PayloadSchema = "syswarden.*"
	if pg.Validate() == nil {
		t.Fatal("wildcard schema accepted")
	}
	tg := transportGrantFixture(t)
	tg.Schema = "other"
	if data, err := EncodeNodeTransportGrant(tg); !errors.Is(err, ErrUnsupportedNodeGrantSchema) || data != nil {
		t.Fatal("invalid transport encoded")
	}
	if hash, err := NodeTransportGrantSHA256(tg); err == nil || hash != "" {
		t.Fatal("invalid transport hashed")
	}
	if data, err := EncodeNodeProducerGrant(pg); err == nil || data != nil {
		t.Fatal("invalid producer encoded")
	}
	if hash, err := NodeProducerGrantSHA256(pg); err == nil || hash != "" {
		t.Fatal("invalid producer hashed")
	}
}

func assertNodeGrantRejected(t testing.TB, kind string, data []byte) {
	t.Helper()
	if kind == "transport" {
		g, err := DecodeNodeTransportGrant(data)
		if err == nil || g != (NodeTransportGrant{}) {
			t.Fatal("partial transport grant returned", err)
		}
		if strings.Contains(err.Error(), "node.fixture") {
			t.Fatal("input reflected in error")
		}
	} else {
		g, err := DecodeNodeProducerGrant(data)
		if err == nil || g != (NodeProducerGrant{}) {
			t.Fatal("partial producer grant returned", err)
		}
		if strings.Contains(err.Error(), "node.fixture") {
			t.Fatal("input reflected in error")
		}
	}
}

func TestNodeAdmissionStrictJSON(t *testing.T) {
	for _, kind := range []string{"transport", "producer"} {
		base := fixture(t, "node-"+kind+"-grant.json")
		for name, data := range map[string][]byte{
			"empty": nil, "null": []byte("null"), "array": []byte("[]"),
			"unknown":           bytes.Replace(base, []byte("{"), []byte(`{"unexpected":"field",`), 1),
			"duplicate":         bytes.Replace(base, []byte("{"), []byte(`{"schema":"other",`), 1),
			"escaped duplicate": bytes.Replace(base, []byte("{"), []byte(`{"\u0073chema":"other",`), 1),
			"alias":             bytes.Replace(base, []byte(`"schema"`), []byte(`"Schema"`), 1),
			"nested alias":      bytes.Replace(base, []byte(`"epoch"`), []byte(`"Epoch"`), 1),
			"missing":           bytes.Replace(base, []byte(`"status":"active",`), nil, 1),
			"null field":        bytes.Replace(base, []byte(`"active"`), []byte(`null`), 1),
			"invalid utf8":      bytes.Replace(base, []byte("node.fixture"), []byte{0xff}, 1),
			"surrogate":         bytes.Replace(base, []byte("node.fixture"), []byte(`\ud800`), 1),
			"unknown version":   bytes.Replace(base, []byte(".v1"), []byte(".v2"), 1),
			"trailing":          append(bytes.Clone(base), []byte(" {}")...),
			"oversized":         bytes.Repeat([]byte(" "), MaxDocumentBytes+1),
		} {
			t.Run(kind+"/"+name, func(t *testing.T) { assertNodeGrantRejected(t, kind, data) })
		}
		for _, other := range []string{"node-reachable.json", "native-ip.json", "bunkerweb-presence.json"} {
			assertNodeGrantRejected(t, kind, fixture(t, other))
		}
		for _, line := range bytes.Split(bytes.TrimSpace(legacyFixture(t)), []byte("\n")) {
			assertNodeGrantRejected(t, kind, line)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, base, "", "  "); err != nil {
			t.Fatal(err)
		}
		for _, accepted := range [][]byte{pretty.Bytes(), append(bytes.Repeat([]byte(" "), MaxDocumentBytes-len(base)), base...)} {
			if kind == "transport" {
				if _, err := DecodeNodeTransportGrant(accepted); err != nil {
					t.Fatal("valid transport encoding rejected", err)
				}
			} else if _, err := DecodeNodeProducerGrant(accepted); err != nil {
				t.Fatal("valid producer encoding rejected", err)
			}
			checkNodeGrantRoundTrip(t, accepted)
		}
		if _, err := DecodeNodeSnapshot(base); err == nil {
			t.Fatal("grant accepted as a node observation")
		}
		if _, err := DecodeBunkerWebPresenceSnapshot(base); err == nil {
			t.Fatal("grant accepted as partner presence")
		}
	}
	assertNodeGrantRejected(t, "transport", fixture(t, "node-producer-grant.json"))
	assertNodeGrantRejected(t, "producer", fixture(t, "node-transport-grant.json"))
}

func checkNodeGrantRoundTrip(t testing.TB, data []byte) {
	t.Helper()
	g, err := DecodeNodeTransportGrant(data)
	if err == nil {
		encoded, err := EncodeNodeTransportGrant(g)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeNodeTransportGrant(encoded)
		if err != nil || again != g {
			t.Fatal("transport round trip", err)
		}
		ctx := transportGrantContext(t, g)
		ctx.Identity.Epoch += ".different"
		if !errors.Is(CheckCurrentNodeTransportGrant(g, ctx), ErrNodeGrantBindingMismatch) {
			t.Fatal("epoch substitution accepted")
		}
	} else if g != (NodeTransportGrant{}) {
		t.Fatal("partial transport")
	}
	p, err := DecodeNodeProducerGrant(data)
	if err == nil {
		encoded, err := EncodeNodeProducerGrant(p)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeNodeProducerGrant(encoded)
		if err != nil || again != p {
			t.Fatal("producer round trip", err)
		}
		ctx := producerGrantContext(t, p)
		ctx.Identity.Epoch += ".different"
		if !errors.Is(CheckCurrentNodeProducerGrant(p, ctx), ErrNodeGrantBindingMismatch) {
			t.Fatal("epoch substitution accepted")
		}
	} else if p != (NodeProducerGrant{}) {
		t.Fatal("partial producer")
	}
}

func FuzzNodeAdmissionRoundTrip(f *testing.F) {
	for _, name := range []string{"node-transport-grant.json", "node-producer-grant.json", "node-reachable.json", "bunkerweb-presence.json"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) { checkNodeGrantRoundTrip(t, data) })
}

package v5

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNodeRegistryDecodeCanonical(t *testing.T) {
	b, members := nodeRegistryFixture(t)
	r := buildRegistry(t, b, members)
	decoded, err := DecodeNodeAdmissionRegistry(r.Manifest(), r.Reference())
	if err != nil || decoded.Reference() != r.Reference() || !bytes.Equal(decoded.Manifest(), r.Manifest()) {
		t.Fatal("canonical registry", err)
	}
	data := r.Manifest()
	data[0] = '!'
	m := decoded.Members()
	m[0].Status = "revoked"
	ctx := nodeRegistryContext(t, decoded)
	if _, _, err := decoded.Transport(ctx, members[0].Identity, members[0].Transport[0].Grant.CredentialID); err != nil {
		t.Fatal("decoded registry borrowed mutable input", err)
	}
	for _, size := range []int{0, 500, MaxNodeAdmissionMembers} {
		ms := make([]NodeAdmissionMember, size)
		for i := range ms {
			ms[i] = uniqueRegistryMember(t, i)
			ms[i].Transport, ms[i].Producers = nil, nil
		}
		r := buildRegistry(t, b, ms)
		got, err := DecodeNodeAdmissionRegistry(r.Manifest(), r.Reference())
		if err != nil || len(got.Members()) != size {
			t.Fatal("bounded population", size, err)
		}
	}
}

func TestNodeRegistryDecodeRejectsWholeInput(t *testing.T) {
	b, m := nodeRegistryFixture(t)
	r := buildRegistry(t, b, m)
	good := r.Manifest()
	cases := map[string][]byte{
		"nil": nil, "null": []byte("null"), "array": []byte("[]"),
		"oversize":                   bytes.Repeat([]byte(" "), MaxNodeAdmissionRegistryBytes+1),
		"newline":                    append(bytes.Clone(good), '\n'),
		"trailing object":            append(bytes.Clone(good), good...),
		"unknown header":             bytes.Replace(good, []byte(`"schema":`), []byte(`"extra":"x","schema":`), 1),
		"duplicate header":           bytes.Replace(good, []byte(`"schema":`), []byte(`"schema":"x","schema":`), 1),
		"null members":               bytes.Replace(good, good[bytes.Index(good, []byte(`"members":`)):], []byte(`"members":null}`), 1),
		"case alias":                 bytes.Replace(good, []byte(`"cluster_id"`), []byte(`"Cluster_ID"`), 1),
		"duplicate identity":         bytes.Replace(good, []byte(`"cluster_id":`), []byte(`"cluster_id":"x","cluster_id":`), 1),
		"unknown grant":              bytes.Replace(good, []byte(`"credential_id":`), []byte(`"extra":{},"credential_id":`), 1),
		"escaped alias":              bytes.Replace(good, []byte(`"members"`), []byte(`"\u006dembers"`), 1),
		"surrogate":                  bytes.Replace(good, []byte("fixture"), []byte(`\ud800`), 1),
		"missing final member brace": good[:len(good)-3],
		"invalid utf8":               append([]byte{0xff}, good...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			// Even an independently pinned malformed candidate must fail closed.
			expected := RateReference{Ref: r.Reference().Ref, SHA256: nodeBytesSHA256(data)}
			got, err := DecodeNodeAdmissionRegistry(data, expected)
			if err == nil || got.Reference() != (RateReference{}) || len(got.Manifest()) != 0 || len(got.Members()) != 0 {
				t.Fatal("malformed snapshot yielded partial authority", err)
			}
		})
	}
	for _, expected := range []RateReference{{}, {Ref: "other", SHA256: r.Reference().SHA256}, {Ref: r.Reference().Ref, SHA256: strings.Repeat("a", 64)}} {
		if got, err := DecodeNodeAdmissionRegistry(good, expected); err == nil || got.Reference() != (RateReference{}) {
			t.Fatal("unapproved snapshot admitted")
		}
	}
}

func TestNodeRegistryDecodeStreamingBounds(t *testing.T) {
	b, m := nodeRegistryFixture(t)
	for _, kind := range []string{"member", "transport", "producer"} {
		t.Run(kind, func(t *testing.T) {
			members := cloneNodeAdmissionMembers(m)
			switch kind {
			case "member":
				members = make([]NodeAdmissionMember, MaxNodeAdmissionMembers+1)
				for i := range members {
					members[i] = uniqueRegistryMember(t, i)
					members[i].Transport, members[i].Producers = []NodeTransportSlot{}, []NodeProducerSlot{}
				}
			case "transport":
				members[0].Transport = []NodeTransportSlot{m[0].Transport[0], m[0].Transport[0], m[0].Transport[0]}
			case "producer":
				members[0].Producers = make([]NodeProducerSlot, MaxNodeAdmissionSources*MaxNodeAdmissionSlots+1)
				for i := range members[0].Producers {
					members[0].Producers[i] = m[0].Producers[0]
				}
			}
			data, err := json.Marshal(nodeRegistryManifest{NodeAdmissionRegistrySchema, "bounded.fixture", b, members})
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeNodeAdmissionRegistry(data, RateReference{"bounded.fixture", nodeBytesSHA256(data)})
			if err == nil || got.Reference() != (RateReference{}) {
				t.Fatal("overfull registry accepted")
			}
		})
	}
}

func FuzzNodeRegistryDecode(f *testing.F) {
	f.Add(fixture(f, "node-admission-registry.json"))
	f.Add([]byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		expected := RateReference{"registry-snapshot.fixture", nodeBytesSHA256(data)}
		r, err := DecodeNodeAdmissionRegistry(data, expected)
		if err != nil {
			if r.Reference() != (RateReference{}) || len(r.Manifest()) != 0 {
				t.Fatal("partial registry")
			}
			return
		}
		if !bytes.Equal(data, r.Manifest()) || r.Reference() != expected {
			t.Fatal("noncanonical registry")
		}
	})
}

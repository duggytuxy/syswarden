package fleetregistry

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	contracts "syswarden-core/contracts/v5"
)

func snapshotFixture(t testing.TB) (Snapshot, contracts.NodeRegistryContinuityContext) {
	t.Helper()
	gb, err := os.ReadFile("../contracts/v5/testdata/node-registry-generation.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := contracts.DecodeNodeRegistryGeneration(gb)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := os.ReadFile("../contracts/v5/testdata/node-registry-checkpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := contracts.DecodeNodeRegistryCheckpoint(cb)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := os.ReadFile("../contracts/v5/testdata/node-admission-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Members []contracts.NodeAdmissionMember `json:"members"`
	}
	if err := json.Unmarshal(rb, &fixture); err != nil {
		t.Fatal(err)
	}
	gr, err := g.Reference()
	if err != nil {
		t.Fatal(err)
	}
	for i := range fixture.Members {
		m := &fixture.Members[i]
		for j := range m.Transport {
			m.Transport[j].Grant.Registry = gr
		}
		for j := range m.Producers {
			m.Producers[j].Grant.Registry = gr
		}
	}
	r, err := contracts.BuildNodeAdmissionRegistry(c.Snapshot.Ref, contracts.NodeAdmissionRegistryBinding{Registry: gr, Policy: g.Policy}, fixture.Members)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := c.Reference()
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{g, c, r}, contracts.NodeRegistryContinuityContext{AuthorityID: g.AuthorityID, LineageID: g.LineageID, Generation: gr, Checkpoint: cr}
}

func encodeFixture(t testing.TB, s Snapshot, x contracts.NodeRegistryContinuityContext) []byte {
	t.Helper()
	b, err := EncodeSnapshot(s, x)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertNoSnapshot(t testing.TB, s Snapshot, err error) {
	t.Helper()
	if err == nil || s.Generation != (contracts.NodeRegistryGeneration{}) || s.Checkpoint != (contracts.NodeRegistryCheckpoint{}) || s.Registry.Reference() != (contracts.RateReference{}) || len(s.Registry.Manifest()) != 0 {
		t.Fatal("failed snapshot yielded partial authority", err)
	}
}

func TestSnapshotGoldenAndOwnership(t *testing.T) {
	s, x := snapshotFixture(t)
	data := encodeFixture(t, s, x)
	hexBytes, err := os.ReadFile("testdata/registry-v1.hex")
	if err != nil {
		t.Fatal(err)
	}
	golden, err := hex.DecodeString(strings.TrimSpace(string(hexBytes)))
	if err != nil || !bytes.Equal(data, golden) {
		t.Fatal("independent binary golden changed", err)
	}
	got, err := DecodeSnapshot(data, x)
	if err != nil || got.Generation != s.Generation || got.Checkpoint != s.Checkpoint || !bytes.Equal(got.Registry.Manifest(), s.Registry.Manifest()) {
		t.Fatal("roundtrip", err)
	}
	data[len(data)-1] = '!'
	got.Generation.Policy.Ref = "changed"
	if !bytes.Equal(s.Registry.Manifest(), golden[len(golden)-len(s.Registry.Manifest()):]) {
		t.Fatal("borrowed mutable input")
	}
	if b, err := EncodeSnapshot(got, x); err == nil || b != nil {
		t.Fatal("changed generation encoded")
	}
}

func TestSnapshotRejectsWholeInput(t *testing.T) {
	s, x := snapshotFixture(t)
	good := encodeFixture(t, s, x)
	cases := map[string][]byte{
		"empty": nil, "magic": bytes.Replace(good, []byte("V1"), []byte("V2"), 1),
		"oversize":  bytes.Repeat([]byte("x"), MaxSnapshotBytes+1),
		"trailing":  append(bytes.Clone(good), 0),
		"cut magic": good[:len(snapshotMagic)-1], "cut length": good[:len(snapshotMagic)+3],
		"cut body":    good[:len(good)-1],
		"changed key": bytes.Replace(good, []byte("ecdsa-p256"), []byte("ecdsa-p384"), 1),
	}
	pos := len(snapshotMagic)
	for _, name := range []string{"generation", "checkpoint", "registry"} {
		n := int(binary.BigEndian.Uint32(good[pos : pos+4]))
		for _, value := range []uint32{0, ^uint32(0)} {
			copy := bytes.Clone(good)
			binary.BigEndian.PutUint32(copy[pos:pos+4], value)
			label := name + " empty"
			if value != 0 {
				label = name + " overflowing"
			}
			cases[label] = copy
		}
		cases[name+" truncated"] = good[:pos+4+n/2]
		pos += 4 + n
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) { got, err := DecodeSnapshot(data, x); assertNoSnapshot(t, got, err) })
	}
	for _, mutate := range []func(*contracts.NodeRegistryContinuityContext){
		func(c *contracts.NodeRegistryContinuityContext) { c.AuthorityID = "other" },
		func(c *contracts.NodeRegistryContinuityContext) { c.LineageID = "other" },
		func(c *contracts.NodeRegistryContinuityContext) { c.Generation.SHA256 = strings.Repeat("f", 64) },
		func(c *contracts.NodeRegistryContinuityContext) { c.Checkpoint.SHA256 = strings.Repeat("f", 64) },
	} {
		wrong := x
		mutate(&wrong)
		got, err := DecodeSnapshot(good, wrong)
		assertNoSnapshot(t, got, err)
		if b, err := EncodeSnapshot(s, wrong); err == nil || b != nil {
			t.Fatal("unapproved encode")
		}
	}
}

func TestSnapshotDisabledIsAdministrativeOnly(t *testing.T) {
	s, x := snapshotFixture(t)
	s.Checkpoint.State = "disabled"
	var err error
	x.Checkpoint, err = s.Checkpoint.Reference()
	if err != nil {
		t.Fatal(err)
	}
	data := encodeFixture(t, s, x)
	got, err := DecodeSnapshot(data, x)
	if err != nil || got.Checkpoint.State != "disabled" {
		t.Fatal("disabled recovery metadata unavailable", err)
	}
	ctx, err := contracts.NodeRegistryReadContext(got.Generation, got.Checkpoint, got.Registry, x, time.Now())
	if err == nil || ctx != (contracts.NodeAdmissionRegistryReadContext{}) {
		t.Fatal("disabled registry grants admission")
	}
}

func FuzzSnapshotDecode(f *testing.F) {
	s, x := snapshotFixture(f)
	f.Add(encodeFixture(f, s, x))
	f.Add([]byte(snapshotMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeSnapshot(data, x)
		if err != nil {
			assertNoSnapshot(t, got, err)
			return
		}
		encoded, err := EncodeSnapshot(got, x)
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatal("noncanonical storage object")
		}
	})
}

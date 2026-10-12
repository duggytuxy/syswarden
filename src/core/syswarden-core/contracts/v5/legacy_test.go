package v5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func migrationContext() MigrationContext {
	return MigrationContext{EventID: Field{State: Missing}, NodeID: Field{State: Unavailable},
		SourceID: Field{State: Unavailable}, ReceivedAt: "2026-08-13T08:00:00Z"}
}

func legacyFixture(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("../../../../../testdata/contracts/waf-events-v4.02.8.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFrozenLegacyProjectionGolden(t *testing.T) {
	input := legacyFixture(t)
	original := bytes.Clone(input)
	lines := bytes.Split(bytes.TrimSuffix(input, []byte("\n")), []byte("\n"))
	goldens := bytes.Split(fixture(t, "legacy-projections.ndjson"), []byte("\n"))
	if len(lines) != 6 || len(goldens) != len(lines) {
		t.Fatal("frozen vector set changed")
	}
	for i, line := range lines {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			e, err := ProjectLegacyV4(line, migrationContext())
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := EncodeEvent(e)
			if err != nil || !bytes.Equal(encoded, goldens[i]) {
				t.Fatalf("migration golden mismatch: %s, %v", encoded, err)
			}
			decoded, err := DecodeEvent(encoded)
			if err != nil || decoded != e {
				t.Fatal("projected event did not round trip", err)
			}
			if e.EventID.State != Missing || e.NodeID.State != Unavailable || e.Provenance.SourceID.State != Unavailable {
				t.Fatal("identity invented from legacy observation")
			}
			if e.ControlRef.State != Unavailable || e.Severity.State != Unavailable || e.Layer.State != Unavailable {
				t.Fatal("legacy label or score promoted into current security evidence")
			}
		})
	}
	if !bytes.Equal(input, original) {
		t.Fatal("original evidence mutated")
	}
}

func TestLegacyExtensionsAreBoundedAndNotAuthority(t *testing.T) {
	base := `{"action":"BANNED","timestamp":"2026-08-13T07:00:00Z","ip":"192.0.2.1","jail":"L7-fixture","payload":"private sample"`
	input := []byte(base + `,"severity":10,"rule_attestation_status":"attested","control_ref":"injected","node_id":"injected","future":{"emoji":"\ud83d\ude00","literal":"\\ud800"}}`)
	e, err := ProjectLegacyV4(input, migrationContext())
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(input)
	if e.Provenance.OriginalSHA256.Value != hex.EncodeToString(hash[:]) {
		t.Fatal("original byte digest changed")
	}
	encoded, err := EncodeEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private sample", "injected", "L7-fixture", "attested"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("unreviewed extension or raw payload exported")
		}
	}
	for _, change := range []func(*Event){
		func(e *Event) { e.Severity = Field{State: Present, Value: "critical"} },
		func(e *Event) { e.ControlRef = Field{State: Present, Value: "control.fixture.1"} },
		func(e *Event) { e.Context.Trust = Field{State: Present, Value: "trust.fixture.1"} },
		func(e *Event) { e.ClockQuality = "synchronized" },
	} {
		modified := e
		change(&modified)
		if _, err := EncodeEvent(modified); err == nil {
			t.Fatal("unavailable legacy evidence was promoted")
		}
	}
	withoutAddress := []byte(strings.Replace(base+"}", `"ip":"192.0.2.1"`, `"ip":""`, 1))
	missing, err := ProjectLegacyV4(withoutAddress, migrationContext())
	if err != nil || missing.Subject.Kind != "unknown" || missing.Subject.Address.State != Missing {
		t.Fatal("missing address was invented or lost", err)
	}
}

func TestLegacyRejectsMalformedAndExcessiveInput(t *testing.T) {
	base := `{"action":"BANNED","timestamp":"2026-08-13T07:00:00Z","ip":"192.0.2.1","jail":"fixture","payload":"fixture"`
	objectMembers := make([]string, 33)
	for i := range objectMembers {
		objectMembers[i] = fmt.Sprintf(`"k%d":0`, i)
	}
	wide := `[` + strings.TrimSuffix(strings.Repeat("0,", 32), ",") + `]`
	cases := []string{
		base + `,"Action":"ALLOWED"}`, base + `,"action":"ALLOWED"}`,
		base + `,"future":{"key":1,"key":2}}`,
		base + `,"future":{"bad":"\ud800"}}`, base + `,"severity":null}`,
		base + `,"severity":1.5}`, base + `,"severity":1e999}`,
		strings.Replace(base+"}", `"BANNED"`, `"FUTURE-ACTION"`, 1),
		strings.Replace(base+"}", `"ip":"192.0.2.1",`, "", 1),
		strings.Replace(base+"}", `"timestamp":"2026-08-13T07:00:00Z"`, `"timestamp":null`, 1),
		base + `,"future":` + strings.Repeat("[", 10) + "0" + strings.Repeat("]", 10) + "}",
		base + `,"future":{` + strings.Join(objectMembers, ",") + "}}",
		base + `,"future":[` + strings.TrimSuffix(strings.Repeat("0,", 33), ",") + "]}",
		base + `,"future":[` + strings.TrimSuffix(strings.Repeat(wide+",", 9), ",") + "]}",
		base + `,"payload2":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`,
	}
	for i, input := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if e, err := ProjectLegacyV4([]byte(input), migrationContext()); err == nil || e != (Event{}) {
				t.Fatal("malformed legacy data accepted or partially returned")
			}
		})
	}
}

func FuzzLegacyProjection(f *testing.F) {
	for _, line := range bytes.Split(bytes.TrimSpace(legacyFixture(f)), []byte("\n")) {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := ProjectLegacyV4(data, migrationContext())
		if err != nil {
			if e != (Event{}) {
				t.Fatal("partial event")
			}
			return
		}
		encoded, err := EncodeEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeEvent(encoded)
		if err != nil || decoded != e {
			t.Fatal("migration round trip failed", err)
		}
		if e.NodeID.State != Unavailable || e.ControlRef.State != Unavailable {
			t.Fatal("authority invented")
		}
	})
}

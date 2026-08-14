package telemetry

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDashboardDataProducerContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", "dashboard-data-v4.02.8.json")
	fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatalf("read shared dashboard fixture: %v", err)
	}

	var decoded DashboardData
	if err := json.Unmarshal(fixture, &decoded); err != nil {
		t.Fatalf("producer schema no longer decodes the shared fixture: %v", err)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("producer schema no longer encodes: %v", err)
	}

	var want, got any
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("producer JSON contract diverged:\ngot=%s\nwant=%s", encoded, fixture)
	}
}

func TestDashboardDataVersionToleranceContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		release string
	}{
		{fixture: "dashboard-data-v4.02.7.json", release: "v4.02.7"},
		{fixture: "dashboard-data-v4.02.8.json", release: "v4.02.8"},
		{fixture: "dashboard-data-forward-extension.json", release: "v4.03.0"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.fixture, func(t *testing.T) {
			t.Parallel()
			fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", test.fixture)
			fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
			if err != nil {
				t.Fatal(err)
			}
			var decoded DashboardData
			if err := json.Unmarshal(fixture, &decoded); err != nil {
				t.Fatalf("compatible dashboard fixture was rejected: %v", err)
			}
			if decoded.GithubRelease != test.release {
				t.Fatalf("release = %q, want %q", decoded.GithubRelease, test.release)
			}
		})
	}
}

func TestWAFEventNDJSONConsumerContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", "waf-events-v4.02.8.ndjson")
	fixture, err := os.Open(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	wantActions := []string{"BANNED", "ALLOWED", "DETECTED", "SHADOW-ALERT", "SIMULATED-BAN", "COMPLIANCE-DRIFT"}
	var gotActions []string
	scanner := bufio.NewScanner(fixture)
	for scanner.Scan() {
		var event TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("WAF event no longer decodes: %v", err)
		}
		if event.Timestamp == "" || event.IP == "" || event.Jail == "" || event.Payload == "" {
			t.Fatalf("required WAF event field missing after decode: %#v", event)
		}
		gotActions = append(gotActions, event.Action)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotActions, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("actions = %v, want %v", gotActions, wantActions)
	}
}

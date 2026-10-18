package network

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Exercise the real authenticated API and persistent ledger. The firewall
// manager is a test dependency; this is not BunkerWeb HTTP or kernel evidence.
func TestBunkerWebWithdrawalPublishedSnapshot(t *testing.T) {
	for _, address := range []string{"8.8.4.40", "2606:4700:4700::44"} {
		for _, end := range []string{"delete", "expiry"} {
			t.Run(address+"/"+end, func(t *testing.T) {
				manager := &recordingHANativeFirewallManager{}
				fixture := newHAAPITestFixture(t, manager, []string{"192.0.2.10", "192.0.2.11"})
				now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				fixture.api.now = func() time.Time { return now }
				mutate := func(method, source, remote string, ttl int) {
					t.Helper()
					body := fmt.Sprintf(`{"ip":%q,"source":%q}`, address, source)
					if method == http.MethodPost {
						body = fmt.Sprintf(`{"ip":%q,"source":%q,"ttl":%d,"reason":"synthetic withdrawal regression"}`, address, source, ttl)
					}
					response := requestDirectHAPath(t, fixture.handler, method, "/ha/sync", "Bearer shared-secret", body, remote)
					if response.Code != http.StatusOK {
						t.Fatalf("%s failed: %d %s", method, response.Code, response.Body.String())
					}
				}
				read := func(want []string, claims int) {
					t.Helper()
					for _, path := range []string{"/ha/sync", "/ha/sync?details=true"} {
						response := requestDirectHAPath(t, fixture.handler, http.MethodGet, path, "Bearer shared-secret", "", "192.0.2.10:43123")
						var payload HASyncPayload
						if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &payload) != nil || !reflect.DeepEqual(payload.IPs, want) {
							t.Fatalf("published union changed: %d %s", response.Code, response.Body.String())
						}
						if strings.Contains(path, "details") && len(payload.Bans) != claims {
							t.Fatalf("published source count = %d, want %d", len(payload.Bans), claims)
						}
						if want == nil && !strings.Contains(response.Body.String(), `"ips":null`) {
							t.Fatal("deployed empty-list wire contract changed")
						}
					}
				}
				mutate(http.MethodPost, "scheduler-a", "192.0.2.10:43123", 30)
				mutate(http.MethodPost, "scheduler-b", "192.0.2.11:43123", 60)
				read([]string{address}, 2)
				// The same source label from another authenticated peer is not ownership.
				mutate(http.MethodDelete, "scheduler-a", "192.0.2.11:43123", 0)
				read([]string{address}, 2)
				if end == "delete" {
					mutate(http.MethodDelete, "scheduler-a", "192.0.2.10:43123", 0)
				} else {
					now = now.Add(30 * time.Second)
					if err := fixture.api.reconcileHABans(now, maxHALedgerRecords); err != nil {
						t.Fatal(err)
					}
				}
				read([]string{address}, 1)
				// A retained persistent administrator entry is separate from scheduler claims.
				path := fixture.ipv4
				if strings.Contains(address, ":") {
					path = fixture.ipv6
				}
				writeHATestRootedFile(t, path, []byte(address+"\n"))
				if end == "delete" {
					mutate(http.MethodDelete, "scheduler-b", "192.0.2.11:43123", 0)
				} else {
					now = now.Add(30 * time.Second)
					if err := fixture.api.reconcileHABans(now, maxHALedgerRecords); err != nil {
						t.Fatal(err)
					}
				}
				read([]string{address}, 0)
				// Simulate independently authorized removal of the persistent entry.
				writeHATestRootedFile(t, path, nil)
				read(nil, 0)
				mutate(http.MethodDelete, "scheduler-b", "192.0.2.11:43123", 0)
				read(nil, 0)
				// Reopening the real API on the same durable files must not resurrect it.
				restarted, err := newHAAPI(fixture.api.cfg, manager, "test", fixture.ipv4, fixture.ipv6, fixture.telemetry, fixture.ledger)
				if err != nil {
					t.Fatal(err)
				}
				restarted.now = func() time.Time { return now }
				fixture.handler = restarted.handler()
				read(nil, 0)
			})
		}
	}
}

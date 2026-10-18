package v5

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func presenceFixture(t testing.TB) BunkerWebPresenceSnapshot {
	t.Helper()
	s, err := DecodeBunkerWebPresenceSnapshot(fixture(t, "bunkerweb-presence.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Test construction is not a production authorization or enrollment provider.
func presenceContext(t testing.TB, s BunkerWebPresenceSnapshot) BunkerWebPresenceReadContext {
	t.Helper()
	hash, err := BunkerWebPresenceSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	return BunkerWebPresenceReadContext{SnapshotID: s.SnapshotID, SnapshotSHA256: hash,
		ExpectedIdentity: s.Identity, CollectorID: s.CollectorID, Scope: s.Scope, Policy: s.Policy,
		Now:          time.Date(2026, time.January, 1, 0, 0, 30, 0, time.UTC),
		MaxReportAge: time.Minute, MaxRegistrationAge: 2 * time.Minute, MaxModeAge: time.Minute}
}

func TestBunkerWebPresenceGolden(t *testing.T) {
	s := presenceFixture(t)
	data, err := EncodeBunkerWebPresenceSnapshot(s)
	if err != nil || !bytes.Equal(data, fixture(t, "bunkerweb-presence.json")) {
		t.Fatal("canonical bytes changed", err)
	}
	hash, err := BunkerWebPresenceSnapshotSHA256(s)
	if err != nil || hash != strings.TrimSpace(string(fixture(t, "bunkerweb-presence-digest.txt"))) {
		t.Fatal("canonical digest changed", err)
	}
}

func TestBunkerWebPresenceConfigurationModes(t *testing.T) {
	for _, mode := range []string{"log_only", "sync_only", "combined", "disabled", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			s := presenceFixture(t)
			s.Mode.Value = mode
			before := s
			view, err := ProjectBunkerWebPresenceSnapshot(s, presenceContext(t, s))
			reason := "current_configuration"
			if mode == "unknown" {
				reason = "mode_unknown"
			}
			if err != nil || view.Relevance != "known" || view.ReportState != Present ||
				view.CurrentMode != mode || view.Reason != reason || view.Identity != s.Identity ||
				view.SnapshotID != s.SnapshotID || view.Mode != s.Mode || view.Registration != s.Registration {
				t.Fatal("configuration changed or hidden", view, err)
			}
			view.Mode.Value = "changed"
			if s != before {
				t.Fatal("projection mutated source")
			}
		})
	}
}

func TestBunkerWebPresenceUncertaintyDoesNotBecomeAbsence(t *testing.T) {
	for _, state := range []string{Stale, Missing, Unavailable, Rejected} {
		for _, field := range []string{"registration", "mode"} {
			t.Run(field+"/"+state, func(t *testing.T) {
				s := presenceFixture(t)
				claim := &s.Mode
				if field == "registration" {
					claim = &s.Registration
				}
				claim.State = state
				if state != Stale {
					*claim = InventoryClassification{State: state}
					if field == "registration" {
						s.Mode = InventoryClassification{State: Unavailable}
					}
				}
				view, err := ProjectBunkerWebPresenceSnapshot(s, presenceContext(t, s))
				relevance := "known"
				if field == "registration" && state != Stale {
					relevance = "unknown"
				}
				if err != nil || view.Relevance != relevance || view.CurrentMode != "unknown" ||
					view.Registration != s.Registration || view.Mode != s.Mode {
					t.Fatal("uncertainty hidden or renewed", view, err)
				}
			})
		}
	}
	for _, registration := range []string{"absent", "unknown"} {
		for _, state := range []string{Present, Stale} {
			t.Run(registration+"/"+state, func(t *testing.T) {
				s := presenceFixture(t)
				s.Registration.Value, s.Registration.State = registration, state
				s.Mode = InventoryClassification{State: Unavailable}
				view, err := ProjectBunkerWebPresenceSnapshot(s, presenceContext(t, s))
				want := "unknown"
				if registration == "absent" && state == Present {
					want = "absent"
				}
				if err != nil || view.Relevance != want || view.CurrentMode != "unknown" {
					t.Fatal("absence inferred", view, err)
				}
			})
		}
	}
}

func TestBunkerWebPresenceFreshness(t *testing.T) {
	cases := []struct {
		name                                     string
		now, reportAge, registrationAge, modeAge time.Duration
		state, reason                            string
		future                                   bool
	}{
		{"future", -time.Nanosecond, time.Minute, 2 * time.Minute, time.Minute, "", "", true},
		{"report start", 0, time.Minute, 2 * time.Minute, time.Minute, Present, "current_configuration", false},
		{"before expiry", time.Minute - time.Nanosecond, time.Minute, 2 * time.Minute, time.Minute, Present, "current_configuration", false},
		{"exact report expiry", time.Minute, 2 * time.Minute, 3 * time.Minute, 2 * time.Minute, Stale, "report_expired", false},
		{"shorter report budget", 30 * time.Second, 30 * time.Second, 2 * time.Minute, time.Minute, Stale, "report_expired", false},
		{"exact registration expiry", 30 * time.Second, time.Minute, 90 * time.Second, time.Minute, Present, "registration_stale", false},
		{"before registration expiry", 30*time.Second - time.Nanosecond, time.Minute, 90 * time.Second, time.Minute, Present, "current_configuration", false},
		{"exact mode expiry", 30 * time.Second, time.Minute, 2 * time.Minute, 30 * time.Second, Present, "mode_stale", false},
		{"before mode expiry", 30*time.Second - time.Nanosecond, time.Minute, 2 * time.Minute, 30 * time.Second, Present, "current_configuration", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := presenceFixture(t)
			c := presenceContext(t, s)
			generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
			c.Now = generated.Add(tc.now)
			c.MaxReportAge, c.MaxRegistrationAge, c.MaxModeAge = tc.reportAge, tc.registrationAge, tc.modeAge
			view, err := ProjectBunkerWebPresenceSnapshot(s, c)
			if tc.future {
				if !errors.Is(err, ErrBunkerWebPresenceFutureReport) || view != (BunkerWebPresenceView{}) {
					t.Fatal("future disclosed", err)
				}
				return
			}
			mode := "unknown"
			if tc.reason == "current_configuration" {
				mode = s.Mode.Value
			}
			if err != nil || view.Relevance != "known" || view.ReportState != tc.state || view.Reason != tc.reason || view.CurrentMode != mode {
				t.Fatal("freshness failed", view, err)
			}
			if view.Mode.Value != s.Mode.Value || view.Mode.Source != s.Mode.Source || view.Mode.AssessedAt != s.Mode.AssessedAt ||
				view.Registration.Value != s.Registration.Value || view.Registration.Source != s.Registration.Source || view.Registration.AssessedAt != s.Registration.AssessedAt {
				t.Fatal("last known provenance lost")
			}
		})
	}
}

func TestBunkerWebPresenceUnavailableClockAndExpiredAbsence(t *testing.T) {
	for _, registration := range []string{"established", "absent", "unknown"} {
		for _, clock := range []string{"unsynchronized", "unknown", "synchronized"} {
			t.Run(registration+"/"+clock, func(t *testing.T) {
				s := presenceFixture(t)
				s.ClockQuality, s.Registration.Value = clock, registration
				if registration != "established" {
					s.Mode.Value = "unknown"
				}
				c := presenceContext(t, s)
				state := Unavailable
				if clock == "synchronized" {
					c.Now = c.Now.Add(24 * time.Hour)
					state = Stale
				}
				view, err := ProjectBunkerWebPresenceSnapshot(s, c)
				relevance := "unknown"
				if registration == "established" {
					relevance = "known"
				}
				if err != nil || view.ReportState != state || view.Relevance != relevance || view.CurrentMode != "unknown" ||
					view.Registration.State != Stale || view.Mode.State != Stale {
					t.Fatal("stale report gave current authority", view, err)
				}
			})
		}
	}
}

func TestBunkerWebPresenceBindingsAndDeniedNodes(t *testing.T) {
	changes := map[string]func(*BunkerWebPresenceSnapshot){
		"snapshot":            func(s *BunkerWebPresenceSnapshot) { s.SnapshotID = "other" },
		"cluster":             func(s *BunkerWebPresenceSnapshot) { s.Identity.ClusterID = "other" },
		"node":                func(s *BunkerWebPresenceSnapshot) { s.Identity.NodeID = "other" },
		"epoch":               func(s *BunkerWebPresenceSnapshot) { s.Identity.Epoch = "other" },
		"collector":           func(s *BunkerWebPresenceSnapshot) { s.CollectorID = "other" },
		"scope ref":           func(s *BunkerWebPresenceSnapshot) { s.Scope.Ref = "other" },
		"scope hash":          func(s *BunkerWebPresenceSnapshot) { s.Scope.SHA256 = strings.Repeat("f", 64) },
		"policy ref":          func(s *BunkerWebPresenceSnapshot) { s.Policy.Ref = "other" },
		"policy hash":         func(s *BunkerWebPresenceSnapshot) { s.Policy.SHA256 = strings.Repeat("f", 64) },
		"registration source": func(s *BunkerWebPresenceSnapshot) { s.Registration.Source.Ref = "other" },
		"registration digest": func(s *BunkerWebPresenceSnapshot) { s.Registration.Source.SHA256 = strings.Repeat("f", 64) },
		"mode source":         func(s *BunkerWebPresenceSnapshot) { s.Mode.Source.Ref = "other" },
		"mode digest":         func(s *BunkerWebPresenceSnapshot) { s.Mode.Source.SHA256 = strings.Repeat("f", 64) },
		"mode":                func(s *BunkerWebPresenceSnapshot) { s.Mode.Value = "disabled" },
		"clock":               func(s *BunkerWebPresenceSnapshot) { s.ClockQuality = "unknown" },
		"expiry":              func(s *BunkerWebPresenceSnapshot) { s.ValidUntil = "2026-01-01T00:00:59Z" },
		"registration time":   func(s *BunkerWebPresenceSnapshot) { s.Registration.AssessedAt = "2025-12-31T23:58:59Z" },
		"mode time":           func(s *BunkerWebPresenceSnapshot) { s.Mode.AssessedAt = "2025-12-31T23:59:59Z" },
	}
	for name, change := range changes {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired=%t", name, expired), func(t *testing.T) {
				s := presenceFixture(t)
				c := presenceContext(t, s)
				if expired {
					c.Now = c.Now.Add(time.Hour)
				}
				change(&s)
				if view, err := ProjectBunkerWebPresenceSnapshot(s, c); !errors.Is(err, ErrBunkerWebPresenceBindingMismatch) || view != (BunkerWebPresenceView{}) {
					t.Fatal("substitution disclosed data", err)
				}
			})
		}
	}
	// Synthetic capacity exercise, not a deployed fleet or performance claim.
	base := presenceFixture(t)
	deniedContext := presenceContext(t, base)
	for i := 0; i < 500; i++ {
		s := base
		s.Identity.NodeID = fmt.Sprintf("node.synthetic.%d", i)
		view, err := ProjectBunkerWebPresenceSnapshot(s, presenceContext(t, s))
		if err != nil || view.Identity != s.Identity || view.Relevance != "known" {
			t.Fatal("authorized identity lost", i, err)
		}
		if rejected, err := ProjectBunkerWebPresenceSnapshot(s, deniedContext); !errors.Is(err, ErrBunkerWebPresenceBindingMismatch) || rejected != (BunkerWebPresenceView{}) {
			t.Fatal("denied node disclosed", i, err)
		}
	}
}

func TestBunkerWebPresenceRejectsInvalidContext(t *testing.T) {
	changes := map[string]func(*BunkerWebPresenceReadContext){
		"identity":  func(c *BunkerWebPresenceReadContext) { c.ExpectedIdentity = NodeIdentity{} },
		"snapshot":  func(c *BunkerWebPresenceReadContext) { c.SnapshotID = "" },
		"hash":      func(c *BunkerWebPresenceReadContext) { c.SnapshotSHA256 = "" },
		"collector": func(c *BunkerWebPresenceReadContext) { c.CollectorID = "" },
		"scope":     func(c *BunkerWebPresenceReadContext) { c.Scope = RateReference{} },
		"policy":    func(c *BunkerWebPresenceReadContext) { c.Policy = RateReference{} },
		"time":      func(c *BunkerWebPresenceReadContext) { c.Now = time.Time{} },
	}
	for _, age := range []time.Duration{0, -time.Second, MaxSnapshotLifetime + 1} {
		changes[fmt.Sprintf("report %d", age)] = func(c *BunkerWebPresenceReadContext) { c.MaxReportAge = age }
		changes[fmt.Sprintf("registration %d", age)] = func(c *BunkerWebPresenceReadContext) { c.MaxRegistrationAge = age }
		changes[fmt.Sprintf("mode %d", age)] = func(c *BunkerWebPresenceReadContext) { c.MaxModeAge = age }
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := presenceFixture(t)
			c := presenceContext(t, s)
			change(&c)
			if view, err := ProjectBunkerWebPresenceSnapshot(s, c); !errors.Is(err, ErrInvalidBunkerWebPresenceContext) || view != (BunkerWebPresenceView{}) {
				t.Fatal("invalid context disclosed data", err)
			}
		})
	}
}

func TestBunkerWebPresenceRejectsIncoherence(t *testing.T) {
	changes := map[string]func(*BunkerWebPresenceSnapshot){
		"wrong schema":              func(s *BunkerWebPresenceSnapshot) { s.Schema = "other" },
		"identity":                  func(s *BunkerWebPresenceSnapshot) { s.Identity.Epoch = "" },
		"scope":                     func(s *BunkerWebPresenceSnapshot) { s.Scope.SHA256 = "invalid" },
		"snapshot":                  func(s *BunkerWebPresenceSnapshot) { s.SnapshotID = "" },
		"collector":                 func(s *BunkerWebPresenceSnapshot) { s.CollectorID = "" },
		"clock":                     func(s *BunkerWebPresenceSnapshot) { s.ClockQuality = "trusted" },
		"generation":                func(s *BunkerWebPresenceSnapshot) { s.GeneratedAt = "" },
		"expiry":                    func(s *BunkerWebPresenceSnapshot) { s.ValidUntil = s.GeneratedAt },
		"reversed time":             func(s *BunkerWebPresenceSnapshot) { s.ValidUntil = "2025-12-31T23:59:00Z" },
		"unbounded lifetime":        func(s *BunkerWebPresenceSnapshot) { s.ValidUntil = "2026-01-02T00:00:00.000000001Z" },
		"registration future":       func(s *BunkerWebPresenceSnapshot) { s.Registration.AssessedAt = s.ValidUntil },
		"mode future":               func(s *BunkerWebPresenceSnapshot) { s.Mode.AssessedAt = s.ValidUntil },
		"mode without registration": func(s *BunkerWebPresenceSnapshot) { s.Registration = InventoryClassification{State: Missing} },
		"absent with mode":          func(s *BunkerWebPresenceSnapshot) { s.Registration.Value = "absent" },
		"unknown with mode":         func(s *BunkerWebPresenceSnapshot) { s.Registration.Value = "unknown" },
		"inferred path":             func(s *BunkerWebPresenceSnapshot) { s.Registration.Value = "/var/log/bunkerweb.log" },
		"invalid mode":              func(s *BunkerWebPresenceSnapshot) { s.Mode.Value = "healthy" },
		"unproven source":           func(s *BunkerWebPresenceSnapshot) { s.Registration.Source = RateReference{} },
		"missing with value":        func(s *BunkerWebPresenceSnapshot) { s.Mode.State = Missing },
		"missing with time": func(s *BunkerWebPresenceSnapshot) {
			s.Mode = InventoryClassification{State: Missing, AssessedAt: s.GeneratedAt}
		},
		"not applicable": func(s *BunkerWebPresenceSnapshot) { s.Mode = InventoryClassification{State: NotApplicable} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := presenceFixture(t)
			c := presenceContext(t, s)
			change(&s)
			if data, err := EncodeBunkerWebPresenceSnapshot(s); err == nil || data != nil {
				t.Fatal("invalid encoded")
			}
			if hash, err := BunkerWebPresenceSnapshotSHA256(s); err == nil || hash != "" {
				t.Fatal("invalid hashed")
			}
			if view, err := ProjectBunkerWebPresenceSnapshot(s, c); err == nil || view != (BunkerWebPresenceView{}) {
				t.Fatal("invalid disclosed")
			}
		})
	}
}

func TestBunkerWebPresenceIndependentReadBindings(t *testing.T) {
	changes := map[string]func(*BunkerWebPresenceReadContext){
		"snapshot":         func(c *BunkerWebPresenceReadContext) { c.SnapshotID = "other" },
		"digest":           func(c *BunkerWebPresenceReadContext) { c.SnapshotSHA256 = strings.Repeat("f", 64) },
		"cluster":          func(c *BunkerWebPresenceReadContext) { c.ExpectedIdentity.ClusterID = "other" },
		"node":             func(c *BunkerWebPresenceReadContext) { c.ExpectedIdentity.NodeID = "other" },
		"epoch":            func(c *BunkerWebPresenceReadContext) { c.ExpectedIdentity.Epoch = "other" },
		"collector":        func(c *BunkerWebPresenceReadContext) { c.CollectorID = "other" },
		"scope reference":  func(c *BunkerWebPresenceReadContext) { c.Scope.Ref = "other" },
		"scope digest":     func(c *BunkerWebPresenceReadContext) { c.Scope.SHA256 = strings.Repeat("f", 64) },
		"policy reference": func(c *BunkerWebPresenceReadContext) { c.Policy.Ref = "other" },
		"policy digest":    func(c *BunkerWebPresenceReadContext) { c.Policy.SHA256 = strings.Repeat("f", 64) },
	}
	for name, change := range changes {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired=%t", name, expired), func(t *testing.T) {
				s := presenceFixture(t)
				c := presenceContext(t, s)
				if expired {
					c.Now = c.Now.Add(time.Hour)
				}
				// All other inputs, including the canonical digest, still match.
				change(&c)
				if view, err := ProjectBunkerWebPresenceSnapshot(s, c); !errors.Is(err, ErrBunkerWebPresenceBindingMismatch) || view != (BunkerWebPresenceView{}) {
					t.Fatal("independent binding bypassed", err)
				}
			})
		}
	}
}

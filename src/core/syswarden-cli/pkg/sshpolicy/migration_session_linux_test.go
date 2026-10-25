//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"

	"golang.org/x/sys/unix"
)

type sshMigrationFixture struct {
	f                                 *inventoryFixture
	plan                              migrationPlan
	a                                 *sshAuthorityFixture
	s                                 *sshMigrationSession
	binds, requests, closes, sessions int
	lease                             *activationTestLease
}

func newSSHMigrationFixture(t *testing.T) *sshMigrationFixture {
	t.Helper()
	f, _, deps := transactionFixture(t)
	// Reserve the enrollment before approving the parent-directory inventory.
	// Filling this existing file does not alter the approved policy inventory.
	f.write(sshAccessAuthorityPath, "")
	plan := f.plan()
	a := newSSHAuthorityFixture(t)
	a.f = f
	a.doc.PlanSHA256 = plan.summary.PlanSHA256
	a.doc.Routes = a.doc.Routes[:1]
	a.doc.Routes[0].ContextID = "administrator"
	a.doc.Routes[0].Jump = nil
	a.doc.Routes[0].Target.Address = "192.0.2.20:22"
	a.doc.Routes[0].Target.User = "administrator"
	a.write(t)
	x := &sshMigrationFixture{f: f, plan: plan, a: a}
	x.s = &sshMigrationSession{root: f.root, uid: os.Geteuid(), deps: deps, authority: a.open(t)}
	x.s.close = func() error { x.sessions++; return x.s.authority.Close() }
	x.lease = &activationTestLease{target: strings.Repeat("c", 64), checkFn: func() error { return nil },
		requestFn: func(ctx context.Context, guard func() error) error {
			x.requests++
			if _, err := os.Stat(f.path(sshJournalDirectory + "/" + sshActivationIntentName)); err != nil {
				t.Fatal("request preceded durable intent", err)
			}
			if journal, err := openSSHJournal(f.root, os.Geteuid()); err == nil {
				_ = journal.Close()
				t.Fatal("request did not retain the publication lock")
			}
			return errors.Join(ctx.Err(), guard())
		}, closeFn: func() error { x.closes++; return nil }}
	x.s.bind = func(ctx context.Context, guard func() error) (sshActivationLease, error) {
		x.binds++
		if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("runtime selected after policy publication", err)
		}
		return x.lease, errors.Join(ctx.Err(), guard())
	}
	return x
}

func (x *sshMigrationFixture) run(ctx context.Context) (sshMigrationResult, error) {
	return runSSHMigrationSession(ctx, x.plan.summary.PlanSHA256, digestBytes(x.a.wire),
		func(context.Context, string, string) (*sshMigrationSession, error) { return x.s, nil })
}

func TestSSHMigrationSessionRetainsOneRuntimeAcrossPublication(t *testing.T) {
	x := newSSHMigrationFixture(t)
	result, err := x.run(t.Context())
	if err != nil || !result.Published || !result.IntentDurable || !result.RequestReturned ||
		!result.RecoveryRequired || result.Transaction == "" || x.binds != 1 || x.requests != 1 || x.closes != 1 || x.sessions != 1 {
		t.Fatal("coordinated publication/reload lost state or resource ownership", result, err, x.binds, x.requests, x.closes, x.sessions)
	}
	// A new invocation must not adopt the existing publication or send another reload.
	x.s.authority = x.a.open(t)
	if _, err := x.run(t.Context()); err == nil || x.binds != 1 || x.requests != 1 {
		t.Fatal("first-migration replay was accepted")
	}
}

func TestSSHMigrationSessionRefusesUnsafePreflightWithoutPublication(t *testing.T) {
	for _, scenario := range []string{"cancelled", "wrong approval", "disabled", "external", "missing route", "wrong endpoint", "wrong user", "unapproved authority", "revoked", "parser", "binder", "nil lease", "identity", "lease changed"} {
		t.Run(scenario, func(t *testing.T) {
			x := newSSHMigrationFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "cancelled":
				cancel()
			case "wrong approval":
				x.plan.summary.PlanSHA256 = strings.Repeat("b", 64)
			case "disabled":
				x.f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "external":
				declaration := x.plan.intent
				declaration.Owner, declaration.Profile = "external", "observe"
				x.f.intent(declaration)
			case "missing route":
				x.s.authority.pins = nil
			case "wrong endpoint":
				x.s.authority.pins[0].Target.Address = "192.0.2.21:22"
			case "wrong user":
				x.s.authority.pins[0].Target.User = "someone-else"
			case "unapproved authority":
				x.s.authority.digest = strings.Repeat("d", 64)
			case "revoked":
				x.f.write(sshAccessAuthorityPath, "revoked")
			case "parser":
				x.s.deps.checkParser = func() error { return unix.EIO }
			case "binder":
				x.s.bind = func(context.Context, func() error) (sshActivationLease, error) { return x.lease, unix.EIO }
			case "nil lease":
				x.s.bind = func(context.Context, func() error) (sshActivationLease, error) { return nil, nil }
			case "identity":
				x.lease.target = "invalid"
			case "lease changed":
				x.lease.checkFn = func() error { return ErrInventoryChanged }
			}
			if scenario == "disabled" || scenario == "external" {
				// Even newly approved inputs cannot bypass independent TOML choice
				// or turn external ownership into mutation authority.
				_ = x.s.authority.Close()
				x.plan = x.f.plan()
				x.a.doc.PlanSHA256 = x.plan.summary.PlanSHA256
				x.a.write(t)
				x.s.authority = x.a.open(t)
			}
			before := fixtureMainImage(t, x.f)
			result, err := x.run(ctx)
			if err == nil || result.Published || result.IntentDurable || result.RequestReturned || result.Transaction != "" || x.requests != 0 {
				t.Fatal("unsafe preflight allowed publication or reload", result, err)
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, x.f)) {
				t.Fatal("preflight changed original policy")
			}
			for _, path := range []string{DropInPath, sshJournalDirectory} {
				if _, err := os.Lstat(x.f.path(path)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("preflight created state", path, err)
				}
			}
		})
	}
}

func TestSSHMigrationSessionPreservesPartialFacts(t *testing.T) {
	for _, scenario := range []string{"publication", "revocation during publication", "request", "lease close", "session close"} {
		t.Run(scenario, func(t *testing.T) {
			x := newSSHMigrationFixture(t)
			switch scenario {
			case "publication", "revocation during publication":
				link := x.s.deps.publication.link
				x.s.deps.publication.link = func(a int, b string, c int, d string, flags int) error {
					if d == "00-syswarden-hardening.conf" {
						if scenario == "publication" {
							return unix.EIO
						}
						x.f.write(sshAccessAuthorityPath, "revoked")
					}
					return link(a, b, c, d, flags)
				}
			case "request":
				x.lease.requestFn = func(context.Context, func() error) error { x.requests++; return unix.EIO }
			case "lease close":
				x.lease.closeFn = func() error { x.closes++; return unix.EIO }
			case "session close":
				x.s.close = func() error { x.sessions++; return errors.Join(x.s.authority.Close(), unix.EIO) }
			}
			result, err := x.run(t.Context())
			if err == nil || !result.RecoveryRequired || result.Transaction == "" || x.closes != 1 || x.sessions != 1 {
				t.Fatal("lost uncertainty or resource failure", result, err, x.closes, x.sessions)
			}
			if strings.Contains(scenario, "publication") {
				if result.Published || result.IntentDurable || x.requests != 0 {
					t.Fatal("interrupted publication triggered reload", result)
				}
			} else if !result.Published || !result.IntentDurable || x.requests != 1 || result.RequestReturned != (scenario != "request") {
				t.Fatal("partial activation facts were misreported", result)
			}
		})
	}
}

func TestSSHMigrationSessionRejectsIncompleteOpeners(t *testing.T) {
	x := newSSHMigrationFixture(t)
	for _, scenario := range []string{"missing", "nil", "partial error", "missing authority"} {
		t.Run(scenario, func(t *testing.T) {
			opener := func(context.Context, string, string) (*sshMigrationSession, error) { return nil, nil }
			switch scenario {
			case "missing":
				opener = nil
			case "partial error":
				opener = func(context.Context, string, string) (*sshMigrationSession, error) { return x.s, unix.EIO }
			case "missing authority":
				opener = func(context.Context, string, string) (*sshMigrationSession, error) {
					return &sshMigrationSession{root: x.f.root, close: func() error { return nil }}, nil
				}
			}
			if result, err := runSSHMigrationSession(t.Context(), x.plan.summary.PlanSHA256, digestBytes(x.a.wire), opener); err == nil || result != (sshMigrationResult{}) {
				t.Fatal("invalid opener accepted", result, err)
			}
		})
	}
	if _, err := beginSSHSystemdMigration(t.Context(), "", ""); err == nil {
		t.Fatal("missing explicit approvals accepted")
	}
}

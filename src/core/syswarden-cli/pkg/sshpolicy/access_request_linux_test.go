//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func accessRequestPin(t *testing.T, peer sshAccessPeer) sshAccessPin {
	t.Helper()
	key, err := ssh.ParsePrivateKey(peer.Identity)
	if err != nil {
		t.Fatal(err)
	}
	return sshAccessPin{peer.Address, peer.User, bytes.Clone(peer.HostKey), key.PublicKey().Marshal()}
}

func syntheticAccessRequest(t *testing.T, target, jump *sshProbeFixture) ([]byte, []sshAccessCredentials) {
	t.Helper()
	direct := target.binding.Access
	via := direct
	via.ID, via.Route = "via-bastion", "proxyjump"
	targetPin, jumpPin := accessRequestPin(t, target.peer), accessRequestPin(t, jump.peer)
	request := sshAccessRequest{1, sshAccessRequestDomain, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64),
		[]sshAccessRequestRoute{{direct, targetPin, nil}, {via, targetPin, &jumpPin}}}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return wire, []sshAccessCredentials{{direct.ID, target.peer.Identity, nil}, {via.ID, target.peer.Identity, jump.peer.Identity}}
}

func TestSSHAccessRequestControllerBatch(t *testing.T) {
	for _, scenario := range []string{"success", "bad-approval", "missing-credential", "extra-credential", "duplicate-credential", "unknown-context", "wrong-last-credential", "wrong-jump-credential", "unexpected-jump-credential", "late-guard", "late-network-failure", "mutated-caller-input", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			target := newSSHProbeFixture(t, "success")
			jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
			wire, credentials := syntheticAccessRequest(t, target, jump)
			approved := digestBytes(wire)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			mutated := false
			guard := func() error {
				if target.signatures.Load() > 0 {
					if scenario == "late-guard" {
						return ErrInventoryChanged
					}
					if scenario == "mutated-caller-input" && !mutated {
						mutated = true
						clear(wire)
						credentials[1].Target = []byte("changed input")
					}
				}
				return nil
			}
			switch scenario {
			case "bad-approval":
				approved = strings.Repeat("f", 64)
			case "missing-credential":
				credentials = credentials[:1]
			case "extra-credential":
				credentials = append(credentials, credentials[0])
			case "duplicate-credential":
				credentials[1].ContextID = credentials[0].ContextID
			case "unknown-context":
				credentials[1].ContextID = "unapproved"
			case "wrong-last-credential":
				credentials[1].Target, _ = sshProbeIdentity(t)
			case "wrong-jump-credential":
				credentials[1].Jump, _ = sshProbeIdentity(t)
			case "unexpected-jump-credential":
				credentials[0].Jump = jump.peer.Identity
			case "late-network-failure":
				var request sshAccessRequest
				if err := json.Unmarshal(wire, &request); err != nil {
					t.Fatal(err)
				}
				request.Routes[1].Target.HostKey = sshProbeSigner(t).PublicKey().Marshal()
				wire, _ = json.Marshal(request)
				approved = digestBytes(wire)
			case "cancelled":
				cancel()
			}
			got, err := probeSSHActivationAccessRequest(ctx, wire, approved, credentials, guard)
			success := scenario == "success" || scenario == "mutated-caller-input"
			if success {
				if err != nil || !got.RecoveryRequired || got.RequestSHA256 != approved || len(got.Observations) != 2 || target.signatures.Load() != 2 || jump.signatures.Load() != 1 {
					t.Fatal(got, err)
				}
				if got.Observations[0].SessionSHA256 == got.Observations[1].SessionSHA256 || got.Observations[0].ChallengeSHA256 == got.Observations[1].ChallengeSHA256 {
					t.Fatal("batch reused session")
				}
				if scenario == "success" {
					next, err := probeSSHActivationAccessRequest(ctx, wire, approved, credentials, guard)
					if err != nil || next.Observations[0].SessionSHA256 == got.Observations[0].SessionSHA256 || next.Observations[0].BindingSHA256 != got.Observations[0].BindingSHA256 {
						t.Fatal("batch reused stale proof", next, err)
					}
					var request sshAccessRequest
					if err := json.Unmarshal(wire, &request); err != nil {
						t.Fatal(err)
					}
					request.Assessment = strings.Repeat("f", 64)
					changed, _ := json.Marshal(request)
					rebound, err := probeSSHActivationAccessRequest(ctx, changed, digestBytes(changed), credentials, guard)
					if err != nil || rebound.Observations[0].BindingSHA256 == got.Observations[0].BindingSHA256 {
						t.Fatal("complete request digest was not bound", err)
					}
				}
				return
			}
			if err == nil || !reflect.DeepEqual(got, sshAccessBatchObservation{}) {
				t.Fatal("partial or unauthorized batch accepted", got, err)
			}
			if scenario != "late-guard" && scenario != "late-network-failure" && (target.connections.Load() != 0 || jump.connections.Load() != 0) {
				t.Fatal("preflight reached network")
			}
			if scenario == "late-network-failure" && target.signatures.Load() != 1 {
				t.Fatal("late failure did not follow one successful route")
			}
		})
	}
}

func TestSSHAccessRequestStrictCanonicalApproval(t *testing.T) {
	target := newSSHProbeFixture(t, "success")
	jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
	good, credentials := syntheticAccessRequest(t, target, jump)
	for _, scenario := range []string{"schema", "domain", "transaction", "plan", "intent", "target", "assessment", "empty-routes", "too-many-routes", "duplicate-context", "invalid-context", "wrong-target", "wrong-user", "unsupported-route", "missing-jump", "unexpected-jump", "same-jump", "invalid-host-key", "invalid-client-key", "oversized-key", "noncanonical", "unknown", "duplicate", "case-folded", "trailing", "oversized", "nil-context", "nil-guard"} {
		t.Run(scenario, func(t *testing.T) {
			var request sshAccessRequest
			if err := json.Unmarshal(good, &request); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "schema":
				request.Schema = 2
			case "domain":
				request.Domain = "other-domain"
			case "transaction":
				request.Transaction = ""
			case "plan":
				request.Plan = "bad"
			case "intent":
				request.Intent = strings.Repeat("A", 64)
			case "target":
				request.Target = "bad"
			case "assessment":
				request.Assessment = "bad"
			case "empty-routes":
				request.Routes = nil
			case "too-many-routes":
				for len(request.Routes) <= MaxAccessContexts {
					request.Routes = append(request.Routes, request.Routes[0])
				}
			case "duplicate-context":
				request.Routes[1].Access.ID = request.Routes[0].Access.ID
			case "invalid-context":
				request.Routes[0].Access.ID = ""
			case "wrong-target":
				request.Routes[0].Target.Address = "192.0.2.1:22"
			case "wrong-user":
				request.Routes[0].Target.User = "another"
			case "unsupported-route":
				request.Routes[0].Access.Route = "ansible"
			case "missing-jump":
				request.Routes[1].Jump = nil
			case "unexpected-jump":
				request.Routes[0].Jump = request.Routes[1].Jump
			case "same-jump":
				pin := request.Routes[1].Target
				request.Routes[1].Jump = &pin
			case "invalid-host-key":
				request.Routes[0].Target.HostKey = []byte("bad")
			case "invalid-client-key":
				request.Routes[1].Target.ClientKey = []byte("bad")
			case "oversized-key":
				request.Routes[0].Target.ClientKey = bytes.Repeat([]byte("x"), (16<<10)+1)
			}
			wire, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			var ctx context.Context = t.Context()
			guard := func() error { return nil }
			switch scenario {
			case "noncanonical":
				wire = append(wire, '\n')
			case "unknown":
				wire = bytes.Replace(wire, []byte("{"), []byte(`{"extra":true,`), 1)
			case "duplicate":
				wire = bytes.Replace(wire, []byte("{"), []byte(`{"schema":1,`), 1)
			case "case-folded":
				wire = bytes.Replace(wire, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "trailing":
				wire = append(wire, []byte("{}")...)
			case "oversized":
				wire = bytes.Repeat([]byte("x"), maxSSHAccessRequestBytes+1)
			case "nil-context":
				ctx = nil
			case "nil-guard":
				guard = nil
			}
			got, err := probeSSHActivationAccessRequest(ctx, wire, digestBytes(wire), credentials, guard)
			if err == nil || !reflect.DeepEqual(got, sshAccessBatchObservation{}) || target.connections.Load() != 0 || jump.connections.Load() != 0 {
				t.Fatal("invalid request reached network", got, err)
			}
		})
	}
}

func protectedAccessFixture(t *testing.T, beforePlan ...func(*inventoryFixture)) (*inventoryFixture, migrationPlan, sshTransactionDependencies, *sshJournal, *sshProbeFixture, *sshProbeFixture, []sshAccessRoutePins, []sshAccessCredentials, sshParserRun, sshEndpointObserver) {
	t.Helper()
	target := newSSHProbeFixture(t, "success")
	jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
	_, credentials := syntheticAccessRequest(t, target, jump)
	f, plan, deps := transactionFixture(t)
	direct := target.binding.Access
	via := direct
	via.ID, via.Route = "via-bastion", "proxyjump"
	plan.intent.Contexts = []accessContext{direct, via}
	f.intent(plan.intent)
	for _, setup := range beforePlan {
		setup(f)
	}
	plan = f.plan()
	result, err := executeSSHTransaction(t.Context(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err != nil || !result.Published {
		t.Fatal(result, err)
	}
	journal := fixtureJournal(t, f)
	calls, closed := 0, 0
	if _, err := attemptSSHActivation(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser, activationTestBinder(t, journal, &calls, &closed)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	targetPin, jumpPin := accessRequestPin(t, target.peer), accessRequestPin(t, jump.peer)
	pins := []sshAccessRoutePins{{via.ID, targetPin, &jumpPin}, {direct.ID, targetPin, nil}}
	run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
		out, err := deps.run(ctx, image, mode, access)
		if mode == "effective" && err == nil {
			out = append(out, []byte("addressfamily inet\nlistenaddress "+target.peer.Address+"\n")...)
		}
		return out, err
	}
	observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return ListenerSummary{}, err
		}
		if len(expected) != 1 || expected[0].String() != target.peer.Address {
			return ListenerSummary{}, ErrInventoryChanged
		}
		return ListenerSummary{TCPListenersObserved: true, ListenerCount: 1, SocketsSHA256: strings.Repeat("b", 64), Process: ProcessSummary{ProcessObserved: true, ExecutableVerified: true, ExecutableSHA256: deps.parserDigest}}, nil
	}
	return f, plan, deps, journal, target, jump, pins, credentials, run, observe
}

func TestSSHProtectedAccessRequestRoundTrip(t *testing.T) {
	f, plan, deps, journal, target, jump, pins, credentials, run, observe := protectedAccessFixture(t)
	prepared, err := journal.read()
	if err != nil {
		t.Fatal(err)
	}
	before, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	records, err := observeSSHOwnedRecordSet(journal, true)
	if err != nil {
		t.Fatal(err)
	}
	journal.syncDirectory = func(*os.File) error { t.Fatal("request repaired durability"); return unix.EIO }
	wrapped := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
		competing, err := openSSHJournal(f.root, os.Geteuid())
		if err == nil {
			_ = competing.Close()
			t.Fatal("journal lock released")
		}
		return observe(ctx, expected, guard)
	}
	wire, err := prepareSSHActivationAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, wrapped, pins)
	if err != nil {
		t.Fatal(err)
	}
	if target.connections.Load() != 0 || jump.connections.Load() != 0 || bytes.Contains(wire, target.peer.Identity) || bytes.Contains(wire, []byte("PRIVATE KEY")) {
		t.Fatal("target preparation authenticated or exposed a private key")
	}
	request, err := parseSSHAccessRequest(wire, digestBytes(wire))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := journal.readRecord(sshActivationIntentName)
	if err != nil {
		t.Fatal(err)
	}
	if request.Transaction != prepared.Transaction || request.Plan != plan.summary.PlanSHA256 || request.Intent != digestBytes(intent) || request.Target != strings.Repeat("a", 64) || request.Routes[0].Access.ID != plan.intent.Contexts[0].ID {
		t.Fatal("protected request binding lost")
	}
	next, err := prepareSSHActivationAccessRequest(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser, wrapped, pins)
	if err != nil || !bytes.Equal(wire, next) {
		t.Fatal("stable request changed", err)
	}
	got, err := probeSSHActivationAccessRequest(t.Context(), wire, digestBytes(wire), credentials, func() error { return nil })
	if err != nil || !got.RecoveryRequired || len(got.Observations) != 2 {
		t.Fatal(got, err)
	}
	after, err := stableSSHRollback(journal, prepared.Transaction)
	afterRecords, recordsErr := observeSSHOwnedRecordSet(journal, true)
	if err != nil || recordsErr != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, afterRecords) {
		t.Fatal("request or access changed protected state", err, recordsErr)
	}
	if err := rollbackSSHConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
		t.Fatal("access batch bypassed activation fence")
	}
}

func TestSSHProtectedAccessRequestRejectsStateOrCoverage(t *testing.T) {
	for _, scenario := range []string{"missing-approval", "wrong-parser", "disabled-selection", "policy-drift", "intent-drift", "missing-context", "extra-context", "duplicate-context", "unknown-context", "bad-target", "missing-jump", "late-record-replacement", "late-parser-drift", "late-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal, target, jump, pins, _, run, observe := protectedAccessFixture(t)
			approved, parser := plan.summary.PlanSHA256, deps.parserDigest
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			changed := false
			check := func() error {
				if changed && scenario == "late-parser-drift" {
					return ErrInventoryChanged
				}
				return nil
			}
			switch scenario {
			case "missing-approval":
				approved = ""
			case "wrong-parser":
				parser = strings.Repeat("c", 64)
			case "disabled-selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "policy-drift":
				f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "intent-drift":
				f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
			case "missing-context":
				pins = pins[:1]
			case "extra-context":
				pins = append(pins, pins[0])
			case "duplicate-context":
				pins[1].ContextID = pins[0].ContextID
			case "unknown-context":
				pins[1].ContextID = "not-declared"
			case "bad-target":
				pins[1].Target.Address = "192.0.2.1:22"
			case "missing-jump":
				pins[0].Jump = nil
			}
			wrapped := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				summary, err := observe(ctx, expected, guard)
				if err != nil {
					return summary, err
				}
				changed = true
				switch scenario {
				case "late-record-replacement":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshActivationIntentName)
				case "late-cancel":
					cancel()
				}
				return summary, nil
			}
			wire, err := prepareSSHActivationAccessRequest(ctx, journal, approved, parser, run, check, wrapped, pins)
			if err == nil || wire != nil || target.connections.Load() != 0 || jump.connections.Load() != 0 {
				t.Fatal("unsafe request returned", err)
			}
		})
	}
}

func FuzzSSHAccessRequestCanonical(f *testing.F) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		f.Fatal(err)
	}
	pin := sshAccessPin{"127.0.0.1:22", "administrator", key.Marshal(), key.Marshal()}
	access := accessContext{"administrator", "direct", "administrator", "controller.example", "127.0.0.1", "127.0.0.1", 22}
	request := sshAccessRequest{1, sshAccessRequestDomain, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), []sshAccessRequestRoute{{access, pin, nil}}}
	valid, err := json.Marshal(request)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Add([]byte(`{"schema":1,"domain":"syswarden-ssh-access-request-v1","routes":[]}`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maxSSHAccessRequestBytes {
			return
		}
		request, err := parseSSHAccessRequest(wire, digestBytes(wire))
		if err != nil {
			return
		}
		canonical, err := json.Marshal(request)
		if err != nil || !bytes.Equal(canonical, wire) || len(request.Routes) == 0 || len(request.Routes) > MaxAccessContexts {
			t.Fatal("noncanonical request accepted")
		}
	})
}

func TestSSHProtectedAccessContinuationFinalGuard(t *testing.T) {
	for _, scenario := range []string{"record-replacement", "selection-drift", "cancel", "action-error"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := activationAssessmentFixture(t, false)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			action := func(ctx context.Context, a *sshActivationAssessment, summary ActivationAssessment, guard func() error) error {
				calls++
				if err := guard(); err != nil {
					t.Fatal(err)
				}
				if !summary.RecoveryRequired || a.owned.prepared.PlanSHA256 != plan.summary.PlanSHA256 {
					t.Fatal("unverified continuation")
				}
				switch scenario {
				case "record-replacement":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshActivationIntentName)
				case "selection-drift":
					f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
				case "cancel":
					cancel()
				case "action-error":
					return unix.EIO
				}
				return nil
			}
			summary, err := withSSHActivationAssessment(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, ownedEndpointParser(deps.run), deps.checkParser, ownedEndpointListener(deps.parserDigest), action)
			if err == nil || calls != 1 || !reflect.DeepEqual(summary, ActivationAssessment{}) {
				t.Fatal("late continuation accepted", summary, calls, err)
			}
		})
	}
}

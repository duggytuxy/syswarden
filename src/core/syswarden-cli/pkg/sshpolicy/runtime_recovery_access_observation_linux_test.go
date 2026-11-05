//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Synthetic private journal data exercises strict consumers. Only the isolated
// native oracle establishes that the production publisher mints this record.
func observedRestoredAccessFixture(t *testing.T) *restoredAccessFixtureState {
	t.Helper()
	x := restoredAccessFixture(t)
	summary, err := assessSSHRuntimeRecovery(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.recovery,
		x.deps.parserDigest, x.run, x.deps.checkParser, x.observe)
	if err != nil || summary.Schema != 1 || summary.ReloadObservationObserved {
		t.Fatal("legacy assessment", summary, err)
	}
	process, err := sshActivationDigest(summary.Endpoints.Listeners.Process)
	if err != nil {
		t.Fatal(err)
	}
	reload, err := readSSHPrivateChild(x.journal.directory, sshRuntimeRecoveryReloadName, x.journal.uid, maxSSHJournalBytes)
	if err != nil {
		t.Fatal(err)
	}
	before := strings.Repeat("a", 64)
	if before == summary.Endpoints.Listeners.SocketsSHA256 {
		before = strings.Repeat("b", 64)
	}
	record := sshRuntimeRecoveryObservation{Schema: 1, Purpose: sshRuntimeRecoveryObservationPurpose,
		Transaction: summary.Transaction, Plan: summary.PlanSHA256, Recovery: summary.RecoverySHA256,
		ReloadIntent: summary.ReloadIntentSHA256, ReloadIntentImage: sshImageDigest(reload),
		Restored: summary.RestoredSHA256, Parser: x.deps.parserDigest, Target: summary.RecordedTargetSHA256,
		Method: sshRuntimeRecoveryObservationMethod, ProcessSummarySHA256: process,
		BeforeSocketsSHA256: before, AfterSocketsSHA256: summary.Endpoints.Listeners.SocketsSHA256}
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	image, err := x.journal.writeRecordImage(sshRuntimeRecoveryObservationName, wire)
	if err != nil {
		t.Fatal(err)
	}
	x.history[sshRuntimeRecoveryObservationName] = sshImageDigest(image)
	x.request, err = prepareSSHRestoredAccessRequest(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.recovery,
		x.deps.parserDigest, x.run, x.deps.checkParser, x.observe, x.authority.pins)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestSSHObservedRestoredAccessRoundTrip(t *testing.T) {
	x := observedRestoredAccessFixture(t)
	var request sshObservedRestoredAccessRequest
	if err := json.Unmarshal(x.request, &request); err != nil {
		t.Fatal(err)
	}
	if request.Schema != 2 || request.Domain != sshObservedRestoredAccessRequestDomain ||
		!lowerDigest.MatchString(request.ReloadObservation) || !lowerDigest.MatchString(request.ReloadObservationImage) || !lowerDigest.MatchString(request.RuntimeGeneration) {
		t.Fatal("missing purpose-specific observation binding")
	}
	if _, err := parseSSHAccessRequest(x.request, digestBytes(x.request)); err == nil {
		t.Fatal("activation accepted restoring v2 request")
	}
	issued, err := x.issue(t.Context(), digestBytes(x.request))
	if err != nil || !issued.IssuanceDurable || !issued.RecoveryRequired {
		t.Fatal(issued, err)
	}
	x.reopen(t)
	record, _, err := readSSHRestoredAccessIssuance(x.journal, x.authority, issued.IssuanceSHA256, issued.IssuanceImageSHA256, x.now)
	if err != nil || record.Schema != 2 || record.Domain != sshObservedRestoredAccessIssuanceDomain {
		t.Fatal(record, err)
	}
	downgraded := record
	downgraded.Schema, downgraded.Domain = 1, sshRestoredAccessIssuanceDomain
	wire, err := json.Marshal(downgraded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSSHRestoredAccessIssuance(wire, digestBytes(wire), x.authority, x.now); err == nil {
		t.Fatal("v1 issuance accepted v2 request")
	}
	receipt := x.receipt(t, issued)
	stored, err := x.record(t.Context(), issued.IssuanceSHA256, receipt)
	if err != nil || !stored.RecordDurable || !stored.RecoveryRequired {
		t.Fatal(stored, err)
	}
	x.reopen(t)
	x.journal.syncDirectory = func(*os.File) error { t.Fatal("inspection repaired durability"); return unix.EIO }
	inspection, err := x.inspect(t.Context(), issued, stored.RecordSHA256)
	if err != nil || !inspection.ReceiptObserved || !inspection.RecoveryRequired {
		t.Fatal(inspection, err)
	}
	x.assertHistory(t)
	data, err := x.journal.readRecord(sshRestoredAccessEvidenceName)
	if err != nil {
		t.Fatal(err)
	}
	var evidence sshRestoredAccessEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Schema != 2 || evidence.Domain != sshObservedRestoredAccessEvidenceDomain || !bytes.Equal(evidence.Request, x.request) {
		t.Fatal("evidence lost v2 binding")
	}
}

func TestSSHObservedRestoredAccessRequestRejectsAmbiguity(t *testing.T) {
	x := observedRestoredAccessFixture(t)
	var request sshObservedRestoredAccessRequest
	if err := json.Unmarshal(x.request, &request); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"observation", "image", "generation", "schema", "domain", "unknown", "duplicate", "whitespace"} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			switch name {
			case "observation":
				candidate.ReloadObservation = ""
			case "image":
				candidate.ReloadObservationImage = strings.Repeat("A", 64)
			case "generation":
				candidate.RuntimeGeneration = "bad"
			case "schema":
				candidate.Schema = 1
			case "domain":
				candidate.Domain = sshRestoredAccessRequestDomain
			}
			wire, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unknown":
				wire = append(wire[:len(wire)-1], []byte(`,"extra":true}`)...)
			case "duplicate":
				wire = append(wire[:len(wire)-1], []byte(`,"schema":2}`)...)
			case "whitespace":
				wire = append(wire, '\n')
			}
			if _, err := parseSSHRestoredAccessRequest(wire, digestBytes(wire)); err == nil {
				t.Fatal("ambiguous request accepted")
			}
		})
	}
}

func TestSSHObservedRestoredAssessmentRejectsRuntimeDrift(t *testing.T) {
	for _, scenario := range []string{"process", "sockets", "parser", "late-process"} {
		t.Run(scenario, func(t *testing.T) {
			x := observedRestoredAccessFixture(t)
			calls := 0
			observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				got, err := x.observe(ctx, expected, guard)
				calls++
				switch scenario {
				case "process":
					got.Process.IdentitySHA256 = strings.Repeat("c", 64)
				case "sockets":
					got.SocketsSHA256 = strings.Repeat("d", 64)
				case "parser":
					got.Process.ExecutableSHA256 = strings.Repeat("e", 64)
				case "late-process":
					if calls > 1 {
						got.Process.IdentitySHA256 = strings.Repeat("c", 64)
					}
				}
				return got, err
			}
			request, err := prepareSSHRestoredAccessRequest(t.Context(), x.journal, x.plan.summary.PlanSHA256, x.recovery,
				x.deps.parserDigest, x.run, x.deps.checkParser, observe, x.authority.pins)
			if !errors.Is(err, ErrInventoryChanged) || len(request) != 0 {
				t.Fatal("drift authorized access request", err)
			}
			x.assertHistory(t)
		})
	}
}

func TestSSHObservedRestoredIssuanceCannotLoseObservation(t *testing.T) {
	for _, scenario := range []string{"missing", "replaced"} {
		t.Run(scenario, func(t *testing.T) {
			x := observedRestoredAccessFixture(t)
			issued, err := x.issue(t.Context(), digestBytes(x.request))
			if err != nil {
				t.Fatal(err)
			}
			x.reopen(t)
			path := x.f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryObservationName)
			fixtureRoot, err := os.OpenRoot(x.f.base)
			if err != nil {
				t.Fatal(err)
			}
			defer fixtureRoot.Close()
			wire, err := fixtureRoot.ReadFile(strings.TrimPrefix(sshJournalDirectory+"/"+sshRuntimeRecoveryObservationName, "/"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if scenario == "replaced" {
				x.f.write(sshJournalDirectory+"/"+sshRuntimeRecoveryObservationName, string(wire))
			}
			if got, err := x.inspect(t.Context(), issued, ""); err == nil || got.IssuanceObserved {
				t.Fatal("lost/replaced observation accepted", got, err)
			}
		})
	}
}

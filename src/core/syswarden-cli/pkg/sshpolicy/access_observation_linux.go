//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

// Approval is independent of the retained record. No key, challenge approval or
// evidence approval can be learned from the object being inspected.
type sshAccessEvidenceApproval struct {
	EvidenceSHA256  string
	ChallengeSHA256 string
	Controller      ed25519.PublicKey
}

// Hash-only diagnostics, never serialized authority for a later action.
// Historical signature validity, current correspondence and time are distinct.
// Visibility cannot reconstruct a missing writer acknowledgement.
type sshAccessEvidenceObservation struct {
	RecordSHA256                string
	RequestSHA256               string
	ChallengeSHA256             string
	ReceiptSHA256               string
	ControllerSHA256            string
	CurrentRequestSHA256        string
	AssessedAt                  int64
	ContextsRecorded            int
	HistoricalSignatureVerified bool
	CurrentRequestMatches       bool
	WindowOpen                  bool
	DurabilityUnknown           bool
	RecoveryRequired            bool
}

func decodeSSHAccessEvidence(wire []byte, approval sshAccessEvidenceApproval, now time.Time) (sshAccessEvidence, sshAccessReceiptAssessment, sshAccessChallenge, error) {
	empty := sshAccessEvidence{}
	failure := func(err error) (sshAccessEvidence, sshAccessReceiptAssessment, sshAccessChallenge, error) {
		return empty, sshAccessReceiptAssessment{}, sshAccessChallenge{}, errors.Join(ErrInventoryUnsafe, err)
	}
	if len(wire) == 0 || len(wire) > maxSSHAccessEvidenceBytes || !lowerDigest.MatchString(approval.EvidenceSHA256) ||
		digestBytes(wire) != approval.EvidenceSHA256 || !lowerDigest.MatchString(approval.ChallengeSHA256) || len(approval.Controller) != ed25519.PublicKeySize {
		return failure(nil)
	}
	var record sshAccessEvidence
	if err := json.Unmarshal(wire, &record); err != nil {
		return failure(err)
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, wire) || record.Schema != 1 || record.Domain != sshAccessEvidenceDomain ||
		!record.RecoveryRequired || record.AssessedAt <= 0 || record.AssessedAt > now.Unix() || record.Controller != digestBytes(approval.Controller) {
		return failure(err)
	}
	for _, digest := range []string{record.Transaction, record.Plan, record.Parser, record.Intent, record.Target, record.Records} {
		if !lowerDigest.MatchString(digest) {
			return failure(nil)
		}
	}
	input, err := copySSHAccessReceiptInput(sshAccessReceiptInput{record.Request, record.Challenge, record.Receipt, approval.ChallengeSHA256, approval.Controller})
	if err != nil {
		return failure(err)
	}
	// Validate historical signature and the window at recorded appraisal time.
	// This is deliberately not fresh acceptance at the observer's current time.
	assessed := time.Unix(record.AssessedAt, 0)
	verified, err := verifySSHAccessReceipt(input, assessed)
	if err != nil {
		return failure(err)
	}
	request, err := parseSSHAccessRequest(record.Request, verified.RequestSHA256)
	if err != nil || request.Transaction != record.Transaction || request.Plan != record.Plan ||
		request.Intent != record.Intent || request.Target != record.Target {
		return failure(err)
	}
	challenge, err := parseSSHAccessChallenge(record.Challenge, approval.ChallengeSHA256, assessed)
	if err != nil {
		return failure(err)
	}
	return record, verified, challenge, nil
}

func copySSHObservationPins(pins []sshAccessRoutePins) ([]sshAccessRoutePins, error) {
	if len(pins) == 0 || len(pins) > MaxAccessContexts {
		return nil, ErrInventoryUnsafe
	}
	result := make([]sshAccessRoutePins, len(pins))
	for index, pin := range pins {
		var err error
		if !contextID.MatchString(pin.ContextID) {
			return nil, ErrInventoryUnsafe
		}
		pin.Target, err = copySSHAccessPin(pin.Target)
		if err != nil {
			return nil, err
		}
		if pin.Jump != nil {
			jump, err := copySSHAccessPin(*pin.Jump)
			if err != nil {
				return nil, err
			}
			pin.Jump = &jump
		}
		result[index] = pin
	}
	return result, nil
}

// Inspect existing evidence under a retained journal lock. This function never
// writes, syncs, probes, reloads, repairs or clears the single-use slot. Expired
// observations can be inspected; they cannot authorize a fresh operation.
func observeSSHActivationAccessEvidence(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins,
	approval sshAccessEvidenceApproval, clock func() time.Time, authorize func() error) (result sshAccessEvidenceObservation, err error) {
	if ctx == nil || journal == nil || journal.retained != nil || parserCheck == nil || clock == nil || authorize == nil ||
		!lowerDigest.MatchString(approval.EvidenceSHA256) || !lowerDigest.MatchString(approval.ChallengeSHA256) || len(approval.Controller) != ed25519.PublicKeySize {
		return result, ErrInventoryUnsafe
	}
	approval.Controller = bytes.Clone(approval.Controller)
	pins, err = copySSHObservationPins(pins)
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			result = sshAccessEvidenceObservation{}
		}
	}()
	last := clock()
	guard := func() error {
		authorityErr := authorize()
		now := clock()
		if now.Before(last) {
			return ErrInventoryChanged
		}
		last = now
		return errors.Join(authorityErr, ctx.Err())
	}
	if err := errors.Join(guard(), journal.recheck()); err != nil {
		return result, err
	}
	image, err := readSSHPrivateChild(journal.directory, sshAccessEvidenceName, journal.uid, maxSSHAccessEvidenceBytes)
	if err != nil {
		return result, err
	}
	record, verified, challenge, err := decodeSSHAccessEvidence(image.data, approval, last)
	if err != nil {
		return result, err
	}
	_, err = withSSHActivationEvidenceAssessment(ctx, journal, approved, parser, run,
		func() error { return errors.Join(guard(), parserCheck(), ctx.Err()) }, observe, &image,
		func(_ context.Context, a *sshActivationAssessment, summary ActivationAssessment, recheck func() error) error {
			history, err := sshActivationDigest(a.owned.records)
			if err != nil || record.Records != history || record.Transaction != a.owned.prepared.Transaction ||
				record.Plan != approved || record.Parser != parser || record.Intent != digestBytes(a.intent.data) || record.Target != a.target {
				return errors.Join(ErrInventoryChanged, err)
			}
			historical, err := parseSSHAccessRequest(record.Request, verified.RequestSHA256)
			if err != nil || len(historical.Routes) != len(a.owned.plan.intent.Contexts) {
				return errors.Join(ErrInventoryChanged, err)
			}
			for index, route := range historical.Routes {
				if route.Access != a.owned.plan.intent.Contexts[index] {
					return ErrInventoryChanged
				}
			}
			current, err := makeSSHActivationAccessRequest(a, summary, pins)
			if err != nil {
				return err
			}
			if err := recheck(); err != nil {
				return err
			}
			result = sshAccessEvidenceObservation{
				RecordSHA256: approval.EvidenceSHA256, RequestSHA256: verified.RequestSHA256,
				ChallengeSHA256: verified.ChallengeSHA256, ReceiptSHA256: verified.ReceiptSHA256,
				ControllerSHA256: verified.ControllerSHA256, CurrentRequestSHA256: digestBytes(current),
				AssessedAt: record.AssessedAt, ContextsRecorded: verified.ContextsObserved,
				HistoricalSignatureVerified: true, CurrentRequestMatches: bytes.Equal(current, record.Request),
				DurabilityUnknown: true, RecoveryRequired: true,
			}
			return nil
		})
	if err == nil {
		result.WindowOpen = last.Unix() < challenge.ExpiresAt
	}
	return result, err
}

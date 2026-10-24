//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"
)

const (
	sshAccessIssuanceName     = "access-issuance.json"
	sshAccessIssuanceDomain   = "syswarden-ssh-access-issuance-v1"
	maxSSHAccessIssuanceBytes = 512 << 10
)

// Issuance binds independently provisioned controller authority to one current
// transaction. The original activation and publication records remain intact.
// This record is not daemon consumption, access success or recovery completion.
type sshAccessIssuance struct {
	Schema           int    `json:"schema"`
	Domain           string `json:"domain"`
	Transaction      string `json:"transaction"`
	Plan             string `json:"plan_sha256"`
	Parser           string `json:"parser_sha256"`
	Intent           string `json:"intent_sha256"`
	Target           string `json:"target_sha256"`
	Records          string `json:"records_sha256"`
	Enrollment       string `json:"enrollment_sha256"`
	EnrollmentImage  string `json:"enrollment_image_sha256"`
	Request          []byte `json:"request"`
	Challenge        []byte `json:"challenge"`
	RecoveryRequired bool   `json:"recovery_required"`
}

// Private payloads may be delivered only after the original writer acknowledged
// durability and all final guards passed. Errors retain write uncertainty, but
// never return a deliverable challenge. Reopen cannot repair that uncertainty.
type sshAccessIssuanceResult struct {
	Transaction         string
	IssuanceSHA256      string
	IssuanceImageSHA256 string
	IssuanceDurable     bool
	Request             []byte
	Challenge           []byte
	RecoveryRequired    bool
}

func issueSSHAuthorizedAccessChallenge(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, authority *sshAccessAuthority,
	approvedRequest string, lifetime time.Duration, clock func() time.Time) (result sshAccessIssuanceResult, err error) {
	if ctx == nil || authority == nil || authority.plan != approved || clock == nil || parserCheck == nil || !lowerDigest.MatchString(approvedRequest) {
		return result, ErrInventoryUnsafe
	}
	last := clock()
	var issued []byte
	guard := func() error {
		authErr := authority.recheck()
		now := clock()
		if now.Before(last) {
			return ErrInventoryChanged
		}
		last = now
		var challengeErr error
		if issued != nil {
			_, challengeErr = parseSSHAccessChallenge(issued, digestBytes(issued), now)
		}
		return errors.Join(authErr, challengeErr, ctx.Err())
	}
	defer func() {
		if result.RecoveryRequired {
			journal.poisoned = true
		}
		if err != nil {
			result.Request, result.Challenge = nil, nil
		}
	}()
	if err := guard(); err != nil {
		return result, err
	}
	_, err = withSSHActivationAssessment(ctx, journal, approved, parser, run,
		func() error { return errors.Join(guard(), parserCheck()) }, observe,
		func(_ context.Context, a *sshActivationAssessment, summary ActivationAssessment, recheck func() error) error {
			request, err := makeSSHActivationAccessRequest(a, summary, authority.pins)
			if err != nil || digestBytes(request) != approvedRequest {
				return errors.Join(ErrInventoryChanged, err)
			}
			if err := recheck(); err != nil {
				return err
			}
			challenge, err := newSSHAccessChallenge(request, approvedRequest, authority.controller, last, lifetime)
			if err != nil {
				return err
			}
			parsed, err := parseSSHAccessChallenge(challenge, digestBytes(challenge), last)
			if err != nil || parsed.ExpiresAt > authority.expiresAt {
				return errors.Join(ErrInventoryUnsafe, err)
			}
			issued = bytes.Clone(challenge)
			history, err := sshActivationDigest(a.owned.records)
			if err != nil {
				return err
			}
			record := sshAccessIssuance{1, sshAccessIssuanceDomain, a.owned.prepared.Transaction,
				approved, parser, digestBytes(a.intent.data), a.target, history, authority.digest,
				sshImageDigest(authority.image), request, challenge, true}
			wire, err := json.Marshal(record)
			if err != nil || len(wire) > maxSSHAccessIssuanceBytes {
				return errors.Join(ErrInventoryBounds, err)
			}
			if err := recheck(); err != nil {
				return err
			}
			// Publication follows every authorization check and uses the existing
			// no-replace, anonymous-inode, fsync protocol under the journal lock.
			result.Transaction, result.RecoveryRequired = record.Transaction, true
			image, err := journal.writeRecordImage(sshAccessIssuanceName, wire)
			if err != nil {
				return err
			}
			result.IssuanceSHA256, result.IssuanceDurable = digestBytes(wire), true
			result.IssuanceImageSHA256 = sshImageDigest(image)
			a.issuance = &image
			// Check time again after storage latency. An expired challenge is never
			// delivered, even if its private record was already durably published.
			if err := recheck(); err != nil {
				return err
			}
			if _, err := parseSSHAccessChallenge(challenge, digestBytes(challenge), last); err != nil {
				return err
			}
			result.Request, result.Challenge = bytes.Clone(request), bytes.Clone(challenge)
			return nil
		})
	return result, err
}

func decodeSSHAccessIssuance(wire []byte, approved string, authority *sshAccessAuthority, now time.Time) (sshAccessIssuance, error) {
	fail := func(err error) (sshAccessIssuance, error) {
		return sshAccessIssuance{}, errors.Join(ErrInventoryUnsafe, err)
	}
	if authority == nil || len(wire) == 0 || len(wire) > maxSSHAccessIssuanceBytes || !lowerDigest.MatchString(approved) || digestBytes(wire) != approved {
		return fail(nil)
	}
	if err := authority.recheck(); err != nil {
		return fail(err)
	}
	var record sshAccessIssuance
	if err := json.Unmarshal(wire, &record); err != nil {
		return fail(err)
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(wire, canonical) || record.Schema != 1 || record.Domain != sshAccessIssuanceDomain || !record.RecoveryRequired ||
		record.Enrollment != authority.digest || record.EnrollmentImage != sshImageDigest(authority.image) {
		return fail(err)
	}
	for _, hash := range []string{record.Transaction, record.Plan, record.Parser, record.Intent, record.Target, record.Records} {
		if !lowerDigest.MatchString(hash) {
			return fail(nil)
		}
	}
	request, err := parseSSHAccessRequest(record.Request, digestBytes(record.Request))
	if err != nil || request.Transaction != record.Transaction || request.Plan != record.Plan || request.Intent != record.Intent || request.Target != record.Target {
		return fail(err)
	}
	challenge, err := parseSSHAccessChallenge(record.Challenge, digestBytes(record.Challenge), now)
	if err != nil || challenge.Request != digestBytes(record.Request) || challenge.Controller != digestBytes(authority.controller) || challenge.ExpiresAt > authority.expiresAt {
		return fail(err)
	}
	return record, nil
}

// Accept only the exact issued challenge, protected enrollment image and current
// request. Receipt bytes never supply a trusted key, route or approval. The
// existing evidence writer consumes the sole receipt slot without networking.
func recordSSHAuthorizedAccessEvidence(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, authority *sshAccessAuthority,
	approvedIssuance, approvedImage string, receipt []byte, clock func() time.Time) (sshAccessEvidenceResult, error) {
	if ctx == nil || journal == nil || authority == nil || authority.plan != approved || clock == nil || parserCheck == nil || len(receipt) == 0 || len(receipt) > maxSSHAccessReceiptBytes || !lowerDigest.MatchString(approvedImage) {
		return sshAccessEvidenceResult{}, ErrInventoryUnsafe
	}
	receipt = bytes.Clone(receipt)
	if err := errors.Join(ctx.Err(), journal.recheck(), authority.recheck()); err != nil {
		return sshAccessEvidenceResult{}, err
	}
	image, err := readSSHPrivateChild(journal.directory, sshAccessIssuanceName, journal.uid, maxSSHAccessIssuanceBytes)
	if err != nil {
		return sshAccessEvidenceResult{}, err
	}
	if sshImageDigest(image) != approvedImage {
		return sshAccessEvidenceResult{}, ErrInventoryChanged
	}
	record, err := decodeSSHAccessIssuance(image.data, approvedIssuance, authority, clock())
	if err != nil {
		return sshAccessEvidenceResult{}, err
	}
	a, err := inspectSSHActivationAccessHistory(journal, approved, parser, nil, &image)
	if err != nil {
		return sshAccessEvidenceResult{}, err
	}
	history, err := sshActivationDigest(a.owned.records)
	if err != nil || record.Transaction != a.owned.prepared.Transaction || record.Plan != approved || record.Parser != parser ||
		record.Intent != digestBytes(a.intent.data) || record.Target != a.target || record.Records != history {
		return sshAccessEvidenceResult{}, errors.Join(ErrInventoryChanged, err)
	}
	// The core's final guard pins this exact issuance inode as well as the
	// original publication and independently rechecks controller revocation.
	input := sshAccessReceiptInput{record.Request, record.Challenge, receipt, digestBytes(record.Challenge), bytes.Clone(authority.controller)}
	result, err := recordSSHIssuedAccessEvidence(ctx, journal, approved, parser, run, parserCheck, observe, authority.pins, input, clock, authority.recheck, &image)
	return result, err
}

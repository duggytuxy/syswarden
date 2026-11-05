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
	sshRestoredAccessAuthorityPath   = "/etc/syswarden/ssh-restoration-access-controller-v1.json"
	sshRestoredAccessAuthorityDomain = "syswarden-ssh-restoration-access-controller-v1"
	sshRestoredAccessRequestDomain   = "syswarden-ssh-restoration-access-request-v1"
	sshRestoredAccessIssuanceName    = "restoration-access-issuance.json"
	sshRestoredAccessIssuanceDomain  = "syswarden-ssh-restoration-access-issuance-v1"
	sshRestoredAccessEvidenceName    = "restoration-access-evidence.json"
	sshRestoredAccessEvidenceDomain  = "syswarden-ssh-restoration-access-evidence-v1"
)

// Restoration requires independently provisioned authority for both approved
// histories. Activation enrollment is never authority for a restored graph.
type sshRestoredAccessAuthorityDocument struct {
	Schema         int                       `json:"schema"`
	Domain         string                    `json:"domain"`
	Scope          string                    `json:"scope"`
	PlanSHA256     string                    `json:"plan_sha256"`
	RecoverySHA256 string                    `json:"recovery_sha256"`
	Controller     []byte                    `json:"controller_public_key"`
	Routes         []sshAccessAuthorityRoute `json:"routes"`
	NotBefore      int64                     `json:"not_before"`
	ExpiresAt      int64                     `json:"expires_at"`
}

func decodeSSHRestoredAccessAuthority(wire []byte, plan, recovery string) (sshAccessAuthorityDocument, []sshAccessRoutePins, error) {
	var document sshRestoredAccessAuthorityDocument
	if len(wire) == 0 || len(wire) > maxSSHAccessAuthorityBytes || !lowerDigest.MatchString(recovery) {
		return sshAccessAuthorityDocument{}, nil, ErrInventoryUnsafe
	}
	if err := json.Unmarshal(wire, &document); err != nil {
		return sshAccessAuthorityDocument{}, nil, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(wire, canonical) || document.Schema != 1 || document.Domain != sshRestoredAccessAuthorityDomain ||
		document.Scope != "restoration-access" || document.PlanSHA256 != plan || document.RecoverySHA256 != recovery {
		return sshAccessAuthorityDocument{}, nil, ErrInventoryUnsafe
	}
	// Reuse only key, route and time validation. No original or new enrollment
	// bytes are rewritten, persisted or accepted through the other purpose path.
	common := sshAccessAuthorityDocument{1, sshAccessAuthorityDomain, "activation-access", plan, document.Controller, document.Routes, document.NotBefore, document.ExpiresAt}
	validation, err := json.Marshal(common)
	if err != nil {
		return sshAccessAuthorityDocument{}, nil, err
	}
	return decodeSSHAccessAuthority(validation, plan)
}

type sshRestoredAccessRequest struct {
	Schema       int                     `json:"schema"`
	Domain       string                  `json:"domain"`
	Transaction  string                  `json:"transaction"`
	Plan         string                  `json:"plan_sha256"`
	Recovery     string                  `json:"recovery_sha256"`
	ReloadIntent string                  `json:"reload_intent_sha256"`
	Restored     string                  `json:"restored_sha256"`
	Target       string                  `json:"target_sha256"`
	Assessment   string                  `json:"assessment_sha256"`
	Routes       []sshAccessRequestRoute `json:"routes"`
}

func parseSSHRestoredAccessRequest(wire []byte, approved string) (sshRestoredAccessRequest, error) {
	var request sshRestoredAccessRequest
	if len(wire) == 0 || len(wire) > maxSSHAccessRequestBytes || !lowerDigest.MatchString(approved) || digestBytes(wire) != approved {
		return request, ErrInventoryUnsafe
	}
	if err := json.Unmarshal(wire, &request); err != nil {
		return sshRestoredAccessRequest{}, ErrInventoryUnsafe
	}
	canonical, err := canonicalSSHRestoredAccessRequest(wire, request)
	if err != nil || !bytes.Equal(wire, canonical) || len(request.Routes) == 0 || len(request.Routes) > MaxAccessContexts {
		return sshRestoredAccessRequest{}, ErrInventoryUnsafe
	}
	for _, hash := range []string{request.Transaction, request.Plan, request.Recovery, request.ReloadIntent, request.Restored, request.Target, request.Assessment} {
		if !lowerDigest.MatchString(hash) {
			return sshRestoredAccessRequest{}, ErrInventoryUnsafe
		}
	}
	seen := make(map[string]bool)
	for index, route := range request.Routes {
		if seen[route.Access.ID] {
			return sshRestoredAccessRequest{}, ErrInventoryUnsafe
		}
		seen[route.Access.ID] = true
		request.Routes[index], err = copySSHAccessRoute(route)
		if err != nil {
			return sshRestoredAccessRequest{}, err
		}
	}
	return request, nil
}

// The shared transport binds the exact original request digest, including its
// distinct domain and recovery fields. This view is never marshaled as a wire
// request and cannot make the activation parser accept restoration bytes.
func normalizedSSHRestoredAccessRequest(wire []byte, approved string) (sshAccessRequest, error) {
	request, err := parseSSHRestoredAccessRequest(wire, approved)
	if err != nil {
		return sshAccessRequest{}, err
	}
	return sshAccessRequest{request.Schema, request.Domain, request.Transaction, request.Plan, request.ReloadIntent, request.Target, request.Assessment, request.Routes}, nil
}

func makeSSHRestoredAccessRequest(a *sshRestoredAccessAssessment, summary RecoveryAssessment, pins []sshAccessRoutePins) ([]byte, error) {
	routes, err := bindSSHAccessRoutes(a.plan.intent.Contexts, pins)
	if err != nil {
		return nil, err
	}
	assessment, err := sshActivationDigest(summary)
	if err != nil {
		return nil, err
	}
	request := sshRestoredAccessRequest{1, sshRestoredAccessRequestDomain, summary.Transaction, summary.PlanSHA256, summary.RecoverySHA256,
		summary.ReloadIntentSHA256, summary.RestoredSHA256, summary.RecordedTargetSHA256, assessment, routes}
	wire, err := marshalSSHRestoredAccessRequest(request, summary)
	if err != nil || len(wire) > maxSSHAccessRequestBytes {
		return nil, errors.Join(ErrInventoryBounds, err)
	}
	return wire, nil
}

func prepareSSHRestoredAccessRequest(ctx context.Context, journal *sshJournal, plan, recovery, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins) ([]byte, error) {
	var wire []byte
	_, err := withSSHRestoredAccessAssessment(ctx, journal, plan, recovery, parser, run, parserCheck, observe, nil, nil,
		func(a *sshRestoredAccessAssessment, summary RecoveryAssessment, guard func() error) error {
			var err error
			wire, err = makeSSHRestoredAccessRequest(a, summary, pins)
			return errors.Join(err, guard())
		})
	if err != nil {
		return nil, err
	}
	return wire, nil
}

type sshRestoredAccessIssuance struct {
	Schema           int    `json:"schema"`
	Domain           string `json:"domain"`
	Transaction      string `json:"transaction"`
	Plan             string `json:"plan_sha256"`
	Recovery         string `json:"recovery_sha256"`
	ReloadIntent     string `json:"reload_intent_sha256"`
	Restored         string `json:"restored_sha256"`
	Target           string `json:"target_sha256"`
	Parser           string `json:"parser_sha256"`
	Records          string `json:"records_sha256"`
	Enrollment       string `json:"enrollment_sha256"`
	EnrollmentImage  string `json:"enrollment_image_sha256"`
	Request          []byte `json:"request"`
	Challenge        []byte `json:"challenge"`
	RecoveryRequired bool   `json:"recovery_required"`
}

type sshRestoredAccessEvidence struct {
	Schema           int    `json:"schema"`
	Domain           string `json:"domain"`
	Transaction      string `json:"transaction"`
	Plan             string `json:"plan_sha256"`
	Recovery         string `json:"recovery_sha256"`
	ReloadIntent     string `json:"reload_intent_sha256"`
	Restored         string `json:"restored_sha256"`
	Target           string `json:"target_sha256"`
	Parser           string `json:"parser_sha256"`
	Records          string `json:"records_sha256"`
	Enrollment       string `json:"enrollment_sha256"`
	EnrollmentImage  string `json:"enrollment_image_sha256"`
	Controller       string `json:"controller_sha256"`
	AssessedAt       int64  `json:"assessed_at"`
	Request          []byte `json:"request"`
	Challenge        []byte `json:"challenge"`
	Receipt          []byte `json:"receipt"`
	Issuance         string `json:"issuance_image_sha256"`
	RecoveryRequired bool   `json:"recovery_required"`
}

// Guard every use of enrolled authority and challenge against expiry and both
// wall-clock and monotonic regression. The caller adds protected file guards.
func sshRestoredAccessClockGuard(ctx context.Context, authority *sshAccessAuthority, clock func() time.Time, challenge *[]byte) (func() error, *time.Time) {
	last := clock()
	guard := func() error {
		authErr := authority.recheck()
		now := clock()
		if now.Before(last) || now.Round(0).Before(last.Round(0)) {
			return ErrInventoryChanged
		}
		last = now
		var challengeErr error
		if challenge != nil && len(*challenge) != 0 {
			_, challengeErr = parseSSHAccessChallenge(*challenge, digestBytes(*challenge), now)
		}
		return errors.Join(ctx.Err(), authErr, challengeErr)
	}
	return guard, &last
}

func validSSHRestoredAccessAuthority(ctx context.Context, journal *sshJournal, plan, recovery string, authority *sshAccessAuthority, parserCheck func() error, clock func() time.Time) error {
	if err := validSSHRecoveryRequest(ctx, plan, recovery, true); err != nil {
		return err
	}
	if journal == nil || authority == nil || authority.plan != plan || authority.recovery != recovery || parserCheck == nil || clock == nil {
		return ErrInventoryUnsafe
	}
	return errors.Join(ctx.Err(), journal.recheck(), authority.recheck())
}

func issueSSHAuthorizedRestoredAccessChallenge(ctx context.Context, journal *sshJournal, plan, recovery, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, authority *sshAccessAuthority,
	approvedRequest string, lifetime time.Duration, clock func() time.Time) (result sshAccessIssuanceResult, err error) {
	if err := validSSHRestoredAccessAuthority(ctx, journal, plan, recovery, authority, parserCheck, clock); err != nil {
		return result, err
	}
	if !lowerDigest.MatchString(approvedRequest) {
		return result, ErrInventoryUnsafe
	}
	var issued []byte
	authorize, last := sshRestoredAccessClockGuard(ctx, authority, clock, &issued)
	defer func() {
		if result.RecoveryRequired {
			journal.poisoned = true
		}
		if err != nil {
			result.Request, result.Challenge = nil, nil
		}
	}()
	_, err = withSSHRestoredAccessAssessment(ctx, journal, plan, recovery, parser, run,
		func() error { return errors.Join(authorize(), parserCheck()) }, observe, nil, nil,
		func(a *sshRestoredAccessAssessment, summary RecoveryAssessment, guard func() error) error {
			request, err := makeSSHRestoredAccessRequest(a, summary, authority.pins)
			if err != nil || digestBytes(request) != approvedRequest {
				return errors.Join(ErrInventoryChanged, err)
			}
			if err := guard(); err != nil {
				return err
			}
			challenge, err := newSSHAccessChallengeWithParser(request, approvedRequest, authority.controller, *last, lifetime, normalizedSSHRestoredAccessRequest)
			if err != nil {
				return err
			}
			parsed, err := parseSSHAccessChallenge(challenge, digestBytes(challenge), *last)
			if err != nil || parsed.ExpiresAt > authority.expiresAt {
				return errors.Join(ErrInventoryUnsafe, err)
			}
			issued = bytes.Clone(challenge)
			history, err := sshActivationDigest(a.records)
			if err != nil {
				return err
			}
			record := sshRestoredAccessIssuance{1, sshRestoredAccessIssuanceDomain, summary.Transaction, plan, recovery, summary.ReloadIntentSHA256,
				summary.RestoredSHA256, summary.RecordedTargetSHA256, parser, history, authority.digest, sshImageDigest(authority.image), request, challenge, true}
			if summary.ReloadObservationObserved {
				record.Schema, record.Domain = 2, sshObservedRestoredAccessIssuanceDomain
			}
			wire, err := json.Marshal(record)
			if err != nil || len(wire) > maxSSHAccessIssuanceBytes {
				return errors.Join(ErrInventoryBounds, err)
			}
			if err := guard(); err != nil {
				return err
			}
			result.Transaction, result.RecoveryRequired = summary.Transaction, true
			image, err := journal.writeRecordImage(sshRestoredAccessIssuanceName, wire)
			if err != nil {
				return err
			}
			result.IssuanceSHA256, result.IssuanceImageSHA256, result.IssuanceDurable = digestBytes(wire), sshImageDigest(image), true
			a.issuance = &image
			if err := guard(); err != nil {
				return err
			}
			result.Request, result.Challenge = bytes.Clone(request), bytes.Clone(challenge)
			return nil
		})
	return result, err
}

func decodeSSHRestoredAccessIssuance(wire []byte, approved string, authority *sshAccessAuthority, now time.Time) (sshRestoredAccessIssuance, error) {
	var record sshRestoredAccessIssuance
	fail := func(err error) (sshRestoredAccessIssuance, error) {
		return sshRestoredAccessIssuance{}, errors.Join(ErrInventoryUnsafe, err)
	}
	if authority == nil || !lowerDigest.MatchString(authority.recovery) || len(wire) == 0 || len(wire) > maxSSHAccessIssuanceBytes || !lowerDigest.MatchString(approved) || digestBytes(wire) != approved {
		return fail(nil)
	}
	if err := authority.recheck(); err != nil {
		return fail(err)
	}
	if err := json.Unmarshal(wire, &record); err != nil {
		return fail(err)
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(wire, canonical) || !validSSHRestoredAccessRecordVersion(record.Schema, record.Domain, false) || !record.RecoveryRequired ||
		record.Plan != authority.plan || record.Recovery != authority.recovery || record.Enrollment != authority.digest || record.EnrollmentImage != sshImageDigest(authority.image) {
		return fail(err)
	}
	for _, hash := range []string{record.Transaction, record.Plan, record.Recovery, record.ReloadIntent, record.Restored, record.Target, record.Parser, record.Records} {
		if !lowerDigest.MatchString(hash) {
			return fail(nil)
		}
	}
	request, err := parseSSHRestoredAccessRequest(record.Request, digestBytes(record.Request))
	if err != nil || request.Schema != record.Schema || request.Transaction != record.Transaction || request.Plan != record.Plan || request.Recovery != record.Recovery ||
		request.ReloadIntent != record.ReloadIntent || request.Restored != record.Restored || request.Target != record.Target {
		return fail(err)
	}
	challenge, err := parseSSHAccessChallenge(record.Challenge, digestBytes(record.Challenge), now)
	if err != nil || challenge.Request != digestBytes(record.Request) || challenge.Controller != digestBytes(authority.controller) || challenge.ExpiresAt > authority.expiresAt {
		return fail(err)
	}
	return record, nil
}

func readSSHRestoredAccessIssuance(journal *sshJournal, authority *sshAccessAuthority, approved, approvedImage string, now time.Time) (sshRestoredAccessIssuance, sshFileImage, error) {
	if !lowerDigest.MatchString(approvedImage) {
		return sshRestoredAccessIssuance{}, sshFileImage{}, ErrInventoryUnsafe
	}
	image, err := readSSHPrivateChild(journal.directory, sshRestoredAccessIssuanceName, journal.uid, maxSSHAccessIssuanceBytes)
	if err != nil || sshImageDigest(image) != approvedImage {
		return sshRestoredAccessIssuance{}, sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	record, err := decodeSSHRestoredAccessIssuance(image.data, approved, authority, now)
	return record, image, err
}

func matchSSHRestoredAccessIssuance(a *sshRestoredAccessAssessment, summary RecoveryAssessment, parser string, authority *sshAccessAuthority, record sshRestoredAccessIssuance) error {
	request, err := makeSSHRestoredAccessRequest(a, summary, authority.pins)
	if err != nil {
		return err
	}
	history, err := sshActivationDigest(a.records)
	if err != nil || !bytes.Equal(request, record.Request) || record.Transaction != summary.Transaction || record.Plan != summary.PlanSHA256 ||
		record.Recovery != summary.RecoverySHA256 || record.ReloadIntent != summary.ReloadIntentSHA256 || record.Restored != summary.RestoredSHA256 ||
		record.Target != summary.RecordedTargetSHA256 || record.Parser != parser || record.Records != history ||
		record.Enrollment != authority.digest || record.EnrollmentImage != sshImageDigest(authority.image) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

func recordSSHAuthorizedRestoredAccessEvidence(ctx context.Context, journal *sshJournal, plan, recovery, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, authority *sshAccessAuthority,
	approvedIssuance, approvedImage string, receipt []byte, clock func() time.Time) (result sshAccessEvidenceResult, err error) {
	if err := validSSHRestoredAccessAuthority(ctx, journal, plan, recovery, authority, parserCheck, clock); err != nil {
		return result, err
	}
	if len(receipt) == 0 || len(receipt) > maxSSHAccessReceiptBytes {
		return result, ErrInventoryUnsafe
	}
	receipt = bytes.Clone(receipt)
	record, image, err := readSSHRestoredAccessIssuance(journal, authority, approvedIssuance, approvedImage, clock())
	if err != nil {
		return result, err
	}
	authorize, last := sshRestoredAccessClockGuard(ctx, authority, clock, &record.Challenge)
	defer func() {
		if result.RecoveryRequired {
			journal.poisoned = true
		}
	}()
	_, err = withSSHRestoredAccessAssessment(ctx, journal, plan, recovery, parser, run,
		func() error { return errors.Join(authorize(), parserCheck()) }, observe, &image, nil,
		func(a *sshRestoredAccessAssessment, summary RecoveryAssessment, guard func() error) error {
			if err := matchSSHRestoredAccessIssuance(a, summary, parser, authority, record); err != nil {
				return err
			}
			if err := guard(); err != nil {
				return err
			}
			input := sshAccessReceiptInput{record.Request, record.Challenge, receipt, digestBytes(record.Challenge), authority.controller}
			if _, err := verifySSHAccessReceiptWithParser(input, *last, normalizedSSHRestoredAccessRequest); err != nil {
				return err
			}
			evidence := sshRestoredAccessEvidence{1, sshRestoredAccessEvidenceDomain, record.Transaction, record.Plan, record.Recovery, record.ReloadIntent,
				record.Restored, record.Target, record.Parser, record.Records, record.Enrollment, record.EnrollmentImage, digestBytes(authority.controller), last.Unix(),
				record.Request, record.Challenge, receipt, approvedImage, true}
			if record.Schema == 2 {
				evidence.Schema, evidence.Domain = 2, sshObservedRestoredAccessEvidenceDomain
			}
			wire, err := json.Marshal(evidence)
			if err != nil || len(wire) > maxSSHAccessEvidenceBytes {
				return errors.Join(ErrInventoryBounds, err)
			}
			if err := guard(); err != nil {
				return err
			}
			result.Transaction, result.RecoveryRequired = record.Transaction, true
			evidenceImage, err := journal.writeRecordImage(sshRestoredAccessEvidenceName, wire)
			if err != nil {
				return err
			}
			result.RecordSHA256, result.RecordDurable = digestBytes(wire), true
			a.evidence = &evidenceImage
			return guard()
		})
	return result, err
}

// RestoredAccessInspection observes exact approved records while enrollment and
// challenge remain current. It does not recover an original writer's durability
// acknowledgment or prove current access, consumption or completed recovery.
type RestoredAccessInspection struct {
	Transaction         string `json:"transaction"`
	IssuanceSHA256      string `json:"issuance_sha256"`
	IssuanceImageSHA256 string `json:"issuance_image_sha256"`
	RecordSHA256        string `json:"record_sha256,omitempty"`
	IssuanceObserved    bool   `json:"issuance_observed"`
	ReceiptObserved     bool   `json:"receipt_observed"`
	RecoveryRequired    bool   `json:"recovery_required"`
}

func inspectSSHAuthorizedRestoredAccess(ctx context.Context, journal *sshJournal, plan, recovery, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, authority *sshAccessAuthority,
	approvedIssuance, approvedImage, approvedRecord string, clock func() time.Time) (result RestoredAccessInspection, err error) {
	if err := validSSHRestoredAccessAuthority(ctx, journal, plan, recovery, authority, parserCheck, clock); err != nil {
		return result, err
	}
	record, image, err := readSSHRestoredAccessIssuance(journal, authority, approvedIssuance, approvedImage, clock())
	if err != nil {
		return result, err
	}
	var evidenceImage *sshFileImage
	var evidence sshRestoredAccessEvidence
	if approvedRecord != "" {
		if !lowerDigest.MatchString(approvedRecord) {
			return result, ErrInventoryUnsafe
		}
		got, err := readSSHPrivateChild(journal.directory, sshRestoredAccessEvidenceName, journal.uid, maxSSHAccessEvidenceBytes)
		if err != nil || digestBytes(got.data) != approvedRecord {
			return result, errors.Join(ErrInventoryChanged, err)
		}
		if err := json.Unmarshal(got.data, &evidence); err != nil {
			return result, ErrInventoryUnsafe
		}
		canonical, err := json.Marshal(evidence)
		if err != nil || !bytes.Equal(got.data, canonical) {
			return result, errors.Join(ErrInventoryUnsafe, err)
		}
		evidenceImage = &got
	}
	authorize, last := sshRestoredAccessClockGuard(ctx, authority, clock, &record.Challenge)
	_, err = withSSHRestoredAccessAssessment(ctx, journal, plan, recovery, parser, run,
		func() error { return errors.Join(authorize(), parserCheck()) }, observe, &image, evidenceImage,
		func(a *sshRestoredAccessAssessment, summary RecoveryAssessment, guard func() error) error {
			if err := matchSSHRestoredAccessIssuance(a, summary, parser, authority, record); err != nil {
				return err
			}
			if err := guard(); err != nil {
				return err
			}
			if evidenceImage != nil {
				if evidence.Schema != record.Schema || !validSSHRestoredAccessRecordVersion(evidence.Schema, evidence.Domain, true) || !evidence.RecoveryRequired || evidence.Transaction != record.Transaction ||
					evidence.Plan != record.Plan || evidence.Recovery != record.Recovery || evidence.ReloadIntent != record.ReloadIntent || evidence.Restored != record.Restored ||
					evidence.Target != record.Target || evidence.Parser != record.Parser || evidence.Records != record.Records || evidence.Enrollment != record.Enrollment ||
					evidence.EnrollmentImage != record.EnrollmentImage || evidence.Controller != digestBytes(authority.controller) || evidence.Issuance != approvedImage ||
					!bytes.Equal(evidence.Request, record.Request) || !bytes.Equal(evidence.Challenge, record.Challenge) || evidence.AssessedAt <= 0 || evidence.AssessedAt > last.Unix() {
					return ErrInventoryChanged
				}
				input := sshAccessReceiptInput{record.Request, record.Challenge, evidence.Receipt, digestBytes(record.Challenge), authority.controller}
				if _, err := verifySSHAccessReceiptWithParser(input, time.Unix(evidence.AssessedAt, 0), normalizedSSHRestoredAccessRequest); err != nil {
					return err
				}
			}
			return guard()
		})
	if err != nil {
		return RestoredAccessInspection{}, err
	}
	return RestoredAccessInspection{record.Transaction, approvedIssuance, approvedImage, approvedRecord, true, evidenceImage != nil, true}, nil
}

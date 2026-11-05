//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

// The controller independently approves the complete prepared request and
// authenticates its exact challenge. Neither callback can accept migration or
// choose target-side authority. Callbacks must honor ctx and keep all request,
// challenge and credential material private.
type sshForwardAccessExchange struct {
	review func(context.Context, AccessRequestPreview) (string, error)
	probe  func(context.Context, AccessChallengePublication) ([]byte, error)
}

// These are partial durable facts, not a terminal acceptance receipt. Even a
// freshly authenticated, durably recorded response leaves recovery required.
// The existing migration lease closes before the independent access exchange;
// each access adapter independently rechecks the complete current assessment.
type sshForwardResult struct {
	Migration           sshMigrationResult
	RequestSHA256       string
	IssuanceSHA256      string
	IssuanceImageSHA256 string
	IssuanceDurable     bool
	RecordSHA256        string
	RecordDurable       bool
	RecoveryRequired    bool
}

type sshForwardOperations struct {
	migrate func(context.Context, string, string) (sshMigrationResult, error)
	request func(context.Context, string, string) (AccessRequestPreview, error)
	issue   func(context.Context, string, string, string, time.Duration) (AccessChallengePublication, error)
	record  func(context.Context, string, string, string, string, []byte) (AccessReceiptPublication, error)
}

// This private composition is exercised by the isolated native oracle. It has
// no CLI or installer caller. Production target adapters retain their fixed
// paths and independently provisioned controller authority; only the original
// migration opener is supplied for the existing isolated label fixture.
func runSSHForwardSession(ctx context.Context, plan, enrollment string,
	open func(context.Context, string, string) (*sshMigrationSession, error), exchange sshForwardAccessExchange) (sshForwardResult, error) {
	if open == nil {
		return sshForwardResult{}, ErrInventoryUnsafe
	}
	operations := sshForwardOperations{
		migrate: func(ctx context.Context, plan, enrollment string) (sshMigrationResult, error) {
			return runSSHMigrationSession(ctx, plan, enrollment, open)
		},
		request: PrepareSystemdAccessRequest,
		issue:   IssueSystemdAccessChallenge,
		record:  RecordSystemdAccessReceipt,
	}
	return runSSHForwardWith(ctx, plan, enrollment, exchange, operations)
}

func runSSHForwardWith(parent context.Context, plan, enrollment string, exchange sshForwardAccessExchange,
	operations sshForwardOperations) (result sshForwardResult, err error) {
	if err := validateSSHAccessAdapter(parent, plan, enrollment, false); err != nil {
		return result, err
	}
	if exchange.review == nil || exchange.probe == nil || operations.migrate == nil || operations.request == nil || operations.issue == nil || operations.record == nil {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	result.Migration, err = operations.migrate(ctx, plan, enrollment)
	migration := result.Migration
	result.RecoveryRequired = migration.RecoveryRequired || migration.Transaction != "" || migration.Published || migration.IntentDurable || migration.RequestReturned
	if err != nil {
		return result, fmt.Errorf("SSH forward publication or reload requires inspection: %w", err)
	}
	// A malformed successful adapter result cannot establish absence of effects.
	result.RecoveryRequired = true
	if !migration.Published || !migration.IntentDurable || !migration.RequestReturned || !migration.RecoveryRequired || !lowerDigest.MatchString(migration.Transaction) {
		return result, ErrInventoryUnsafe
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	preview, err := operations.request(ctx, plan, enrollment)
	if err != nil {
		return result, fmt.Errorf("SSH forward access preparation requires recovery: %w", err)
	}
	request, err := parseSSHAccessRequest(preview.Request, preview.RequestSHA256)
	if err != nil || !preview.RecoveryRequired || request.Plan != plan || request.Transaction != migration.Transaction {
		return result, errors.Join(ErrInventoryChanged, err)
	}
	result.RequestSHA256 = preview.RequestSHA256
	requestWire := bytes.Clone(preview.Request)
	preview.Request = bytes.Clone(requestWire)
	if err := ctx.Err(); err != nil {
		return result, err
	}
	approved, reviewErr := exchange.review(ctx, preview)
	if reviewErr != nil {
		// A controller transport/review error may contain private routing or
		// credential context. Preserve cancellation without exposing its text.
		return result, errors.Join(errors.New("independent SSH request approval failed; recovery remains required"), ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if approved != result.RequestSHA256 {
		return result, errors.New("independent SSH request approval differs; recovery remains required")
	}
	issued, err := operations.issue(ctx, plan, enrollment, approved, 3*time.Minute)
	result.IssuanceSHA256, result.IssuanceImageSHA256, result.IssuanceDurable = issued.IssuanceSHA256, issued.IssuanceImageSHA256, issued.IssuanceDurable
	if err != nil {
		return result, fmt.Errorf("SSH forward issuance requires inspection without replay: %w", err)
	}
	if issued.Transaction != migration.Transaction || !issued.IssuanceDurable || !issued.RecoveryRequired ||
		!lowerDigest.MatchString(issued.IssuanceSHA256) || !lowerDigest.MatchString(issued.IssuanceImageSHA256) ||
		!bytes.Equal(issued.Request, requestWire) || len(issued.Challenge) == 0 || len(issued.Challenge) > maxSSHAccessChallengeBytes {
		return result, ErrInventoryChanged
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	issued.Request, issued.Challenge = bytes.Clone(issued.Request), bytes.Clone(issued.Challenge)
	receipt, probeErr := exchange.probe(ctx, issued)
	if probeErr != nil {
		return result, errors.Join(errors.New("independent SSH authentication failed; issued challenge and recovery evidence remain retained"), ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(receipt) == 0 || len(receipt) > maxSSHAccessReceiptBytes {
		return result, ErrInventoryBounds
	}
	recorded, err := operations.record(ctx, plan, enrollment, result.IssuanceSHA256, result.IssuanceImageSHA256, bytes.Clone(receipt))
	result.RecordSHA256, result.RecordDurable = recorded.RecordSHA256, recorded.RecordDurable
	if err != nil {
		return result, fmt.Errorf("SSH forward receipt recording requires inspection without replay: %w", err)
	}
	if recorded.Transaction != migration.Transaction || !recorded.RecordDurable || !recorded.RecoveryRequired || !lowerDigest.MatchString(recorded.RecordSHA256) {
		return result, ErrInventoryChanged
	}
	// The signed receipt proves only scoped fresh access. No stock-build
	// consumed-policy contract exists here, so no terminal record is written,
	// no journal is retired and no recovery requirement is cleared.
	return result, ctx.Err()
}

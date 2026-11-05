//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"time"
)

type sshRestoredAccessSessionOpen func(context.Context, string, string, string) (*sshAccessSession, error)

func validateSSHRestoredAccessAdapter(ctx context.Context, plan, recovery, enrollment string, root bool) error {
	if err := validateSSHAccessAdapter(ctx, plan, enrollment, root); err != nil {
		return err
	}
	if !lowerDigest.MatchString(recovery) {
		return errors.New("SSH restoration access requires an independently approved recovery SHA-256")
	}
	return nil
}

func withSSHRestoredAccessSession(ctx context.Context, plan, recovery, enrollment string, open sshRestoredAccessSessionOpen, action func(*sshAccessSession) error) (err error) {
	if err := validateSSHRestoredAccessAdapter(ctx, plan, recovery, enrollment, false); err != nil {
		return err
	}
	if open == nil || action == nil {
		return ErrInventoryUnsafe
	}
	session, openErr := open(ctx, plan, recovery, enrollment)
	if session != nil && session.close != nil {
		defer func() {
			closeErr := session.close()
			err = errors.Join(err, closeErr, ctx.Err())
		}()
	}
	if openErr != nil {
		return openErr
	}
	if session == nil || session.journal == nil || session.run == nil || session.check == nil || session.observe == nil || session.authority == nil || session.clock == nil || session.close == nil ||
		session.authority.plan != plan || session.authority.recovery != recovery || session.authority.digest != enrollment {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), session.check(), session.authority.recheck()); err != nil {
		return err
	}
	return action(session)
}

// PrepareSystemdRestoredAccessRequest inspects the fully recorded original
// restoration using independent restoration enrollment. It neither reloads nor
// authenticates and leaves all activation and recovery records untouched.
func PrepareSystemdRestoredAccessRequest(ctx context.Context, plan, recovery, enrollment string) (AccessRequestPreview, error) {
	if err := validateSSHRestoredAccessAdapter(ctx, plan, recovery, enrollment, true); err != nil {
		return AccessRequestPreview{}, err
	}
	return prepareSystemdRestoredAccessRequest(ctx, plan, recovery, enrollment, openSSHRestoredAccessSession)
}

func prepareSystemdRestoredAccessRequest(ctx context.Context, plan, recovery, enrollment string, open sshRestoredAccessSessionOpen) (result AccessRequestPreview, err error) {
	err = withSSHRestoredAccessSession(ctx, plan, recovery, enrollment, open, func(s *sshAccessSession) error {
		request, err := prepareSSHRestoredAccessRequest(ctx, s.journal, plan, recovery, s.parser, s.run, s.check, s.observe, s.authority.pins)
		if err != nil {
			return err
		}
		result = AccessRequestPreview{digestBytes(request), request, true}
		return nil
	})
	if err != nil {
		result = AccessRequestPreview{}
	}
	return result, err
}

// IssueSystemdRestoredAccessChallenge consumes a separate no-replace issuance
// slot after exact request approval. It grants no authority to complete recovery.
func IssueSystemdRestoredAccessChallenge(ctx context.Context, plan, recovery, enrollment, request string, lifetime time.Duration) (AccessChallengePublication, error) {
	if err := validateSSHRestoredAccessAdapter(ctx, plan, recovery, enrollment, true); err != nil {
		return AccessChallengePublication{}, err
	}
	return issueSystemdRestoredAccessChallenge(ctx, plan, recovery, enrollment, request, lifetime, openSSHRestoredAccessSession)
}

func issueSystemdRestoredAccessChallenge(ctx context.Context, plan, recovery, enrollment, request string, lifetime time.Duration, open sshRestoredAccessSessionOpen) (result AccessChallengePublication, err error) {
	if !lowerDigest.MatchString(request) || lifetime < time.Second || lifetime > 5*time.Minute || lifetime%time.Second != 0 {
		return result, ErrInventoryUnsafe
	}
	err = withSSHRestoredAccessSession(ctx, plan, recovery, enrollment, open, func(s *sshAccessSession) error {
		got, err := issueSSHAuthorizedRestoredAccessChallenge(ctx, s.journal, plan, recovery, s.parser, s.run, s.check, s.observe, s.authority, request, lifetime, s.clock)
		result = AccessChallengePublication(got)
		return err
	})
	if err != nil {
		result.Request, result.Challenge = nil, nil
	}
	return result, err
}

// RecordSystemdRestoredAccessReceipt verifies a separately delivered controller
// receipt against current restoration state and the original issuance inode.
// A successful write remains an observation with recovery_required=true.
func RecordSystemdRestoredAccessReceipt(ctx context.Context, plan, recovery, enrollment, issuance, image string, receipt []byte) (AccessReceiptPublication, error) {
	if err := validateSSHRestoredAccessAdapter(ctx, plan, recovery, enrollment, true); err != nil {
		return AccessReceiptPublication{}, err
	}
	return recordSystemdRestoredAccessReceipt(ctx, plan, recovery, enrollment, issuance, image, receipt, openSSHRestoredAccessSession)
}

func recordSystemdRestoredAccessReceipt(ctx context.Context, plan, recovery, enrollment, issuance, image string, receipt []byte, open sshRestoredAccessSessionOpen) (result AccessReceiptPublication, err error) {
	if !lowerDigest.MatchString(issuance) || !lowerDigest.MatchString(image) || len(receipt) == 0 || len(receipt) > maxSSHAccessReceiptBytes {
		return result, ErrInventoryUnsafe
	}
	err = withSSHRestoredAccessSession(ctx, plan, recovery, enrollment, open, func(s *sshAccessSession) error {
		got, err := recordSSHAuthorizedRestoredAccessEvidence(ctx, s.journal, plan, recovery, s.parser, s.run, s.check, s.observe, s.authority, issuance, image, receipt, s.clock)
		result = AccessReceiptPublication(got)
		return err
	})
	return result, err
}

// InspectSystemdRestoredAccess is read-only and conservatively refuses expired
// enrollment or challenges. Empty recordSHA requires the evidence slot absent;
// a supplied digest approves exact evidence bytes whose inode is pinned during
// inspection. No observed record establishes its original writer's durability.
func InspectSystemdRestoredAccess(ctx context.Context, plan, recovery, enrollment, issuance, issuanceImage, recordSHA string) (RestoredAccessInspection, error) {
	if err := validateSSHRestoredAccessAdapter(ctx, plan, recovery, enrollment, true); err != nil {
		return RestoredAccessInspection{}, err
	}
	return inspectSystemdRestoredAccess(ctx, plan, recovery, enrollment, issuance, issuanceImage, recordSHA, openSSHRestoredAccessSession)
}

func inspectSystemdRestoredAccess(ctx context.Context, plan, recovery, enrollment, issuance, issuanceImage, recordSHA string, open sshRestoredAccessSessionOpen) (result RestoredAccessInspection, err error) {
	if !lowerDigest.MatchString(issuance) || !lowerDigest.MatchString(issuanceImage) || (recordSHA != "" && !lowerDigest.MatchString(recordSHA)) {
		return result, ErrInventoryUnsafe
	}
	err = withSSHRestoredAccessSession(ctx, plan, recovery, enrollment, open, func(s *sshAccessSession) error {
		var err error
		result, err = inspectSSHAuthorizedRestoredAccess(ctx, s.journal, plan, recovery, s.parser, s.run, s.check, s.observe, s.authority, issuance, issuanceImage, recordSHA, s.clock)
		return err
	})
	if err != nil {
		result = RestoredAccessInspection{}
	}
	return result, err
}

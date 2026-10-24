//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// AccessRequestPreview contains private route and public-key pins. Callers must
// keep it private and obtain approval of RequestSHA256 before issuing a challenge.
// It contains no authentication or signing private key and is not access proof.
type AccessRequestPreview struct {
	RequestSHA256    string `json:"request_sha256"`
	Request          []byte `json:"request"`
	RecoveryRequired bool   `json:"recovery_required"`
}

// AccessChallengePublication preserves partial write facts on error, while
// suppressing delivery bytes. A failed operation may have occupied the one-time
// slot and must not be retried by deleting its record.
type AccessChallengePublication struct {
	Transaction         string `json:"transaction"`
	IssuanceSHA256      string `json:"issuance_sha256"`
	IssuanceImageSHA256 string `json:"issuance_image_sha256"`
	IssuanceDurable     bool   `json:"issuance_durable"`
	Request             []byte `json:"request,omitempty"`
	Challenge           []byte `json:"challenge,omitempty"`
	RecoveryRequired    bool   `json:"recovery_required"`
}

// AccessReceiptPublication is a durable observation, never a claim that the
// daemon consumed policy or that migration/recovery has completed.
type AccessReceiptPublication struct {
	Transaction      string `json:"transaction"`
	RecordSHA256     string `json:"record_sha256"`
	RecordDurable    bool   `json:"record_durable"`
	RecoveryRequired bool   `json:"recovery_required"`
}

type sshAccessSession struct {
	journal   *sshJournal
	parser    string
	run       sshParserRun
	check     func() error
	observe   sshEndpointObserver
	authority *sshAccessAuthority
	clock     func() time.Time
	close     func() error
}

type sshAccessSessionOpen func(context.Context, string, string) (*sshAccessSession, error)

func openSSHAccessSession(ctx context.Context, plan, enrollment string) (_ *sshAccessSession, err error) {
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	var authority *sshAccessAuthority
	var daemon *pinnedSSHD
	var journal *sshJournal
	closeAll := func() error {
		var errs []error
		if journal != nil {
			errs = append(errs, journal.Close())
		}
		if daemon != nil {
			errs = append(errs, daemon.file.Close())
		}
		if authority != nil {
			errs = append(errs, authority.Close())
		}
		return errors.Join(append(errs, root.Close())...)
	}
	keep := false
	defer func() {
		if !keep {
			err = errors.Join(err, closeAll())
		}
	}()
	authority, err = openSSHAccessAuthority(root, 0, plan, enrollment, time.Now)
	if err != nil {
		return nil, err
	}
	daemon, err = openSSHD(root, 0)
	if err != nil {
		return nil, err
	}
	journal, err = openSSHJournal(root, 0)
	if err != nil {
		return nil, err
	}
	check := func() error { return errors.Join(ctx.Err(), authority.recheck(), daemon.recheck(root, 0)) }
	if err := check(); err != nil {
		return nil, err
	}
	keep = true
	return &sshAccessSession{journal, daemon.digest, daemon.run, check, observeSSHConfiguredListeners, authority, time.Now, closeAll}, nil
}

func validateSSHAccessAdapter(ctx context.Context, plan, enrollment string, root bool) error {
	if ctx == nil || !lowerDigest.MatchString(plan) || !lowerDigest.MatchString(enrollment) {
		return errors.New("SSH access exchange requires an original plan and independently approved enrollment SHA-256")
	}
	if root && os.Geteuid() != 0 {
		return errors.New("SSH access exchange requires root")
	}
	return ctx.Err()
}

func withSSHAccessSession(ctx context.Context, plan, enrollment string, open sshAccessSessionOpen, action func(*sshAccessSession) error) (err error) {
	if err := validateSSHAccessAdapter(ctx, plan, enrollment, false); err != nil {
		return err
	}
	if open == nil || action == nil {
		return ErrInventoryUnsafe
	}
	session, openErr := open(ctx, plan, enrollment)
	if session != nil && session.close != nil {
		defer func() { err = errors.Join(err, session.close()) }()
	}
	if openErr != nil {
		return openErr
	}
	if session == nil || session.journal == nil || session.run == nil || session.check == nil || session.observe == nil || session.authority == nil || session.clock == nil || session.close == nil ||
		session.authority.plan != plan || session.authority.digest != enrollment {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), session.check(), session.authority.recheck()); err != nil {
		return err
	}
	return action(session)
}

// PrepareSystemdAccessRequest uses only fixed protected production paths. It
// performs parser/endpoint inspection, never networking, issuance or repair.
func PrepareSystemdAccessRequest(ctx context.Context, plan, enrollment string) (AccessRequestPreview, error) {
	if err := validateSSHAccessAdapter(ctx, plan, enrollment, true); err != nil {
		return AccessRequestPreview{}, err
	}
	return prepareSystemdAccessRequest(ctx, plan, enrollment, openSSHAccessSession)
}

func prepareSystemdAccessRequest(ctx context.Context, plan, enrollment string, open sshAccessSessionOpen) (result AccessRequestPreview, err error) {
	err = withSSHAccessSession(ctx, plan, enrollment, open, func(s *sshAccessSession) error {
		request, err := prepareSSHActivationAccessRequest(ctx, s.journal, plan, s.parser, s.run, s.check, s.observe, s.authority.pins)
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

// IssueSystemdAccessChallenge needs independent approval of the current private
// request, in addition to plan and enrollment approval. It creates only the
// single-use journal record, not a network connection or a reload request.
func IssueSystemdAccessChallenge(ctx context.Context, plan, enrollment, request string, lifetime time.Duration) (AccessChallengePublication, error) {
	if err := validateSSHAccessAdapter(ctx, plan, enrollment, true); err != nil {
		return AccessChallengePublication{}, err
	}
	return issueSystemdAccessChallenge(ctx, plan, enrollment, request, lifetime, openSSHAccessSession)
}

func issueSystemdAccessChallenge(ctx context.Context, plan, enrollment, request string, lifetime time.Duration, open sshAccessSessionOpen) (result AccessChallengePublication, err error) {
	if !lowerDigest.MatchString(request) || lifetime < time.Second || lifetime > 5*time.Minute || lifetime%time.Second != 0 {
		return result, fmt.Errorf("SSH access issuance requires an exact request SHA-256 and a whole-second lifetime from 1 to 300 seconds")
	}
	err = withSSHAccessSession(ctx, plan, enrollment, open, func(s *sshAccessSession) error {
		got, err := issueSSHAuthorizedAccessChallenge(ctx, s.journal, plan, s.parser, s.run, s.check, s.observe, s.authority, request, lifetime, s.clock)
		result = AccessChallengePublication(got)
		return err
	})
	if err != nil {
		result.Request, result.Challenge = nil, nil
	}
	return result, err
}

// RecordSystemdAccessReceipt reads the separately approved issuance record and
// uses the current protected enrollment key. Untrusted receipt input cannot
// choose keys, routes, paths or approval. This function never authenticates.
func RecordSystemdAccessReceipt(ctx context.Context, plan, enrollment, issuance, image string, receipt []byte) (AccessReceiptPublication, error) {
	if err := validateSSHAccessAdapter(ctx, plan, enrollment, true); err != nil {
		return AccessReceiptPublication{}, err
	}
	return recordSystemdAccessReceipt(ctx, plan, enrollment, issuance, image, receipt, openSSHAccessSession)
}

func recordSystemdAccessReceipt(ctx context.Context, plan, enrollment, issuance, image string, receipt []byte, open sshAccessSessionOpen) (result AccessReceiptPublication, err error) {
	if !lowerDigest.MatchString(issuance) || !lowerDigest.MatchString(image) || len(receipt) == 0 || len(receipt) > maxSSHAccessReceiptBytes {
		return result, ErrInventoryUnsafe
	}
	err = withSSHAccessSession(ctx, plan, enrollment, open, func(s *sshAccessSession) error {
		got, err := recordSSHAuthorizedAccessEvidence(ctx, s.journal, plan, s.parser, s.run, s.check, s.observe, s.authority, issuance, image, receipt, s.clock)
		result = AccessReceiptPublication(got)
		return err
	})
	return result, err
}

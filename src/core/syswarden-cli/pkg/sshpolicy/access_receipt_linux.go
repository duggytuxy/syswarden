//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	maxSSHAccessChallengeBytes = 2048
	maxSSHAccessReceiptBytes   = 16 << 10
	sshAccessChallengeDomain   = "syswarden-ssh-access-challenge-v1"
	sshAccessReceiptDomain     = "syswarden-ssh-access-receipt-v1"
)

// A challenge is private caller-held state, not an enrollment or durable grant.
// Independent approval binds its complete bytes, including the controller pin.
type sshAccessChallenge struct {
	Schema     int    `json:"schema"`
	Domain     string `json:"domain"`
	Request    string `json:"request_sha256"`
	Controller string `json:"controller_sha256"`
	Nonce      string `json:"nonce"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

type sshAccessReceipt struct {
	Schema      int                       `json:"schema"`
	Domain      string                    `json:"domain"`
	Challenge   string                    `json:"challenge_sha256"`
	StartedAt   int64                     `json:"started_at"`
	CompletedAt int64                     `json:"completed_at"`
	Batch       sshAccessBatchObservation `json:"batch"`
}

type sshAccessSignedReceipt struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// These bytes and the public key must come through independently authorized
// delivery. A receipt never supplies its own trusted controller key.
type sshAccessReceiptInput struct {
	Request           []byte
	Challenge         []byte
	Receipt           []byte
	ApprovedChallenge string
	Controller        ed25519.PublicKey
}

type sshAccessReceiptAssessment struct {
	RequestSHA256    string
	ChallengeSHA256  string
	ReceiptSHA256    string
	ControllerSHA256 string
	ContextsObserved int
	RecoveryRequired bool
}

func newSSHAccessChallenge(request []byte, approved string, controller ed25519.PublicKey, now time.Time, lifetime time.Duration) ([]byte, error) {
	if _, err := parseSSHAccessRequest(request, approved); err != nil {
		return nil, err
	}
	if len(controller) != ed25519.PublicKeySize || now.Unix() <= 0 || lifetime < time.Second || lifetime > 5*time.Minute || lifetime%time.Second != 0 {
		return nil, ErrInventoryUnsafe
	}
	expires := now.Add(lifetime).Unix()
	if expires <= now.Unix() {
		return nil, ErrInventoryUnsafe
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return json.Marshal(sshAccessChallenge{1, sshAccessChallengeDomain, approved, digestBytes(controller), hex.EncodeToString(nonce[:]), now.Unix(), expires})
}

func parseSSHAccessChallenge(wire []byte, approved string, now time.Time) (sshAccessChallenge, error) {
	var c sshAccessChallenge
	if len(wire) == 0 || len(wire) > maxSSHAccessChallengeBytes || !lowerDigest.MatchString(approved) || digestBytes(wire) != approved {
		return c, ErrInventoryUnsafe
	}
	if err := json.Unmarshal(wire, &c); err != nil {
		return sshAccessChallenge{}, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(wire, canonical) || c.Schema != 1 || c.Domain != sshAccessChallengeDomain ||
		!lowerDigest.MatchString(c.Request) || !lowerDigest.MatchString(c.Controller) || !lowerDigest.MatchString(c.Nonce) ||
		c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 300 || now.Unix() < c.IssuedAt || now.Unix() >= c.ExpiresAt {
		return sshAccessChallenge{}, ErrInventoryUnsafe
	}
	return c, nil
}

// Only actual all-context transport execution can produce a controller receipt.
// The clock and authorization guard are trusted, promptly returning dependencies.
// No controller secret or authentication credential is sent to target preparation.
func probeSSHAccessChallenge(parent context.Context, requestWire, challengeWire []byte, approved string,
	key ed25519.PrivateKey, credentials []sshAccessCredentials, clock func() time.Time, guard func() error) (wire []byte, err error) {
	if parent == nil || clock == nil || guard == nil || len(key) != ed25519.PrivateKeySize ||
		len(requestWire) == 0 || len(requestWire) > maxSSHAccessRequestBytes || len(challengeWire) == 0 || len(challengeWire) > maxSSHAccessChallengeBytes {
		return nil, ErrInventoryUnsafe
	}
	requestWire, challengeWire, key = bytes.Clone(requestWire), bytes.Clone(challengeWire), bytes.Clone(key)
	defer clear(key)
	// Reject inconsistent seed/public halves instead of accepting malformed private keys.
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	same := bytes.Equal(key, derived)
	clear(derived)
	if !same {
		return nil, ErrInventoryUnsafe
	}
	started := clock()
	challenge, err := parseSSHAccessChallenge(challengeWire, approved, started)
	if err != nil || challenge.Controller != digestBytes(key[ed25519.SeedSize:]) || challenge.Request != digestBytes(requestWire) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	last := started
	check := func() error {
		authorizationErr := guard()
		now := clock()
		if now.Before(last) {
			return ErrInventoryChanged
		}
		last = now
		if _, err := parseSSHAccessChallenge(challengeWire, approved, now); err != nil {
			return err
		}
		return errors.Join(authorizationErr, parent.Err())
	}
	defer func() {
		if err == nil {
			err = check()
		}
		if err != nil {
			wire = nil
		}
	}()
	if err := check(); err != nil {
		return nil, err
	}
	batch, err := probeSSHActivationAccessRequest(parent, requestWire, challenge.Request, credentials, check)
	if err != nil {
		return nil, err
	}
	if err := check(); err != nil {
		return nil, err
	}
	receipt := sshAccessReceipt{1, sshAccessReceiptDomain, approved, started.Unix(), last.Unix(), batch}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	wire, err = json.Marshal(sshAccessSignedReceipt{payload, ed25519.Sign(key, payload)})
	if err != nil || len(wire) > maxSSHAccessReceiptBytes {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	return wire, nil
}

func copySSHAccessReceiptInput(input sshAccessReceiptInput) (sshAccessReceiptInput, error) {
	if len(input.Request) == 0 || len(input.Request) > maxSSHAccessRequestBytes ||
		len(input.Challenge) == 0 || len(input.Challenge) > maxSSHAccessChallengeBytes ||
		len(input.Receipt) == 0 || len(input.Receipt) > maxSSHAccessReceiptBytes || len(input.Controller) != ed25519.PublicKeySize {
		return sshAccessReceiptInput{}, ErrInventoryUnsafe
	}
	input.Request, input.Challenge, input.Receipt, input.Controller = bytes.Clone(input.Request), bytes.Clone(input.Challenge), bytes.Clone(input.Receipt), bytes.Clone(input.Controller)
	return input, nil
}

func verifySSHAccessReceipt(input sshAccessReceiptInput, now time.Time) (sshAccessReceiptAssessment, error) {
	empty := sshAccessReceiptAssessment{}
	if len(input.Receipt) == 0 || len(input.Receipt) > maxSSHAccessReceiptBytes || len(input.Controller) != ed25519.PublicKeySize {
		return empty, ErrInventoryUnsafe
	}
	challenge, err := parseSSHAccessChallenge(input.Challenge, input.ApprovedChallenge, now)
	if err != nil || challenge.Controller != digestBytes(input.Controller) {
		return empty, errors.Join(ErrInventoryUnsafe, err)
	}
	request, err := parseSSHAccessRequest(input.Request, challenge.Request)
	if err != nil {
		return empty, err
	}
	var signed sshAccessSignedReceipt
	if err := json.Unmarshal(input.Receipt, &signed); err != nil {
		return empty, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(input.Receipt, canonical) || len(signed.Payload) == 0 || len(signed.Payload) > maxSSHAccessReceiptBytes ||
		len(signed.Signature) != ed25519.SignatureSize || !ed25519.Verify(input.Controller, signed.Payload, signed.Signature) {
		return empty, ErrInventoryUnsafe
	}
	var receipt sshAccessReceipt
	if err := json.Unmarshal(signed.Payload, &receipt); err != nil {
		return empty, ErrInventoryUnsafe
	}
	canonical, err = json.Marshal(receipt)
	if err != nil || !bytes.Equal(signed.Payload, canonical) || receipt.Schema != 1 || receipt.Domain != sshAccessReceiptDomain ||
		receipt.Challenge != input.ApprovedChallenge || receipt.StartedAt < challenge.IssuedAt || receipt.CompletedAt < receipt.StartedAt ||
		receipt.CompletedAt > now.Unix() || receipt.CompletedAt >= challenge.ExpiresAt || !receipt.Batch.RecoveryRequired ||
		receipt.Batch.RequestSHA256 != challenge.Request || len(receipt.Batch.Observations) != len(request.Routes) {
		return empty, ErrInventoryUnsafe
	}
	seen := make(map[string]bool)
	pinID := func(pin sshAccessPin) sshAccessIdentity {
		return sshAccessIdentity{pin.Address, pin.User, digestBytes(pin.HostKey), digestBytes(pin.ClientKey)}
	}
	for index, route := range request.Routes {
		observation := receipt.Batch.Observations[index]
		var jump *sshAccessIdentity
		if route.Jump != nil {
			id := pinID(*route.Jump)
			jump = &id
		}
		binding := sshAccessBinding{request.Transaction, request.Plan, request.Intent, request.Target, challenge.Request, route.Access}
		expected, err := sshAccessBindingDigest(binding, pinID(route.Target), jump)
		if err != nil || observation.BindingSHA256 != expected || !observation.RecoveryRequired ||
			(route.Jump == nil && observation.JumpSessionSHA256 != "") || (route.Jump != nil && !lowerDigest.MatchString(observation.JumpSessionSHA256)) {
			return empty, ErrInventoryUnsafe
		}
		// Every authentication and challenge must be distinct across the entire batch.
		values := []string{observation.ChallengeSHA256, observation.SessionSHA256}
		if route.Jump != nil {
			values = append(values, observation.JumpSessionSHA256)
		}
		for _, digest := range values {
			if !lowerDigest.MatchString(digest) || seen[digest] {
				return empty, ErrInventoryUnsafe
			}
			seen[digest] = true
		}
	}
	return sshAccessReceiptAssessment{challenge.Request, input.ApprovedChallenge, digestBytes(input.Receipt), challenge.Controller, len(request.Routes), true}, nil
}

// Read-only appraisal, not receipt acceptance: no replay token is consumed and
// no durable completion record is written. Repeated appraisal is diagnostic.
// The target regenerates the request under its protected assessment guards and
// requires exact current state before returning a hash-only result.
func assessSSHActivationAccessReceipt(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins,
	input sshAccessReceiptInput, clock func() time.Time, authorize func() error) (result sshAccessReceiptAssessment, err error) {
	return withSSHActivationAccessReceipt(ctx, journal, approved, parser, run, parserCheck, observe, pins, input, clock, authorize, nil)
}

// The optional private action runs after exact current-request appraisal, inside
// the original lock and final guards. It receives only frozen public input.
func withSSHActivationAccessReceipt(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins,
	input sshAccessReceiptInput, clock func() time.Time, authorize func() error,
	action func(*sshActivationAssessment, sshAccessReceiptInput, time.Time, func() error) error) (result sshAccessReceiptAssessment, err error) {
	return withSSHIssuedAccessReceipt(ctx, journal, approved, parser, run, parserCheck, observe, pins, input, clock, authorize, nil, action)
}

func withSSHIssuedAccessReceipt(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins,
	input sshAccessReceiptInput, clock func() time.Time, authorize func() error, issuance *sshFileImage,
	action func(*sshActivationAssessment, sshAccessReceiptInput, time.Time, func() error) error) (result sshAccessReceiptAssessment, err error) {
	if ctx == nil || clock == nil || authorize == nil {
		return result, ErrInventoryUnsafe
	}
	input, err = copySSHAccessReceiptInput(input)
	if err != nil {
		return result, err
	}
	started := clock()
	if _, err := verifySSHAccessReceipt(input, started); err != nil {
		return result, err
	}
	last := started
	guard := func() error {
		authorizationErr := authorize()
		now := clock()
		if now.Before(last) {
			return ErrInventoryChanged
		}
		last = now
		_, err := verifySSHAccessReceipt(input, now)
		return errors.Join(err, authorizationErr, ctx.Err())
	}
	defer func() {
		if err != nil {
			result = sshAccessReceiptAssessment{}
		}
	}()
	if parserCheck == nil {
		return result, ErrInventoryUnsafe
	}
	if err := guard(); err != nil {
		return result, err
	}
	// The final shared guard calls authorization before checking protected files.
	// No authorization callback runs after those final inode checks.
	_, err = withSSHActivationAccessAssessment(ctx, journal, approved, parser, run,
		func() error { return errors.Join(guard(), parserCheck(), ctx.Err()) }, observe, nil, issuance,
		func(_ context.Context, a *sshActivationAssessment, summary ActivationAssessment, recheck func() error) error {
			current, err := makeSSHActivationAccessRequest(a, summary, pins)
			if err != nil || !bytes.Equal(current, input.Request) {
				return errors.Join(ErrInventoryChanged, err)
			}
			if err := recheck(); err != nil {
				return err
			}
			result, err = verifySSHAccessReceipt(input, last)
			if err == nil && action != nil {
				err = action(a, input, last, recheck)
			}
			return err
		})
	return result, err
}

//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// ControllerAccessCredentials is controller-local secret input. Its complete
// bytes require independent approval. Never transfer this document to a target.
// Keys are byte strings encoded as base64 by JSON, not paths or agent references.
type ControllerAccessCredentials struct {
	Schema      int                          `json:"schema"`
	SigningSeed []byte                       `json:"signing_seed"`
	Routes      []ControllerAccessCredential `json:"routes"`
}

type ControllerAccessCredential struct {
	ContextID string `json:"context_id"`
	Target    []byte `json:"target"`
	Jump      []byte `json:"jump,omitempty"`
}

// ProbeAccessChallenge authenticates all independently approved routes from the
// controller. It does not load target configuration, publish policy or acknowledge
// consumption. The guard must recheck the controller's protected local inputs.
func ProbeAccessChallenge(ctx context.Context, request, challenge []byte, requestSHA, challengeSHA string,
	secret []byte, guard func() error) ([]byte, error) {
	return probeAccessChallengeWithParser(ctx, request, challenge, requestSHA, challengeSHA, secret, guard, parseSSHAccessRequest)
}

// ProbeRestoredAccessChallenge accepts only independently approved restoration
// requests. Authentication is an observation and never completes recovery.
func ProbeRestoredAccessChallenge(ctx context.Context, request, challenge []byte, requestSHA, challengeSHA string,
	secret []byte, guard func() error) ([]byte, error) {
	return probeAccessChallengeWithParser(ctx, request, challenge, requestSHA, challengeSHA, secret, guard, normalizedSSHRestoredAccessRequest)
}

func probeAccessChallengeWithParser(ctx context.Context, request, challenge []byte, requestSHA, challengeSHA string,
	secret []byte, guard func() error, parse sshAccessRequestParser) ([]byte, error) {
	if ctx == nil || guard == nil || parse == nil || len(secret) == 0 || len(secret) > 1<<20 {
		return nil, ErrInventoryUnsafe
	}
	if _, err := parse(request, requestSHA); err != nil {
		return nil, err
	}
	var document ControllerAccessCredentials
	if err := json.Unmarshal(secret, &document); err != nil {
		clearControllerCredentials(&document)
		return nil, ErrInventoryUnsafe
	}
	defer clearControllerCredentials(&document)
	canonical, err := json.Marshal(document)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, secret) || document.Schema != 1 || len(document.SigningSeed) != ed25519.SeedSize ||
		len(document.Routes) == 0 || len(document.Routes) > MaxAccessContexts {
		return nil, ErrInventoryUnsafe
	}
	credentials := make([]sshAccessCredentials, 0, len(document.Routes))
	for _, route := range document.Routes {
		if !contextID.MatchString(route.ContextID) || len(route.Target) == 0 || len(route.Target) > 16<<10 || len(route.Jump) > 16<<10 {
			return nil, ErrInventoryUnsafe
		}
		credentials = append(credentials, sshAccessCredentials(route))
	}
	key := ed25519.NewKeyFromSeed(document.SigningSeed)
	defer clear(key)
	return probeSSHAccessChallengeWithParser(ctx, request, challenge, challengeSHA, key, credentials, time.Now, guard, parse)
}

func clearControllerCredentials(document *ControllerAccessCredentials) {
	clear(document.SigningSeed)
	for _, route := range document.Routes {
		clear(route.Target)
		clear(route.Jump)
	}
}

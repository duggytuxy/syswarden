//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// RuntimeRecoverySummary reports facts from this invocation, never acceptance
// of loaded policy, authenticated access or a completed recovery. Private
// configuration, history, process identifiers and endpoints are omitted.
type RuntimeRecoverySummary struct {
	Schema                int    `json:"schema"`
	Operation             string `json:"operation"`
	PlanSHA256            string `json:"plan_sha256"`
	RecoverySHA256        string `json:"recovery_sha256"`
	Transaction           string `json:"transaction"`
	IntentDurable         bool   `json:"intent_durable"`
	ConfigurationRestored bool   `json:"configuration_restored"`
	RequestReturned       bool   `json:"request_returned"`
	RecoveryRequired      bool   `json:"recovery_required"`
	RuntimeActivated      bool   `json:"runtime_activated"`
	AccessVerified        bool   `json:"access_verified"`
}

// InspectSystemdRecovery reads only fixed protected paths. It neither repairs
// durability nor provisions state and never signals the retained daemon.
func InspectSystemdRecovery(ctx context.Context, original string) (RuntimeRecoverySummary, error) {
	return systemdSSHRecovery(ctx, original, "", false)
}

// RestoreOriginalSystemd requires a distinct exact recovery approval. It never
// silently falls back to inspection. Partial facts survive errors, including
// resource closure failure, because a reload may already have been requested.
func RestoreOriginalSystemd(ctx context.Context, original, recovery string) (RuntimeRecoverySummary, error) {
	return systemdSSHRecovery(ctx, original, recovery, true)
}

func validSSHRecoveryRequest(ctx context.Context, original, recovery string, apply bool) error {
	if ctx == nil || !lowerDigest.MatchString(original) ||
		(apply && !lowerDigest.MatchString(recovery)) || (!apply && recovery != "") {
		return fmt.Errorf("SSH recovery requires the original lowercase plan SHA-256 and a separate recovery SHA-256 for application")
	}
	return ctx.Err()
}

func systemdSSHRecovery(ctx context.Context, original, recovery string, apply bool) (RuntimeRecoverySummary, error) {
	if err := validSSHRecoveryRequest(ctx, original, recovery, apply); err != nil {
		return RuntimeRecoverySummary{}, err
	}
	if os.Geteuid() != 0 {
		return RuntimeRecoverySummary{}, fmt.Errorf("SSH recovery requires root")
	}
	return runSSHRecoverySession(ctx, original, recovery, apply, openSSHRecoverySession)
}

type sshRecoverySession struct {
	journal *sshJournal
	parser  string
	run     sshParserRun
	check   func() error
	bind    sshActivationBind
	close   func() error
}

// Only this production opener selects live paths. Fixtures may supply an
// isolated opener to the private session runner, never to an exported API.
func openSSHRecoverySession(ctx context.Context) (_ *sshRecoverySession, err error) {
	if ctx == nil || os.Geteuid() != 0 {
		return nil, ErrInventoryUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	var daemon *pinnedSSHD
	var journal *sshJournal
	closeResources := func() error {
		var result error
		if journal != nil {
			result = errors.Join(result, journal.Close())
		}
		if daemon != nil {
			result = errors.Join(result, daemon.file.Close())
		}
		return errors.Join(result, root.Close())
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeResources())
		}
	}()
	daemon, err = openSSHD(root, 0)
	if err != nil {
		return nil, err
	}
	journal, err = openSSHJournal(root, 0)
	if err != nil {
		return nil, err
	}
	return &sshRecoverySession{journal, daemon.digest, daemon.run,
		func() error { return errors.Join(ctx.Err(), daemon.recheck(root, 0)) },
		bindSSHSystemdActivation, closeResources}, nil
}

func runSSHRecoverySession(ctx context.Context, original, recovery string, apply bool,
	open func(context.Context) (*sshRecoverySession, error)) (summary RuntimeRecoverySummary, err error) {
	// Inspection can never present a plan when any final close failed.
	defer func() {
		if err != nil && !apply {
			summary = RuntimeRecoverySummary{}
		}
	}()
	if err := validSSHRecoveryRequest(ctx, original, recovery, apply); err != nil {
		return summary, err
	}
	if open == nil {
		return summary, ErrInventoryUnsafe
	}
	session, openErr := open(ctx)
	if session != nil && session.close != nil {
		defer func() { err = errors.Join(err, session.close()) }()
	}
	if openErr != nil {
		return summary, openErr
	}
	if session == nil || session.close == nil {
		return summary, ErrInventoryUnsafe
	}
	result, err := recoverSSHActivatedConfiguration(ctx, session.journal, original, session.parser, recovery,
		session.run, session.check, session.bind, sshPublicationDefaults())
	if result.Transaction != "" {
		summary = RuntimeRecoverySummary{Schema: 1, Operation: "restore-original", PlanSHA256: original,
			RecoverySHA256: result.RecoverySHA256, Transaction: result.Transaction,
			IntentDurable: result.IntentDurable, ConfigurationRestored: result.ConfigurationRestored,
			RequestReturned: result.RequestReturned, RecoveryRequired: true}
	}
	return summary, err
}

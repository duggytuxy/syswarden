//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"
)

// This internal coordinator retains the original live process across publication
// and one reload attempt. No CLI or installer activates it until access, recovery
// completion and native lifecycle qualification are integrated.
type sshMigrationResult struct {
	Transaction      string
	Published        bool
	IntentDurable    bool
	RequestReturned  bool
	RecoveryRequired bool
}

type sshMigrationSession struct {
	root      *os.File
	uid       int
	deps      sshTransactionDependencies
	authority *sshAccessAuthority
	bind      sshActivationBind
	close     func() error
}

func beginSSHSystemdMigration(ctx context.Context, plan, enrollment string) (sshMigrationResult, error) {
	if err := validateSSHAccessAdapter(ctx, plan, enrollment, true); err != nil {
		return sshMigrationResult{}, err
	}
	return runSSHMigrationSession(ctx, plan, enrollment, openSSHMigrationSession)
}

func openSSHMigrationSession(ctx context.Context, plan, enrollment string) (_ *sshMigrationSession, err error) {
	if err := validateSSHAccessAdapter(ctx, plan, enrollment, true); err != nil {
		return nil, err
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	var daemon *pinnedSSHD
	var authority *sshAccessAuthority
	closeAll := func() error {
		var daemonErr error
		if daemon != nil {
			daemonErr = daemon.file.Close()
		}
		return errors.Join(authority.Close(), daemonErr, root.Close())
	}
	defer func() {
		if err != nil {
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
	deps := sshTransactionDependencies{
		parserDigest: daemon.digest, run: daemon.run,
		checkParser: func() error { return daemon.recheck(root, 0) },
		resolveLabel: func(ctx context.Context, inventory inventorySnapshot) (*sshTargetLabel, error) {
			return resolveSSHTargetLabel(ctx, root, 0, inventory)
		},
		provision: sshProvisionDefaults(), publication: sshPublicationDefaults(),
	}
	return &sshMigrationSession{root, 0, deps, authority, bindSSHSystemdActivation, closeAll}, nil
}

func runSSHMigrationSession(ctx context.Context, approved, enrollment string,
	open func(context.Context, string, string) (*sshMigrationSession, error)) (result sshMigrationResult, err error) {
	if err := validateSSHAccessAdapter(ctx, approved, enrollment, false); err != nil {
		return result, err
	}
	if open == nil {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	session, openErr := open(ctx, approved, enrollment)
	if session != nil && session.close != nil {
		defer func() { err = errors.Join(err, session.close()) }()
	}
	if openErr != nil {
		return result, openErr
	}
	if session == nil || session.root == nil || session.close == nil || session.authority == nil ||
		session.bind == nil || session.deps.checkParser == nil || session.deps.run == nil ||
		session.authority.plan != approved || session.authority.digest != enrollment {
		return result, ErrInventoryUnsafe
	}
	plan, err := inspectPlan(session.root, session.uid)
	if err != nil || plan.summary.PlanSHA256 != approved || planDigest(plan) != approved || plan.intent.Owner != "syswarden" {
		return result, errors.Join(ErrInventoryChanged, err)
	}
	if err := plan.selection.Authorize(plan.intent.Owner, plan.intent.Profile); err != nil {
		return result, err
	}
	if _, err := bindSSHAccessRoutes(plan.intent.Contexts, session.authority.pins); err != nil {
		return result, err
	}
	check := func() error { return errors.Join(ctx.Err(), session.deps.checkParser(), session.authority.recheck()) }
	beforePublication := func() error {
		current, err := collectPlanInventory(session.root, session.uid)
		if err != nil || !reflect.DeepEqual(current, plan.inventory) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return check()
	}
	if err := beforePublication(); err != nil {
		return result, err
	}
	// Select and retain the actual service before writing configuration. The
	// production lease does not retain this pre-publication inventory guard.
	lease, bindErr := session.bind(ctx, beforePublication)
	leaseOwned := lease != nil
	defer func() {
		if leaseOwned {
			err = errors.Join(err, lease.Close())
		}
	}()
	if err := errors.Join(bindErr, beforePublication()); err != nil {
		return result, err
	}
	if lease == nil || !lowerDigest.MatchString(lease.identity()) {
		return result, ErrInventoryUnsafe
	}
	target := lease.identity()
	deps := session.deps
	deps.checkParser = func() error {
		if lease.identity() != target {
			return ErrInventoryChanged
		}
		return errors.Join(check(), lease.check())
	}
	publication, err := executeSSHTransaction(ctx, session.root, session.uid, approved, deps)
	result.Transaction, result.Published = publication.Transaction, publication.Published
	result.RecoveryRequired = publication.RecoveryRequired || publication.Transaction != ""
	if err != nil || !publication.Published {
		return result, errors.Join(err, ErrInventoryUnsafe)
	}
	// Reopening is not adoption: the original approval, full publication history,
	// retained process and enrollment are checked again before durable intent.
	journal, err := openSSHJournal(session.root, session.uid)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	bound := false
	activation, err := attemptSSHActivation(ctx, journal, approved, deps.parserDigest, deps.run, check,
		func(ctx context.Context, guard func() error) (sshActivationLease, error) {
			if bound || lease.identity() != target {
				return nil, ErrInventoryChanged
			}
			if err := errors.Join(ctx.Err(), guard(), check(), lease.check()); err != nil {
				return nil, err
			}
			bound, leaseOwned = true, false // The dispatcher now owns Close, even on failure.
			return lease, nil
		})
	result.IntentDurable, result.RequestReturned = activation.IntentDurable, activation.RequestReturned
	return result, err
}

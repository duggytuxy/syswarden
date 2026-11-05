//go:build linux

package system

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
)

// This boundary borrows publication custody from its coordinator. Execution
// cleanup closes the borrower, never the owner needed by independent closure.
type apkInactiveExecutionBoundary struct {
	owner    *apkInactiveCustody
	prepared *verifiedPreparedAPKTransition
	closed   bool
}

func (boundary *apkInactiveExecutionBoundary) EffectPlanSHA256() string {
	if boundary == nil || boundary.closed || boundary.owner == nil || boundary.owner.closed {
		return ""
	}
	return boundary.owner.effectSHA256
}

func (boundary *apkInactiveExecutionBoundary) Revalidate(ctx context.Context) error {
	if boundary.EffectPlanSHA256() == "" || boundary.prepared == nil || boundary.prepared.closed || !boundary.prepared.locked || boundary.prepared.digest != boundary.owner.preparationSHA256 {
		return errors.New("APK inactive execution lost original preparation or publication custody")
	}
	return boundary.owner.Revalidate(ctx, false)
}

func (boundary *apkInactiveExecutionBoundary) PrepareLaunchers(ctx context.Context, path string, binding apkLauncherCustodyBinding, original []apkTransitionHostEntry) (apkExecutionLaunchers, error) {
	if err := boundary.Revalidate(ctx); err != nil {
		return nil, err
	}
	if !validSHA256(boundary.owner.executionSHA256) || binding.PlanSHA256 != boundary.owner.executionSHA256 || path != filepath.Join(boundary.prepared.services.root, "execution-"+binding.PlanSHA256) {
		return nil, errors.New("APK inactive launcher mutation requires the exact approved execution")
	}
	// The launcher owner independently verifies the retained execution approval,
	// candidate inventory, original targets and prior ownership transfer.
	return prepareAPKLauncherCustodyWithTargetsAt(ctx, boundary.prepared.services.hostRoot, path, binding, original, boundary.prepared.plan.Inventory, boundary.owner.effectSHA256)
}

func (boundary *apkInactiveExecutionBoundary) AttestResult(ctx context.Context) error {
	if boundary.EffectPlanSHA256() == "" || !validSHA256(boundary.owner.executionSHA256) {
		return errors.New("APK inactive result requires retained execution custody")
	}
	return boundary.owner.Revalidate(ctx, true)
}

func (boundary *apkInactiveExecutionBoundary) Close() error {
	if boundary != nil {
		boundary.closed = true
	}
	return nil
}

// Planning may acquire exclusion to inspect original state, but never binds an
// execution approval. Its owner always closes before returning the review.
func planAPKInactiveTransitionExecution(ctx context.Context, preparation string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, custody apkInactiveCustodyServices) (_ *APKTransitionExecutionReview, result error) {
	var owner *apkInactiveCustody
	defer func() { result = errors.Join(result, owner.Close()) }()
	factory := func(check context.Context, prepared *verifiedPreparedAPKTransition) (apkExecutionBoundary, error) {
		var err error
		owner, err = openAPKInactivePreparationCustody(check, prepared, custody)
		if err != nil {
			return nil, err
		}
		return &apkInactiveExecutionBoundary{owner: owner, prepared: prepared}, nil
	}
	return planAPKTransitionExecution(ctx, preparation, keys, attest, services, factory)
}

type apkInactiveExecute func(context.Context, string, string, map[string]ed25519.PublicKey, installedVersionAttestor, apkTransitionServices, apkExecutionBoundaryFactory) error

// The internal coordinator composes original custody, the real native engine,
// positive execution cleanup and independent terminal verification. It remains
// private until full signed-product native qualification permits public ingress.
func executeAPKInactiveTransition(ctx context.Context, preparation, execution string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, custody apkInactiveCustodyServices) error {
	run := func(check context.Context, preparation, execution string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, factory apkExecutionBoundaryFactory) error {
		return executeAPKTransitionWith(check, preparation, execution, keys, attest, services, factory, apkExecutionServices{})
	}
	return executeAPKInactiveTransitionWith(ctx, preparation, execution, keys, attest, services, custody, run)
}

func executeAPKInactiveTransitionWith(ctx context.Context, preparation, execution string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, custody apkInactiveCustodyServices, run apkInactiveExecute) (result error) {
	if ctx == nil || !validSHA256(preparation) || !validSHA256(execution) || run == nil {
		return errors.New("APK inactive coordination requires separate preparation and execution approvals")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var owner *apkInactiveCustody
	defer func() { result = errors.Join(result, owner.Close()) }()
	factory := func(check context.Context, prepared *verifiedPreparedAPKTransition) (apkExecutionBoundary, error) {
		if owner != nil {
			return nil, errors.New("APK inactive coordination cannot reacquire original custody")
		}
		var err error
		owner, err = openAPKInactiveCustody(check, prepared, execution, custody)
		if err != nil {
			return nil, err
		}
		return &apkInactiveExecutionBoundary{owner: owner, prepared: prepared}, nil
	}
	if err := run(ctx, preparation, execution, keys, attest, services, factory); err != nil {
		return err
	}
	if owner == nil {
		return errors.New("APK inactive execution returned without original publication custody")
	}
	if err := owner.Revalidate(ctx, true); err != nil {
		return err
	}
	if err := retainAPKExecutionClosure(ctx, services.root, execution); err != nil {
		return &APKTransitionExecutionError{Directory: filepath.Join(services.root, "execution-"+execution), Unresolved: true, Cause: err}
	}
	return finalizeAPKInactiveTransition(ctx, execution, keys, attest, services, owner)
}

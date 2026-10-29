//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"reflect"
)

// Only the recovery coordinator constructs this anchor, after validating the
// original publication and exact inverse phase. It is neither serialized nor
// accepted by an exported API. Published values reproduce the existing v1
// selection and v4 target; current values constrain the live parser probe.
type sshRecoveryPolicyAnchor struct {
	parser             string
	published, current sshEffective
}

type sshRecoveryBind func(context.Context, func() error, *sshRecoveryPolicyAnchor) (sshActivationLease, error)

func bindSSHSystemdRecovery(ctx context.Context, guard func() error, anchor *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
	if anchor == nil {
		return nil, ErrInventoryUnsafe
	}
	return bindSSHSystemdTarget(ctx, guard, anchor)
}

func (anchor *sshRecoveryPolicyAnchor) selection(startup StartupSummary, parser string, current sshEffective) (string, error) {
	if anchor == nil || parser != anchor.parser || !lowerDigest.MatchString(parser) || len(anchor.published) == 0 || len(anchor.current) == 0 {
		return "", ErrInventoryUnsafe
	}
	if err := compareEffective(anchor.current, current, nil); err != nil {
		return "", err
	}
	publishedEndpoints, publishedErr := sshExpectedEndpoints(anchor.published)
	currentEndpoints, currentErr := sshExpectedEndpoints(current)
	if publishedErr != nil || currentErr != nil || !reflect.DeepEqual(publishedEndpoints, currentEndpoints) {
		return "", errors.Join(ErrInventoryChanged, publishedErr, currentErr)
	}
	// The ordinary binder already verified the current selected main path and
	// full effective policy. Hash the sealed published policy here, so an
	// approved inverse transition cannot invalidate its own saved target.
	return sshConfigurationSelectionDigest(startup, parser, anchor.published)
}

func prepareSSHRecoveryPolicyAnchor(ctx context.Context, plan migrationPlan, parser string, position sshPublicationPosition,
	run sshParserRun, guard func() error) (*sshRecoveryPolicyAnchor, error) {
	if ctx == nil || run == nil || guard == nil || !lowerDigest.MatchString(parser) {
		return nil, ErrInventoryUnsafe
	}
	completed := position.Step
	switch position.State {
	case "before":
		if completed < 1 || completed > 2 {
			return nil, ErrInventoryUnsafe
		}
		completed--
	case "after":
		if completed < 1 || completed > 2 {
			return nil, ErrInventoryUnsafe
		}
	case "complete":
		if completed < 0 || completed > 2 {
			return nil, ErrInventoryUnsafe
		}
	default:
		return nil, ErrInventoryUnsafe
	}
	parse := func(inverse int, access string) (values sshEffective, err error) {
		files := make(map[string][]byte, len(plan.inventory.files)+1)
		for name, data := range plan.inventory.files {
			if isSSHConfiguration(name) {
				files[name] = data
			}
		}
		if inverse < 2 {
			files[DropInPath] = plan.candidate.Bytes()
		}
		if inverse == 0 {
			files[MainPath] = plan.main
		}
		image, err := newParserImage(files)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, image.Close()) }()
		wire, err := sshRollbackParserCall(ctx, run, guard, image, "effective", access)
		defer clear(wire)
		if err != nil {
			return nil, err
		}
		return parseEffective(wire)
	}
	published, err := parse(0, "")
	if err != nil {
		return nil, err
	}
	current := published
	if completed != 0 {
		current, err = parse(completed, "")
		if err != nil {
			return nil, err
		}
	}
	if _, err := sshRollbackParserCall(ctx, run, guard, nil, "syntax", ""); err != nil {
		return nil, err
	}
	contexts := []string{""}
	for _, access := range plan.intent.Contexts {
		contexts = append(contexts, access.sshdArgument())
	}
	for _, access := range contexts {
		wanted := current
		if access != "" {
			wanted, err = parse(completed, access)
			if err != nil {
				return nil, err
			}
		}
		wire, err := sshRollbackParserCall(ctx, run, guard, nil, "effective", access)
		if err != nil {
			clear(wire)
			return nil, err
		}
		actual, err := parseEffective(wire)
		clear(wire)
		if err := errors.Join(err, compareEffective(wanted, actual, nil)); err != nil {
			return nil, err
		}
	}
	if err := errors.Join(ctx.Err(), guard()); err != nil {
		return nil, err
	}
	return &sshRecoveryPolicyAnchor{parser: parser, published: published, current: current}, nil
}

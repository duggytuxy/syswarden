//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"strings"
)

func sshRollbackParserCall(ctx context.Context, run sshParserRun, guard func() error, image *parserImage, mode, access string) ([]byte, error) {
	if err := guard(); err != nil {
		return nil, err
	}
	output, err := run(ctx, image, mode, access)
	return output, errors.Join(err, guard())
}

// Check all inverse graphs with the currently pinned parser. Unlike forward
// verification, the current live graph need not be the original baseline.
func verifySSHRollbackCandidates(ctx context.Context, plan migrationPlan, run sshParserRun, guard func() error) error {
	files := make(map[string][]byte, len(plan.inventory.files))
	for name, data := range plan.inventory.files {
		if isSSHConfiguration(name) {
			files[name] = data
		}
	}
	images := make([]*parserImage, 0, 3)
	defer func() {
		for _, image := range images {
			_ = image.Close()
		}
	}()
	for step := 0; step < 3; step++ {
		if step == 1 {
			files[DropInPath] = plan.candidate.Bytes()
		}
		if step == 2 {
			files[MainPath] = plan.main
		}
		image, err := newParserImage(files)
		if err != nil {
			return err
		}
		images = append(images, image)
		if _, err := sshRollbackParserCall(ctx, run, guard, image, "syntax", ""); err != nil {
			return err
		}
	}
	allowed := make(map[string]bool)
	policy, err := directives(plan.candidate.profile)
	if err != nil {
		return err
	}
	for _, item := range policy {
		allowed[strings.ToLower(item.key)] = true
	}
	contexts := []string{""}
	for _, access := range plan.intent.Contexts {
		contexts = append(contexts, access.sshdArgument())
	}
	for _, access := range contexts {
		values := make([]sshEffective, 3)
		for step, image := range images {
			output, err := sshRollbackParserCall(ctx, run, guard, image, "effective", access)
			if err != nil {
				return err
			}
			values[step], err = parseEffective(output)
			if err != nil {
				return err
			}
			if step == 2 {
				if err := plan.candidate.CheckEffective(output); err != nil {
					return err
				}
			}
		}
		if err := errors.Join(compareEffective(values[0], values[2], allowed), compareSSHIntermediate(values[0], values[1], values[2], allowed)); err != nil {
			return err
		}
	}
	return guard()
}

func verifySSHRestored(ctx context.Context, journal *sshJournal, plan migrationPlan, prepared sshPreparation, expected sshStoredInventory, run sshParserRun, parserCheck func() error) error {
	if !matchesSSHRecovery(expected, MainPath, prepared.MainBefore) || expected.Nodes[DropInPath] != (sshStoredStamp{}) {
		return ErrInventoryChanged
	}
	files := make(map[string][]byte, len(plan.inventory.files))
	for name, data := range plan.inventory.files {
		if isSSHConfiguration(name) {
			files[name] = data
		}
	}
	baseline, err := newParserImage(files)
	if err != nil {
		return err
	}
	defer baseline.Close()
	guard := sshRollbackGuard(ctx, journal, prepared.Transaction, expected, parserCheck)
	if _, err := sshRollbackParserCall(ctx, run, guard, nil, "syntax", ""); err != nil {
		return err
	}
	contexts := []string{""}
	for _, access := range plan.intent.Contexts {
		contexts = append(contexts, access.sshdArgument())
	}
	for _, access := range contexts {
		live, liveErr := sshRollbackParserCall(ctx, run, guard, nil, "effective", access)
		sealed, sealedErr := sshRollbackParserCall(ctx, run, guard, baseline, "effective", access)
		if err := errors.Join(liveErr, sealedErr); err != nil {
			return err
		}
		actual, actualErr := parseEffective(live)
		wanted, wantedErr := parseEffective(sealed)
		if err := errors.Join(actualErr, wantedErr); err != nil {
			return err
		}
		if err := compareEffective(actual, wanted, nil); err != nil {
			return err
		}
	}
	return guard()
}
